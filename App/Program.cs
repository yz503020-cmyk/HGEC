using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Management;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Win32;

namespace DG;

public static class Program
{
  public static string? Code; // קוד הכניסה של התוכנה (בזיכרון בלבד, לאימות מחדש מול השירות)
  static string? ver;

  // גרסת השירות = גיבוב של קובץ ההפעלה. כשמעדכנים את התוכנה, השירות מתעדכן אוטומטית (בלי מספר גרסה ידני)
  public static string Ver
  {
    get
    {
      if (ver == null)
      {
        try
        {
          using var s = File.OpenRead(Environment.ProcessPath!);
          ver = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(s))[..16];
        }
        catch
        {
          ver = "0";
        }
      }
      return ver;
    }
  }

  // ---------- מצב השירות ----------
  static volatile Config cur = new();
  static volatile Dictionary<string, Rule> curMap = new();
  static volatile HashSet<string> killSet = new(StringComparer.OrdinalIgnoreCase);
  static volatile Dictionary<string, string> codeKillMap = new(StringComparer.OrdinalIgnoreCase);
  static readonly ConcurrentDictionary<string, DateTime> tokens = new(),
    lease = new(),
    ruleAuth = new();
  static readonly ConcurrentDictionary<int, (string Rule, DateTime Start)> authPid = new(); // תהליכים שאושרו בקוד (או בנו של תהליך מאושר)
  static readonly ConcurrentDictionary<int, (string Rule, DateTime Start)> promptedPid = new();
  static readonly ConcurrentDictionary<(int Gate, string Rule), DateTime> grants = new(); // אישורים חד-פעמיים ל-AUTHPID: ניתנים רק אחרי VERIFY מוצלח או ISAUTH חיובי מאותו תהליך שער
  static readonly ConcurrentDictionary<string, string> leaseTok = new(); // אסימון PING -> מזהה החוק שנפתח בקוד (רק מי שפתח בקוד יכול להאריך את הפתיחה)
  static readonly ConcurrentDictionary<int, int> connCount = new(); // חיבורים פתוחים לכל לקוח ב-Pipe (הגנה מהצפה)
  static readonly ConcurrentDictionary<int, byte> renameSeen = new(); // תהליכים שכבר נבדקו לזיהוי עותק שהשם שלו שונה
  static readonly ConcurrentDictionary<string, string> origNames = new(StringComparer.OrdinalIgnoreCase);
  static readonly ConcurrentDictionary<string, (long L, DateTime W, string H)> hashCache = new(StringComparer.OrdinalIgnoreCase);
  static volatile Dictionary<long, List<(string Hash, string Name)>> sizeMap = new(); // גודל קובץ -> גיבוב של תוכנות חסומות (זיהוי עותקים ששינו להם שם)
  static volatile bool removing;
  static readonly ConcurrentDictionary<int, int> internalPids = new(); // תהליכים של DeviceGuard עצמו שמריצים כלי מערכת
  static readonly object lk = new();
  static readonly Dictionary<string, (int N, int Level, DateTime Until)> fails = new();
  static int authFails,
    authLevel;
  static DateTime authLock = DateTime.MinValue;
  static int applyBusy;
  static DateTime reconBackoff = DateTime.MinValue;
  static volatile bool overflow;
  static ManagementEventWatcher? pw;
  static readonly Dictionary<string, string[]> alias = new(StringComparer.OrdinalIgnoreCase)
  {
    ["calc"] = new[] { "CalculatorApp", "Calculator" },
    ["SystemSettings"] = new[] { "SystemSettings" },
  };

  // האם החסימות אמורות להיות פעילות כרגע (מתג ראשי, פתיחה זמנית, תזמון)
  public static bool Blocking(Config c) =>
    c.Master && c.TempOpenUntil <= DateTime.UtcNow.Ticks && (!c.Sched.On || c.Sched.Active(c.Sched.NowPinned()));

  public static void InternalAdd(int pid, int d)
  {
    internalPids.AddOrUpdate(pid, d > 0 ? 1 : 0, (k, v) => Math.Max(0, v + d));
    if (internalPids.TryGetValue(pid, out var v2) && v2 <= 0)
      internalPids.TryRemove(pid, out _);
  }

  static bool Locked(string key)
  {
    lock (lk)
      return fails.TryGetValue(key, out var f) && DateTime.UtcNow < f.Until;
  }

  static void Fail(string key, string what)
  {
    lock (lk)
    {
      fails.TryGetValue(key, out var f);
      var n = f.N + 1;
      var lvl = f.Level;
      var until = f.Until;
      Alerts.Log("קוד שגוי: " + what, false);
      if (n >= 5)
      {
        n = 0;
        lvl = Math.Min(lvl + 1, 5);
        until = DateTime.UtcNow.AddSeconds(30 << lvl);
        Alerts.Log("נעילה זמנית אחרי ניסיונות קוד שגויים: " + what);
      }
      fails[key] = (n, lvl, until);
    }
  }

  static void Ok(string key)
  {
    lock (lk)
      fails.Remove(key);
  }

  static void DropTokens(string rid)
  {
    foreach (var kv in leaseTok.ToArray())
      if (kv.Value == rid)
        leaseTok.TryRemove(kv.Key, out _);
  }

  // מונה ניסיונות לפי הקוד שנבדק: כל החסימות שמשתמשות בקוד ברירת המחדל חולקות מונה אחד (אחרת כל חסימה נוספת מכפילה את מספר הניחושים)
  static string LockKey(Rule r, string sid) => r.OwnCode != null ? "r|" + r.Id + "|" + sid : "d|" + sid;

  static bool TokenOk(string t)
  {
    if (tokens.TryGetValue(t, out var d) && (DateTime.UtcNow - d).TotalHours < 8)
      return true;
    tokens.TryRemove(t, out _);
    return false;
  }

  static bool IsAuth(int pid, string rid) => authPid.TryGetValue(pid, out var a) && a.Rule == rid && Native.SameStart(pid, a.Start);

  static bool FromGate(int pid)
  {
    var ip = pid > 0 ? Native.ImagePath(pid) : null;
    if (ip == null)
      return false;
    var full = System.IO.Path.GetFullPath(ip);
    return string.Equals(full, System.IO.Path.GetFullPath(Enforcer.GateExe), StringComparison.OrdinalIgnoreCase)
      || string.Equals(full, System.IO.Path.GetFullPath(Enforcer.LightGateExe), StringComparison.OrdinalIgnoreCase);
  }

  static bool IsAuthAny(int pid) => authPid.TryGetValue(pid, out var a) && Native.SameStart(pid, a.Start);

  // מסמן תהליך כ"נשאל" פעם אחת (לפי זמן ההתחלה, כך שמספר תהליך שנעשה בו שימוש חוזר לא יידלג)
  static bool TryPrompt(int pid, string rid)
  {
    DateTime st;
    try
    {
      using var pr = Process.GetProcessById(pid);
      st = pr.StartTime;
    }
    catch
    {
      return false;
    }
    lock (lk)
    {
      if (promptedPid.TryGetValue(pid, out var v) && v.Start == st)
        return false;
      promptedPid[pid] = (rid, st);
      return true;
    }
  }

  static void RegisterAuth(int pid, string rule)
  {
    try
    {
      using var pr = Process.GetProcessById(pid);
      authPid[pid] = (rule, pr.StartTime);
      ruleAuth[rule] = DateTime.UtcNow;
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  static string ExtOf(string p) => System.IO.Path.GetExtension(p).TrimStart('.').ToLowerInvariant();

  // ---------- שירות ----------
  class GuardService : System.ServiceProcess.ServiceBase
  {
    public GuardService()
    {
      ServiceName = "DeviceGuard";
      CanShutdown = true;
    }

    protected override void OnStart(string[] a)
    {
      new Thread(Watch) { IsBackground = true }.Start();
    }

    protected override void OnShutdown()
    {
      Alerts.Log("המחשב נכבה – השירות נעצר", false);
    } // כיבוי רגיל של המחשב: בלי התראה

    protected override void OnStop()
    {
      if (removing)
        return;
      Alerts.Log("שירות ההגנה נעצר", true, true);
      Alerts.Event("שירות ההגנה נעצר");
    }
  }

  static void LockDir()
  { // תיקיית ההגדרות: רק SYSTEM כותב; מנהלים וקבצי ההפעלה לקריאה. קובץ ההגדרות עצמו נעול גם בפני משתמשים רגילים
    try
    {
      Directory.CreateDirectory(Config.Dir);
      Directory.CreateDirectory(System.IO.Path.Combine(Config.Dir, "var"));
      Directory.CreateDirectory(System.IO.Path.Combine(Config.Dir, "var", "net")); // net = תיקיית חילוץ מוגנת של השירות
      Enforcer.RunExe(
        "icacls",
        $"\"{Config.Dir}\" /inheritance:r /grant *S-1-5-18:(OI)(CI)F /grant *S-1-5-32-544:(OI)(CI)RX /grant *S-1-5-32-545:(OI)(CI)RX"
      );
      Enforcer.RunExe(
        "icacls",
        $"\"{System.IO.Path.Combine(Config.Dir, "var")}\" /inheritance:r /grant *S-1-5-18:(OI)(CI)F /grant *S-1-5-32-544:(OI)(CI)F"
      );
      Config.SecureFile(Config.CfgPath);
      Config.SecureFile(Config.BakPath);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  // ---------- הפעלה / סגירה אוטומטית (תזמון ופתיחה זמנית) ----------
  static void Reconcile(Config c)
  {
    if (Interlocked.CompareExchange(ref applyBusy, 0, 0) != 0 || DateTime.UtcNow < reconBackoff)
      return;
    bool need = Blocking(c),
      applied = c.State == 1 || c.Applied.Count > 0;
    if (need && !applied && c.AnyOn() && (c.Sched.On || c.TempOpenUntil != 0))
      Job(true);
    else if (!need && applied)
      Job(false);
  }

  static void Job(bool apply)
  {
    if (Interlocked.Exchange(ref applyBusy, 1) == 1)
      return;
    Task.Factory.StartNew(
      () =>
      {
        try
        {
          var cfg = Config.TryLoad();
          if (cfg == null)
            return;
          Enforcer.SetSkip(cfg);
          if (apply)
          {
            cfg.TempOpenUntil = 0;
            Alerts.Log(cfg.Sched.On ? "תחילת חלון הזמנים: החסימות מופעלות" : "הפתיחה הזמנית הסתיימה: החסימות מופעלות", false);
            Enforcer.Apply(cfg);
          }
          else
          {
            Alerts.Log("מחוץ לחלון הזמנים: החסימות הוסרו", false);
            Enforcer.Release(cfg);
          }
        }
        catch (Exception x)
        {
          Alerts.Log("שגיאה בהפעלה/הסרה אוטומטית: " + x.Message);
          reconBackoff = DateTime.UtcNow.AddMinutes(2);
        }
        finally
        {
          Interlocked.Exchange(ref applyBusy, 0);
        }
      },
      CancellationToken.None,
      TaskCreationOptions.None,
      Enforcer.Sta
    );
  }

  // ---------- ניטור תהליכים ----------
  static void StartWmi()
  {
    try
    {
      pw = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
      pw.EventArrived += (s, e) =>
      {
        try
        {
          var n = (string)e.NewEvent["ProcessName"];
          int pid = Convert.ToInt32(e.NewEvent["ProcessID"]);
          int ppid = 0;
          try
          {
            ppid = Convert.ToInt32(e.NewEvent["ParentProcessID"]);
          }
          catch (Exception __e)
          {
            Diag.Log(__e);
          }
          HandleProc(n.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? n[..^4] : n, pid, ppid);
        }
        catch (Exception __e)
        {
          Diag.Log(__e);
        }
      };
      pw.Stopped += (s, e) =>
      {
        pw = null;
      }; // ה-Watch ינסה להפעיל מחדש
      pw.Start();
    }
    catch
    {
      pw = null;
    }
  }

  static bool OwnerApplies(Config c, int pid) =>
    c.AllUsers || string.IsNullOrEmpty(c.OwnerSid) || string.Equals(Native.ProcSid(pid), c.OwnerSid, StringComparison.OrdinalIgnoreCase);

  static void KillPid(int pid)
  {
    try
    {
      using var p = Process.GetProcessById(pid);
      p.Kill();
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  static string? OrigNameCached(string path)
  {
    if (origNames.TryGetValue(path, out var v))
      return v.Length == 0 ? null : v;
    var o = Native.OriginalName(path);
    if (origNames.Count > 5000)
      origNames.Clear();
    origNames[path] = o ?? "";
    return o;
  }

  static string? HashOf(string path)
  {
    try
    {
      var fi = new FileInfo(path);
      if (hashCache.TryGetValue(path, out var v) && v.L == fi.Length && v.W == fi.LastWriteTimeUtc)
        return v.H;
      using var s = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
      var h = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(s));
      hashCache[path] = (fi.Length, fi.LastWriteTimeUtc, h);
      return h;
    }
    catch
    {
      return null;
    }
  }

  // עותק של תוכנה חסומה ששונה לו השם (copy notepad.exe x.exe): מזהים לפי שם הקובץ המקורי שבמשאב הגרסה, ואם אין – לפי גיבוב התוכן (רק כשהגודל זהה)
  static string? RenamedIdentity(int pid)
  {
    // כל תהליך נבדק פעם אחת – אבל מסומן כ"נבדק" רק כשהבדיקה הושלמה. אם היא נכשלה (למשל התהליך רק עלה והנתיב עוד לא זמין) – ננסה שוב בסבב הבא
    try
    {
      if (renameSeen.ContainsKey(pid))
        return null;
      var path = Native.ImagePath(pid);
      if (path == null)
        return null;
      var on = OrigNameCached(path);
      if (on != null && (killSet.Contains(on) || codeKillMap.ContainsKey(on)))
      {
        renameSeen.TryAdd(pid, 0);
        return on;
      }
      var sm = sizeMap;
      if (sm.Count == 0)
        return null; // הגיבובים עוד לא חושבו (או שאין) – בדיקה זולה, אפשר לחזור עליה
      long len;
      try
      {
        len = new FileInfo(path).Length;
      }
      catch
      {
        return null;
      }
      if (!sm.TryGetValue(len, out var cands))
      {
        renameSeen.TryAdd(pid, 0);
        return null;
      }
      var h = HashOf(path);
      if (h == null)
        return null;
      renameSeen.TryAdd(pid, 0);
      foreach (var cd in cands)
        if (cd.Hash == h)
          return cd.Name;
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    return null;
  }

  static void HandleProc(string n, int pid, int ppid = 0)
  {
    var c = cur;
    if (!Blocking(c))
      return;
    if (killSet.Count == 0 && codeKillMap.Count == 0)
      return;
    if (!killSet.Contains(n) && !codeKillMap.ContainsKey(n))
    {
      var real = RenamedIdentity(pid);
      if (real == null)
        return;
      n = real;
    }
    if (ppid <= 0)
      ppid = Native.ParentOf(pid);
    if (ppid > 0 && internalPids.ContainsKey(ppid))
      return; // כלי מערכת שהאפליקציה עצמה הפעילה (PowerShell, netsh, sc ...)
    if (killSet.Contains(n))
    {
      if (!OwnerApplies(c, pid) || IsAuthAny(pid))
        return;
      var name = n;
      if (ppid > 0 && FromGate(ppid))
      { // הופעל על ידי השער: ממתינים לרגע שהאישור יירשם (קריאה פנימית מאושרת), ואם אין אישור – סוגרים
        Task.Run(async () =>
        {
          for (int i = 0; i < 15; i++)
          {
            await Task.Delay(100);
            if (IsAuthAny(pid) || !Native.Alive(pid))
              return;
          }
          KillPid(pid);
          Alerts.Log("נסגרה תוכנה חסומה: " + name, false);
        });
        return;
      }
      KillPid(pid);
      Alerts.Log("נסגרה תוכנה חסומה: " + n, false);
      return;
    }
    if (codeKillMap.TryGetValue(n, out var rid) && !IsAuth(pid, rid) && TryPrompt(pid, rid))
    {
      int sess = 0;
      try
      {
        using var p = Process.GetProcessById(pid);
        sess = p.SessionId;
      }
      catch
      {
        return;
      }
      // ממתינים רגע: אם התוכנה הופעלה דרך השער, הקוד כבר הוקש והאישור מגיע בעוד מילישניות
      Task.Run(async () =>
      {
        await Task.Delay(2500);
        try
        {
          if (IsAuth(pid, rid) || !Native.Alive(pid) || !OwnerApplies(c, pid))
            return;
          UserSession.Launch(Enforcer.GateExe, $"--promptkill {rid} {pid}", sess);
        }
        catch (Exception __e)
        {
          Diag.Log(__e);
        }
      });
    }
  }

  static void Reload(Config c)
  {
    var blocking = Blocking(c);
    var ks = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    var ck = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    var progs = new List<(string Name, string Path)>();
    void Names(Rule r, bool full)
    {
      var n = System.IO.Path.GetFileNameWithoutExtension(r.Path);
      if (n.Length == 0 || Enforcer.IsCritical(n))
        return;
      progs.Add((n, r.Path));
      var all = new List<string> { n };
      if (alias.TryGetValue(n, out var al))
        all.AddRange(al);
      foreach (var x in all)
      {
        if (full)
          ks.Add(x);
        else
          ck[x] = r.Id;
      }
    }
    if (blocking)
    {
      foreach (var r in c.Programs.Where(r => r.On))
        Names(r, r.Mode == Mode.Full);
      if (c.Settings.On && c.Settings.Mode == Mode.Code)
        ck["SystemSettings"] = c.Settings.Id; // רשת ביטחון: אפליקציית ההגדרות של Windows לא תמיד נתפסת ב-IFEO
    }
    killSet = ks;
    codeKillMap = ck;
    if (progs.Count == 0)
      sizeMap = new();
    else
      Task.Run(() =>
      { // גיבוב התוכנות החסומות ברקע (לזיהוי עותקים ששינו להם שם)
        var d = new Dictionary<long, List<(string Hash, string Name)>>();
        foreach (var (nm, pth) in progs)
        {
          try
          {
            if (!File.Exists(pth))
              continue;
            var h = HashOf(pth);
            if (h == null)
              continue;
            var len = new FileInfo(pth).Length;
            if (!d.TryGetValue(len, out var l))
              d[len] = l = new();
            l.Add((h, nm));
          }
          catch (Exception __e)
          {
            Diag.Log(__e);
          }
        }
        sizeMap = d;
      });
    curMap = blocking ? Enforcer.ExtMap(c) : new Dictionary<string, Rule>();
    Enforcer.SetSkip(c);
    Alerts.SetUrl(c.AlertUrl);
  }

  // ---------- הפקודות של ה-Pipe ----------
  static string RuleInfo(string id, string sid)
  {
    var c = cur;
    var r = c.Find(id);
    if (r == null)
      return "NONE";
    bool applies =
      Blocking(c)
      && r.On
      && (c.AllUsers || string.IsNullOrEmpty(c.OwnerSid) || string.Equals(sid, c.OwnerSid, StringComparison.OrdinalIgnoreCase));
    var kind =
      c.Paths.Contains(r) ? "path"
      : Enforcer.IsExt(c, r) ? "ext"
      : "other";
    return string.Join("|", "OK", r.Name.Replace('|', '/'), (int)r.Mode, r.OwnCode != null ? 1 : 0, applies ? 1 : 0, kind, r.Path ?? "");
  }

  static string Auth(string code)
  {
    lock (lk)
    {
      if (DateTime.UtcNow < authLock)
        return "LOCK";
    }
    if (Config.Check(code, cur.AppCode))
    {
      lock (lk)
      {
        authFails = 0;
        authLevel = 0;
      }
      var t = Guid.NewGuid().ToString("N");
      tokens[t] = DateTime.UtcNow;
      return "TOKEN|" + t;
    }
    lock (lk)
    {
      Alerts.Log("קוד כניסה שגוי לתוכנה", false);
      if (++authFails >= 5)
      {
        authFails = 0;
        authLevel = Math.Min(authLevel + 1, 5);
        authLock = DateTime.UtcNow.AddSeconds(30 << authLevel);
        Alerts.Log("נעילה זמנית אחרי ניסיונות כניסה שגויים לתוכנה");
      }
    }
    return "BAD";
  }

  // admin = הלקוח הוא מנהל מורם (נבדק דרך הזדהות ה-Pipe). פקודות ניהול נענות רק למנהל, כך שמשתמש רגיל לא יכול לנעול את המנהל מחוץ לשירות
  static string Handle(string line, int clientPid, bool admin, string sid)
  {
    try
    {
      var p = line.Split('|', 4);
      switch (p[0])
      {
        case "HELLO":
          return "OK";
        case "VER":
          return Ver;
        case "AUTH":
          if (!admin)
            return "DENY";
          return Auth(string.Join("|", p.Skip(1)));
        case "SAVE":
        case "SAVERT":
        { // SAVE: הגדרות בלבד (מצב ההחלה נשמר מהקובץ הקיים). SAVERT: כולל מצב החלה
          if (!admin || p.Length < 3 || !TokenOk(p[1]))
            return "DENY";
          var json = Encoding.UTF8.GetString(Convert.FromBase64String(p[2]));
          if (json.Length > 8_000_000)
            return "ERR";
          var inc = JsonSerializer.Deserialize<Config>(json, Config.O);
          if (inc == null)
            return "ERR";
          if (p[0] == "SAVE")
          {
            var latest = Config.TryLoad();
            if (latest != null)
            {
              inc.Applied = latest.Applied;
              inc.State = latest.State;
              inc.TempOpenUntil = latest.TempOpenUntil;
              json = JsonSerializer.Serialize(inc, Config.O);
            }
          }
          Config.WriteSecure(json);
          return "OK";
        }
        case "RULE":
          return RuleInfo(p[1], p.Length > 2 && p[2].Length > 0 ? string.Join("|", p.Skip(2)) : sid); // בלי SID – משתמשים בזהות של הלקוח
        case "VERIFY":
        {
          var c = cur;
          var r = c.Find(p[1]);
          if (r == null)
            return "ERR";
          var k = LockKey(r, sid);
          if (Locked(k))
            return "LOCK"; // הנעילה לפי משתמש: משתמש רגיל לא יכול לנעול את המנהל
          if (c.CodeOk(r, string.Join("|", p.Skip(2))))
          {
            Ok(k);
            if (clientPid > 0)
              grants[(clientPid, p[1])] = DateTime.UtcNow;
            return "OK";
          }
          Fail(k, r.Name);
          return "BAD";
        }
        case "OPEN":
        {
          var c = cur;
          var r = c.Find(p[1]);
          if (r == null || !r.On || !Blocking(c) || r.Mode != Mode.Code || !(c.Paths.Contains(r) || Enforcer.IsExt(c, r)))
            return "ERR";
          var k = LockKey(r, sid);
          if (Locked(k))
            return "LOCK";
          if (!c.CodeOk(r, string.Join("|", p.Skip(2))))
          {
            Fail(k, r.Name);
            return "BAD";
          }
          Ok(k);
          Enforcer.Unlock(r, c);
          lease[p[1]] = DateTime.UtcNow;
          Alerts.Log("נפתח בקוד: " + r.Name, false);
          var lt = Guid.NewGuid().ToString("N");
          leaseTok[lt] = p[1];
          return "OK|" + lt;
        }
        case "ISAUTH":
        { // ISAUTH|ruleId|parentPid[|SYS]: האם ההפעלה הזו מאושרת בלי קוד (הורה מאושר / הפעלה פנימית של DeviceGuard / שירות מערכת אחרי אישור)
          if (p.Length < 3 || !int.TryParse(p[2], out var pp))
            return "NO";
          if (clientPid > 0 && Native.ParentOf(clientPid) != pp)
            return "NO"; // ההורה שהלקוח מצהיר עליו חייב להיות ההורה האמיתי שלו
          bool yes = internalPids.ContainsKey(pp) || IsAuth(pp, p[1]);
          if (!yes && p.Length > 3 && p[3] == "SYS")
          {
            var r = cur.Find(p[1]);
            yes = r != null && r.Mode == Mode.Code && ruleAuth.TryGetValue(p[1], out var t) && (DateTime.UtcNow - t).TotalMinutes < 15;
          }
          if (yes && clientPid > 0)
            grants[(clientPid, p[1])] = DateTime.UtcNow;
          return yes ? "OK" : "NO";
        }
        case "INTERNAL":
        {
          if (!admin || p.Length < 4 || !TokenOk(p[1]) || !int.TryParse(p[2], out var ip))
            return "DENY";
          InternalAdd(ip, p[3] == "1" ? 1 : -1);
          return "OK";
        }
        case "AUTHPID":
        {
          // השער רץ בהרשאות המשתמש ולכן לא סומכים עליו: נדרש אישור שהשירות עצמו נתן לאותו תהליך שער ולאותו חוק (חד-פעמי, עד 60 שניות),
          // והתהליך המאושר חייב להיות בן של השער – או התהליך שעליו נשאל הקוד (PromptKill)
          if (!FromGate(clientPid) || p.Length < 3 || !int.TryParse(p[1], out var ap))
            return "DENY";
          if (!grants.TryRemove((clientPid, p[2]), out var gt) || (DateTime.UtcNow - gt).TotalSeconds > 60)
            return "DENY";
          bool child = Native.ParentOf(ap) == clientPid;
          bool prompted = promptedPid.TryGetValue(ap, out var pr) && pr.Rule == p[2] && Native.SameStart(ap, pr.Start);
          if (!child && !prompted)
            return "DENY";
          RegisterAuth(ap, p[2]);
          return "OK";
        }
        case "KILL":
        {
          if (!FromGate(clientPid) || p.Length < 3 || !int.TryParse(p[1], out var kp))
            return "DENY";
          if (promptedPid.TryGetValue(kp, out var rr) && rr.Rule == p[2] && Native.SameStart(kp, rr.Start) && !IsAuth(kp, rr.Rule))
          {
            KillPid(kp);
            Alerts.Log("תוכנה חסומה נסגרה (לא הוקש קוד)", false);
          }
          return "OK";
        }
        case "PING":
        { // PING|ruleId|token
          if (p.Length < 3 || !leaseTok.TryGetValue(p[2], out var lid) || lid != p[1] || !lease.ContainsKey(p[1]))
            return "DENY";
          lease[p[1]] = DateTime.UtcNow;
          return "OK";
        }
        case "RELOCK":
        {
          lease.TryRemove(p[1], out _);
          DropTokens(p[1]);
          var c = cur;
          var r = c.Find(p[1]);
          if (r != null && Blocking(c) && r.On)
            Enforcer.Relock(r, c);
          return "OK";
        }
        case "SCAN":
          return $"{Enforcer.ScanId}|{Enforcer.ScanStartTicks}|{Enforcer.ScanDone}|{Enforcer.ScanTotal}|{(Enforcer.ScanRunning ? 1 : 0)}|{(Enforcer.ScanFinished ? 1 : 0)}|{string.Join(",", Enforcer.NoAclDrives.Keys)}";
        case "UNREG": // הסרת השירות לצורך עדכון (נקרא מהחלון בעדכון גרסה)
        case "UNINSTALL":
        {
          if (!admin || p.Length < 2 || !TokenOk(p[1]))
            return "DENY";
          bool full = p[0] == "UNINSTALL";
          removing = true;
          Task.Run(() => SelfRemove(full));
          return "OK";
        }
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    return "ERR";
  }

  // הסרה עצמית של השירות (עדכון או הסרה מלאה). הכול נעשה מתוך השירות עצמו; cmd משמש רק למחיקת קובץ ההפעלה אחרי העצירה, והוא מסומן כפנימי כדי שהשער לא יחסום אותו
  static void SelfRemove(bool full)
  {
    Alerts.Log(full ? "התוכנה הוסרה" : "השירות מתעדכן");
    try
    {
      Enforcer.RunExe("sc.exe", "sdset DeviceGuard D:(A;;GA;;;SY)(A;;GA;;;BA)");
      Enforcer.RunExe("icacls", $"\"{Config.Dir}\" /grant *S-1-5-32-544:(OI)(CI)F");
      if (full)
        foreach (var m in new[] { "Minimal", "Network" })
        {
          try
          {
            Registry.LocalMachine.DeleteSubKeyTree($@"SYSTEM\CurrentControlSet\Control\SafeBoot\{m}\DeviceGuard", false);
          }
          catch (Exception __e)
          {
            Diag.Log(__e);
          }
        }
      Enforcer.RunExe("sc.exe", "delete DeviceGuard"); // מסומן למחיקה; יימחק סופית כשהשירות ייעצר
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    Thread.Sleep(1000);
    if (full)
    {
      try
      {
        InternalAdd(Environment.ProcessId, 1);
        Process.Start(
          new ProcessStartInfo("cmd.exe", $"/c ping -n 4 127.0.0.1 >nul & del /f /q \"{Enforcer.GateExe}\" \"{Enforcer.LightGateExe}\"")
          {
            CreateNoWindow = true,
            UseShellExecute = false,
          }
        );
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
    try
    {
      using var sc = new System.ServiceProcess.ServiceController("DeviceGuard");
      sc.Stop();
    }
    catch
    {
      Environment.Exit(0);
    }
  }

  static void PipeServer()
  {
    var ps = new PipeSecurity();
    ps.AddAccessRule(
      new PipeAccessRule(
        new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
        PipeAccessRights.ReadWrite,
        AccessControlType.Allow
      )
    );
    ps.AddAccessRule(
      new PipeAccessRule(
        new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
        PipeAccessRights.FullControl,
        AccessControlType.Allow
      )
    );
    ps.AddAccessRule(
      new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny)
    );
    bool first = true;
    DateTime lastWarn = DateTime.MinValue;
    while (true)
    {
      NamedPipeServerStream? st = null;
      try
      {
        // המופע הראשון נוצר עם FirstPipeInstance: אם מישהו אחר כבר פתח Pipe בשם הזה – היצירה נכשלת (ומתועדת) במקום לחלוק איתו את השם
        st = NamedPipeServerStreamAcl.Create(
          "DeviceGuard.Unlock",
          PipeDirection.InOut,
          254,
          PipeTransmissionMode.Byte,
          PipeOptions.Asynchronous | (first ? PipeOptions.FirstPipeInstance : 0),
          0,
          0,
          ps
        );
        first = false;
        st.WaitForConnection();
        var s2 = st;
        st = null;
        _ = Task.Run(() => Serve(s2));
      }
      catch
      {
        try
        {
          st?.Dispose();
        }
        catch (Exception __e)
        {
          Diag.Log(__e);
        }
        if (first && (DateTime.UtcNow - lastWarn).TotalMinutes >= 10)
        {
          lastWarn = DateTime.UtcNow;
          Alerts.Log("תהליך אחר תפס את ערוץ התקשורת של שירות ההגנה");
        }
        Thread.Sleep(500);
      }
    }
  }

  // קריאת שורה אחת עם הגבלת גודל: 64KB לפקודות רגילות, 12MB ל-SAVE. מונע מלקוח לנפח את זיכרון השירות
  static async Task<string?> ReadLimited(Stream s, CancellationToken ct)
  {
    var buf = new byte[8192];
    using var ms = new MemoryStream();
    int limit = 65536;
    bool decided = false;
    while (true)
    {
      int n = await s.ReadAsync(buf.AsMemory(0, buf.Length), ct);
      if (n <= 0)
        break;
      int nl = Array.IndexOf(buf, (byte)'\n', 0, n);
      ms.Write(buf, 0, nl >= 0 ? nl : n);
      if (!decided && ms.Length >= 4)
      {
        decided = true;
        var b = ms.GetBuffer();
        if (b[0] == 'S' && b[1] == 'A' && b[2] == 'V' && b[3] == 'E')
          limit = 12_000_000;
      }
      if (ms.Length > limit)
        return null;
      if (nl >= 0)
        break;
    }
    if (ms.Length == 0)
      return null;
    return Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length).TrimEnd('\r');
  }

  // כל חיבור מוגבל ל-5 שניות קריאה: אי אפשר לתפוס את השרת בחיבור שלא שולח כלום. ולכל לקוח עד 16 חיבורים במקביל
  static async Task Serve(NamedPipeServerStream st)
  {
    int cpid = 0;
    try
    {
      using (st)
      {
        try
        {
          if (Native.GetNamedPipeClientProcessId(st.SafePipeHandle.DangerousGetHandle(), out var u))
            cpid = (int)u;
        }
        catch (Exception __e)
        {
          Diag.Log(__e);
        }
        if (cpid != 0 && connCount.AddOrUpdate(cpid, 1, (k, v) => v + 1) > 16)
          return;
        string? l;
        try
        {
          using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
          l = await ReadLimited(st, cts.Token);
        }
        catch
        {
          return;
        }
        if (l == null)
          return;
        bool admin = false;
        string sid = "";
        try
        {
          st.RunAsClient(() =>
          {
            using var id = WindowsIdentity.GetCurrent();
            sid = id.User?.Value ?? "";
            admin = new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
          });
        }
        catch (Exception __e)
        {
          Diag.Log(__e);
        }
        var resp = await Task.Run(() => Handle(l, cpid, admin, sid));
        var wr = new StreamWriter(st, new UTF8Encoding(false)) { AutoFlush = true };
        await wr.WriteLineAsync(resp);
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    finally
    {
      if (cpid != 0 && connCount.AddOrUpdate(cpid, 0, (k, v) => v - 1) <= 0)
        connCount.TryRemove(cpid, out _);
    }
  }

  // ---------- הלולאה הראשית של השירות ----------
  // חתימה של כל מה שמשפיע על חסימת קבצים לפי סיומת. כשהיא לא משתנה אין צורך בסריקה מחדש של הדיסקים
  static string MapSig(Config c)
  {
    var sb = new StringBuilder();
    foreach (var kv in curMap.OrderBy(k => k.Key, StringComparer.Ordinal))
      sb.Append(kv.Key).Append('=').Append(kv.Value.Id).Append(kv.Value.Hidden && kv.Value.Mode == Mode.Full ? 'h' : '-').Append(';');
    sb.Append('|')
      .Append(string.Join(",", c.Exclude))
      .Append('|')
      .Append(c.SkipAppData)
      .Append(c.Harden)
      .Append(c.IncludeRemovable)
      .Append(c.SkipProgramDirs);
    return sb.ToString();
  }

  public static void Watch()
  {
    Config.InService = true;
    Enforcer.InService = true;
    LockDir();
    new Thread(PipeServer) { IsBackground = true }.Start();
    Alerts.Log("שירות ההגנה הופעל", false);
    StartWmi();
    var q = new ConcurrentQueue<(string P, int T, DateTime At)>();
    var fsw = new List<FileSystemWatcher>();
    var watched = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    void Add(string p)
    {
      if (curMap.ContainsKey(ExtOf(p)))
        q.Enqueue((p, 0, DateTime.UtcNow.AddSeconds(2)));
    }
    void Watch1(string root)
    {
      if (!watched.Add(root))
        return;
      try
      {
        var w = new FileSystemWatcher(root)
        {
          IncludeSubdirectories = true,
          NotifyFilter = NotifyFilters.FileName,
          InternalBufferSize = 65536,
        };
        w.Created += (s, e) => Add(e.FullPath);
        w.Renamed += (s, e) => Add(e.FullPath);
        w.Error += (s, e) => overflow = true;
        w.EnableRaisingEvents = true;
        fsw.Add(w);
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
    IEnumerable<string> Drives() =>
      DriveInfo.GetDrives().Where(x => Enforcer.ScanDrive(x) && x.IsReady).Select(x => x.RootDirectory.FullName);
    foreach (var d in Drives())
      Watch1(d);

    var stamp = DateTime.MinValue;
    var c = new Config();
    var ifeo = new List<(string Exe, string Id)>();
    var regs = new List<RegWant>();
    var lastScan = DateTime.MinValue;
    var lastIfeo = DateTime.UtcNow;
    var lastReg = DateTime.UtcNow;
    var lastFw = DateTime.UtcNow;
    var lastAd = DateTime.UtcNow;
    var lastPoll = DateTime.MinValue;
    var lastRec = DateTime.UtcNow;
    var lastSweep = DateTime.UtcNow;
    var lastOverflow = DateTime.MinValue;
    var lastDrv = DateTime.MinValue;
    var lastWmi = DateTime.UtcNow;
    string? lastSig = null;
    bool pendingDone = false;
    Task scanTask = Task.CompletedTask;
    CancellationTokenSource? scanCts = null;
    void StartScan(Dictionary<string, Rule> map, bool release, string? root = null)
    {
      if (release)
        scanCts?.Cancel();
      var cts = release || scanCts == null ? (scanCts = new CancellationTokenSource()) : scanCts;
      var prev = scanTask;
      scanTask = Task.Run(() =>
      {
        try
        {
          prev.Wait();
        }
        catch (Exception __e)
        {
          Diag.Log(__e);
        }
        try
        {
          if (release)
            Enforcer.ReleaseStale(map);
          Enforcer.ScanNew(map, cts.Token, root);
        }
        catch (Exception __e)
        {
          Diag.Log(__e);
        }
      });
    }
    while (true)
    {
      try
      {
        if ((DateTime.UtcNow - lastDrv).TotalSeconds >= 5)
        { // בדיקת כוננים חדשים כל כמה שניות (ולא כל שנייה)
          lastDrv = DateTime.UtcNow;
          try
          {
            foreach (var d in Drives())
            {
              if (watched.Contains(d))
                continue;
              Enforcer.ResetDriveCache();
              Watch1(d);
              if (curMap.Count > 0)
                StartScan(curMap, false, d);
            }
          }
          catch (Exception __e)
          {
            Diag.Log(__e);
          }
        }
        if (pw == null && (DateTime.UtcNow - lastWmi).TotalSeconds >= 30)
        {
          lastWmi = DateTime.UtcNow;
          StartWmi();
        } // ניטור WMI שנפל – מפעילים מחדש
        var ts = File.GetLastWriteTimeUtc(Config.CfgPath);
        if (ts != stamp)
        {
          var nc = Config.TryLoad(); // null = קריאה נכשלה: נשארים עם ההגדרות הקודמות ומנסים שוב (לא מתאפסים להגדרות ריקות)
          if (nc != null)
          {
            stamp = ts;
            c = nc;
            cur = nc;
            Reload(nc);
            var bl = Blocking(nc);
            ifeo = bl ? Enforcer.IfeoList(nc) : new();
            regs = bl ? Enforcer.RegWants(nc) : new();
            if (!pendingDone)
            {
              pendingDone = true;
              Enforcer.RelockPending(nc);
            }
            var sig = MapSig(nc); // סורקים מחדש רק אם משהו שמשפיע על חסימת הקבצים השתנה (ולא בכל שמירה של הגדרה כלשהי)
            if (sig != lastSig)
            {
              lastSig = sig;
              StartScan(curMap, true);
              lastScan = DateTime.UtcNow;
            }
          }
        }
        var blocking = Blocking(c);
        var now = DateTime.UtcNow;
        foreach (var kv in lease.ToArray())
          if ((now - kv.Value).TotalSeconds > 15 && lease.TryRemove(kv.Key, out _))
          {
            DropTokens(kv.Key);
            var lr = c.Find(kv.Key);
            if (lr != null && blocking && lr.On)
              Enforcer.Relock(lr, c);
          }
        if ((now - lastRec).TotalSeconds >= 5)
        {
          lastRec = now;
          Reconcile(c);
        }
        if (blocking)
        {
          if ((now - lastPoll).TotalSeconds >= 3 && (killSet.Count > 0 || codeKillMap.Count > 0))
          { // גיבוי לאירועי ה-WMI
            lastPoll = now;
            foreach (var pr in Process.GetProcesses())
            {
              try
              {
                HandleProc(pr.ProcessName, pr.Id);
              }
              catch (Exception __e)
              {
                Diag.Log(__e);
              }
              finally
              {
                pr.Dispose();
              }
            }
          }
          for (int n = q.Count; n > 0 && q.TryDequeue(out var it); n--)
          {
            if (it.At > DateTime.UtcNow)
            {
              q.Enqueue(it);
              continue;
            }
            if (curMap.TryGetValue(ExtOf(it.P), out var rule) && !Enforcer.BlockNewFile(rule, it.P) && it.T < 5)
              q.Enqueue((it.P, it.T + 1, DateTime.UtcNow.AddSeconds(3)));
          }
          if (scanTask.IsCompleted && curMap.Count > 0)
          {
            if (overflow && (now - lastOverflow).TotalMinutes >= 5)
            {
              overflow = false;
              lastOverflow = now;
              StartScan(curMap, false);
              lastScan = now;
            }
            else if ((now - lastScan).TotalMinutes >= 60)
            {
              Enforcer.ForgetKnown();
              StartScan(curMap, false);
              lastScan = now;
            }
          }
          bool quiet = !Enforcer.Applying() && Interlocked.CompareExchange(ref applyBusy, 0, 0) == 0 && (now - stamp).TotalSeconds > 5;
          if (quiet && (now - lastIfeo).TotalSeconds >= 5)
          {
            lastIfeo = now;
            var n = Enforcer.Heal(ifeo);
            if (n > 0)
              Alerts.Log($"זוהה שינוי בחסימות תוכנות ({n}) – שוחזר");
          }
          if (quiet && (now - lastReg).TotalSeconds >= 10)
          {
            lastReg = now;
            var n = Enforcer.HealReg(regs);
            if (n > 0)
              Alerts.Log($"זוהה שינוי במדיניות מערכת ({n}) – שוחזר");
          }
          if ((now - lastFw).TotalSeconds >= 30)
          {
            lastFw = now;
            Enforcer.NetHeal(c);
          }
          if ((now - lastAd).TotalSeconds >= 15)
          {
            lastAd = now;
            Enforcer.NetAdapterHeal(c);
          }
        }
        else
          while (q.TryDequeue(out _)) { }
        if ((now - lastSweep).TotalSeconds >= 30)
        {
          lastSweep = now;
          foreach (var k in authPid.Keys.ToArray())
            if (!Native.Alive(k))
              authPid.TryRemove(k, out _);
          foreach (var kv in promptedPid.ToArray())
            if (!Native.SameStart(kv.Key, kv.Value.Start))
              promptedPid.TryRemove(kv.Key, out _);
          foreach (var k in renameSeen.Keys.ToArray())
            if (!Native.Alive(k))
              renameSeen.TryRemove(k, out _);
          foreach (var k in internalPids.Keys.ToArray())
            if (!Native.Alive(k))
              internalPids.TryRemove(k, out _);
          foreach (var kv in tokens.ToArray())
            if ((now - kv.Value).TotalHours >= 8)
              tokens.TryRemove(kv.Key, out _);
          foreach (var kv in ruleAuth.ToArray())
            if ((now - kv.Value).TotalHours >= 1)
              ruleAuth.TryRemove(kv.Key, out _);
          foreach (var kv in grants.ToArray())
            if ((now - kv.Value).TotalSeconds > 60)
              grants.TryRemove(kv.Key, out _);
        }
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
      Thread.Sleep(1000);
    }
  }

  // ---------- נקודת כניסה ----------
  static bool IsAdmin()
  {
    using var id = WindowsIdentity.GetCurrent();
    return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
  }

  [STAThread]
  public static void Main(string[] args)
  {
    if (args.Contains("--service"))
    {
      Config.InService = true;
      System.ServiceProcess.ServiceBase.Run(new GuardService());
      return;
    }
    if (args.Contains("--watch"))
    {
      using var wid = WindowsIdentity.GetCurrent();
      if (wid.IsSystem)
        Watch();
      return;
    } // מצב ישן: רק כ-SYSTEM
    if (args.Length >= 2 && args[0] == "--gate")
    {
      GateMode.RunGate(args);
      return;
    }
    if (args.Length >= 3 && args[0] == "--promptkill")
    {
      GateMode.PromptKill(args);
      return;
    }
    if (args.Length >= 2 && args[0] == "--open")
    {
      GateMode.OpenFlow(args[1]);
      return;
    }
    if (args.Length >= 2 && args[0] == "--openext")
    {
      GateMode.OpenExt(args[1]);
      return;
    }
    if (!IsAdmin())
    {
      try
      {
        Process.Start(new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true, Verb = "runas" });
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
      return;
    }
    RunUi();
  }

  static void RunUi()
  {
    try
    {
      using var single = new Mutex(true, "Global\\DeviceGuard.UI", out var created); // מופע אחד בלבד של החלון (שני חלונות היו דורסים זה את ההגדרות של זה)
      if (!created)
      {
        MainWin.Say("DeviceGuard כבר פתוח.");
        return;
      }
      var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
      Theme.Apply(app);
      app.DispatcherUnhandledException += (s, e) =>
      {
        MainWin.Say(e.Exception.Message, "DeviceGuard");
        e.Handled = true;
      };
      var c = Config.Load();
      bool dirty = false;
      if (c.AppCode == null)
      {
        var k = MainWin.Ask("הגדר קוד כניסה לתוכנה", true);
        if (k == null)
          return;
        Code = k;
        c.AppCode = Config.Hash(k);
        dirty = true;
        c.Save();
        dirty = false;
      }
      else
      {
        while (true)
        {
          var k = MainWin.Ask("הזן קוד כניסה");
          if (k == null)
            return;
          if (Config.Check(k, c.AppCode))
          {
            Code = k;
            break;
          }
          MainWin.Say("קוד שגוי");
        }
      }
      Enforcer.TryStartService(); // אם השירות מותקן אך כבוי – מפעילים אותו, אחרת אי אפשר לשמור הגדרות
      if (Code != null && Config.Up() && !Config.Auth(Code))
        MainWin.Say("האימות מול שירות ההגנה נכשל (ייתכן שיש נעילה זמנית אחרי ניסיונות שגויים)");
      if (string.IsNullOrEmpty(c.OwnerSid))
      {
        c.OwnerSid = Native.InteractiveUserSid();
        c.OwnerUser = Native.AccountName(c.OwnerSid) ?? Environment.UserName;
        dirty = true;
      }
      if (!string.Equals(c.UiExe, Environment.ProcessPath, StringComparison.OrdinalIgnoreCase))
      {
        c.UiExe = Environment.ProcessPath;
        dirty = true;
      }
      if (!c.Terms)
      {
        if (!MainWin.TermsDialog())
          return;
        c.Terms = true;
        dirty = true;
      }
      if (dirty)
      {
        try
        {
          c.Save();
        }
        catch (Exception __e)
        {
          Diag.Log(__e);
        }
      }
      var w = new MainWin(c);
      app.MainWindow = w;
      app.ShutdownMode = ShutdownMode.OnMainWindowClose;
      app.Run(w);
    }
    catch (Exception x)
    {
      MainWin.Say(x.ToString(), "DeviceGuard – שגיאה");
    }
  }
}
