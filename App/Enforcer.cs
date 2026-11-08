using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using Microsoft.Win32;

namespace DG;

public readonly record struct RegWant(string Hive, string Path, string Name, string Kind, string Enc);

public static class Enforcer
{
  const string IFEO = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\";
  const string EXP = @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";
  const string SYSPOL = @"Software\Microsoft\Windows\CurrentVersion\Policies\System";
  const string SAFER = @"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers";
  const string DEVREST = @"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions";
  const string RSD = @"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices";
  const string INS = @"SOFTWARE\Policies\Microsoft\Windows\Installer";
  const string USBSTOR = @"SYSTEM\CurrentControlSet\Services\USBSTOR";
  const string UASPSTOR = @"SYSTEM\CurrentControlSet\Services\UASPStor";

  // התקני אחסון USB שמחוברים כרגע: USBSTOR, וגם כונני UASP (מופיעים כ-SCSI עם התקן אב מסוג USB).
  // הדיסק שעליו Windows מותקן לעולם לא נכלל (גם אם הוא בחיבור USB), כדי שהשבתה לא תקריס את המחשב. פלט: מזהה|שם|התקן אב
  const string UsbQuery =
    "$sp = ''; try { $sp = [string](Get-Partition -DriveLetter $env:SystemDrive.Substring(0,1) -ErrorAction Stop | Get-Disk -ErrorAction Stop).Path } catch {}\n"
    + "$sp = $sp.ToUpperInvariant()\n"
    + "Get-PnpDevice -PresentOnly | ? { $_.InstanceId -like 'USBSTOR*' -or ($_.Class -eq 'DiskDrive' -and $_.InstanceId -like 'SCSI*') } | % {\n"
    + "  $p = [string](Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName 'DEVPKEY_Device_Parent' -ErrorAction SilentlyContinue).Data\n"
    + "  $usb = $_.InstanceId -like 'USBSTOR*' -or $p -like 'USB\\*'\n"
    + "  $sys = $sp.Length -gt 0 -and $sp.Contains(($_.InstanceId -replace '\\\\','#').ToUpperInvariant())\n"
    + "  if ($usb -and -not $sys) { $_.InstanceId + '|' + $_.FriendlyName + '|' + $p }\n"
    + "}";

  // הערכה בשכבות של מדיניות התקנת התקנים (AllowDenyLayered): Windows 11 (גרסה 22000 ואילך). ב-Windows 10 התמיכה תלויה בעדכונים – לא סומכים עליה
  static bool LayeredOk => Environment.OSVersion.Version.Build >= 22000;

  static bool SystemOnUsb()
  {
    try
    {
      var r = System.IO.Path.GetPathRoot(Environment.SystemDirectory);
      return r != null && Native.IsUsbBus(r);
    }
    catch
    {
      return false;
    }
  }
  const string ADV = @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced";
  public static int Blocked,
    Failed;
  public static string? LastErr; // תוצאת החסימה האחרונה (לחיווי בחלון)
  public static bool InService; // true כשרצים בתוך השירות (SYSTEM)
  public static readonly StaTaskScheduler Sta = new(); // תהליכון STA יחיד (יצירת קיצורים ב-COM, שימוש חוזר בין החלות)
  public static string GateExe => System.IO.Path.Combine(Config.Dir, "DeviceGuardWatch.exe");

  // שער קל (NativeAOT) שמוטמע בקובץ הראשי: מכריע מהר אם להפעיל, ומפעיל את השער המלא רק כשצריך חלון קוד. אם הוא חסר – משתמשים בשער המלא
  public static string LightGateExe => System.IO.Path.Combine(Config.Dir, "DeviceGuardGate.exe");

  public static string GateCmd(string id) => $"\"{(File.Exists(LightGateExe) ? LightGateExe : GateExe)}\" --gate {id}";

  static void AddA(Config c, string e)
  {
    lock (c.Applied)
      c.Applied.Add(e);
    JournalAdd(e);
  }

  // ---------- יומן החלה (נרשם לפני כל שינוי) ----------
  // רשימת "מה הוחל" נשמרת בקובץ ההגדרות רק בסוף ההחלה. החלה שנקטעה באמצע (כיבוי המחשב בתחילת חלון הזמנים, הפסקת חשמל, תהליך שנסגר)
  // השאירה שינויים בלי רישום – והם לא בוטלו אף פעם (ובהחלה הבאה אף נרשמו כ"ערך המקורי"). עכשיו כל רשומה נכתבת ליומן לפני הפעולה עצמה,
  // והיומן נמחק רק אחרי שההגדרות נשמרו. יומן שנשאר = החלה שנקטעה: הרשומות שלו מצטרפות לרשימה, כך שהביטול הבא מבטל אותן.
  // השירות: תיקייה שרק המערכת כותבת אליה (run). החלון: var – ורק החלון קורא את היומן הזה (השירות לא מקבל רשומות מקובץ שמנהלים יכולים לכתוב)
  static string JournalPath =>
    InService ? System.IO.Path.Combine(Config.Dir, "run", "applying.journal") : System.IO.Path.Combine(Config.Dir, "var", "applying-ui.journal");

  static readonly object JLock = new();
  static FileStream? jfs;
  static StreamWriter? jw;

  [ThreadStatic]
  static bool savedOk; // ההחלה הנוכחית שמרה את ההגדרות (אפשר למחוק את היומן)

  static void JournalBegin(Config c)
  {
    lock (JLock)
    {
      try
      {
        JournalClose();
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(JournalPath)!);
        jfs = new FileStream(JournalPath, FileMode.Create, FileAccess.Write, FileShare.Read);
        jw = new StreamWriter(jfs, new UTF8Encoding(false));
        // מה שכבר רשום (כולל רשומות שנמצאו ביומן קודם): אם ההחלה הזו תיקטע, גם הן לא ילכו לאיבוד
        List<string> snap;
        lock (c.Applied)
          snap = c.Applied.ToList();
        foreach (var l in snap)
          if (l.IndexOfAny(new[] { '\r', '\n' }) < 0)
            jw.WriteLine(l);
        jw.Flush();
        jfs.Flush(true);
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
        JournalClose();
      }
    }
  }

  static void JournalAdd(string e)
  {
    lock (JLock)
    {
      if (jw == null || e.IndexOfAny(new[] { '\r', '\n' }) >= 0)
        return;
      try
      {
        jw.WriteLine(e);
        jw.Flush();
        // רשומות של מדיניות/רשת/התקנים – גם לדיסק עצמו (מעטות). רשומות קבצים (אלפים) – רק למערכת ההפעלה, כדי לא להאט
        if (!(e.StartsWith("acl|") || e.StartsWith("fid|") || e.StartsWith("hid|")))
          jfs!.Flush(true);
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
  }

  static void JournalClose()
  {
    try
    {
      jw?.Dispose();
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    jw = null;
    jfs = null;
  }

  static void JournalEnd(bool delete)
  {
    lock (JLock)
    {
      JournalClose();
      if (delete)
        try
        {
          File.Delete(JournalPath);
        }
        catch (Exception __e)
        {
          Diag.Log(__e);
        }
    }
  }

  // רשומות מיומן של החלה שנקטעה, שלא נמצאות ברשימה: מצטרפות אליה (הביטול הבא יבטל אותן). true = נוספו רשומות
  static bool JournalMerge(Config c)
  {
    try
    {
      if (!File.Exists(JournalPath))
        return false;
      var lines = File.ReadAllLines(JournalPath).Where(l => l.Length > 0 && l.Contains('|')).ToList();
      int n = 0;
      lock (c.Applied)
        foreach (var l in lines)
          if (!c.Applied.Contains(l))
          {
            c.Applied.Add(l);
            n++;
          }
      if (n > 0)
        Alerts.Log($"נמצאו {n} שינויים מהחלה שנקטעה באמצע – נרשמו, כדי שיבוטלו בביטול החסימה", false);
      return n > 0;
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
      return false;
    }
  }

  public static bool HasJournal()
  {
    try
    {
      return File.Exists(JournalPath);
    }
    catch
    {
      return false;
    }
  }

  // בשירות (טעינת ההגדרות הראשונה) ובחלון (בפתיחה): יומן של החלה שנקטעה מצטרף לרשימה ונשמר. true = נמצאו רשומות.
  // מחזיר false גם כשאין יומן. היומן נמחק רק אחרי שמירה מוצלחת
  public static bool RecoverJournal(Config c)
  {
    if (!HasJournal())
      return false;
    using var lk = ApplyLock();
    if (!InService)
      RefreshRuntime(c);
    var any = JournalMerge(c);
    try
    {
      if (any)
        c.Save(true);
      JournalEnd(true);
    }
    catch (Exception __e)
    {
      Diag.Log(__e); // השמירה נכשלה: היומן נשאר, וננסה שוב בפעם הבאה
    }
    return any;
  }

  static void SaveRt(Config c)
  {
    c.Save(true);
    savedOk = true;
  }

  static readonly int Par = Math.Min(16, Math.Max(4, Environment.ProcessorCount * 2));

  // חסימות קבצים שכבר קיימות מההחלה הקודמת: לא משחררים ונועלים מחדש, רק מדלגים (מה שלא נדרש יותר משוחרר בסוף)
  static readonly ConcurrentDictionary<string, byte> prevAcl = new(StringComparer.OrdinalIgnoreCase),
    prevUsb = new();
  static readonly ConcurrentDictionary<string, string> prevHid = new(StringComparer.OrdinalIgnoreCase);
  static readonly ConcurrentDictionary<string, byte> prevNet = new(StringComparer.OrdinalIgnoreCase); // מתאמי רשת שהושבתו על ידינו בהחלה הקודמת ונשארים מושבתים (שומרים שייכות לביטול)
  static readonly string CdT = Config.Dir.TrimEnd('\\'),
    BdT = AppContext.BaseDirectory.TrimEnd('\\');
  static readonly RegistryView[] Views = { RegistryView.Registry64, RegistryView.Registry32 };

  // תהליכי מערכת שלעולם לא חוסמים ולא סוגרים (חסימה שלהם מקריסה את המחשב)
  static readonly HashSet<string> Critical = new(StringComparer.OrdinalIgnoreCase)
  {
    "csrss",
    "wininit",
    "winlogon",
    "lsass",
    "services",
    "smss",
    "system",
    "svchost",
    "dwm",
    "fontdrvhost",
    "explorer",
    "sihost",
    "ctfmon",
    "taskhostw",
    "runtimebroker",
    "startmenuexperiencehost",
    "searchhost",
    "shellexperiencehost",
    "audiodg",
    "dllhost",
    "conhost",
    "wmiprvse",
    "consent", // חלון אישור הרשאות מנהל (UAC): בלעדיו אי אפשר להפעיל את DeviceGuard כדי לבטל חסימות
    "logonui",
    "userinit",
    "lsaiso",
    "rundll32",
    "regsvr32",
    "spoolsv",
    "searchindexer",
    "msmpeng", // Windows Defender
    "securityhealthservice",
    "nissrv",
    "trustedinstaller", // עדכוני Windows
    "tiworker",
    "werfault",
    "wermgr",
    "smartscreen",
    "sppsvc",
    "DeviceGuard",
    "DeviceGuardWatch",
    "DeviceGuardGate",
  };

  public static bool IsCritical(string name) => Critical.Contains(System.IO.Path.GetFileNameWithoutExtension(name));

  // שמות קבצים כלליים: IFEO וסגירת התהליכים עובדים לפי שם הקובץ בלבד, ולכן חסימה של תוכנה עם שם כזה חוסמת גם כל תוכנה אחרת באותו שם
  static readonly HashSet<string> GenericNames = new(StringComparer.OrdinalIgnoreCase)
  {
    "update",
    "updater",
    "setup",
    "install",
    "installer",
    "uninstall",
    "uninst",
    "launcher",
    "helper",
    "app",
    "main",
    "start",
    "run",
    "service",
    "server",
    "client",
    "python",
    "pythonw",
    "java",
    "javaw",
    "node",
    "electron",
    "squirrel",
    "crashpad_handler",
  };

  public static bool IsGenericName(string path) => GenericNames.Contains(System.IO.Path.GetFileNameWithoutExtension(path));

  // ---------- הרצת תהליכים עזר ----------
  // כשהשירות/החלון מריצים כלי מערכת (PowerShell, sc, netsh...) שייתכן שחסום בשער – הם מסומנים כ"פנימיים" והשער מאפשר אותם
  sealed class InternalScope : IDisposable
  {
    public InternalScope() => Adjust(1);

    public void Dispose() => Adjust(0);

    static void Adjust(int on)
    {
      try
      {
        if (Config.InService)
          Program.InternalAdd(Environment.ProcessId, on == 1 ? 1 : -1);
        else if (Config.Token != null)
          Config.PipeAuth(t => $"INTERNAL|{t}|{Environment.ProcessId}|{on}", 2000); // טוקן שפג – אימות מחדש (אחרת כלי מערכת חסום שהחלון מריץ היה נחסם בשקט)
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
  }

  // זמן קצוב: כלי שנתקע (למשל PowerShell ב-Get-PnpDevice) נסגר, כדי שההחלה והתזמון האוטומטי לא ייתקעו לתמיד
  const int ExeTimeoutMs = 180_000;

  public static (int Code, string Out) RunExe2(string exe, string args)
  {
    using var _ = new InternalScope();
    try
    {
      using var p = Process.Start(
        new ProcessStartInfo(exe, args)
        {
          CreateNoWindow = true,
          UseShellExecute = false,
          RedirectStandardOutput = true,
        }
      )!;
      var ot = p.StandardOutput.ReadToEndAsync();
      if (!p.WaitForExit(ExeTimeoutMs))
      {
        try
        {
          p.Kill(true);
        }
        catch (Exception __e)
        {
          Diag.Log(__e);
        }
        Alerts.Log($"פעולת מערכת נתקעה ונעצרה אחרי {ExeTimeoutMs / 1000} שניות: {System.IO.Path.GetFileName(exe)}", false);
        return (-1, ot.Wait(2000) ? ot.Result : "");
      }
      p.WaitForExit();
      return (p.ExitCode, ot.Wait(5000) ? ot.Result : "");
    }
    catch
    {
      return (-1, "");
    }
  }

  public static string RunExe(string exe, string args) => RunExe2(exe, args).Out;

  // מרכאות בודדות בתוך מחרוזת PowerShell. PowerShell מתייחס גם לגרשיים החכמים ‘ ’ ‚ ‛ כגרש, ולכן מכפילים גם אותם (אחרת שם כמו "John’s" שובר את הפקודה)
  static string Q(string s) =>
    s.Replace("'", "''")
      .Replace("\u2018", "\u2018\u2018")
      .Replace("\u2019", "\u2019\u2019")
      .Replace("\u201A", "\u201A\u201A")
      .Replace("\u201B", "\u201B\u201B");

  static string PS(string cmd)
  {
    var enc = Convert.ToBase64String(Encoding.Unicode.GetBytes(cmd));
    if (enc.Length < 24000)
      return RunExe("powershell.exe", "-NoLogo -NoProfile -NonInteractive -EncodedCommand " + enc);
    // סקריפט ארוך חורג ממגבלת שורת הפקודה של Windows (32K תווים), ולכן מועבר דרך קובץ זמני בתיקייה המוגנת
    string? file = null;
    try
    {
      // בשירות: תיקייה שרק המערכת כותבת אליה (יורשת את ההרשאות של תיקיית ההגדרות) – מנהל לא יכול להחליף את הסקריפט לפני שהוא רץ כ-SYSTEM
      var dir = System.IO.Path.Combine(Config.Dir, InService ? "run" : "var");
      Directory.CreateDirectory(dir);
      file = System.IO.Path.Combine(dir, "ps-" + Guid.NewGuid().ToString("N") + ".ps1");
      File.WriteAllText(file, cmd, new UTF8Encoding(true));
      return RunExe("powershell.exe", "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + file + "\"");
    }
    catch
    {
      return "";
    }
    finally
    {
      try
      {
        if (file != null)
          File.Delete(file);
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
  }

  static void PSAll(List<string> cmds)
  {
    if (cmds.Count > 0)
      PS(string.Join("\n", cmds));
  }

  static void Schtasks(string a) => RunExe("schtasks.exe", a);

  static void Netsh(string a) => RunExe("netsh.exe", a);

  static string[] Lines(string s) => s.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

  // ---------- רישום: כתיבה עם שמירת הערך הקודם (לשחזור מדויק בביטול) ----------
  // רשומות ב-Applied:  reg|hive|path|name|prevKind|prevB64|wantKind|wantB64   (prevKind='-' = לא היה ערך)   ,   regkey|hive|path  (מפתח שנוצר על ידינו)
  public static string UserHive(Config c) =>
    c.AllUsers ? "HKLM"
    : string.IsNullOrEmpty(c.OwnerSid) ? "HKCU"
    : "HKU:" + c.OwnerSid;

  // מפתח השורש של היבה. HKLM/HKCU הם מפתחות קבועים (לא נסגרים); HKU:SID נפתח בכל שימוש – ונסגר בסופו (using).
  // קודם המפתח של המשתמש לא נסגר, ובמצב "רק המשתמש הנוכחי" השירות השאיר כל 10 שניות מפתח פתוח להיבה שלו – מה שמעכב את פריקת הפרופיל ביציאה
  sealed class RootLease : IDisposable
  {
    public readonly RegistryKey? Key;
    readonly bool own;

    public RootLease(RegistryKey? key, bool own)
    {
      Key = key;
      this.own = own;
    }

    public void Dispose()
    {
      if (own)
        Key?.Dispose();
    }
  }

  // היבות של משתמשים לא מחוברים שנטענו זמנית (בהסרת התוכנה): SID -> שם המפתח הזמני תחת HKEY_USERS
  static readonly ConcurrentDictionary<string, string> hiveAlias = new(StringComparer.OrdinalIgnoreCase);

  static RootLease Root(string hive)
  {
    if (hive == "HKLM")
      return new RootLease(Registry.LocalMachine, false);
    if (hive == "HKCU")
      return new RootLease(Registry.CurrentUser, false);
    if (hive.StartsWith("HKU:"))
    {
      try
      {
        var sid = hive[4..];
        return new RootLease(Registry.Users.OpenSubKey(hiveAlias.TryGetValue(sid, out var a) ? a : sid, true), true);
      }
      catch
      {
        return new RootLease(null, false);
      }
    }
    return new RootLease(null, false);
  }

  // MultiString נשמר כמחרוזת אחת שהפריטים שלה מופרדים בתו 0. QWord ו-Binary – כדי שערך קודם מהסוגים האלה יוחזר בביטול (קודם הוא נמחק)
  static string Enc(object v, RegistryValueKind k) =>
    k == RegistryValueKind.DWord ? Convert.ToInt32(v).ToString(System.Globalization.CultureInfo.InvariantCulture)
    : k == RegistryValueKind.QWord ? Convert.ToInt64(v).ToString(System.Globalization.CultureInfo.InvariantCulture)
    : k == RegistryValueKind.Binary ? Convert.ToBase64String((byte[])v)
    : k == RegistryValueKind.MultiString ? Convert.ToBase64String(Encoding.UTF8.GetBytes(string.Join("\0", (string[])v)))
    : Convert.ToBase64String(Encoding.UTF8.GetBytes(v?.ToString() ?? ""));

  static object Dec(string s, RegistryValueKind k) =>
    k == RegistryValueKind.DWord ? (int)ParseNum(s)
    : k == RegistryValueKind.QWord ? ParseNum(s)
    : k == RegistryValueKind.Binary ? Convert.FromBase64String(s)
    : k == RegistryValueKind.MultiString ? DecMulti(s)
    : Encoding.UTF8.GetString(Convert.FromBase64String(s));

  // מספר שנשמר בפורמט קבוע (Invariant). רשומות מגרסאות קודמות נשמרו לפי הגדרות האזור של Windows – גם הן מתקבלות
  static long ParseNum(string s) =>
    long.TryParse(s, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out var v) ? v : long.Parse(s);

  // בדיקה עצמית (לבדיקות האוטומטיות): ערך שנשמר כ"ערך קודם" חוזר בדיוק כפי שהיה
  public static bool EncRoundTrip(object v, RegistryValueKind k)
  {
    var d = Dec(Enc(v, k), k);
    return d switch
    {
      byte[] b => v is byte[] vb && b.AsSpan().SequenceEqual(vb),
      string[] a => v is string[] va && a.SequenceEqual(va),
      _ => Equals(d, v),
    };
  }

  static string[] DecMulti(string s)
  {
    var j = Encoding.UTF8.GetString(Convert.FromBase64String(s));
    return j.Length > 0 ? j.Split('\0') : Array.Empty<string>();
  }

  static bool SameValue(object? have, object want, RegistryValueKind kind) =>
    have != null
    && (
      kind == RegistryValueKind.DWord ? have is int hi && hi == (int)want
      : kind == RegistryValueKind.MultiString ? have is string[] ha && ha.SequenceEqual((string[])want, StringComparer.Ordinal)
      : string.Equals(have as string, want as string, StringComparison.Ordinal)
    );

  static void SetReg(Config c, string hive, string path, string name, object value, RegistryValueKind kind = RegistryValueKind.DWord)
  {
    using var rl = Root(hive);
    var root = rl.Key;
    if (root == null)
    {
      // רישום של משתמש שאינו מחובר כרגע (ההיבה שלו לא טעונה): נרשם כ"ממתין", והשירות מחיל אותו כשהמשתמש נכנס
      if (hive.StartsWith("HKU:"))
        AddA(c, $"regpend|{hive}|{path}|{name}|{kind}|{Enc(value, kind)}");
      return;
    }
    bool existed;
    using (var t = root.OpenSubKey(path))
      existed = t != null;
    // הרישום לפני הפעולה (יומן ההחלה): גם אם התהליך נקטע מיד אחריה, הביטול ימצא אותה
    if (!existed)
      AddA(c, $"regkey|{hive}|{path}");
    using var k = root.CreateSubKey(path, true);
    if (k == null)
      return;
    string pk = "-",
      pv = "";
    var old = k.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
    if (old != null)
    {
      var ok = k.GetValueKind(name);
      if (
        ok == RegistryValueKind.DWord
        || ok == RegistryValueKind.QWord
        || ok == RegistryValueKind.Binary
        || ok == RegistryValueKind.String
        || ok == RegistryValueKind.ExpandString
        || ok == RegistryValueKind.MultiString
      )
      {
        pk = ok.ToString();
        pv = Enc(old, ok);
      }
    }
    AddA(c, $"reg|{hive}|{path}|{name}|{pk}|{pv}|{kind}|{Enc(value, kind)}");
    k.SetValue(name, value, kind);
  }

  static bool HasValues(RegistryKey k, int depth = 0)
  {
    if (k.ValueCount > 0 || depth > 16)
      return true;
    foreach (var n in k.GetSubKeyNames())
    {
      using var sk = k.OpenSubKey(n);
      if (sk != null && HasValues(sk, depth + 1))
        return true;
    }
    return false;
  }

  // false = ההיבה של המשתמש לא טעונה כרגע (המשתמש לא מחובר): צריך לנסות שוב מאוחר יותר
  static bool RevertReg(string e)
  {
    var p = e.Split('|');
    if (p.Length < 4)
      return true;
    using var rl = Root(p[1]);
    var root = rl.Key;
    if (root == null)
      return !p[1].StartsWith("HKU:");
    using var k = root.OpenSubKey(p[2], true);
    if (k == null)
      return true;
    if (p.Length >= 8 && p[4] != "-")
      k.SetValue(p[3], Dec(p[5], Enum.Parse<RegistryValueKind>(p[4])), Enum.Parse<RegistryValueKind>(p[4]));
    else
      k.DeleteValue(p[3], false);
    return true;
  }

  // false = ההיבה לא טעונה
  static bool RevertRegKey(string e)
  {
    var p = e.Split('|');
    if (p.Length < 3)
      return true;
    using var rl = Root(p[1]);
    var root = rl.Key;
    if (root == null)
      return !p[1].StartsWith("HKU:");
    bool empty;
    using (var k = root.OpenSubKey(p[2]))
    {
      if (k == null)
        return true;
      empty = !HasValues(k);
    }
    if (empty)
      root.DeleteSubKeyTree(p[2], false);
    return true;
  }

  // ---------- ביטולי רישום שממתינים (משתמש שלא היה מחובר בזמן הביטול) ----------
  // בלי זה, ביטול בזמן שהמשתמש מנותק (למשל השירות עולה בבוקר לפני הכניסה) היה מוחק את הרישום של מה שהוחל, וההגבלה נשארת אצלו לתמיד
  static string RegPendFile => System.IO.Path.Combine(Config.Dir, "var", "regpending.txt");
  static readonly object RegPendLock = new();

  static void AddRegPending(List<string> lines)
  {
    if (lines.Count == 0)
      return;
    lock (RegPendLock)
      for (int i = 0; ; i++)
      {
        try
        {
          Directory.CreateDirectory(System.IO.Path.GetDirectoryName(RegPendFile)!);
          File.AppendAllLines(RegPendFile, lines);
          return;
        }
        catch (IOException) when (i < 10)
        {
          Thread.Sleep(200);
        }
      }
  }

  // הקובץ של הביטולים הממתינים נמצא בתיקייה var, שמנהלים יכולים לכתוב אליה – והשירות מבצע אותו כ-SYSTEM.
  // לכן מתקבלות רק רשומות של מפתחות שהתוכנה עצמה כותבת אליהם (מדיניות, הגדרות הסייר, שירותי USB/WSL).
  // רשומה אחרת (למשל למפתחות המוגנים של DeviceGuard – השעה האמינה, ההגדרות המהימנות, השירות) נזרקת בלי לבצע אותה
  static readonly string[] RegPendRoots = { @"SOFTWARE\Policies", @"Software\Microsoft\Windows\CurrentVersion\Policies", ADV };
  static readonly string[] RegPendKeys =
  {
    USBSTOR,
    UASPSTOR,
    @"SYSTEM\CurrentControlSet\Services\LxssManager",
    @"SYSTEM\CurrentControlSet\Services\WslService",
  };

  public static bool RegPendAllowed(string hive, string path)
  {
    if (!(hive == "HKLM" || hive == "HKCU" || hive.StartsWith("HKU:S-1-", StringComparison.Ordinal)))
      return false;
    var p = path.Trim('\\');
    if (p.Length == 0 || p.Contains(@"\\"))
      return false;
    if (RegPendRoots.Any(r => p.Equals(r, StringComparison.OrdinalIgnoreCase) || p.StartsWith(r + "\\", StringComparison.OrdinalIgnoreCase)))
      return true;
    return hive == "HKLM" && RegPendKeys.Any(k => p.Equals(k, StringComparison.OrdinalIgnoreCase));
  }

  static bool RegPendLineOk(string l)
  {
    var q = l.Split('|');
    return q.Length >= 3 && (q[0] == "reg" || q[0] == "regkey") && RegPendAllowed(q[1], q[2]);
  }

  // מבטל רשומות ממתינות של משתמשים שההיבה שלהם טעונה עכשיו. מחזיר כמה בוטלו
  public static int ProcessRegPending()
  {
    lock (RegPendLock)
    {
      try
      {
        if (!File.Exists(RegPendFile))
          return 0;
        var raw = File.ReadAllLines(RegPendFile).Where(l => l.Length > 0).ToList();
        var all = raw.Where(RegPendLineOk).ToList();
        if (all.Count != raw.Count)
          Alerts.Log("נמצאו בקובץ הביטולים הממתינים רשומות שהתוכנה לא כתבה – נזרקו בלי לבצע אותן");
        var keep = new List<string>();
        int done = 0;
        // אותו סדר כמו בביטול: ערכים בסדר הפוך, ואחר כך מפתחות מהעמוק לרדוד
        foreach (var e in Enumerable.Reverse(all.Where(x => x.StartsWith("reg|")).ToList()))
        {
          try
          {
            if (RevertReg(e))
              done++;
            else
              keep.Insert(0, e);
          }
          catch (Exception __e)
          {
            Diag.Log(__e);
            keep.Insert(0, e);
          }
        }
        foreach (var e in all.Where(x => x.StartsWith("regkey|")).OrderByDescending(x => x.Length))
        {
          try
          {
            if (!RevertRegKey(e))
              keep.Add(e);
          }
          catch (Exception __e)
          {
            Diag.Log(__e);
            keep.Add(e);
          }
        }
        if (keep.Count == 0)
          File.Delete(RegPendFile);
        else if (keep.Count != raw.Count)
          File.WriteAllLines(RegPendFile, keep);
        return done;
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
        return 0;
      }
    }
  }

  // ---- הסרת התוכנה כשמשתמש מוגבל לא מחובר ----
  // ההגבלות שלו (מנהל המשימות, עורך הרישום, לוח הבקרה, חסימת הרצה מתיקיות המשתמש...) נמצאות ברישום הפרטי שלו (NTUSER.DAT), שטעון רק כשהוא מחובר.
  // בביטול רגיל השירות משחרר אותן כשהוא נכנס – אבל אחרי הסרה אין שירות, והן היו נשארות לתמיד (וגם עורך הרישום חסום אצלו).
  // לכן בהסרה טוענים זמנית את הרישום שלו (RegLoadKey, בהרשאות הגיבוי/שחזור של מנהל מורם), מבטלים, ופורקים
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
  static extern int RegLoadKeyW(IntPtr hKey, string sub, string file);

  [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
  static extern int RegUnLoadKeyW(IntPtr hKey, string sub);

  static readonly IntPtr HKEY_USERS = unchecked((IntPtr)(int)0x80000003);

  // משתמשים (SID) שיש להם ביטולי רישום שממתינים
  public static List<string> PendingUsers()
  {
    lock (RegPendLock)
      try
      {
        if (!File.Exists(RegPendFile))
          return new List<string>();
        return File.ReadAllLines(RegPendFile)
          .Select(l => l.Split('|'))
          .Where(q => q.Length > 1 && q[1].StartsWith("HKU:"))
          .Select(q => q[1][4..])
          .Distinct(StringComparer.OrdinalIgnoreCase)
          .ToList();
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
        return new List<string>();
      }
  }

  static string? ProfileHive(string sid)
  {
    try
    {
      using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\" + sid);
      if (k?.GetValue("ProfileImagePath") is not string dir)
        return null;
      var f = System.IO.Path.Combine(Environment.ExpandEnvironmentVariables(dir), "NTUSER.DAT");
      return File.Exists(f) ? f : null;
    }
    catch
    {
      return null;
    }
  }

  // מבטל את כל ביטולי הרישום הממתינים, גם של משתמשים לא מחוברים. מחזיר את המשתמשים שעדיין נשארו (לא ניתן היה לטעון את הרישום שלהם)
  public static List<string> ProcessRegPendingOffline()
  {
    ProcessRegPending(); // משתמשים שמחוברים עכשיו
    foreach (var sid in PendingUsers())
    {
      try
      {
        using (var loaded = Registry.Users.OpenSubKey(sid))
          if (loaded != null)
            continue; // המשתמש מחובר: ProcessRegPending כבר טיפל
        var file = ProfileHive(sid);
        if (file == null)
          continue;
        EnablePrivs();
        var tmp = "DG_" + Guid.NewGuid().ToString("N");
        if (RegLoadKeyW(HKEY_USERS, tmp, file) != 0)
          continue; // אין הרשאות (למשל ההקשחה החזקה) או שהקובץ תפוס
        hiveAlias[sid] = tmp;
        try
        {
          ProcessRegPending();
        }
        finally
        {
          hiveAlias.TryRemove(sid, out _);
          // כל המפתחות לרישום הזה חייבים להיסגר לפני הפריקה
          GC.Collect();
          GC.WaitForPendingFinalizers();
          for (int i = 0; i < 10 && RegUnLoadKeyW(HKEY_USERS, tmp) != 0; i++)
            Thread.Sleep(300);
        }
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
    return PendingUsers();
  }

  // ---- שחרורים שלא הושלמו לפני הסרה: כוננים לא מחוברים ----
  // כוננים שיש בהם עדיין קבצים/תיקיות נעולים שלא ניתן היה לשחרר (הכונן לא מחובר)
  public static List<string> PendingDrives()
  {
    var res = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    void Add(string? path)
    {
      try
      {
        var r = string.IsNullOrEmpty(path) ? null : System.IO.Path.GetPathRoot(path);
        if (!string.IsNullOrEmpty(r) && !Directory.Exists(r))
          res.Add(r);
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
    try
    {
      lock (PathPendLock)
        if (File.Exists(PathPendFile))
          foreach (var l in File.ReadAllLines(PathPendFile))
          {
            var q = l.Split('\t')[0].Split('|');
            if (q.Length > 1)
              Add(q[1]);
          }
      lock (LogLock)
        if (File.Exists(WatchLog))
          foreach (var l in File.ReadAllLines(WatchLog))
          {
            var i = l.LastIndexOf('|');
            if (i > 0)
              Add(l[..i]);
          }
      lock (LostLock)
        if (File.Exists(LostFile))
          foreach (var l in File.ReadAllLines(LostFile))
            Add(l.Split('|')[0]);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    return res.OrderBy(x => x).ToList();
  }

  // ניסיון חוזר לשחרר (אחרי שהמשתמש חיבר את הכונן)
  public static void RetryReleases(Config c)
  {
    ResetDriveCache();
    try
    {
      ProcessPathPending(c);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    try
    {
      ReleaseWatchLogAll();
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    try
    {
      ProcessLost(new(), new(StringComparer.OrdinalIgnoreCase));
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  // מחיל רשומות "ממתינות" (משתמש שלא היה מחובר בזמן ההחלה) כשההיבה שלו נטענת. true = משהו השתנה וצריך לשמור
  public static bool ApplyRegPending(Config c)
  {
    List<string> pend;
    lock (c.Applied)
      pend = c.Applied.Where(x => x.StartsWith("regpend|")).ToList();
    bool changed = false;
    foreach (var e in pend)
    {
      var p = e.Split('|');
      if (p.Length < 6)
        continue;
      using (var rl = Root(p[1]))
        if (rl.Key == null)
          continue;
      try
      {
        var kind = Enum.Parse<RegistryValueKind>(p[4]);
        lock (c.Applied)
          c.Applied.Remove(e);
        SetReg(c, p[1], p[2], p[3], Dec(p[5], kind), kind);
        changed = true;
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
    return changed;
  }

  public static List<RegWant> RegWants(Config c)
  {
    List<string> snap;
    lock (c.Applied)
      snap = c.Applied.Where(x => x.StartsWith("reg|")).ToList();
    return snap.Select(x => x.Split('|')).Where(p => p.Length >= 8).Select(p => new RegWant(p[1], p[2], p[3], p[6], p[7])).ToList();
  }

  // שחזור מדיניות רישום שנמחקה/שונתה (נקרא מהשירות)
  public static int HealReg(List<RegWant> list)
  {
    int n = 0;
    foreach (var w in list)
    {
      try
      {
        using var rl = Root(w.Hive);
        var root = rl.Key;
        if (root == null)
          continue;
        using var k = root.CreateSubKey(w.Path, true);
        if (k == null)
          continue;
        var kind = Enum.Parse<RegistryValueKind>(w.Kind);
        var want = Dec(w.Enc, kind);
        var have = k.GetValue(w.Name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        if (!SameValue(have, want, kind))
        {
          k.SetValue(w.Name, want, kind);
          n++;
        }
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
    return n;
  }

  // ---------- החלה ----------
  static string ApplyFlag => System.IO.Path.Combine(Config.Dir, "var", "applying.flag");

  // החלה/ביטול רץ כרגע. בשירות: לפי הזיכרון בלבד – החלה של השירות עצמו, או הודעה מהחלון דרך ה-Pipe (מאומתת בקוד הכניסה).
  // הקובץ applying.flag בתיקיית var (שמנהלים יכולים לכתוב אליה) כבר לא נחשב בשירות: עדכון שלו כל כמה דקות כיבה את כל השחזורים.
  // הוא עדיין נכתב, לטובת שירות מגרסה ישנה בזמן עדכון
  static int localApplying;
  static long uiApplyUntil; // ticks (UTC)

  public static void UiApplying(bool on) => Interlocked.Exchange(ref uiApplyUntil, on ? DateTime.UtcNow.AddMinutes(5).Ticks : 0);

  public static bool Applying()
  {
    if (InService)
      return Volatile.Read(ref localApplying) > 0 || DateTime.UtcNow.Ticks < Interlocked.Read(ref uiApplyUntil);
    try
    {
      var f = ApplyFlag;
      return File.Exists(f) && (DateTime.UtcNow - File.GetLastWriteTimeUtc(f)).TotalMinutes < 5;
    }
    catch
    {
      return false;
    }
  }

  // ---- נעילה בין החלון לשירות: רק החלה/ביטול אחד בכל רגע ----
  // בלי זה, לחיצה על "החל" בדיוק כשחלון הזמנים מתחיל הייתה מריצה שתי החלות במקביל, וכל אחת שומרת רשימת "מה הוחל" אחרת – ודברים נשארים חסומים בלי רישום.
  // קובץ פתוח בבלעדיות (משתחרר אוטומטית גם אם התהליך קורס). בתוך אותו תהליכון אפשר להיכנס שוב
  static string ApplyLockFile => System.IO.Path.Combine(Config.Dir, "var", "apply.lock");

  [ThreadStatic]
  static int applyLockDepth;

  sealed class ApplyLockRel : IDisposable
  {
    FileStream? fs;
    bool done;

    public ApplyLockRel(FileStream? fs) => this.fs = fs;

    public void Dispose()
    {
      if (done)
        return;
      done = true;
      applyLockDepth--;
      fs?.Dispose();
    }
  }

  public static IDisposable ApplyLock()
  {
    if (applyLockDepth++ > 0)
      return new ApplyLockRel(null);
    var start = DateTime.UtcNow;
    var until = start.AddMinutes(10);
    while (true)
    {
      try
      {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(ApplyLockFile)!);
        return new ApplyLockRel(new FileStream(ApplyLockFile, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None));
      }
      catch (IOException) when (DateTime.UtcNow < until)
      {
        // בשירות: מי שמחזיק את הנעילה חייב להיות החלה אמיתית – של השירות, או של החלון (שמודיע עליה דרך ה-Pipe בקוד הכניסה).
        // אם אחרי 15 שניות אין החלה כזו, מישהו אחר מחזיק את הקובץ (מנהל שמנסה לעכב את תחילת החסימה): ממשיכים בלי לחכות
        if (InService && (DateTime.UtcNow - start).TotalSeconds > 15 && !Applying())
        {
          Alerts.Log("קובץ הנעילה של ההחלה תפוס על ידי תהליך אחר – ממשיכים בלי לחכות", false);
          return new ApplyLockRel(null);
        }
        Thread.Sleep(250); // החלה אחרת רצה כרגע: מחכים שתסתיים
      }
      catch (Exception __e)
      {
        Diag.Log(__e); // לא ניתן לנעול (או המתנה ארוכה מדי): ממשיכים בלי נעילה, כמו קודם
        return new ApplyLockRel(null);
      }
    }
  }

  // אחרי ההמתנה לנעילה: רשימת "מה הוחל" נלקחת מהקובץ, כי ייתכן שהצד השני שינה אותה בזמן שחיכינו
  static void RefreshRuntime(Config c)
  {
    try
    {
      var cur = Config.TryLoad();
      if (cur == null || ReferenceEquals(cur, c) || ReferenceEquals(cur.Applied, c.Applied))
        return;
      lock (c.Applied)
      {
        c.Applied.Clear();
        c.Applied.AddRange(cur.Applied);
      }
      c.State = cur.State;
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  // דגל "החלה רצה" עם דופק: מתעדכן כל דקה כל עוד ההחלה רצה. בלי הדופק, החלה שנמשכה יותר מ-5 דקות (תיקייה גדולה, PowerShell איטי)
  // נחשבה "תקועה", והשירות היה "משחזר" באמצע ערכי רישום שבוטלו זה עתה – וההחלה רשמה אותם כערך המקורי, כך שההגבלה נשארה גם אחרי הפתיחה
  sealed class ApplyingFlag : IDisposable
  {
    readonly System.Threading.Timer t;
    volatile bool done;
    static ApplyingFlag? current; // בחלון: ההחלה שרצה עכשיו (לשליחה מחדש לשירות חדש שהותקן באמצע)

    public ApplyingFlag()
    {
      if (InService)
        Interlocked.Increment(ref localApplying);
      else
      {
        // השירות חייב לדעת שהחלון מחיל/מבטל עכשיו, אחרת הוא "משחזר" כל שינוי ברגע שהוא נעשה – וחסימות שבוטלו חוזרות בלי רישום
        // ונשארות אחרי הפתיחה. השירות דחה את ההודעה גם אחרי אימות מחדש: לא ממשיכים. (השירות לא זמין – אין מי שישחזר; ממשיכים)
        if (Notify(true) == "DENY")
          throw new IOException(
            "לא ניתן היה לתאם את הפעולה עם שירות ההגנה (האימות נדחה – ייתכן שיש נעילה זמנית אחרי ניסיונות שגויים). סגור את התוכנה, פתח אותה שוב ונסה שוב."
          );
        current = this;
      }
      Touch(false);
      t = new System.Threading.Timer(_ => Touch(true), null, 20_000, 20_000);
    }

    void Touch(bool notify)
    {
      if (done)
        return;
      if (!InService && notify)
        Notify(true);
      try
      {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(ApplyFlag)!);
        File.WriteAllText(ApplyFlag, "1");
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }

    // מחזיר את תשובת השירות (null = לא זמין). טוקן שפג מחודש אוטומטית (PipeAuth)
    static string? Notify(bool on)
    {
      try
      {
        return Config.PipeAuth(t => $"APPLYING|{t}|{(on ? 1 : 0)}", 2000);
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
        return null;
      }
    }

    // השירות הותקן/עודכן באמצע ההחלה: מודיעים לו מיד (בלי זה הוא היה "משחזר" באמצע ההחלה)
    public static void Resend()
    {
      if (current is { done: false })
        Notify(true);
    }

    public void Dispose()
    {
      if (done)
        return;
      done = true;
      t.Dispose();
      if (InService)
        Interlocked.Decrement(ref localApplying);
      else
      {
        Notify(false);
        if (current == this)
          current = null;
      }
      try
      {
        File.Delete(ApplyFlag);
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
  }

  public static void Apply(Config c)
  {
    using var lk = ApplyLock();
    RefreshRuntime(c);
    JournalMerge(c); // החלה קודמת שנקטעה: מה שהיא שינתה מבוטל עכשיו (Revert) לפני ההחלה החדשה
    using var fl = new ApplyingFlag();
    JournalBegin(c);
    savedOk = false;
    try
    {
      ApplyInner(c);
    }
    finally
    {
      JournalEnd(savedOk); // לא נשמר – היומן נשאר, והרשומות שלו יצטרפו בפעם הבאה
    }
  }

  public static void Release(Config c)
  {
    using var lk = ApplyLock();
    RefreshRuntime(c);
    JournalMerge(c);
    using var fl = new ApplyingFlag();
    Revert(c);
    c.State = 0;
    c.Save(true);
    JournalEnd(true);
  }

  // פתיחה זמנית מהחלון: הדגל מסמן לשירות לא "לשחזר" חסימות בזמן הביטול. הדגל נשאר עוד רגע אחרי השמירה, כדי שהשירות יטען את ההגדרות החדשות לפני שהוא בודק שוב
  public static void TempOpen(Config c, long until)
  {
    using var lk = ApplyLock();
    RefreshRuntime(c);
    JournalMerge(c);
    using var fl = new ApplyingFlag();
    Revert(c);
    c.TempOpenUntil = until;
    c.Save(true);
    JournalEnd(true);
    Thread.Sleep(3000);
  }

  static void ApplyInner(Config c)
  {
    SetSkip(c);
    ProcessRegPending(); // ביטולים ממתינים מהפעם הקודמת מבוצעים לפני ההחלה החדשה
    NeedReboot = false;
    Revert(c, true);
    Blocked = 0;
    Failed = 0;
    LastErr = null;
    try
    {
      PurgeIfeo(); // מנקה שערים יתומים שנשארו מהחלה שנכשלה
      if (!c.Master)
      {
        FinishRevert(c);
        SafeBootSet(false); // החסימות כבויות: השירות לא צריך לעלות ב-Safe Mode (נרשם שוב בהחלה הבאה, אם האפשרות מסומנת)
        c.State = 0;
        SaveRt(c);
        return;
      }
      ApplyCore(c);
      FinishRevert(c); // משחרר רק מה שכבר לא נדרש
      c.State = 1;
      SaveRt(c);
      Alerts.Log("הוחלו חסימות", false);
    }
    catch
    {
      try
      {
        FinishRevert(c);
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
      try
      {
        SaveRt(c);
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
      throw;
    } // שומרים את מה שכבר הוחל, כדי שאפשר יהיה לבטל אותו
  }

  public static void SetSkip(Config c)
  {
    Harden = c.Harden;
    SkipAppData = c.SkipAppData;
    Exclude = c.Exclude.ToArray();
    IncludeRemovable = c.IncludeRemovable;
    SkipProgramDirs = c.SkipProgramDirs;
    UiExe = string.IsNullOrWhiteSpace(c.UiExe) ? null : c.UiExe.TrimEnd('\\');
    DenyTo = World;
    if (ScopeHive(c) != "HKLM")
      try
      {
        DenyTo = new SecurityIdentifier(c.OwnerSid!);
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
  }

  // "רק החשבון שנבחר": החסימות שאפשר להחיל על חשבון אחד (נעילת קבצים/תיקיות/סוגי קבצים, USB, תוכנות ניידות, מדיניות דפדפנים וכו')
  // נכתבות לחשבון הזה בלבד. בלי חשבון ידוע – כמו קודם, לכל המחשב
  public static string ScopeHive(Config c) => c.AllUsers || string.IsNullOrEmpty(c.OwnerSid) ? "HKLM" : "HKU:" + c.OwnerSid;

  // חסימת התוכנות הניידות הוחלה בפועל (ולא רק סומנה בלי "החל שינויים"). רשומה מגרסה קודמת: DefaultLevel=0 ברמת המחשב
  public static bool PortableApplied(Config c)
  {
    var legacy = "reg|HKLM|" + SAFER + "|DefaultLevel|";
    var want0 = "|DWord|" + Enc(0, RegistryValueKind.DWord);
    lock (c.Applied)
      return c.Applied.Contains("portableapplied") || c.Applied.Any(x => x.StartsWith(legacy, StringComparison.Ordinal) && x.EndsWith(want0, StringComparison.Ordinal));
  }

  // חסימת USB לחשבון אחד בלבד. עם רשימה לבנה של כוננים אי אפשר (Windows מאפשר כונן מסוים רק ברמת המחשב) – ואז החסימה חלה על כל המחשב, כמו קודם
  public static bool UsbUser(Config c) => ScopeHive(c) != "HKLM" && !c.Usb.White.Any(w => !w.StartsWith("usbparent:"));

  // חסימת רשת לחשבון אחד בלבד: כלל חסימה יוצא בחומת האש של Windows, שחל רק על התעבורה של החשבון שנבחר (לפי ה-SID).
  // מתאמי הרשת וה-Wi-Fi לא מושבתים, ושאר החשבונות (גם המנהל) מתחברים כרגיל. עם רשימה לבנה: הכלל חל על כל המתאמים חוץ ממתאם
  // שברשימה וכרטיס Wi-Fi שמחובר עכשיו לרשת שברשימה – והשירות מעדכן אותו בכל שינוי ברשת (NetUserHeal)
  public static bool NetUser(Config c) => ScopeHive(c) != "HKLM" && SidOk(c.OwnerSid);

  const string NetUserGroup = "DeviceGuardNetUser";
  const string NetUserRule = "DeviceGuard Block User Outbound";

  // SID תקין בלבד (נכנס לפקודת PowerShell)
  public static bool SidOk(string? sid) =>
    sid != null && sid.Length < 200 && sid.StartsWith("S-1-", StringComparison.Ordinal) && sid.Skip(4).All(ch => char.IsAsciiDigit(ch) || ch == '-');

  // מה שהוחל: netuser|SID[|רשימה לבנה – Base64 של JSON]. בלי רשימה – חסימה בכל המתאמים
  static string NetUserEntry(string sid, List<string> white) =>
    "netuser|" + sid + (white.Count > 0 ? "|" + Convert.ToBase64String(Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(white))) : "");

  static (string Sid, List<string> White)? NetUserApplied(Config c)
  {
    string? e;
    lock (c.Applied)
      e = c.Applied.FirstOrDefault(x => x.StartsWith("netuser|"));
    if (e == null)
      return null;
    var q = e.Split('|');
    if (q.Length < 2 || !SidOk(q[1]))
      return null;
    var w = new List<string>();
    if (q.Length > 2 && q[2].Length > 0)
      try
      {
        w = System.Text.Json.JsonSerializer.Deserialize<List<string>>(Encoding.UTF8.GetString(Convert.FromBase64String(q[2]))) ?? new List<string>();
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    return (q[1], w);
  }

  // המתאמים שמותרים עכשיו לחשבון: מתאם מהרשימה הלבנה, וכרטיס Wi-Fi שמחובר כרגע לרשת מהרשימה הלבנה (לפי שם הרשת או שם הפרופיל)
  public static List<string> NetUserAllowed(List<string> white)
  {
    var res = white.Where(w => !w.StartsWith("ssid:")).ToList();
    var ssids = white.Where(w => w.StartsWith("ssid:")).Select(w => w[5..]).ToHashSet(StringComparer.Ordinal);
    if (ssids.Count == 0)
      return res;
    var conn = Wlan.Connected();
    if (conn.Count == 0)
      return res;
    try
    {
      foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        if (Guid.TryParse(ni.Id, out var g) && conn.TryGetValue(g, out var cn) && (ssids.Contains(cn.Ssid) || ssids.Contains(cn.Profile)))
          res.Add(ni.Name);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    return res;
  }

  // פקודות PowerShell שבונות מחדש את כלל החסימה. השורה האחרונה בפלט: "#all" (כל המתאמים) או "#מספר" (כמה מתאמים נחסמו)
  static List<string> NetUserCmds(string sid, List<string> white)
  {
    var l = new List<string> { $"Remove-NetFirewallRule -Group '{NetUserGroup}' -ErrorAction SilentlyContinue" };
    var nr = $"New-NetFirewallRule -DisplayName '{NetUserRule}' -Group '{NetUserGroup}' -Direction Outbound -Action Block -LocalUser 'D:(A;;CC;;;{sid})' -Profile Any";
    if (white.Count == 0)
    {
      l.Add(nr + " | Out-Null");
      l.Add("'#all'");
      return l;
    }
    var allow = NetUserAllowed(white);
    l.Add("$dgAllow = @(" + string.Join(",", allow.Select(a => "'" + Q(a) + "'")) + ")");
    // כל המתאמים (גם מוסתרים, למשל חיבור VPN) חוץ מהמותרים. אם Windows דוחה את הרשימה – רק המתאמים הגלויים, ואם גם זה נכשל – חסימה בכל המתאמים
    l.Add("function dgIfs($h) { @(Get-NetAdapter -IncludeHidden:$h -ErrorAction SilentlyContinue | ? { $dgAllow -notcontains $_.Name } | % { [System.Management.Automation.WildcardPattern]::Escape($_.Name) }) }");
    l.Add("$dgN = '#0'");
    l.Add("foreach ($h in @($true, $false)) { $i = dgIfs $h; if ($i.Count -eq 0) { $dgN = '#0'; break }; try { " + nr + " -InterfaceAlias $i -ErrorAction Stop | Out-Null; $dgN = '#' + $i.Count; break } catch { $dgN = '#fail' } }");
    l.Add("if ($dgN -eq '#fail') { " + nr + " | Out-Null; $dgN = '#all' }");
    l.Add("$dgN");
    return l;
  }

  // סיכום קצר של מה שעומד להיות מוחל (לחלון האישור)
  public static string Describe(Config c)
  {
    if (!c.Master)
      return "החסימות מושבתות: כל החסימות הקיימות יוסרו.";
    var l = new List<string>();
    foreach (var r in new[] { c.Settings, c.Install, c.Net, c.Usb, c.Portable, c.Movies, c.Songs, c.Images }.Where(r => r.On))
      l.Add("• " + r.Name + (r.Mode == Mode.Code ? " (בקוד)" : ""));
    int pr = c.Programs.Count(r => r.On),
      ex = c.Exts.Count(r => r.On),
      pa = c.Paths.Count(r => r.On);
    if (pr > 0)
      l.Add($"• חסימת {pr} תוכנות");
    if (ex > 0)
      l.Add($"• חסימת {ex} סיומות נוספות");
    if (pa > 0)
      l.Add($"• חסימת {pa} קבצים/תיקיות");
    if (c.NetApps.On)
      l.Add("• חסימת רשת לפי תוכנה" + (c.NetAppsWhite ? " (רשימה לבנה)" : ""));
    if (c.Adv.On)
      l.Add("• הגנה מתקדמת");
    if (c.Sched.On)
      l.Add($"• תזמון: פעיל בין {c.Sched.From} ל-{c.Sched.To}");
    return l.Count == 0 ? "לא מסומנת אף חסימה." : "יוחלו החסימות הבאות:\n" + string.Join("\n", l);
  }

  static void SafeBootSet(bool on)
  {
    foreach (var m in new[] { "Minimal", "Network" })
    {
      var path = $@"SYSTEM\CurrentControlSet\Control\SafeBoot\{m}\DeviceGuard";
      try
      {
        if (on)
        {
          using var k = Registry.LocalMachine.CreateSubKey(path);
          k.SetValue("", "Service");
        }
        else
          Registry.LocalMachine.DeleteSubKeyTree(path, false);
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
  }

  static void ApplyCore(Config c)
  {
    if (!InService)
      EnsureService();
    SafeBootSet(c.AdvOpts.SafeBoot);
    var uh = UserHive(c);
    // שאילתות PowerShell רצות במקביל. חסימת סיומות (תמונות/שירים/סרטים) נעשית ברקע בשירות, ולכן ההחלה חוזרת מיד
    var netUser = c.Net.On && NetUser(c); // חסימת רשת לחשבון אחד (חומת האש), בלי השבתת מתאמים
    Task<string>? netT = c.Net.On && !netUser
      ? Task.Run(() =>
        PS(
          "Get-NetAdapter | % { $w = ($_.PhysicalMediaType -like '*802.11*' -or $_.InterfaceDescription -match 'Wireless|Wi-Fi'); $(if ($w) { 'W' } else { 'E' }) + '|' + $_.Status + '|' + $_.PnPDeviceID + '|' + $_.Name }"
        )
      )
      : null;
    Task<string>? usbT = c.Usb.On && !UsbUser(c) ? Task.Run(() => PS(UsbQuery)) : null;
    Task<string>? fwT = c.NetApps.On || netUser
      ? Task.Run(() => PS("Get-NetFirewallProfile | % { [string]$_.Name + '|' + [string]$_.DefaultOutboundAction + '|' + [string]$_.Enabled }"))
      : null;
    var netCmds = new List<string>();
    var usbCmds = new List<string>();
    var fwCmds = new List<string>();
    var wlanArgs = new List<string>();

    // 1) פעולות PowerShell / netsh
    if (c.Net.On && !netUser)
    {
      var ssidWhite = c.Net.White.Where(w => w.StartsWith("ssid:")).Select(w => w[5..]).ToList();
      var adapterWhite = c.Net.White.Where(w => !w.StartsWith("ssid:")).ToList();
      var nl = Lines(netT!.Result);
      // מתאמי רשת שאינם Wi-Fi (Ethernet וכדומה): נחסמים כולם חוץ מהרשימה הלבנה; מתאם שכבר מושבת לא נוגעים בו שוב
      // שורה: סוג|מצב|מזהה התקן|שם. מזהה ההתקן נשמר בנוסף לשם (netpnp): מתאם שלא מחובר בזמן הביטול (מתאם רשת ב-USB)
      // לא מופיע לפי השם, ובלי המזהה היה נשאר מושבת כשמחברים אותו שוב
      foreach (var l in nl)
      {
        var q = l.Split('|', 4);
        if (q.Length < 4 || q[0] != "E" || adapterWhite.Contains(q[3]))
          continue;
        if (q[1] != "Disabled")
        {
          netCmds.Add($"Disable-NetAdapter -Name '{Q(q[3])}' -Confirm:$false");
          AddA(c, "net|" + q[3]);
        }
        else if (prevNet.ContainsKey(q[3]))
          AddA(c, "net|" + q[3]);
        else
          continue;
        if (q[2].Length > 0)
          AddA(c, $"netpnp|{q[2]}|{q[3]}");
      } // מתאם שהיה מושבת לפני כן (לא על ידינו) לא יופעל בביטול
      // Wi-Fi: חסימה לפי שם הרשת (SSID). נשלח ישירות ל-netsh (בלי PowerShell), כדי ששם רשת זדוני לא יוכל להריץ פקודות.
      // המסנן נוסף תמיד – גם כשאין כרגע מתאם Wi-Fi – כדי שמתאם Wi-Fi ב-USB שיחובר אחר כך לא יעקוף את החסימה (וגם NetAdapterHeal מוסיף אותו שוב כשמתאם כזה מופיע)
      wlanArgs.AddRange(WlanArgs(ssidWhite));
      AddA(c, "wlanfilter|denyall");
      AddA(c, "netapplied"); // סימון: חסימת הרשת הוחלה (השירות חוסם מתאמים חדשים רק אחרי "החל שינויים")
      foreach (var ssid in ssidWhite)
        AddA(c, "wlanfilter|allow|" + ssid);
    }
    // חומת האש של Windows חייבת לפעול: לחסימת רשת לפי תוכנה, ולחסימת רשת של חשבון אחד
    var fwl = fwT != null ? Lines(fwT.Result) : Array.Empty<string>();
    if (fwT != null)
    {
      // חומת אש שהייתה כבויה לפני ההחלה (למשל בגלל חומת אש אחרת) חוזרת להיות כבויה בביטול
      foreach (var l in fwl)
      {
        var q = l.Split('|');
        bool has;
        lock (c.Applied)
          has = c.Applied.Contains("fwenabled|" + q[0] + "|False");
        if (q.Length >= 3 && q[2].Equals("False", StringComparison.OrdinalIgnoreCase) && !has)
          AddA(c, "fwenabled|" + q[0] + "|False");
      }
      fwCmds.Add("Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True");
    }
    // חסימת רשת לחשבון אחד: כלל חסימה יוצא בחומת האש, שחל רק על התעבורה של החשבון שנבחר. שאר החשבונות (גם המנהל) לא מושפעים
    if (netUser)
    {
      var nw = c.Net.White.ToList();
      AddA(c, NetUserEntry(c.OwnerSid!, nw));
      fwCmds.AddRange(NetUserCmds(c.OwnerSid!, nw));
    }
    // חסימת חיבור לרשת לפי תוכנה (חומת האש של Windows)
    if (c.NetApps.On)
    {
      fwCmds.AddRange(NetAppsRules(c, new List<string>()));
      if (c.NetAppsWhite)
      {
        foreach (var l in fwl)
        {
          var q = l.Split('|');
          if (q.Length < 2 || q[1] == "Block")
            continue;
          AddA(c, "fwpolicy|" + q[0] + "|" + q[1]);
        }
        fwCmds.Add("Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block");
      }
      AddA(c, "fwrules");
      AddA(c, FwCfg(c));
    }
    if (c.Usb.On && UsbUser(c))
    {
      // רק החשבון שנבחר: מדיניות "אחסון נשלף – דחיית כל גישה" ברישום של החשבון. Windows מחיל אותה על החשבון הזה בלבד
      // (כונני USB, כרטיסי זיכרון, דיסקים וטלפונים), והתקנים לא מושבתים – כך שבשאר החשבונות הכול עובד כרגיל
      SetReg(c, ScopeHive(c), RSD, "Deny_All", 1);
    }
    else if (c.Usb.On)
    {
      AddA(c, "usbapplied"); // סימון: חסימת ה-USB הוחלה (השירות חוסם כוננים חדשים רק אחרי "החל שינויים")
      // רשימה לבנה לפי מזהה מופע (כולל מספר סידורי): כונן אחר מאותו דגם לא יאושר. ערכים ישנים (שם ידידותי) עדיין נתמכים
      var allow = new List<string>();
      foreach (var l in Lines(usbT!.Result))
      {
        var q = l.Split('|', 3);
        if (q.Length < 2)
          continue;
        var parent = q.Length > 2 ? q[2].Trim() : "";
        if (c.Usb.White.Contains(q[0]) || c.Usb.White.Contains(q[1]))
        {
          allow.Add(q[0]);
          if (parent.Length > 0)
          {
            allow.Add(parent);
            var pw = "usbparent:" + parent;
            if (!c.Usb.White.Contains(pw))
              c.Usb.White.Add(pw);
          } // גם התקן ה-USB האב חייב להיות מותר, אחרת הכונן לא יותקן
          continue;
        }
        if (!prevUsb.TryRemove(q[0], out _))
          usbCmds.Add($"Disable-PnpDevice -InstanceId '{Q(q[0])}' -Confirm:$false");
        AddA(c, "usb|" + q[0]);
      }
      foreach (var w in c.Usb.White.ToList())
      {
        var wv = w.StartsWith("usbparent:") ? w[10..] : w;
        if (wv.Contains('\\') && !allow.Contains(wv))
          allow.Add(wv);
      }
      bool hasWhite = c.Usb.White.Any(w => !w.StartsWith("usbparent:"));
      if (!hasWhite)
      {
        // כש-Windows עצמו רץ מדיסק USB, השבתת מנהלי ההתקן של אחסון USB הייתה מונעת את עליית המחשב – לכן מדלגים עליה
        if (!SystemOnUsb())
        {
          SetReg(c, "HKLM", USBSTOR, "Start", 4);
          using var ua = Registry.LocalMachine.OpenSubKey(UASPSTOR);
          if (ua != null)
            SetReg(c, "HKLM", UASPSTOR, "Start", 4); // כונני SSD מהירים (UASP) לא עוברים דרך USBSTOR
        }
        SetReg(c, "HKLM", RSD, "Deny_All", 1);
      } // חוסם גם אמצעי אחסון שכבר הותקנו
      // חסימה ברמת המדיניות: חלה גם על התקנים עתידיים.
      // "חסימת התקנים נשלפים" בטוחה רק כש-Windows מעריך את המדיניות בשכבות (AllowDenyLayered, נתמך בוודאות ב-Windows 11).
      // בלי זה החסימה גוברת על ההיתר לפי סוג התקן – ומקלדת/עכבר חדשים (או ביציאה אחרת) לא היו מותקנים.
      // לכן ב-Windows 10 חוסמים במקומה רק לפי סוג החיבור של ההתקן: אחסון USB, מצלמות/סורקים (PTP) וטלפונים (MTP). מקלדות ועכברים לא נפגעים
      if (LayeredOk)
        SetReg(c, "HKLM", DEVREST, "DenyRemovableDevices", 1);
      else
      {
        SetReg(c, "HKLM", DEVREST, "DenyDeviceIDs", 1);
        int dd = 1;
        foreach (var id in new[] { @"USB\Class_08", @"USB\Class_06", @"USB\MS_COMP_MTP" })
          SetReg(c, "HKLM", DEVREST + @"\DenyDeviceIDs", (dd++).ToString(), id, RegistryValueKind.String);
      }
      // הערכה בשכבות: היתר לפי סוג התקן גובר על "חסימת התקנים נשלפים", כך שמקלדת, עכבר, אוזניות ורמקולים חדשים עדיין מותקנים.
      // (כונן ה-USB עצמו הוא מסוג "כונן דיסק" ולכן נשאר חסום, גם כשההתקן האב שלו מסוג USB מותר)
      SetReg(c, "HKLM", DEVREST, "AllowDenyLayered", 1);
      SetReg(c, "HKLM", DEVREST, "AllowDeviceClasses", 1);
      int ci = 1;
      foreach (
        var cls in new[]
        {
          "{745a17a0-74d3-11d0-b6fe-00a0c90f57da}", // HIDClass
          "{4d36e96b-e325-11ce-bfc1-08002be10318}", // Keyboard
          "{4d36e96f-e325-11ce-bfc1-08002be10318}", // Mouse
          "{36fc9e60-c465-11cf-8056-444553540000}", // USB (רכזות והתקנים מורכבים)
          "{4d36e96c-e325-11ce-bfc1-08002be10318}", // Media (כרטיסי קול / אוזניות)
          "{c166523c-fe0c-4a94-a586-f1a80cfbbf3e}", // AudioEndpoint
          "{4d36e979-e325-11ce-bfc1-08002be10318}", // Printer (מדפסת USB חדשה)
          "{1ed2bbf9-11f0-4084-b21f-ad83a8e6dcdc}", // PrintQueue
          // מצלמות, סורקים, Bluetooth וטלפונים (WPD) נשארים חסומים בכוונה: דרכם אפשר להכניס תמונות וקבצים למחשב
        }
      )
        SetReg(c, "HKLM", DEVREST + @"\AllowDeviceClasses", (ci++).ToString(), cls, RegistryValueKind.String);
      if (hasWhite)
      {
        SetReg(c, "HKLM", DEVREST, "AllowInstanceIDs", 1);
        int ai = 1;
        foreach (var id in allow)
          SetReg(c, "HKLM", DEVREST + @"\AllowInstanceIDs", (ai++).ToString(), id, RegistryValueKind.String);
        // כוננים שכבר חוברו בעבר למחשב (ולכן כבר "מותקנים") אינם מושפעים מחסימת התקנה רגילה: חוסמים אותם במפורש, כולל מה שכבר מותקן
        var deny = KnownUsbStor().Where(id => !allow.Contains(id, StringComparer.OrdinalIgnoreCase)).ToList();
        if (deny.Count > 0)
        {
          SetReg(c, "HKLM", DEVREST, "DenyInstanceIDs", 1);
          SetReg(c, "HKLM", DEVREST, "DenyInstanceIDsRetroactive", 1);
          int di = 1;
          foreach (var id in deny)
            SetReg(c, "HKLM", DEVREST + @"\DenyInstanceIDs", (di++).ToString(), id, RegistryValueKind.String);
        }
        // טלפונים ונגנים (MTP) אינם כונני USB רגילים: חסימת גישה אליהם (ברשימה הלבנה אין Deny_All שמכסה אותם)
        foreach (var wpd in new[] { "{6AC27878-A6FA-4155-BA85-F98F491D4F33}", "{F33FDC04-D1AC-4E8E-9A30-19BBD4B108AE}" })
        {
          SetReg(c, "HKLM", RSD + "\\" + wpd, "Deny_Read", 1);
          SetReg(c, "HKLM", RSD + "\\" + wpd, "Deny_Write", 1);
        }
      }
    }
    Task.WaitAll(
      Task.Run(() => PSAll(netCmds)),
      Task.Run(() => PSAll(usbCmds)),
      Task.Run(() => PSAll(fwCmds)),
      Task.Run(() =>
      {
        foreach (var a in wlanArgs)
          Netsh(a);
      })
    );
    // רשימה לבנה: כללי היתר קיימים (אפליקציות מהחנות ותוכנות) מושבתים, כדי שבאמת רק התוכנות שברשימה יתחברו. חוזרים לפעול בביטול
    if (c.NetApps.On && c.NetAppsWhite)
      FwLeakOff();
    // 2) הגדרות מחשב
    var s = c.Settings;
    if (s.On)
    {
      if (s.Mode == Mode.Code)
      {
        Ifeo(c, "control.exe", s);
        Ifeo(c, "SystemSettings.exe", s);
      }
      else
      {
        if (s.White.Count > 0)
          SetReg(c, uh, EXP, "SettingsPageVisibility", "showonly:" + string.Join(";", s.White), RegistryValueKind.String);
        else
          SetReg(c, uh, EXP, "NoControlPanel", 1);
        if (s.White.Count > 0)
          Ifeo(c, "control.exe", s); // עם רשימה לבנה נחסמת רק אפליקציית ההגדרות החדשה, ולכן לוח הבקרה הישן נחסם בנפרד
      }
    }
    if (c.Install.On)
    {
      Ifeo(c, "msiexec.exe", c.Install);
      if (c.Install.Mode == Mode.Full)
      {
        // DisableMSI היא מדיניות מחשב בלבד (Windows מתעלם ממנה ברישום של משתמש), ולכן נכתבת רק כשהחסימה לכל המשתמשים
        if (uh == "HKLM")
          SetReg(c, "HKLM", INS, "DisableMSI", 2);
        // רוב תוכנות ההתקנה הן קובצי EXE ולא MSI: חוסמים הרצה מתיקיית ההורדות, שאליה מורידים אותן.
        // כשחסימת התוכנות הניידות פעילה היא כבר מכסה את זה (חוסמת כל מה שמחוץ ל-Windows ו-Program Files)
        if (!c.Portable.On)
          InstallSrp(c, uh);
      }
    }
    // 3) תוכנות
    // IFEO עובד לפי שם הקובץ, ולכן החסימה מוחלת גם אם הנתיב השתנה (תוכנה שמתעדכנת לתיקייה חדשה בכל גרסה)
    foreach (var r in c.Programs.Where(r => r.On && !string.IsNullOrWhiteSpace(r.Path)))
    {
      var f = System.IO.Path.GetFileName(r.Path);
      if (f.Length == 0 || IsCritical(f))
        continue;
      Ifeo(c, f, r);
      if (r.Hidden && r.Mode == Mode.Full && File.Exists(r.Path))
        Hide(c, r.Path);
    }
    // 4) תוכנות ניידות (Software Restriction Policies: ברירת מחדל = חסום, מותר: מערכת + רשימה לבנה). מותר רק קובץ ההפעלה של התוכנה עצמה, לא כל התיקייה שלו
    if (c.Portable.On)
    {
      SrpFix(c);
      // רק החשבון שנבחר: המדיניות נכתבת ברישום של החשבון (כמו חסימת ההתקנות), ושאר החשבונות לא מושפעים. סוגי הקבצים – רק ברמת המחשב
      var ph = ScopeHive(c);
      AddA(c, "portableapplied"); // סימון: חסימת התוכנות הניידות הוחלה (השירות סוגר rundll32/regsvr32 רק אחרי "החל שינויים")
      SetReg(c, ph, SAFER, "DefaultLevel", 0);
      if (ph == "HKLM")
        SetReg(c, "HKLM", SAFER, "PolicyScope", 0);
      SetReg(c, ph, SAFER, "TransparentEnabled", 1);
      SetReg(c, "HKLM", SAFER, "ExecutableTypes", SrpTypes, RegistryValueKind.MultiString);
      // DeviceGuard.exe עצמו לא מותר לפי המיקום שלו (פרצה – ראו EnsureUiShortcut): פותחים אותו מהקיצור לעותק שב-ProgramData
      var allow = new List<string>
      {
        Environment.GetFolderPath(Environment.SpecialFolder.Windows),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        Config.Dir,
      };
      EnsureUiShortcut();
      allow.AddRange(c.Portable.White);
      foreach (var a in allow.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase))
      {
        var pp = SAFER + @"\262144\Paths\{" + Guid.NewGuid() + "}";
        SetReg(c, ph, pp, "ItemData", a, RegistryValueKind.String);
        SetReg(c, ph, pp, "SaferFlags", 0);
      }
      // תיקיות שמשתמש רגיל יכול לכתוב אליהן בתוך Windows: חוסמים הרצה מהן (כלל מפורש גובר על הכלל הכללי של Windows)
      foreach (var wd in WinUserWritable)
      {
        var dp = SAFER + @"\0\Paths\{" + Guid.NewGuid() + "}";
        SetReg(c, ph, dp, "ItemData", WinDir + wd, RegistryValueKind.String);
        SetReg(c, ph, dp, "SaferFlags", 0);
      }
    }
    // 5) קבצים, תיקיות וסיומות
    if (DenyTo.Value != "S-1-1-0")
      AddA(c, "denyto|" + DenyTo.Value); // היקף הנעילה של ההחלה הזו (רק החשבון שנבחר) – לזיהוי שינוי היקף בהחלה הבאה
    foreach (var r in c.Paths.Where(r => r.On))
      if (!ProtectedPath(r.Path))
      {
        Block(c, r, r.Path);
        if (r.Mode == Mode.Code)
          MakeLnk(c, r);
      }
    foreach (var r in new[] { c.Movies, c.Songs, c.Images }.Concat(c.Exts).Where(r => r.On && r.Mode == Mode.Code))
      MakeExtLnk(c, r);
    if (c.Applied.Any(x => x.StartsWith("hid|")))
    { // מונע הצגת קבצים מוסתרים בסייר הקבצים
      try
      {
        SetReg(c, uh, ADV, "Hidden", 2);
        SetReg(c, uh, ADV, "ShowSuperHidden", 0);
        if (ScopeHive(c) == "HKLM") // הגדרה של כל המחשב: במצב "רק החשבון שנבחר" לא נוגעים בה (ההגבלות שבשורות האחרות הן של החשבון)
          SetReg(c, "HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL", "CheckedValue", 0);
        SetReg(c, uh, EXP, "NoFolderOptions", 1);
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
    // 6) הגנה מתקדמת (חלון 7)
    if (c.Adv.On)
      ApplyAdv(c, uh);
  }

  // כל כונני ה-USB שאי פעם חוברו למחשב (גם כשאינם מחוברים עכשיו), לפי הרישום של Windows
  static List<string> KnownUsbStor()
  {
    var res = new List<string>();
    try
    {
      using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\USBSTOR");
      if (k == null)
        return res;
      foreach (var dev in k.GetSubKeyNames())
      {
        using var dk = k.OpenSubKey(dev);
        if (dk == null)
          continue;
        foreach (var inst in dk.GetSubKeyNames())
          res.Add(@"USBSTOR\" + dev + @"\" + inst);
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    return res;
  }

  // תיקיות שמשתמש רגיל יכול לכתוב אליהן בתוך Windows (יחסית לתיקיית Windows): אסורות להרצה בחסימת תוכנות ניידות
  static readonly string[] WinUserWritable =
  {
    @"\Temp",
    @"\Tasks",
    @"\tracing",
    @"\Registration\CRMLog",
    @"\System32\Tasks",
    @"\System32\spool\drivers\color",
    @"\System32\spool\PRINTERS",
  };

  // ---- rundll32 / regsvr32 בחסימת תוכנות ניידות ----
  // Windows מריץ את הכלים האלה מתיקיית המערכת (מותרת), והם טוענים קובץ DLL מכל מקום – כך אפשר היה להריץ קוד מתיקיית ההורדות למרות החסימה.
  // מחזיר את קובץ ה-DLL שאינו בתיקייה מותרת (null = הכול מותר). מותר: Windows (חוץ מהתיקיות שמשתמש יכול לכתוב אליהן), Program Files,
  // תיקיית DeviceGuard, והתיקייה של תוכנה ברשימה הלבנה. שם בלי נתיב מותר רק אם הוא קיים בתיקיות המערכת (אחרת הוא נטען מהתיקייה הנוכחית)
  public static string? BadDllArg(string name, string cmdLine, Config c)
  {
    var tail = cmdLine.TrimStart();
    if (tail.StartsWith('"'))
    {
      var e = tail.IndexOf('"', 1);
      tail = e < 0 ? "" : tail[(e + 1)..];
    }
    else
    {
      var sp = tail.IndexOfAny(new[] { ' ', '\t' });
      tail = sp < 0 ? "" : tail[(sp + 1)..];
    }
    tail = tail.Trim();
    var dlls = new List<string>();
    if (name.Equals("rundll32", StringComparison.OrdinalIgnoreCase))
    {
      if (tail.Length == 0)
        return null;
      string d;
      if (tail.StartsWith('"'))
      {
        var e = tail.IndexOf('"', 1);
        d = e < 0 ? tail[1..] : tail[1..e];
      }
      else
      {
        // "קובץ,פונקציה": עד הפסיק (נתיב בלי מרכאות יכול להכיל רווחים). אם לפני הפסיק יש רווח והנתיב לא קיים – עד הרווח
        var comma = tail.IndexOf(',');
        var ws = tail.IndexOfAny(new[] { ' ', '\t' });
        var a = comma >= 0 ? tail[..comma] : tail;
        var b = ws >= 0 ? tail[..ws] : tail;
        d = a.IndexOfAny(new[] { ' ', '\t' }) < 0 || File.Exists(a) ? a : b;
      }
      dlls.Add(d.Trim());
    }
    else
    {
      // regsvr32 [/s] [/u] [/i[:...]] [/n] קובץ [קובץ...]
      var tok = new StringBuilder();
      bool inQ = false;
      void Flush()
      {
        if (tok.Length == 0)
          return;
        var t = tok.ToString();
        tok.Clear();
        if (!(t.StartsWith('/') || t.StartsWith('-')))
          dlls.Add(t);
      }
      foreach (var ch in tail)
      {
        if (ch == '"')
          inQ = !inQ;
        else if (!inQ && (ch == ' ' || ch == '\t'))
          Flush();
        else
          tok.Append(ch);
      }
      Flush();
    }
    foreach (var d in dlls)
    {
      if (d.Length == 0)
        continue;
      if (!DllAllowed(d, c))
        return d;
    }
    return null;
  }

  static bool DllAllowed(string d, Config c)
  {
    try
    {
      if (d.IndexOfAny(new[] { '\\', '/', ':' }) < 0)
      {
        // שם בלי נתיב: Windows מחפש קודם בתיקיות המערכת. אם הוא לא שם – הוא ייטען מהתיקייה הנוכחית / מה-PATH (מקום שהמשתמש קובע)
        var f = System.IO.Path.HasExtension(d) ? d : d + ".dll";
        foreach (var sd in new[] { Environment.SystemDirectory, Environment.GetFolderPath(Environment.SpecialFolder.SystemX86), WinDir })
          if (!string.IsNullOrEmpty(sd) && File.Exists(System.IO.Path.Combine(sd, f)))
            return true;
        return false;
      }
      if (!System.IO.Path.IsPathFullyQualified(d))
        return false; // נתיב יחסי (תיקייה\קובץ, C:קובץ): תלוי בתיקייה הנוכחית
      var p = System.IO.Path.GetFullPath(d).TrimEnd('\\');
      if (Under(p, WinDir))
        return !WinUserWritable.Any(w => Under(p, WinDir + w));
      foreach (var r in new[] { PF, PF86, CdT })
        if (!string.IsNullOrEmpty(r) && Under(p, r))
          return true;
      foreach (var w in c.Portable.White)
      {
        if (string.IsNullOrWhiteSpace(w))
          continue;
        var wt = w.Trim().TrimEnd('\\');
        var dir = Directory.Exists(wt) ? wt : System.IO.Path.GetDirectoryName(wt);
        if (!string.IsNullOrEmpty(dir) && Under(p, dir.TrimEnd('\\')))
          return true;
      }
      return false;
    }
    catch
    {
      return false;
    }
  }

  // ---------- Software Restriction Policies ב-Windows 11 ----------
  // בהתקנה נקייה של Windows 11 (22H2 ואילך) קיימים ערכי AppLocker שגויים (RuleCount שאינו 0 בלי שום כלל), ובגללם Windows מתעלם מ-SRP.
  // מאפסים את הערך (רק כשאין כללי AppLocker אמיתיים). הערך לא משוחזר בביטול בכוונה: הוא שגוי מלכתחילה, ואיפוסו לא משנה שום דבר אחר במחשב.
  // (אם היה משוחזר, כל תחילת חלון זמנים הייתה דורשת שוב הפעלה מחדש.) נדרשת הפעלה מחדש אחת של המחשב
  const string SRPGP = @"SYSTEM\CurrentControlSet\Control\Srp\Gp";
  public static bool NeedReboot;

  static void SrpFix(Config c)
  {
    try
    {
      using (var gp = Registry.LocalMachine.OpenSubKey(SRPGP))
        if (!(gp?.GetValue("RuleCount") is int rc && rc != 0))
          return;
      using (var v2 = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\SrpV2"))
        if (v2 != null && HasValues(v2))
          return; // יש מדיניות AppLocker אמיתית: לא נוגעים
      using (var gp = Registry.LocalMachine.OpenSubKey(SRPGP, true))
        gp?.SetValue("RuleCount", 0, RegistryValueKind.DWord);
      NeedReboot = true;
      Alerts.Log("תוקנה הגדרת Windows שמשביתה חסימת תוכנות (SRP). נדרשת הפעלה מחדש של המחשב", false);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  // חסימת התקנה מקובצי EXE: איסור הרצה מתיקיית ההורדות (שם נמצאות כמעט תמיד תוכנות ההתקנה שהורדו).
  // שולחן העבודה לא נכלל בכוונה, כדי לא לשבור קיצורי דרך שהמשתמש שם שם
  static void InstallSrp(Config c, string uh)
  {
    SrpFix(c);
    SetReg(c, uh, SAFER, "DefaultLevel", 262144); // ברירת מחדל: מותר. רק הנתיב שלמטה אסור
    SetReg(c, uh, SAFER, "TransparentEnabled", 1);
    if (uh == "HKLM")
      SetReg(c, uh, SAFER, "PolicyScope", 0);
    // קיצורי דרך (LNK) לא נבדקים בעצמם – אחרת קיצורים בשולחן העבודה היו נחסמים (סוגי הקבצים נקראים רק ממדיניות המחשב)
    SetReg(c, "HKLM", SAFER, "ExecutableTypes", SrpTypes, RegistryValueKind.MultiString);
    // כל תיקיית המשתמש אסורה להרצה (הורדות, שולחן עבודה, מסמכים, וכל תיקייה שהדפדפן שומר אליה), חוץ מ-AppData – שם מותקנות התוכנות של המשתמש.
    // גם התיקייה הציבורית (C:\Users\Public) וקבצים שנפתחים מתוך ZIP / 7-Zip / WinRAR (מחולצים לתיקייה זמנית ב-AppData) אסורים.
    // כלל ספציפי יותר גובר: AppData מותר בתוך תיקיית המשתמש האסורה, ותיקיות החילוץ אסורות בתוך AppData המותר
    void AddPath(string path, int level)
    {
      var k = SAFER + $@"\{level}\Paths\{{" + Guid.NewGuid() + "}";
      SetReg(c, uh, k, "ItemData", path, RegistryValueKind.ExpandString);
      SetReg(c, uh, k, "SaferFlags", 0);
    }
    AddPath(@"%USERPROFILE%", 0);
    AddPath(@"%PUBLIC%", 0);
    AddPath(@"%USERPROFILE%\AppData", 262144);
    AddPath(@"%USERPROFILE%\AppData\Local\Temp\Temp*.zip", 0);
    AddPath(@"%USERPROFILE%\AppData\Local\Temp\7zO*", 0);
    AddPath(@"%USERPROFILE%\AppData\Local\Temp\Rar$*", 0);
    EnsureUiShortcut();
  }

  // DeviceGuard.exe עצמו בדרך כלל בתיקיית ההורדות / שולחן העבודה, ושם הוא נחסם (חסימת התקנות / תוכנות ניידות). היתר לקובץ הזה היה פרצה:
  // משתמש שיכול לכתוב לתיקייה מחליף אותו בכל תוכנה אחרת באותו שם. במקום זה – קיצור "DeviceGuard" לעותק המוגן ב-ProgramData
  // (אותו קובץ בדיוק, ותיקייה שרק המערכת כותבת אליה). הקיצורים נשארים עד הסרת התוכנה
  public static bool UiShortcutNote; // החלון מודיע פעם אחת שמעכשיו פותחים מהקיצור

  static IEnumerable<string> UiShortcuts()
  {
    foreach (var f in new[] { Environment.SpecialFolder.CommonDesktopDirectory, Environment.SpecialFolder.CommonPrograms })
    {
      var d = Environment.GetFolderPath(f);
      if (!string.IsNullOrEmpty(d))
        yield return System.IO.Path.Combine(d, "DeviceGuard.lnk");
    }
  }

  public static void EnsureUiShortcut()
  {
    foreach (var lnk in UiShortcuts())
    {
      try
      {
        if (File.Exists(lnk) && LnkIsOurs(lnk))
          continue;
        if (File.Exists(lnk))
          continue; // קיצור של מישהו אחר באותו שם – לא נוגעים
        dynamic sh = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell")!)!;
        dynamic l = sh.CreateShortcut(lnk);
        l.TargetPath = GateExe;
        l.Arguments = "";
        l.IconLocation = GateExe + ",0";
        l.Description = "DeviceGuard";
        l.Save();
        UiShortcutNote = true;
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
  }

  static void RemoveUiShortcuts()
  {
    foreach (var lnk in UiShortcuts())
      try
      {
        if (File.Exists(lnk) && LnkIsOurs(lnk))
          File.Delete(lnk);
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
  }

  // סוגי הקבצים ש-SRP בודק (ברירת המחדל של Windows), בלי LNK ו-URL: אחרת קיצורי דרך בשולחן העבודה ובתפריט התחל (שנמצאים מחוץ לתיקיות המותרות)
  // היו נחסמים, גם כשהם מפנים לתוכנה מותרת ב-Program Files. התוכנה שהקיצור מפעיל עדיין נבדקת לפי המיקום שלה
  static readonly string[] SrpTypes =
    "ADE ADP BAS BAT CHM CMD COM CPL CRT EXE HLP HTA INF INS ISP MDB MDE MSC MSI MSP MST OCX PCD PIF REG SCR SHS VB WSC".Split(' ');

  static void ApplyAdv(Config c, string uh)
  {
    var a = c.AdvOpts;
    // מדיניות שקיימת גם לחשבון בודד (החנות, הדפדפנים, Proxy): במצב "רק החשבון שנבחר" נכתבת רק לחשבון הזה
    var sh = ScopeHive(c);
    if (a.BlockBoot)
      foreach (var e in new[] { "bcdedit.exe", "msconfig.exe", "reagentc.exe" })
        Ifeo(c, e, c.Adv);
    if (a.NoVirt)
    {
      // חסימה לפי שם קובץ (IFEO) חלה על כל קובץ בשם הזה במחשב. bash.exe לא נחסם כך: זה גם השם של Git Bash, MSYS2, Cygwin ועוד.
      // במקום זה מושבתים שירותי WSL עצמם – כך ש-bash.exe של WSL (וכל דרך אחרת להפעיל WSL) לא עובד, ו-bash אחרים לא נפגעים.
      // הערך הקודם נשמר ומוחזר בביטול (כמו כל מדיניות רישום). שירות שכבר רץ נעצר רק בהפעלה מחדש – wsl.exe נחסם מיד בכל מקרה
      foreach (var e in new[] { "wsl.exe", "WindowsSandbox.exe", "vmconnect.exe" })
        Ifeo(c, e, c.Adv);
      if (sh != "HKLM")
      {
        // רק החשבון שנבחר: שירותי WSL ממשיכים לפעול (שאר החשבונות משתמשים בהם). אצל החשבון הזה נסגרים: wsl.exe (השער למעלה),
        // wslg.exe, ה-bash של WSL (רק מתיקיית המערכת – Git Bash ודומיו לא נפגעים) ותוכנות ההפעלה של ההפצות מהחנות (Ubuntu וכו')
        AddA(c, "kill|wslg|" + c.Adv.Id);
        AddA(c, "wslbash|" + c.Adv.Id);
      }
      else
        foreach (var svc in new[] { "LxssManager", "WslService" })
        {
          try
          {
            var sk = @"SYSTEM\CurrentControlSet\Services\" + svc;
            bool has;
            using (var k = Registry.LocalMachine.OpenSubKey(sk))
              has = k?.GetValue("Start") is int;
            if (has)
              SetReg(c, "HKLM", sk, "Start", 4);
          }
          catch (Exception __e)
          {
            Diag.Log(__e);
          }
        }
    }
    if (a.NoTaskMgr)
      SetReg(c, uh, SYSPOL, "DisableTaskMgr", 1);
    if (a.NoRegedit)
      SetReg(c, uh, SYSPOL, "DisableRegistryTools", 1);
    if (a.NoStore)
      SetReg(c, sh, @"SOFTWARE\Policies\Microsoft\WindowsStore", "RemoveWindowsStore", 1);
    if (a.NoWinget)
    {
      if (sh == "HKLM")
        SetReg(c, "HKLM", @"SOFTWARE\Policies\Microsoft\Windows\AppInstaller", "EnableAppInstaller", 0);
      else
        AddA(c, "kill|winget|" + c.Adv.Id); // המדיניות קיימת רק לכל המחשב: אצל החשבון שנבחר winget נסגר כשהוא מופעל
    }
    if (a.Browsers)
    { // מונע עקיפת סינון: DNS מוצפן בדפדפן וגלישה פרטית
      SetReg(c, sh, @"SOFTWARE\Policies\Google\Chrome", "IncognitoModeAvailability", 1);
      SetReg(c, sh, @"SOFTWARE\Policies\Google\Chrome", "DnsOverHttpsMode", "off", RegistryValueKind.String);
      SetReg(c, sh, @"SOFTWARE\Policies\Microsoft\Edge", "InPrivateModeAvailability", 1);
      SetReg(c, sh, @"SOFTWARE\Policies\Microsoft\Edge", "DnsOverHttpsMode", "off", RegistryValueKind.String);
      SetReg(c, sh, @"SOFTWARE\Policies\Google\Chrome", "BrowserGuestModeEnabled", 0);
      SetReg(c, sh, @"SOFTWARE\Policies\Microsoft\Edge", "BrowserGuestModeEnabled", 0); // מצב אורח עוקף פרופיל מסונן
      SetReg(c, sh, @"SOFTWARE\Policies\BraveSoftware\Brave", "IncognitoModeAvailability", 1);
      SetReg(c, sh, @"SOFTWARE\Policies\BraveSoftware\Brave", "DnsOverHttpsMode", "off", RegistryValueKind.String);
      SetReg(c, sh, @"SOFTWARE\Policies\BraveSoftware\Brave", "BrowserGuestModeEnabled", 0);
      SetReg(c, sh, @"SOFTWARE\Policies\BraveSoftware\Brave", "TorDisabled", 1); // חלון Tor עוקף כל סינון
      SetReg(c, sh, @"SOFTWARE\Policies\Mozilla\Firefox", "DisablePrivateBrowsing", 1);
      SetReg(c, sh, @"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS", "Enabled", 0);
      SetReg(c, sh, @"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS", "Locked", 1);
    }
    if (a.NoTether)
      SetReg(c, "HKLM", @"SOFTWARE\Policies\Microsoft\Windows\Network Connections", "NC_ShowSharedAccessUI", 0);
    if (a.NoTcpip)
      SetReg(c, "HKLM", @"SOFTWARE\Policies\Microsoft\Windows\Network Connections", "NC_AllowAdvancedTCPIPConfig", 0);
    if (a.NoProxy)
      SetReg(c, sh, @"SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel", "Proxy", 1); // מונע הגדרת Proxy (עקיפת סינון) בהגדרות המערכת, שמשפיעות גם על Chrome ו-Edge
    if (a.StrongAdmin)
      StrongApply(c);
    if (a.LockHosts)
    {
      try
      {
        var fi = new FileInfo(HostsPath);
        if (fi.Exists)
        {
          // רק החשבון שנבחר: הדחייה רק לחשבון הזה, ושאר החשבונות (גם המנהל) יכולים לערוך את הקובץ
          var hs = sh == "HKLM" ? null : c.OwnerSid;
          AddA(c, hs == null ? "hostslock" : "hostslock|" + hs); // לפני השינוי (יומן ההחלה)
          var sec = fi.GetAccessControl();
          sec.AddAccessRule(HostsDenyFor(hs));
          fi.SetAccessControl(sec);
        }
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
  }

  // ---- הקשחה חזקה (אופציונלית) ----
  // בזמן החסימה: מנהלים (וקבוצת Backup Operators, וחשבונות משתמש שקיבלו את הזכות ישירות) מאבדים את הזכויות שבעזרתן עוקפים הכול:
  // גיבוי/שחזור (קריאה וכתיבה של כל קובץ, למשל robocopy /B), לקיחת בעלות, ודיבאג (סגירת השירות ממנהל המשימות).
  // נכנס לתוקף בכניסה הבאה למשתמש. כל זכות שהוסרה נרשמת (lsaright) ומוחזרת בביטול / בסוף חלון הזמנים / בהסרה.
  // חשבונות המערכת והשירותים (SYSTEM, NT SERVICE\...) לא נוגעים בהם – Windows ממשיך לעבוד כרגיל
  public static string? StrongWarn; // החלון מציג אחרי ההחלה, אם ההקשחה החזקה לא הוחלה במלואה

  static readonly string[] StrongRights = { "SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeDebugPrivilege" };

  static bool StrongTarget(string sid) => sid == "S-1-5-32-544" || sid == "S-1-5-32-551" || sid.StartsWith("S-1-5-21-");

  static void StrongApply(Config c)
  {
    var failed = new List<string>();
    foreach (var r in StrongRights)
    {
      var holders = Lsa.Holders(r);
      if (holders == null)
      {
        failed.Add(r);
        continue;
      }
      foreach (var sid in holders.Where(StrongTarget))
      {
        // לפני ההסרה (יומן ההחלה): זכות שהוסרה בלי רישום לא הייתה חוזרת אף פעם. נכשלה – הרישום יורד (ביומן הוא נשאר, ובשחזור רק מוסיף זכות שכבר קיימת)
        var e = $"lsaright|{sid}|{r}";
        AddA(c, e);
        if (!Lsa.Change(sid, r, false))
        {
          lock (c.Applied)
            c.Applied.Remove(e);
          failed.Add(r + " (" + sid + ")");
        }
      }
    }
    // Windows סירב (למשל מדיניות קבוצתית שמנהלת את הזכויות): ההקשחה החזקה לא פעילה במלואה – מודיעים, ולא בשקט
    if (failed.Count > 0)
    {
      StrongWarn = "ההקשחה החזקה לא הוחלה במלואה: Windows לא אפשר להסיר את הזכויות " + string.Join(", ", failed) + ". שאר החסימות הוחלו.";
      Alerts.Log(StrongWarn);
    }
  }

  // נקרא מהשירות: זכות שהוחזרה בזמן החסימה (למשל דרך secpol.msc) מוסרת שוב. השינוי של מנהל ייכנס לתוקף רק בכניסה הבאה – והשירות מקדים אותו.
  // רק אחרי החלה אמיתית של ההקשחה (יש רשומות lsaright): סימון האפשרות בלי "החל שינויים" לא מסיר כלום – אחרת הזכויות היו מוסרות בלי רישום,
  // ולא היו חוזרות בביטול. זכות שנוספה לחשבון אחר בזמן החסימה מוסרת ולא מוחזרת – כך חוזרים בדיוק למצב שלפני החסימה
  public static void StrongHeal(Config c)
  {
    if (!c.Master || !c.Adv.On || !c.AdvOpts.StrongAdmin || Applying())
      return;
    lock (c.Applied)
      if (!c.Applied.Any(x => x.StartsWith("lsaright|")))
        return;
    var back = new List<string>();
    foreach (var r in StrongRights)
      foreach (var sid in (Lsa.Holders(r) ?? new()).Where(StrongTarget))
        if (Lsa.Change(sid, r, false))
          back.Add(r + " (" + sid + ")");
    if (back.Count > 0)
      Alerts.Log("זכויות מנהל שהוסרו בהקשחה החזקה הוחזרו – הוסרו שוב: " + string.Join(", ", back));
  }

  static string LsaPendFile => System.IO.Path.Combine(Config.Dir, "var", "lsapending.txt");

  static void AddLsaPending(string line)
  {
    try
    {
      Directory.CreateDirectory(System.IO.Path.GetDirectoryName(LsaPendFile)!);
      File.AppendAllLines(LsaPendFile, new[] { line });
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  // נקרא מהחלון (מנהל מורם, אחרי קוד כניסה) כשהשירות לא עובד והשמירה נכשלה כי ההקשחה החזקה הסירה את הרשאת השחזור:
  // מחזירים עכשיו את הזכויות שנרשמו (ייכנסו לתוקף בכניסה הבאה למשתמש). כשהשירות יחזור לעבוד והחסימה עדיין פעילה – הוא יסיר אותן שוב
  public static int RestoreStrongRights(Config c)
  {
    List<string> l;
    lock (c.Applied)
      l = c.Applied.Where(x => x.StartsWith("lsaright|")).ToList();
    int n = 0;
    foreach (var e in l)
    {
      var q = e.Split('|');
      if (q.Length >= 3 && StrongTarget(q[1]) && StrongRights.Contains(q[2]) && Lsa.Change(q[1], q[2], true))
        n++;
    }
    return n;
  }

  public static bool HasLsaPending() => File.Exists(LsaPendFile);

  // נקרא מהשירות: זכויות שלא הוחזרו בביטול. רק זכויות וחשבונות שההקשחה עצמה מסירה (הקובץ בתיקייה שמנהלים יכולים לכתוב אליה – לא נותנים ממנו זכויות אחרות),
  // ולא בזמן שההקשחה החזקה פעילה
  public static void ProcessLsaPending(Config c, bool blocking)
  {
    try
    {
      if (!File.Exists(LsaPendFile) || (blocking && c.Master && c.Adv.On && c.AdvOpts.StrongAdmin))
        return;
      var keep = new List<string>();
      foreach (var l in File.ReadAllLines(LsaPendFile).Distinct())
      {
        var q = l.Split('|');
        if (q.Length != 2 || !StrongTarget(q[0]) || !StrongRights.Contains(q[1]))
          continue;
        if (!Lsa.Change(q[0], q[1], true))
          keep.Add(l);
      }
      if (keep.Count == 0)
        File.Delete(LsaPendFile);
      else
        File.WriteAllLines(LsaPendFile, keep);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  static string HostsPath => System.IO.Path.Combine(Environment.SystemDirectory, @"drivers\etc\hosts");
  const FileSystemRights HostsDenyMask = FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.Delete;

  // נעילת hosts: לכל המשתמשים (sid = null → Everyone), או רק לחשבון שנבחר. כלל דחייה לחשבון חל גם כשהוא מנהל (ה-SID שלו בטוקן)
  static FileSystemAccessRule HostsDenyFor(string? sid) =>
    new(
      sid == null || !SidOk(sid) ? new SecurityIdentifier(WellKnownSidType.WorldSid, null) : new SecurityIdentifier(sid),
      HostsDenyMask,
      AccessControlType.Deny
    );

  static bool HasHostsDeny(FileSystemSecurity sec, string? sid)
  {
    var who = sid == null || !SidOk(sid) ? "S-1-1-0" : sid;
    return sec.GetAccessRules(true, false, typeof(SecurityIdentifier))
      .Cast<FileSystemAccessRule>()
      .Any(x => x.AccessControlType == AccessControlType.Deny && x.IdentityReference.Value == who && (x.FileSystemRights & FileSystemRights.WriteData) != 0);
  }

  // ---------- הגנה על נתיבי מערכת ותוכנה עצמה ----------
  static string UsersDir => System.IO.Path.Combine(Environment.GetEnvironmentVariable("SystemDrive") ?? "C:", "Users");
  static readonly string WinDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\'),
    PF = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).TrimEnd('\\'),
    PF86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86).TrimEnd('\\'),
    PData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData).TrimEnd('\\');

  static bool Under(string p, string d) =>
    p.Equals(d, StringComparison.OrdinalIgnoreCase) || p.StartsWith(d + "\\", StringComparison.OrdinalIgnoreCase);

  // נתיבים שחסימתם עלולה להקריס את המחשב (שורש כונן, Windows, Program Files, ProgramData, Users, ותיקיית הבית של כל משתמש).
  // נבדק גם הנתיב האמיתי אחרי קיצורי תיקייה (junction / symlink): למשל "C:\ProgramData\Application Data" מפנה ל-C:\ProgramData עצמה,
  // ותיקייה שמשתמש יצר עם mklink יכולה להפנות ל-C:\Windows. חסימה דרכה הייתה נועלת את תיקיית המערכת האמיתית
  public static bool IsDangerous(string p) => IsDangerousText(p) || (Resolved(p) is { } f && IsDangerousText(f));

  // הנתיב האמיתי, רק אם הוא שונה מהנתיב שנכתב (אחרת null)
  static string? Resolved(string p)
  {
    var f = Native.FinalPath(p);
    return f != null && !f.TrimEnd('\\').Equals(p.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase) ? f : null;
  }

  static bool IsDangerousText(string p)
  {
    var t = p.TrimEnd('\\');
    if (t.Length <= 2)
      return true;
    var root = System.IO.Path.GetPathRoot(p);
    if (root != null && t.Equals(root.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
      return true;
    if (Under(t, WinDir))
      return true;
    foreach (var d in new[] { PF, PF86, PData, UsersDir })
      if (t.Equals(d, StringComparison.OrdinalIgnoreCase) || d.StartsWith(t + "\\", StringComparison.OrdinalIgnoreCase))
        return true;
    // תיקיות משותפות שתוכנות רבות (או Windows עצמו) תלויות בהן: כל מה שבתוכן אסור לחסימה
    foreach (var d in SharedSystemDirs())
      if (Under(t, d))
        return true;
    // תיקיות מערכת בשורש כל כונן
    if (root != null && t.Length > root.TrimEnd('\\').Length)
    {
      var first = t[root.TrimEnd('\\').Length..].TrimStart('\\').Split('\\')[0];
      if (RootSystemNames.Any(x => x.Equals(first, StringComparison.OrdinalIgnoreCase)))
        return true;
    }
    try
    {
      foreach (var u in Directory.GetDirectories(UsersDir))
      {
        if (t.Equals(u, StringComparison.OrdinalIgnoreCase))
          return true;
        if (Under(t, System.IO.Path.Combine(u, "AppData"))) // חסימת AppData שוברת את פרופיל המשתמש ואת כל התוכנות שלו
          return true;
        // הרישום הפרטי של המשתמש (NTUSER.DAT והקבצים הנלווים) בשורש הפרופיל: חסימה שלו עלולה למנוע כניסה לחשבון
        if (
          string.Equals(System.IO.Path.GetDirectoryName(t), u, StringComparison.OrdinalIgnoreCase)
          && System.IO.Path.GetFileName(t).StartsWith("ntuser", StringComparison.OrdinalIgnoreCase)
        )
          return true;
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    // תיקייה/קובץ שמכילים שירות או מנהל התקן רשומים של Windows (למשל אנטי-וירוס או מנהל התקן ב-Program Files): חסימה מונעת מהם לעלות
    if (HasServiceBinary(t))
      return true;
    return false;
  }

  // שמות בשורש של כל כונן שחסימתם מסכנת את המחשב: תיקיות מערכת, קובצי זיכרון/שינה ואתחול, ותיקיות עדכון של Windows
  static readonly string[] RootSystemNames =
  {
    "Boot",
    "Recovery",
    "EFI",
    "$Recycle.Bin",
    "System Volume Information",
    "$WinREAgent",
    "Config.Msi",
    "pagefile.sys",
    "hiberfil.sys",
    "swapfile.sys",
    "DumpStack.log",
    "DumpStack.log.tmp",
    "bootmgr",
    "BOOTNXT",
    "BOOTSECT.BAK",
    "$WINDOWS.~BT",
    "$Windows.~WS",
    "$SysReset",
    "$GetCurrent",
  };

  // קובצי ההפעלה של כל השירותים ומנהלי ההתקן הרשומים (מתוך הרישום, נשמר לדקה)
  static List<string>? svcBins;
  static DateTime svcBinsAt = DateTime.MinValue;
  static readonly object SvcLock = new();

  static bool HasServiceBinary(string t)
  {
    List<string> bins;
    lock (SvcLock)
    {
      if (svcBins == null || (DateTime.UtcNow - svcBinsAt).TotalMinutes >= 1)
      {
        svcBins = ServiceBinaries();
        svcBinsAt = DateTime.UtcNow;
      }
      bins = svcBins;
    }
    return bins.Any(b => Under(b, t));
  }

  static List<string> ServiceBinaries()
  {
    var res = new List<string>();
    try
    {
      using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
      if (k == null)
        return res;
      foreach (var n in k.GetSubKeyNames())
        try
        {
          using var sk = k.OpenSubKey(n);
          if (sk?.GetValue("ImagePath") is string ip && ServicePath(ip) is { } f)
            res.Add(f);
        }
        catch (Exception __e)
        {
          Diag.Log(__e);
        }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    return res;
  }

  // נתיב קובץ ההפעלה מתוך ImagePath של שירות ("C:\x\a.exe" -k ..., \SystemRoot\..., \??\C:\..., system32\drivers\...). null = לא ניתן לפענח
  public static string? ServicePath(string ip)
  {
    var s = Environment.ExpandEnvironmentVariables(ip.Trim());
    if (s.Length == 0)
      return null;
    string path;
    if (s[0] == '"')
    {
      var e = s.IndexOf('"', 1);
      if (e < 0)
        return null;
      path = s[1..e];
    }
    else
    {
      // בלי מרכאות: עד סוף ה-exe/sys הראשון (נתיבים עם רווחים בלי מרכאות קיימים)
      var low = s.ToLowerInvariant();
      int cut = -1;
      foreach (var ext in new[] { ".exe", ".sys", ".dll" })
      {
        var i = low.IndexOf(ext, StringComparison.Ordinal);
        if (i >= 0 && (cut < 0 || i < cut))
          cut = i + ext.Length;
      }
      path = cut > 0 ? s[..cut] : s.Split(' ')[0];
    }
    if (path.StartsWith(@"\??\", StringComparison.Ordinal))
      path = path[4..];
    if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
      path = WinDir + path[11..];
    else if (!System.IO.Path.IsPathRooted(path) || path.StartsWith('\\'))
      path = System.IO.Path.Combine(WinDir, path.TrimStart('\\')); // system32\drivers\x.sys – יחסית לתיקיית Windows
    try
    {
      return System.IO.Path.GetFullPath(path);
    }
    catch
    {
      return null;
    }
  }

  static IEnumerable<string> SharedSystemDirs()
  {
    yield return System.IO.Path.Combine(PData, "Microsoft"); // כולל Windows Defender
    foreach (var pf in new[] { PF, PF86 })
    {
      if (string.IsNullOrEmpty(pf))
        continue;
      yield return System.IO.Path.Combine(pf, "Common Files");
      yield return System.IO.Path.Combine(pf, "WindowsApps");
      yield return System.IO.Path.Combine(pf, "Windows Defender");
      yield return System.IO.Path.Combine(pf, "Windows Defender Advanced Threat Protection");
      yield return System.IO.Path.Combine(pf, "Windows NT");
      yield return System.IO.Path.Combine(pf, "dotnet");
      yield return System.IO.Path.Combine(pf, "ModifiableWindowsApps");
      yield return System.IO.Path.Combine(pf, @"Microsoft\EdgeWebView");
      yield return System.IO.Path.Combine(pf, "Reference Assemblies");
    }
  }

  // מגן על התוכנה עצמה: אי אפשר לחסום את תיקיית ההגדרות, את תיקיית ההרצה, תיקייה שמכילה אותן, או קובץ בשם התוכנה בכל מיקום
  static bool Protected(string p) => ProtectedText(p) || (Resolved(p) is { } f && ProtectedText(f));

  static bool ProtectedText(string p)
  {
    var t = p.TrimEnd('\\');
    var cd = CdT;
    var bd = BdT;
    bool Covers(string a, string b) =>
      a.Equals(b, StringComparison.OrdinalIgnoreCase)
      || a.StartsWith(b + "\\", StringComparison.OrdinalIgnoreCase)
      || b.StartsWith(a + "\\", StringComparison.OrdinalIgnoreCase);
    // a מכיל את b (או שווה לו)
    bool Contains(string a, string? b) =>
      !string.IsNullOrEmpty(b)
      && (a.Equals(b, StringComparison.OrdinalIgnoreCase) || b.StartsWith(a + "\\", StringComparison.OrdinalIgnoreCase));
    // אותה בדיקה בחלון ובשירות: תיקיית ההגדרות, ותיקייה שמכילה את התוכנה שרצה כרגע או את DeviceGuard.exe שממנו נפתח החלון (UiExe).
    // קודם החלון חסם כל תיקייה שבתוך תיקיית התוכנה, והשירות (בתחילת חלון זמנים) דווקא חסם תיקייה שמכילה את DeviceGuard.exe – ואז התוכנה לא נפתחה
    return Covers(t, cd)
      || Contains(t, bd)
      || Contains(t, UiExe)
      || System.IO.Path.GetFileName(t).Equals("DeviceGuard.exe", StringComparison.OrdinalIgnoreCase)
      || System.IO.Path.GetFileName(t).Equals("DeviceGuardWatch.exe", StringComparison.OrdinalIgnoreCase);
  }

  public static string? UiExe; // DeviceGuard.exe שממנו נפתח החלון (מההגדרות)

  static bool ProtectedPath(string p) => IsDangerous(p) || Protected(p);

  // ---------- IFEO (שער חסימה) ----------
  static void Ifeo(Config c, string exe, Rule r)
  {
    if (IsCritical(exe))
      return;
    AddA(c, "ifeo|" + exe + "|" + r.Id); // לפני הכתיבה (יומן ההחלה)
    foreach (var v in Views)
    {
      using var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, v);
      using var k = b.CreateSubKey(IFEO + exe);
      // ערך Debugger קודם שאינו שלנו (למשל Process Explorer במקום מנהל המשימות): נשמר ומוחזר בביטול
      if (k.GetValue("Debugger") is string old && old.Length > 0 && !IsOurGate(old))
        AddA(c, $"ifeoprev|{exe}|{(int)v}|{Convert.ToBase64String(Encoding.UTF8.GetBytes(old))}");
      k.SetValue("Debugger", GateCmd(r.Id));
    }
  }

  // שער של DeviceGuard: קובץ כלשהו בתיקיית DeviceGuard עם --gate. כולל שערים של גרסאות ישנות (Gate.exe), כדי ששער יתום כזה
  // לא ייחשב "ערך של תוכנה אחרת" ויוחזר בביטול – אחרת התוכנה החסומה לא הייתה נפתחת גם אחרי הפתיחה
  static bool IsOurGate(string d)
  {
    var t = d.TrimStart();
    if (!t.StartsWith('"'))
      return false;
    var end = t.IndexOf('"', 1);
    if (end < 0)
      return false;
    string? dir;
    try
    {
      dir = System.IO.Path.GetDirectoryName(t[1..end])?.TrimEnd('\\');
    }
    catch
    {
      return false;
    }
    return t[(end + 1)..].TrimStart().StartsWith("--gate", StringComparison.Ordinal)
      && string.Equals(dir, CdT, StringComparison.OrdinalIgnoreCase);
  }

  // לביטול: ערך שנראה כמו שער של DeviceGuard בכל צורה שהייתה אי פעם (גם מגרסאות ישנות). בספק – נחשב שלנו ונמחק,
  // כדי שתוכנה לא תישאר חסומה מאחורי שער אחרי הביטול
  static bool LooksOurGate(string d) =>
    IsOurGate(d) || d.Contains("--gate", StringComparison.Ordinal) || d.Contains(CdT, StringComparison.OrdinalIgnoreCase);

  // IFEO על הקבצים של DeviceGuard עצמו (Debugger, GlobalFlag, מסנני נתיב...) היה מאפשר לחטוף את השער – כל תוכנה חסומה הייתה רצה דרך כלי אחר –
  // או למנוע מהשירות לעלות. השירות מוחק כל הגדרה כזו מיד (RegWatch). DeviceGuard עצמו אף פעם לא כותב לשם (IsCritical)
  public static void GuardOwnIfeo(bool removing)
  {
    if (removing)
      return;
    var names = new List<string> { "DeviceGuard.exe", "DeviceGuardWatch.exe", "DeviceGuardGate.exe" };
    // DeviceGuard.exe ששמו שונה (למשל "DeviceGuard (1).exe") – רק אם השם עדיין מתחיל ב-DeviceGuard: שם אחר עלול להיות של תוכנה שהמשתמש חוסם
    var ui = string.IsNullOrEmpty(UiExe) ? null : System.IO.Path.GetFileName(UiExe);
    if (ui != null && ui.StartsWith("DeviceGuard", StringComparison.OrdinalIgnoreCase))
      names.Add(ui);
    foreach (var v in Views)
      try
      {
        using var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, v);
        using var ifeo = b.OpenSubKey(IFEO.TrimEnd('\\'), true);
        if (ifeo == null)
          continue;
        foreach (var n in ifeo.GetSubKeyNames())
          if (names.Contains(n, StringComparer.OrdinalIgnoreCase))
          {
            ifeo.DeleteSubKeyTree(n, false);
            Alerts.Log("זוהתה הגדרת IFEO על קובץ של DeviceGuard (" + n + ") – נמחקה");
          }
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
  }

  // מוחק כל שער של DeviceGuard מהרישום (גם יתומים שאינם רשומים ב-Applied)
  public static void PurgeIfeo()
  {
    foreach (var v in Views)
    {
      try
      {
        using var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, v);
        using var ifeo = b.OpenSubKey(IFEO.TrimEnd('\\'), true);
        if (ifeo == null)
          continue;
        foreach (var n in ifeo.GetSubKeyNames())
        {
          try
          {
            using var k = ifeo.OpenSubKey(n, true);
            if (k?.GetValue("Debugger") is string d && IsOurGate(d))
              k.DeleteValue("Debugger", false);
          }
          catch (Exception __e)
          {
            Diag.Log(__e);
          }
        }
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
  }

  // ניקוי מלא בהסרת התוכנה: שערים, כללי חומת אש, נעילת קובץ hosts
  public static void PurgeAll()
  {
    PurgeIfeo();
    RemoveUiShortcuts();
    try
    {
      PSAll(new List<string> { "Remove-NetFirewallRule -Group 'DeviceGuardNet' -ErrorAction SilentlyContinue" });
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    try
    {
      PSAll(new List<string> { $"Remove-NetFirewallRule -Group '{NetUserGroup}' -ErrorAction SilentlyContinue" });
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    try
    {
      // כל כלל דחייה שלנו על hosts – לכל המשתמשים או לחשבון מסוים
      var fi = new FileInfo(HostsPath);
      if (fi.Exists)
      {
        var sec = fi.GetAccessControl();
        foreach (var x in sec.GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToList())
          if (x.AccessControlType == AccessControlType.Deny && (x.FileSystemRights & ~FileSystemRights.Synchronize) == HostsDenyMask && x.InheritanceFlags == InheritanceFlags.None)
            sec.RemoveAccessRuleSpecific(x);
        fi.SetAccessControl(sec);
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  static void Hide(Config c, string p)
  {
    try
    {
      if (prevHid.TryRemove(p, out var old))
      {
        AddA(c, old);
        AddFid(c, p);
        return;
      }
      var a = File.GetAttributes(p);
      AddA(c, $"hid|{p}|{(int)a}");
      AddFid(c, p);
      File.SetAttributes(p, a | FileAttributes.Hidden | FileAttributes.System);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  // ---------- חסימת קבצים ותיקיות (ACL) ----------
  // חיזוק: כלל OWNER RIGHTS (S-1-3-4) מבטל לבעל הקובץ את הזכות המובנית לשנות הרשאות, כך שמשתמש רגיל לא יכול להסיר את החסימה בעצמו.
  public static bool Harden = true,
    SkipAppData = true,
    IncludeRemovable,
    SkipProgramDirs = true;
  public static string[] Exclude = Array.Empty<string>();
  static readonly SecurityIdentifier OwnerSid = new("S-1-3-4");

  static FileSystemAccessRule OwnerRule(bool dir) =>
    new(
      OwnerSid,
      FileSystemRights.ReadAttributes | FileSystemRights.ReadPermissions | FileSystemRights.Synchronize,
      dir ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit : InheritanceFlags.None,
      PropagationFlags.None,
      AccessControlType.Allow
    );

  // תווית שלמות High עם No-Write-Up: תהליך לא מורם (משתמש רגיל, או מנהל בלי אישור UAC) לא יכול לשנות הרשאות/בעלות של הקובץ,
  // גם כשיש לו "שליטה מלאה" מפורשת (כמו בכל קובץ בתיקיות המשתמש). השירות (SYSTEM) והחלון המורם (High) לא מושפעים
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint rev, out IntPtr sd, IntPtr size);

  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool GetSecurityDescriptorSacl(IntPtr sd, out bool present, out IntPtr sacl, out bool defaulted);

  [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
  static extern uint SetNamedSecurityInfoW(string name, int type, uint info, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

  [DllImport("kernel32.dll")]
  static extern IntPtr LocalFree(IntPtr h);

  [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
  static extern uint GetNamedSecurityInfoW(
    string name,
    int type,
    uint info,
    IntPtr owner,
    IntPtr group,
    IntPtr dacl,
    IntPtr sacl,
    out IntPtr sd
  );

  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(IntPtr sd, uint rev, uint info, out IntPtr str, IntPtr len);

  // תווית השלמות הנוכחית כטקסט SDDL ("" = אין תווית). null = לא ניתן לקרוא
  static string? LabelSddl(string p)
  {
    const uint LABEL = 0x10;
    try
    {
      if (GetNamedSecurityInfoW(p, 1, LABEL, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out var sd) != 0)
        return null;
      try
      {
        if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, LABEL, out var str, IntPtr.Zero))
          return null;
        try
        {
          return Marshal.PtrToStringUni(str) ?? "";
        }
        finally
        {
          LocalFree(str);
        }
      }
      finally
      {
        LocalFree(sd);
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
      return null;
    }
  }

  // התווית שלנו: No-Write-Up ברמה High (ישירה או בירושה מתיקייה חסומה). כל תווית אחרת שייכת למישהו אחר ולא נוגעים בה
  static bool HasLabel(string sddl) => sddl.Contains("(ML;", StringComparison.OrdinalIgnoreCase);

  static bool IsOurLabel(string sddl) => sddl.Contains(";NW;;;HI)", StringComparison.OrdinalIgnoreCase);

  static readonly byte[] EmptyAcl = MakeEmptyAcl();

  static byte[] MakeEmptyAcl()
  {
    var a = new RawAcl(GenericAcl.AclRevision, 0);
    var b = new byte[a.BinaryLength];
    a.GetBinaryForm(b, 0);
    return b;
  }

  static void Label(string p, bool dir, bool on)
  {
    const int SE_FILE_OBJECT = 1;
    const uint LABEL_SECURITY_INFORMATION = 0x10;
    try
    {
      var cur = LabelSddl(p);
      if (on)
      {
        // לקובץ כבר יש תווית אחרת (למשל Low של תוכנה מסוימת): לא דורסים אותה – אחרת בשחרור אי אפשר היה להחזיר אותה
        if (cur != null && HasLabel(cur) && !IsOurLabel(cur))
          return;
        if (
          !ConvertStringSecurityDescriptorToSecurityDescriptorW(dir ? "S:(ML;OICI;NW;;;HI)" : "S:(ML;;NW;;;HI)", 1, out var sd, IntPtr.Zero)
        )
          return;
        try
        {
          if (GetSecurityDescriptorSacl(sd, out var present, out var sacl, out _) && present)
            SetNamedSecurityInfoW(p, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, sacl);
        }
        finally
        {
          LocalFree(sd);
        }
      }
      else
      {
        // מסירים רק את התווית שלנו. (אם אי אפשר לקרוא – מסירים כמו קודם, כדי שתווית שלנו לא תשאיר את הקובץ נעול לשינויים)
        if (cur != null && !IsOurLabel(cur))
          return;
        var h = GCHandle.Alloc(EmptyAcl, GCHandleType.Pinned);
        try
        {
          SetNamedSecurityInfoW(
            p,
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            IntPtr.Zero,
            IntPtr.Zero,
            IntPtr.Zero,
            h.AddrOfPinnedObject()
          );
        }
        finally
        {
          h.Free();
        }
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  // נתיבים שהשירות עצמו שינה בהם הרשאות לאחרונה: המעקב אחרי שינויי הרשאות (Program.Watch) מתעלם מהם, ומזהה רק שינוי מבחוץ
  static readonly ConcurrentDictionary<string, long> touched = new(StringComparer.OrdinalIgnoreCase);

  static void Mine(string p)
  {
    if (touched.Count > 300_000)
      touched.Clear();
    touched[p] = Environment.TickCount64;
  }

  public static bool RecentlyMine(string p) => touched.TryGetValue(p, out var t) && Environment.TickCount64 - t < 20_000;

  // נעילה/שחרור של קובץ או תיקייה: כלל הדחייה + (בחיזוק) כלל OWNER RIGHTS ותווית השלמות
  static void AclOn(FileSystemInfo i, bool dir)
  {
    Mine(i.FullName);
    var s = i is DirectoryInfo d ? (FileSystemSecurity)d.GetAccessControl() : ((FileInfo)i).GetAccessControl();
    s.AddAccessRule(Deny(dir));
    var hard = HardenFor(s);
    if (hard)
      Own(s, dir);
    if (i is DirectoryInfo d2)
      d2.SetAccessControl((DirectorySecurity)s);
    else
      ((FileInfo)i).SetAccessControl((FileSecurity)s);
    if (hard)
      Label(i.FullName, dir, true);
  }

  static void AclOff(FileSystemInfo i, bool dir)
  {
    Mine(i.FullName);
    Label(i.FullName, dir, false);
    try
    {
      var s = i is DirectoryInfo d ? (FileSystemSecurity)d.GetAccessControl() : ((FileInfo)i).GetAccessControl();
      RemoveOurDeny(s, dir);
      Unown(s, dir);
      if (i is DirectoryInfo d2)
        d2.SetAccessControl((DirectorySecurity)s);
      else
        ((FileInfo)i).SetAccessControl((FileSecurity)s);
    }
    catch (Exception x) when (!dir && (x is UnauthorizedAccessException || x is PrivilegeNotHeldException))
    {
      // קובץ שאין בהרשאות שלו גישה ל-SYSTEM/מנהלים (וחיזוק OWNER RIGHTS חוסם גם את הבעלים): משחררים בעזרת הרשאת השחזור של המערכת, כדי שהקובץ לא יישאר נעול לתמיד
      if (!ForceFileAclOff(i.FullName))
        throw;
    }
  }

  // ---- שחרור בכוח (הרשאות SeRestore/SeBackup, קיימות לשירות ולמנהל מורם) ----
  [StructLayout(LayoutKind.Sequential, Pack = 4)]
  struct TokPriv
  {
    public int Count;
    public long Luid;
    public int Attr;
  }

  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool OpenProcessToken(IntPtr h, uint acc, out IntPtr tok);

  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern bool LookupPrivilegeValueW(string? sys, string name, out long luid);

  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool AdjustTokenPrivileges(IntPtr tok, bool disableAll, ref TokPriv ns, int len, IntPtr prev, IntPtr retLen);

  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFileW(
    string name,
    uint access,
    uint share,
    IntPtr sec,
    uint disp,
    uint flags,
    IntPtr tmpl
  );

  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool GetKernelObjectSecurity(SafeHandle h, uint info, byte[]? sd, uint len, out uint needed);

  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool SetKernelObjectSecurity(SafeHandle h, uint info, byte[] sd);

  [DllImport("kernel32.dll")]
  static extern bool CloseHandle(IntPtr h);

  static int privsOn;

  static void EnablePrivs()
  {
    if (Interlocked.Exchange(ref privsOn, 1) == 1)
      return;
    try
    {
      using var me = Process.GetCurrentProcess();
      if (!OpenProcessToken(me.Handle, 0x20 | 0x8, out var tok)) // TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
        return;
      try
      {
        foreach (var n in new[] { "SeRestorePrivilege", "SeBackupPrivilege" })
          if (LookupPrivilegeValueW(null, n, out var luid))
          {
            var tp = new TokPriv { Count = 1, Luid = luid, Attr = 2 }; // SE_PRIVILEGE_ENABLED
            AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
          }
      }
      finally
      {
        CloseHandle(tok);
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  // האם לתהליך הנוכחי יש הרשאת שחזור (SeRestore). אין – למשל כי ההקשחה החזקה הסירה אותה ממנהלים (גם אם כבר הוחזרה, היא נכנסת לתוקף רק בכניסה הבאה)
  internal static bool HasRestorePriv()
  {
    try
    {
      using var me = Process.GetCurrentProcess();
      if (!OpenProcessToken(me.Handle, 0x20 | 0x8, out var tok))
        return false;
      try
      {
        if (!LookupPrivilegeValueW(null, "SeRestorePrivilege", out var luid))
          return false;
        var tp = new TokPriv { Count = 1, Luid = luid, Attr = 2 };
        return AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero) && Marshal.GetLastWin32Error() == 0; // 1300 = ההרשאה לא קיימת
      }
      finally
      {
        CloseHandle(tok);
      }
    }
    catch
    {
      return false;
    }
  }

  // כתיבת קובץ בעזרת הרשאת השחזור (SeRestore) – גם כשההרשאות של הקובץ לא מאפשרות כתיבה רגילה. משמש את החלון (מנהל מורם) כשהשירות לא עובד,
  // כדי שביטול החסימות/הסרה יישמרו בקובץ ההגדרות. אחרת השירות, כשהיה חוזר לעבוד, היה מחיל שוב חלק מהחסימות לפי ההגדרות הישנות
  internal static bool WriteFileBackup(string path, string text)
  {
    try
    {
      EnablePrivs();
      // GENERIC_WRITE, CREATE_ALWAYS, FILE_FLAG_BACKUP_SEMANTICS
      using var h = CreateFileW(path, 0x40000000, 0, IntPtr.Zero, 2, 0x02000000 | 0x80, IntPtr.Zero);
      if (h.IsInvalid)
        return false;
      using var fs = new FileStream(h, FileAccess.Write);
      fs.Write(new UTF8Encoding(false).GetBytes(text));
      return true;
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
      return false;
    }
  }

  static bool ForceFileAclOff(string path)
  {
    Mine(path);
    try
    {
      EnablePrivs();
      const uint DACL = 4;
      // READ_CONTROL | WRITE_DAC, עם FILE_FLAG_BACKUP_SEMANTICS: ההרשאות SeBackup/SeRestore עוקפות את רשימת ההרשאות של הקובץ
      using var h = CreateFileW(path, 0x20000 | 0x40000, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
      if (h.IsInvalid)
        return false;
      GetKernelObjectSecurity(h, DACL, null, 0, out var need);
      if (need == 0)
        return false;
      var buf = new byte[need];
      if (!GetKernelObjectSecurity(h, DACL, buf, need, out _))
        return false;
      var fs = new FileSecurity();
      fs.SetSecurityDescriptorBinaryForm(buf, AccessControlSections.Access);
      RemoveOurDeny(fs, false);
      fs.RemoveAccessRule(OwnerRule(false));
      return SetKernelObjectSecurity(h, DACL, fs.GetSecurityDescriptorBinaryForm());
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
      return false;
    }
  }

  static void Own(FileSystemSecurity s, bool dir)
  {
    if (Harden)
      s.AddAccessRule(OwnerRule(dir));
  }

  static void Unown(FileSystemSecurity s, bool dir)
  {
    s.RemoveAccessRule(OwnerRule(dir));
  }

  static readonly SecurityIdentifier World = new(WellKnownSidType.WorldSid, null);

  // על מי חלה נעילת הקבצים: כל המשתמשים (Everyone), או רק החשבון שנבחר (נקבע ב-SetSkip)
  static volatile SecurityIdentifier DenyTo = World;

  const FileSystemRights DenyMask = FileSystemRights.ReadData | FileSystemRights.ExecuteFile | FileSystemRights.Delete;

  static FileSystemAccessRule Deny(bool dir, SecurityIdentifier? to = null) =>
    new(
      to ?? DenyTo,
      DenyMask,
      dir ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit : InheritanceFlags.None,
      PropagationFlags.None,
      AccessControlType.Deny
    );

  // כלל דחייה שלנו: ל-Everyone (כמו קודם), או לחשבון משתמש (מצב "רק החשבון שנבחר") – רק עם בדיוק הזכויות שאנחנו כותבים
  public static bool IsOurDeny(FileSystemAccessRule x)
  {
    if (x.AccessControlType != AccessControlType.Deny)
      return false;
    var sid = x.IdentityReference.Value;
    if (sid == "S-1-1-0")
      return (x.FileSystemRights & FileSystemRights.ReadData) != 0 && (x.FileSystemRights & FileSystemRights.Delete) != 0;
    return sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) && (x.FileSystemRights & ~FileSystemRights.Synchronize) == DenyMask;
  }

  // הסרת כלל הדחייה שלנו – גם אם הוחל בהיקף אחר (כל המשתמשים / חשבון אחר) מזה שנבחר עכשיו
  static void RemoveOurDeny(FileSystemSecurity s, bool dir)
  {
    s.RemoveAccessRule(Deny(dir, World));
    foreach (var x in s.GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().ToList())
      if (x.IdentityReference.Value != "S-1-1-0" && IsOurDeny(x))
        s.RemoveAccessRuleSpecific(x);
  }

  // חיזוק (OWNER RIGHTS + תווית שלמות) מונע כתיבה גם מתהליך לא מורם. במצב "רק החשבון שנבחר" – רק בקובץ/תיקייה של החשבון הזה,
  // כדי שקבצים של חשבונות אחרים (למשל המנהל) יישארו ניתנים לעריכה
  static bool HardenFor(FileSystemSecurity s)
  {
    if (!Harden)
      return false;
    var to = DenyTo;
    if (to.Value == "S-1-1-0")
      return true;
    try
    {
      return s.GetOwner(typeof(SecurityIdentifier)) is SecurityIdentifier o && o.Equals(to);
    }
    catch
    {
      return false;
    }
  }

  static List<string> ListDirs(string root)
  { // חייב לרוץ לפני החסימה, כי אחריה אי אפשר לרשום את תוכן התיקייה
    var all = new List<string>();
    void Walk(string d)
    {
      string[] subs;
      try
      {
        subs = Directory.GetDirectories(d);
      }
      catch
      {
        return;
      }
      foreach (var x in subs)
      {
        try
        {
          if ((File.GetAttributes(x) & FileAttributes.ReparsePoint) != 0)
            continue;
        }
        catch
        {
          continue;
        }
        all.Add(x);
        Walk(x);
      }
    }
    Walk(root);
    return all;
  }

  static bool HasDeny(string d, bool inherited)
  {
    try
    {
      return new DirectoryInfo(d)
        .GetAccessControl()
        .GetAccessRules(true, inherited, typeof(SecurityIdentifier))
        .Cast<FileSystemAccessRule>()
        .Any(x => IsOurDeny(x) && (x.FileSystemRights & FileSystemRights.ListDirectory) != 0);
    }
    catch
    {
      return false;
    }
  }

  static void DenySubs(List<string> subs)
  {
    Parallel.ForEach(
      subs,
      new ParallelOptions { MaxDegreeOfParallelism = Par },
      d =>
      {
        try
        {
          if (HasDeny(d, true))
            return;
          AclOn(new DirectoryInfo(d), true);
        }
        catch (Exception __e)
        {
          Diag.Log(__e);
        }
      }
    );
  }

  static void UnwalkDir(string d, bool root = true)
  { // משחרר מלמעלה למטה: קודם התיקייה עצמה, ואז אפשר לרשום את מה שבתוכה
    try
    {
      if (root || HasDeny(d, false))
      {
        AclOff(new DirectoryInfo(d), true);
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    string[] subs;
    try
    {
      subs = Directory.GetDirectories(d);
    }
    catch
    {
      return;
    }
    foreach (var x in subs)
    {
      try
      {
        if ((File.GetAttributes(x) & FileAttributes.ReparsePoint) == 0)
          UnwalkDir(x, false);
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
  }

  static void Block(Config c, Rule r, string p)
  {
    try
    {
      bool dir = Directory.Exists(p);
      if (!dir && !File.Exists(p))
      {
        // החלה מחדש בזמן חסימה, והפריט שנחסם קודם כבר לא בנתיב הזה (שם התיקייה שונה / הועבר): נשאר חסום במקומו החדש,
        // והרישום (כולל המזהה) עובר הלאה – כך שהביטול ימצא אותו. בלי זה ההחלה מחדש הייתה משחררת אותו
        if (prevAcl.TryRemove(p, out _))
        {
          AddA(c, "acl|" + p + (Harden ? "|h2" : ""));
          if (fids.TryGetValue(p, out var fid))
            AddA(c, $"fid|{fid}|{p}");
          if (prevHid.TryRemove(p, out var oldHid))
            AddA(c, oldHid);
          Interlocked.Increment(ref Blocked);
        }
        return;
      }
      if ((r.Hidden && r.Mode == Mode.Full) || (r.Mode == Mode.Code && c.Paths.Contains(r)))
        Hide(c, p);
      // הרישום לפני הנעילה (יומן ההחלה): גם אם ההחלה נקטעת באמצע, הביטול ימצא את הפריט. נעילה שנכשלה – השחרור פשוט לא ישנה כלום
      bool same = !dir && prevAcl.ContainsKey(p) && (!fids.TryGetValue(p, out var oid) || Native.FileId(p) == oid);
      AddA(c, "acl|" + p + (Harden ? "|h2" : ""));
      AddFid(c, p);
      if (dir)
      {
        var subs = ListDirs(p);
        AclOn(new DirectoryInfo(p), true);
        DenySubs(subs);
      }
      else
      {
        // כבר נעול מההחלה הקודמת – רק אם זה אותו קובץ (ולא קובץ חדש באותו שם, אחרי שהמקורי הועבר: המקורי ישוחרר ב-FinishRevert לפי המזהה)
        if (same)
          prevAcl.TryRemove(p, out _);
        else
          AclOn(new FileInfo(p), false);
      }
      Interlocked.Increment(ref Blocked);
    }
    catch (Exception x)
    {
      Interlocked.Increment(ref Failed);
      LastErr = x.Message;
    }
  }

  // ---------- חסימת סיומות ברקע (השירות) ----------
  static string WatchLog => System.IO.Path.Combine(Config.Dir, "var", "watched.log");

  // דילוג לפי נתיב מלא (ולא לפי שם תיקייה, שאפשר לעקוף בקלות): Windows (חוץ מ-Temp), Program Files, חלק מ-ProgramData, AppData של משתמשים (אופציונלי) וההחרגות שהוגדרו
  static readonly string[] SkipFull = { PF, PF86, System.IO.Path.Combine(PData, "Microsoft"), System.IO.Path.Combine(PData, "Packages") };

  // תיקיית תוכנה: תיקייה (או אחת מהתיקיות שמעליה) שיש בה קובצי dll, וכן תיקיות נקודה, node_modules ו-site-packages. חסימת תמונות/סרטים שם שוברת תוכנות
  static readonly ConcurrentDictionary<string, (bool V, DateTime T)> dllDirs = new(StringComparer.OrdinalIgnoreCase);

  // בעלים "מערכתי" (SYSTEM, מנהלים, TrustedInstaller ושירותים): קבצים שהותקנו על ידי תוכנת התקנה. קובץ שמשתמש רגיל יצר בעצמו – הבעלים שלו הוא המשתמש
  static bool PrivSid(string? sid) =>
    sid != null && (sid == "S-1-5-18" || sid == "S-1-5-19" || sid == "S-1-5-20" || sid == "S-1-5-32-544" || sid.StartsWith("S-1-5-80-"));

  // בעלים של קובץ שנוצר על ידי התקנה/שירות (לא על ידי המשתמש). קבוצת המנהלים נחשבת כזו רק כש-UAC פעיל: כש-UAC כבוי, כל קובץ שמנהל יוצר
  // שייך לקבוצת המנהלים, ואז קבצים של המשתמש עצמו (במחשב שבו המשתמש מנהל) היו מדולגים
  static bool InstallerSid(string? sid) =>
    sid != null && (sid == "S-1-5-18" || sid == "S-1-5-19" || sid == "S-1-5-20" || sid.StartsWith("S-1-5-80-") || (sid == "S-1-5-32-544" && UacOn.Value));

  // לפי הנתיב: קובץ בבעלות קבוצת המנהלים נחשב "של התקנה" רק ב-ProgramData, ב-Windows ובתיקייה הזמנית (משאבים וחילוץ של תוכנות התקנה). בכל מקום אחר (תיקיות המשתמש, כונן D וכו')
  // זה בדרך כלל קובץ שמנהל העתיק בחלון מורם (העתקה כמנהל יוצרת קובץ בבעלות קבוצת המנהלים) – ולכן נחסם, אחרת זו הייתה עקיפה קלה.
  // תוכנות שהותקנו מחוץ ל-Program Files (משחקים ב-D:\Games וכד') עדיין מדולגות לפי קובצי ה-dll שלהן (IsProgramPath)
  static bool InstallerSid(string? sid, string path) =>
    InstallerSid(sid)
    && (
      sid != "S-1-5-32-544"
      || path.StartsWith(PData + "\\", StringComparison.OrdinalIgnoreCase)
      || path.StartsWith(WinDir + "\\", StringComparison.OrdinalIgnoreCase)
      || path.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase) // התקנה שרצה כמנהל מחלצת קבצים לתיקייה הזמנית
    );

  static readonly Lazy<bool> UacOn = new(() =>
  {
    try
    {
      using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
      return !(k?.GetValue("EnableLUA") is int v && v == 0);
    }
    catch
    {
      return true;
    }
  });

  static bool InstallerOwned(string path)
  {
    try
    {
      return InstallerSid(new FileInfo(path).GetAccessControl(AccessControlSections.Owner).GetOwner(typeof(SecurityIdentifier))?.Value, path);
    }
    catch
    {
      return false;
    }
  }

  public static bool PrivOwned(string path)
  {
    try
    {
      FileSystemSecurity s = Directory.Exists(path)
        ? new DirectoryInfo(path).GetAccessControl(AccessControlSections.Owner)
        : new FileInfo(path).GetAccessControl(AccessControlSections.Owner);
      return PrivSid(s.GetOwner(typeof(SecurityIdentifier))?.Value);
    }
    catch
    {
      return false;
    }
  }

  static bool Cached(string key, Func<bool> f)
  {
    var now = DateTime.UtcNow;
    if (dllDirs.TryGetValue(key, out var e) && (now - e.T).TotalMinutes < 10)
      return e.V;
    var v = f();
    if (dllDirs.Count > 20000)
      dllDirs.Clear();
    dllDirs[key] = (v, now);
    return v;
  }

  // תיקיית תוכנה = יש בה קובץ dll שהותקן על ידי תוכנת התקנה. dll שהמשתמש עצמו שם לא נחשב – אחרת קובץ dll ריק בתיקייה היה משחרר את כל הקבצים שבה
  static bool HasDll(string d) =>
    Cached(
      "d|" + d,
      () =>
      {
        try
        {
          return Directory.EnumerateFiles(d, "*.dll").Take(5).Any(PrivOwned);
        }
        catch
        {
          return false;
        }
      }
    );

  static bool IsProgramPath(string p)
  {
    var root = System.IO.Path.GetPathRoot(p) ?? "";
    if (p.Length > root.Length)
    {
      var parts = p[root.Length..].Split('\\');
      for (int i = 0; i < parts.Length - 1; i++)
      {
        var s = parts[i];
        if (
          (s.Length > 1 && s[0] == '.')
          || s.Equals("node_modules", StringComparison.OrdinalIgnoreCase)
          || s.Equals("site-packages", StringComparison.OrdinalIgnoreCase)
        )
        {
          // גם כאן: רק תיקייה שנוצרה על ידי תוכנת התקנה, ולא תיקייה שהמשתמש יצר ונתן לה שם כזה כדי לעקוף
          var dir = System.IO.Path.Combine(root, string.Join("\\", parts[..(i + 1)]));
          if (Cached("o|" + dir, () => PrivOwned(dir)))
            return true;
        }
      }
    }
    var d = System.IO.Path.GetDirectoryName(p);
    for (int depth = 0; d != null && depth < 12; depth++, d = System.IO.Path.GetDirectoryName(d))
      if (HasDll(d))
        return true;
    return false;
  }

  static readonly ConcurrentDictionary<string, bool> removableRoots = new(StringComparer.OrdinalIgnoreCase);

  static bool RemovableExcluded(string p)
  {
    if (IncludeRemovable)
      return false;
    try
    {
      var r = System.IO.Path.GetPathRoot(p);
      if (string.IsNullOrEmpty(r))
        return false;
      return removableRoots.GetOrAdd(
        r,
        x =>
        {
          try
          {
            return new DriveInfo(x).DriveType == DriveType.Removable || Native.IsUsbBus(x);
          }
          catch
          {
            return false;
          }
        }
      );
    }
    catch
    {
      return false;
    }
  }

  // דיסק USB חיצוני (גם כש-Windows מסווג אותו כ"קבוע") נחשב נשלף: כברירת מחדל לא נועלים בו קבצים, כדי שלא יישארו נעולים כשמחברים אותו למחשב אחר
  static readonly ConcurrentDictionary<string, bool> usbRoots = new(StringComparer.OrdinalIgnoreCase);

  public static bool UsbRoot(string root) => usbRoots.GetOrAdd(root, Native.IsUsbBus);

  public static bool ScanDrive(DriveInfo d)
  {
    if (d.DriveType != DriveType.Fixed && d.DriveType != DriveType.Removable)
      return false;
    return IncludeRemovable || (d.DriveType == DriveType.Fixed && !UsbRoot(d.RootDirectory.FullName));
  }

  static bool DriveUp(string p)
  {
    try
    {
      var r = System.IO.Path.GetPathRoot(p);
      return !string.IsNullOrEmpty(r) && Directory.Exists(r);
    }
    catch
    {
      return false;
    }
  }

  // תיקיות שאליהן נחלצים קבצים שנפתחים מתוך ארכיון (ZIP בסייר הקבצים, 7-Zip, WinRAR). הן בתוך AppData אבל לא מדלגים עליהן,
  // אחרת פתיחת תמונה מתוך קובץ ZIP עוקפת את החסימה. parts = הנתיב שאחרי C:\Users (שם המשתמש, AppData, Local, Temp, ...)
  static bool ArchiveTemp(string[] parts)
  {
    if (
      parts.Length < 6
      || !parts[2].Equals("Local", StringComparison.OrdinalIgnoreCase)
      || !parts[3].Equals("Temp", StringComparison.OrdinalIgnoreCase)
    )
      return false;
    var t = parts[4];
    if (t.StartsWith("7zO", StringComparison.OrdinalIgnoreCase) || t.StartsWith("Rar$", StringComparison.OrdinalIgnoreCase))
      return true;
    if (t.StartsWith("Temp", StringComparison.OrdinalIgnoreCase))
    {
      var u = t.IndexOf('_');
      return u > 4 && t[4..u].All(char.IsDigit);
    }
    return false;
  }

  // סינון מהיר בלי גישה לדיסק (למעקב אחרי קבצים חדשים ושינויי הרשאות): Windows (חוץ מ-Temp), Program Files וחלק מ-ProgramData
  public static bool CheapSkip(string p)
  {
    if (Under(p, WinDir) && !Under(p, WinDir + @"\Temp"))
      return true;
    foreach (var s in SkipFull)
      if (Under(p, s))
        return true;
    return false;
  }

  // fresh = קובץ חדש שנוצר/הועבר עכשיו (המעקב אחרי קבצים חדשים), ולא סריקה של קבצים קיימים
  public static bool InSkipped(string p, bool fresh = false)
  {
    if (Under(p, WinDir) && !Under(p, WinDir + @"\Temp"))
      return true;
    foreach (var s in SkipFull)
      if (Under(p, s))
        return true;
    var root = System.IO.Path.GetPathRoot(p) ?? "";
    if (p.Length > root.Length)
    {
      var first = p[root.Length..].Split('\\')[0];
      if (
        first.Equals("$Recycle.Bin", StringComparison.OrdinalIgnoreCase)
        || first.Equals("System Volume Information", StringComparison.OrdinalIgnoreCase)
      )
        return true;
    }
    if (SkipAppData && p.StartsWith(UsersDir + "\\", StringComparison.OrdinalIgnoreCase))
    {
      var parts = p[(UsersDir.Length + 1)..].Split('\\');
      if (
        parts.Length >= 2
        && parts[1].Equals("AppData", StringComparison.OrdinalIgnoreCase)
        && !ArchiveTemp(parts)
        && !(fresh && AppDataLockable(parts))
      )
        return true;
    }
    foreach (var e in Exclude)
      if (!string.IsNullOrWhiteSpace(e) && Under(p, e.TrimEnd('\\')))
        return true;
    if (SkipProgramDirs && IsProgramPath(p))
      return true;
    return false;
  }

  // AppData: קבצים שמוכנסים לשם בזמן החסימה (העתקה, העברה, הורדה, חילוץ) ננעלים – כדי שאי אפשר יהיה "להחביא" שם תמונות/שירים/סרטים.
  // הסריקה של קבצים קיימים עדיין מדלגת על AppData (תמונות ואייקונים של תוכנות לא ננעלים). גם קבצים חדשים לא ננעלים בנתוני Windows
  // ואפליקציות Store, בנתוני דפדפנים, ובתיקייה של תוכנה (יש בה קובצי exe/dll) – כדי לא לשבור תוכנות. parts = הנתיב שאחרי C:\Users
  static readonly string[] AppDataKeep = { "Microsoft", "Packages", "Google", "BraveSoftware", "Mozilla", "Opera Software", "Vivaldi", "Chromium" };

  static bool AppDataLockable(string[] parts)
  {
    // parts: משתמש, AppData, Local/Roaming/LocalLow, ...תיקיות, שם הקובץ. קובץ ישירות בתיקייה הזו (בלי תיקיית תוכנה) – ננעל
    if (parts.Length < 5)
      return true;
    if (AppDataKeep.Any(x => x.Equals(parts[3], StringComparison.OrdinalIgnoreCase)))
      return false;
    // תיקיית התוכנה: AppData\Local\<שם>. ב-Programs וב-Temp – תיקיית המשנה (אחרת כל Programs / Temp היו נחשבים תיקיית תוכנה אחת)
    int n = 4;
    if (parts[3].Equals("Programs", StringComparison.OrdinalIgnoreCase) || parts[3].Equals("Temp", StringComparison.OrdinalIgnoreCase))
    {
      if (parts.Length < 6)
        return true;
      n = 5;
    }
    var app = System.IO.Path.Combine(UsersDir, string.Join("\\", parts[..n]));
    return !Cached("a|" + app, () => HasBin(app, 3));
  }

  // יש בתיקייה (או בתיקיות המשנה שלה, עד עומק מוגבל) קובץ תוכנה. שגיאה בקריאה – נחשב תיקיית תוכנה (לא נועלים כשלא בטוחים)
  static bool HasBin(string d, int depth)
  {
    try
    {
      foreach (var f in Directory.EnumerateFiles(d))
      {
        var e = System.IO.Path.GetExtension(f);
        if (e.Equals(".exe", StringComparison.OrdinalIgnoreCase) || e.Equals(".dll", StringComparison.OrdinalIgnoreCase))
          return true;
      }
      if (depth > 0)
        foreach (var s in Directory.EnumerateDirectories(d))
        {
          if ((File.GetAttributes(s) & FileAttributes.ReparsePoint) != 0)
            continue;
          if (HasBin(s, depth - 1))
            return true;
        }
      return false;
    }
    catch
    {
      return true;
    }
  }

  // כוננים שאינם NTFS/ReFS (FAT, exFAT) לא תומכים בהרשאות, ולכן אי אפשר לחסום בהם קבצים
  static readonly ConcurrentDictionary<string, bool> aclRoots = new(StringComparer.OrdinalIgnoreCase);
  public static readonly ConcurrentDictionary<string, byte> NoAclDrives = new(StringComparer.OrdinalIgnoreCase);

  public static void ResetDriveCache()
  {
    aclRoots.Clear();
    NoAclDrives.Clear();
    removableRoots.Clear();
    usbRoots.Clear();
  }

  static bool AclOk(string p)
  {
    var root = System.IO.Path.GetPathRoot(p);
    if (string.IsNullOrEmpty(root))
      return true;
    return aclRoots.GetOrAdd(
      root,
      r =>
      {
        try
        {
          var f = new DriveInfo(r).DriveFormat;
          bool ok = f.Equals("NTFS", StringComparison.OrdinalIgnoreCase) || f.Equals("ReFS", StringComparison.OrdinalIgnoreCase);
          if (!ok)
            NoAclDrives[r] = 0;
          return ok;
        }
        catch
        {
          return true;
        }
      }
    );
  }

  static readonly string[] DangerExt = Config.Danger.ToArray();

  public static Dictionary<string, Rule> ExtMap(Config c)
  {
    var map = new Dictionary<string, Rule>();
    void M(Rule r, string[] x)
    {
      if (r.On)
        foreach (var y in x)
          map[y] = r;
    }
    M(c.Movies, Config.Vid);
    M(c.Songs, Config.Aud);
    M(c.Images, Config.Img);
    foreach (var r in c.Exts.Where(r => r.On))
    {
      var x = r.Path.TrimStart('.').ToLowerInvariant();
      if (x.Length > 0 && !Config.Danger.Contains(x))
        map[x] = r;
    }
    return map;
  }

  static readonly object LogLock = new(),
    logInit = new();
  static readonly ConcurrentQueue<string> pendingLog = new();
  static Thread? logThread;
  static readonly ConcurrentDictionary<string, byte> known = new(StringComparer.OrdinalIgnoreCase); // קבצים שכבר נחסמו על ידי השירות (חוסך קריאת הרשאות בכל סריקה)
  static readonly int ParSvc = Math.Max(2, Environment.ProcessorCount / 2); // השירות רץ ברקע ולכן משתמש בפחות ליבות

  // ---- עבודת רקע בעדיפות נמוכה (סריקות בשירות) ----
  // מצב רקע של Windows: עדיפות נמוכה למעבד ולדיסק, כך שהסריקה (אחרי הפעלה, כל שעה, אחרי שינוי) לא מאטה את המחשב.
  // רק בשירות, ורק בתהליכונים של הסריקה (לא בתשובות לשער ולא בפתיחה בקוד, שהמשתמש מחכה להן)
  [DllImport("kernel32.dll")]
  static extern IntPtr GetCurrentThread();

  [DllImport("kernel32.dll")]
  static extern bool SetThreadPriority(IntPtr h, int p);

  [ThreadStatic]
  static int bgDepth;

  public static void BgEnter()
  {
    if (InService && bgDepth++ == 0)
      SetThreadPriority(GetCurrentThread(), 0x00010000); // THREAD_MODE_BACKGROUND_BEGIN
  }

  public static void BgExit()
  {
    if (InService && --bgDepth == 0)
      SetThreadPriority(GetCurrentThread(), 0x00020000); // THREAD_MODE_BACKGROUND_END
  }

  // מחזיר תהליכון לעדיפות רגילה (נקרא בתחילת כל תשובה ב-Pipe). התשובה אף פעם לא רצה בתוך סריקה באותו תהליכון, ולכן בטוח לאפס
  public static void BgReset()
  {
    if (!InService)
      return;
    bgDepth = 0;
    SetThreadPriority(GetCurrentThread(), 0x00020000); // THREAD_MODE_BACKGROUND_END (אם לא היה במצב רקע – לא קורה כלום)
  }

  // כמו Parallel.ForEach, אבל כל תהליכון עובד במצב רקע (ויוצא ממנו בסוף, לפני שהוא חוזר למאגר)
  static void ParBg<T>(IEnumerable<T> src, ParallelOptions po, Action<T> body) =>
    Parallel.ForEach(
      src,
      po,
      () =>
      {
        BgEnter();
        return 0;
      },
      (x, _, l) =>
      {
        body(x);
        return l;
      },
      _ => BgExit()
    );

  // כתיבת היומן נעשית באצוות בתהליכון נפרד: הלולאה הראשית של השירות אף פעם לא ממתינה לנעילה
  static void EnqueueLog(string line)
  {
    var li = line.LastIndexOf('|');
    if (li > 0)
      logged[line[..li]] = 0;
    pendingLog.Enqueue(line);
    if (logThread != null)
      return;
    lock (logInit)
      if (logThread == null)
      {
        logThread = new Thread(() =>
        {
          while (true)
          {
            Thread.Sleep(700);
            try
            {
              lock (LogLock)
                DrainLog();
            }
            catch (Exception __e)
            {
              Diag.Log(__e);
            }
          }
        })
        {
          IsBackground = true,
        };
        logThread.Start();
      }
  }

  static void DrainLog()
  { // חייב לרוץ בתוך LogLock
    if (pendingLog.IsEmpty)
      return;
    var lines = new List<string>();
    while (pendingLog.TryDequeue(out var l))
      lines.Add(l);
    try
    {
      Directory.CreateDirectory(System.IO.Path.GetDirectoryName(WatchLog)!);
      File.AppendAllLines(WatchLog, lines);
    }
    catch
    {
      foreach (var l in lines)
        pendingLog.Enqueue(l); // הקובץ תפוס רגע (למשל החלון משחרר קבצים): השורות לא הולכות לאיבוד, ננסה שוב בסבב הבא
      throw;
    }
  }

  // קבצים שרשומים ביומן החסימות (בשירות). משמש לזיהוי קובץ שנעול על ידינו אבל לא רשום (למשל אחרי שחזור כונן שהיה מנותק), כדי לרשום אותו מחדש
  static readonly ConcurrentDictionary<string, byte> logged = new(StringComparer.OrdinalIgnoreCase);

  static bool HasOurDeny(FileSystemSecurity s) =>
    s.GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().Any(IsOurDeny);

  // עטיפות אלבום ש-Windows Media Player יוצר מוסתרות כקובצי מערכת מלכתחילה (Folder.jpg, AlbumArtSmall.jpg, AlbumArt_{...}_Large.jpg).
  // כשאין רישום של המצב המקורי, לא מניחים שהן הוסתרו על ידינו – אחרת הן היו נחשפות אחרי השחרור
  static bool WinHiddenArt(string p)
  {
    var n = System.IO.Path.GetFileName(p);
    return n.Equals("Folder.jpg", StringComparison.OrdinalIgnoreCase) || n.StartsWith("AlbumArt", StringComparison.OrdinalIgnoreCase);
  }

  // שחרור כל הקבצים שנחסמו ברקע. היומן מועבר הצידה לפני הקריאה (ולא נמחק אחריה), כך ששורות שהשירות מוסיף בינתיים נשמרות ביומן חדש ומשוחררות על ידו.
  // קבצים שלא שוחררו (כונן מנותק, שגיאה) נשארים ביומן ומשוחררים כשאפשר
  static void ReleaseWatchLogAll()
  {
    string taken;
    lock (LogLock)
    {
      try
      {
        DrainLog();
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
      known.Clear();
      if (!File.Exists(WatchLog))
        return;
      taken = WatchLog + "." + DateTime.UtcNow.Ticks + "_" + Guid.NewGuid().ToString("N") + ".rel";
      for (int i = 0; ; i++)
      {
        try
        {
          File.Move(WatchLog, taken);
          break;
        }
        catch (IOException) when (i < 50)
        {
          Thread.Sleep(100);
        }
      }
    }
    var keep = new ConcurrentBag<string>();
    Parallel.ForEach(
      File.ReadAllLines(taken),
      new ParallelOptions { MaxDegreeOfParallelism = Par },
      l =>
      {
        if (!UnblockLine(l))
          keep.Add(l);
      }
    );
    lock (LogLock)
    {
      logged.Clear();
      if (!keep.IsEmpty)
      {
        foreach (var l in keep)
        {
          var i = l.LastIndexOf('|');
          if (i > 0)
            logged[l[..i]] = 0;
        }
        for (int i = 0; ; i++)
        {
          try
          {
            File.AppendAllLines(WatchLog, keep);
            break;
          }
          catch (IOException) when (i < 50)
          {
            Thread.Sleep(100);
          }
        }
      }
    }
    try
    {
      File.Delete(taken);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  // חוסם קובץ (נקרא משירות הרקע: קבצים חדשים וגם קבצים קיימים). מחזיר false אם צריך לנסות שוב
  // הסריקה התקופתית בודקת מחדש כל קובץ (ולא סומכת על המטמון), כדי שחסימה שהוסרה תחזור
  public static void ForgetKnown()
  {
    lock (LogLock)
      known.Clear();
  }

  public static bool BlockNewFile(Rule r, string p, bool fresh = false)
  {
    try
    {
      if (known.ContainsKey(p))
        return true;
      if (RemovableExcluded(p) || InSkipped(p, fresh) || !AclOk(p))
        return true;
      var fi = new FileInfo(p);
      if (!fi.Exists || Protected(p))
        return true;
      var s = fi.GetAccessControl();
      // קובץ שהבעלים שלו הוא המערכת / מנהלים / TrustedInstaller – נוצר על ידי תוכנת התקנה או שירות (משאבים של תוכנות ב-ProgramData, קבצים שמתקין דרייבר מחלץ ל-Windows\Temp).
      // לא נועלים אותו, כדי לא לשבור תוכנות והתקנות. משתמש רגיל לא יכול ליצור קובץ בבעלות כזו (העתקה יוצרת קובץ בבעלותו).
      // בבעלות קבוצת המנהלים – רק ב-ProgramData (העתקה בחלון מורם מחוץ לשם נחסמת)
      if (InstallerSid(s.GetOwner(typeof(SecurityIdentifier))?.Value, p))
        return true;
      if (
        s.GetAccessRules(true, false, typeof(SecurityIdentifier))
          .Cast<FileSystemAccessRule>()
          .Any(x =>
            x.AccessControlType == AccessControlType.Deny
            && (x.IdentityReference.Value == "S-1-1-0" || IsOurDeny(x))
          )
      )
      {
        // קובץ שכבר נעול בחסימה שלנו אבל לא רשום ביומן (למשל אחרי שביטול קודם איבד את הרישום): רושמים אותו, כדי שישוחרר בביטול הבא
        if (!logged.ContainsKey(p) && HasOurDeny(s))
        {
          var cur = File.GetAttributes(p);
          var hs = FileAttributes.Hidden | FileAttributes.System;
          EnqueueLog($"{p}|{(int)((cur & hs) == hs && !WinHiddenArt(p) ? cur & ~hs : cur)}"); // מוסתר+מערכת = הוסתר על ידינו (חוץ מעטיפות אלבום של Windows)
        }
        known[p] = 0;
        return true;
      }
      var a = File.GetAttributes(p);
      // החוק פתוח עכשיו בקוד ("פתיחת תמונות (קוד)"): לא נועלים – לא קובץ חדש ולא בסריקה התקופתית. רק רושמים ביומן,
      // כך שכשהחלון נסגר (RelockExt) גם הקובץ הזה ננעל
      if (openIds.ContainsKey(r.Id))
      {
        if (!logged.ContainsKey(p))
          EnqueueLog($"{p}|{(int)a}");
        known[p] = 0;
        return true;
      }
      if (r.Hidden && r.Mode == Mode.Full)
        File.SetAttributes(p, a | FileAttributes.Hidden | FileAttributes.System);
      Mine(p);
      s.AddAccessRule(Deny(false));
      var hard = HardenFor(s);
      if (hard)
        Own(s, false);
      fi.SetAccessControl(s);
      if (hard)
        Label(p, false, true);
      EnqueueLog($"{p}|{(int)a}");
      known[p] = 0;
      return true;
    }
    catch
    {
      return false;
    }
  }

  // התקדמות הסריקה המלאה (נקראת מהחלון דרך הפקודה SCAN): כל תיקייה עד עומק 2 היא "יחידה", ותיקיות עמוקות יותר נספרות בתוך היחידה שלהן
  public static long ScanId,
    ScanStartTicks;
  public static int ScanDone,
    ScanTotal;
  public static volatile bool ScanRunning,
    ScanFinished;

  static List<string> SubDirs(string dir)
  {
    var subs = new List<string>();
    try
    {
      foreach (var d in Directory.EnumerateDirectories(dir))
      {
        if (InSkipped(d))
          continue;
        try
        {
          if ((File.GetAttributes(d) & FileAttributes.ReparsePoint) != 0)
            continue;
        }
        catch
        {
          continue;
        }
        subs.Add(d);
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    return subs;
  }

  static int CountUnits(string root)
  {
    int n = 1;
    foreach (var d1 in SubDirs(root))
    {
      n++;
      n += SubDirs(d1).Count;
    }
    return n;
  }

  public static void ScanNew(Dictionary<string, Rule> map, CancellationToken ct = default, string? only = null)
  {
    if (map.Count == 0)
      return; // אין סיומות חסומות – אין מה לסרוק
    var roots = (
      only != null
        ? new[] { only }
        : DriveInfo.GetDrives().Where(d => ScanDrive(d) && d.IsReady).Select(d => d.RootDirectory.FullName).ToArray()
    )
      .Where(AclOk)
      .ToArray();
    bool track = only == null;
    if (track)
    {
      ScanFinished = false;
      ScanDone = 0;
      ScanTotal = 0;
      ScanStartTicks = DateTime.UtcNow.Ticks;
      ScanId++;
      ScanRunning = true;
    }
    try
    {
      // סריקה מהירה דרך יומן ה-USN (קריאת ה-MFT) כשאפשר; אחרת – מעבר על התיקיות כמו קודם
      var usn = new List<(string Root, List<string> Files)>();
      var crawl = new List<string>();
      foreach (var r in roots)
      {
        if (ct.IsCancellationRequested)
          break;
        var l = UsnScan.TryList(r, map.Keys, ct);
        if (l != null)
          usn.Add((r, l));
        else
          crawl.Add(r);
      }
      if (track)
        ScanTotal = Math.Max(1, usn.Sum(u => u.Files.Count) + crawl.Sum(CountUnits));
      var po = new ParallelOptions { MaxDegreeOfParallelism = ParSvc, CancellationToken = ct };
      foreach (var u in usn)
        ParBg(
          u.Files,
          po,
          f =>
          {
            if (map.TryGetValue(System.IO.Path.GetExtension(f).TrimStart('.').ToLowerInvariant(), out var rl))
              BlockNewFile(rl, f);
            if (track)
              Interlocked.Increment(ref ScanDone);
          }
        );
      ParBg(crawl, po, d => ScanN(d, map, ct, 0));
      if (track && !ct.IsCancellationRequested)
      {
        ScanDone = ScanTotal;
        ScanFinished = true;
      }
    }
    finally
    {
      if (track)
        ScanRunning = false;
    }
  }

  static void ScanN(string dir, Dictionary<string, Rule> map, CancellationToken ct, int depth)
  {
    if (ct.IsCancellationRequested)
      return;
    try
    {
      foreach (var f in Directory.EnumerateFiles(dir))
      {
        if (ct.IsCancellationRequested)
          return;
        if (map.TryGetValue(System.IO.Path.GetExtension(f).TrimStart('.').ToLowerInvariant(), out var r))
          BlockNewFile(r, f);
      }
      var subs = SubDirs(dir);
      if (depth < 2 && subs.Count > 1)
        ParBg(
          subs,
          new ParallelOptions { MaxDegreeOfParallelism = ParSvc, CancellationToken = ct },
          d => ScanN(d, map, ct, depth + 1)
        );
      else
        foreach (var d in subs)
          ScanN(d, map, ct, depth + 1);
    }
    catch (OperationCanceledException) { }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    finally
    {
      if (depth <= 2 && !ct.IsCancellationRequested)
        Interlocked.Increment(ref ScanDone);
    }
  }

  // true = טופל (שוחרר, או שהקובץ נמחק). false = לא ניתן כרגע (הכונן מנותק / שגיאה) – השורה נשארת ביומן לניסיון נוסף
  static bool UnblockLine(string l)
  {
    var i = l.LastIndexOf('|');
    if (i < 0)
      return true;
    var p = l[..i];
    try
    {
      var fi = new FileInfo(p);
      if (!fi.Exists)
      {
        if (!DriveUp(p))
          return false;
        AddLost(p); // הקובץ נמחק – או הועבר (שינוי שם של תיקייה שמעליו). אם הועבר, הוא עדיין נעול: נחפש אותו בדיסק ונשחרר
        return true;
      }
      AclOff(fi, false);
      if (int.TryParse(l[(i + 1)..], out var at))
        File.SetAttributes(p, (FileAttributes)at);
      return true;
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
      return false;
    }
  }

  // ---- קבצים "אבודים": רשומים ביומן אבל כבר לא בנתיב שנרשם (תיקייה שמעליהם הועברה או שינתה שם בזמן החסימה) ----
  // בלי זה, שחרור לפני הסריקה התקופתית הבאה השאיר אותם נעולים לתמיד. נשמר: כונן|סיומת. השירות סורק את הכונן (כשהסיומת כבר לא חסומה)
  // ומשחרר כל קובץ שעדיין יש בו את כלל החסימה שלנו ואינו רשום ביומן
  static string LostFile => System.IO.Path.Combine(Config.Dir, "var", "lost.txt");
  static readonly object LostLock = new();

  static void AddLost(string p)
  {
    try
    {
      var root = System.IO.Path.GetPathRoot(p);
      var ext = System.IO.Path.GetExtension(p).TrimStart('.').ToLowerInvariant();
      if (string.IsNullOrEmpty(root) || ext.Length == 0)
        return;
      lock (LostLock)
      {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(LostFile)!);
        File.AppendAllLines(LostFile, new[] { root + "|" + ext });
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  public static bool HasLost()
  {
    try
    {
      return File.Exists(LostFile);
    }
    catch
    {
      return false;
    }
  }

  // map = הסיומות שחסומות כרגע (קבצים בסיומת חסומה מטופלים בסריקה הרגילה). keep = קבצים שחסומים במפורש בחלון "קבצים ותיקיות" – לא נוגעים בהם
  public static void ProcessLost(Dictionary<string, Rule> map, HashSet<string> keep, CancellationToken ct = default)
  {
    List<(string Root, string Ext)> items;
    lock (LostLock)
    {
      try
      {
        if (!File.Exists(LostFile))
          return;
        items = File.ReadAllLines(LostFile)
          .Select(l => l.Split('|'))
          .Where(p => p.Length == 2 && p[0].Length > 0 && p[1].Length > 0)
          .Select(p => (p[0], p[1]))
          .Distinct()
          .ToList();
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
        return;
      }
    }
    var todo = items.Where(x => !map.ContainsKey(x.Ext) && Directory.Exists(x.Root)).ToList();
    var done = new HashSet<(string, string)>();
    foreach (var g in todo.GroupBy(x => x.Root, StringComparer.OrdinalIgnoreCase))
    {
      if (ct.IsCancellationRequested)
        return;
      var exts = g.Select(x => x.Ext).Distinct().ToList();
      var files = UsnScan.TryList(g.Key, exts, ct) ?? CrawlExt(g.Key, exts, ct);
      if (ct.IsCancellationRequested)
        return;
      int n = 0;
      ParBg(
        files,
        new ParallelOptions { MaxDegreeOfParallelism = ParSvc },
        f =>
        {
          if (keep.Contains(f) || logged.ContainsKey(f))
            return;
          try
          {
            var fi = new FileInfo(f);
            if (!fi.Exists || !HasOurDeny(fi.GetAccessControl()))
              return;
            AclOff(fi, false);
            var a = File.GetAttributes(f);
            var hs = FileAttributes.Hidden | FileAttributes.System;
            if ((a & hs) == hs && !WinHiddenArt(f))
              File.SetAttributes(f, a & ~hs); // מוסתר+מערכת = הוסתר על ידינו (חוץ מעטיפות אלבום של Windows)
            Interlocked.Increment(ref n);
          }
          catch (Exception __e)
          {
            Diag.Log(__e);
          }
        }
      );
      if (n > 0)
        Alerts.Log($"שוחררו {n} קבצים שהועברו ממקומם בזמן החסימה ({g.Key})", false);
      foreach (var x in g)
        done.Add(x);
    }
    lock (LostLock)
    {
      try
      {
        // קריאה מחדש: ייתכן שנוספו שורות בזמן הסריקה
        var rest = File.ReadAllLines(LostFile)
          .Where(l =>
          {
            var p = l.Split('|');
            return p.Length == 2 && !done.Contains((p[0], p[1]));
          })
          .Distinct()
          .ToList();
        if (rest.Count == 0)
          File.Delete(LostFile);
        else
          File.WriteAllLines(LostFile, rest);
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
  }

  // הסרת התוכנה: סריקה של כל הכוננים (כולל נשלפים) לכל סוגי הקבצים שאי פעם יכלו להיחסם, ושחרור כל קובץ שעדיין יש בו את כלל החסימה שלנו.
  // רשת ביטחון למקרה שיומן החסימות נפגע – אחרי ההסרה אין שירות שישחרר מאוחר יותר
  public static void SweepAll(Config c)
  {
    try
    {
      var exts = Config.Vid.Concat(Config.Aud).Concat(Config.Img)
        .Concat(c.Exts.Select(r => r.Path.TrimStart('.').ToLowerInvariant()))
        .Where(x => x.Length > 0 && !Config.Danger.Contains(x))
        .Distinct()
        .ToList();
      foreach (var d in DriveInfo.GetDrives().Where(d => (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable) && d.IsReady))
        foreach (var x in exts)
          AddLost(System.IO.Path.Combine(d.RootDirectory.FullName, "x." + x));
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    ProcessLost(new(), new(StringComparer.OrdinalIgnoreCase));
  }

  static List<string> CrawlExt(string root, List<string> exts, CancellationToken ct)
  {
    var set = new HashSet<string>(exts.Select(e => "." + e), StringComparer.OrdinalIgnoreCase);
    var res = new List<string>();
    try
    {
      foreach (
        var f in Directory.EnumerateFiles(
          root,
          "*",
          new EnumerationOptions
          {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint,
          }
        )
      )
      {
        if (ct.IsCancellationRequested)
          break;
        if (set.Contains(System.IO.Path.GetExtension(f)))
          res.Add(f);
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    return res;
  }

  static string HardFlag => System.IO.Path.Combine(Config.Dir, "var", "harden.flag");

  static void SetOwner(string l, bool on)
  {
    var i = l.LastIndexOf('|');
    if (i < 0)
      return;
    var p = l[..i];
    try
    {
      var fi = new FileInfo(p);
      if (!fi.Exists)
        return;
      Mine(p);
      var s = fi.GetAccessControl();
      on = on && HardenFor(s);
      if (on)
        s.AddAccessRule(OwnerRule(false));
      else
        s.RemoveAccessRule(OwnerRule(false));
      fi.SetAccessControl(s);
      Label(p, false, on);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  static string DenyFlag => System.IO.Path.Combine(Config.Dir, "var", "denyto.flag");

  // קובץ נעול עובר להיקף הנעילה הנוכחי (DenyTo): כלל הדחייה הישן מוסר, החדש נוסף, והחיזוק לפי הבעלים
  static void ReDeny(string l)
  {
    var i = l.LastIndexOf('|');
    if (i < 0)
      return;
    var p = l[..i];
    try
    {
      var fi = new FileInfo(p);
      if (!fi.Exists)
        return;
      Mine(p);
      var s = fi.GetAccessControl();
      RemoveOurDeny(s, false);
      s.AddAccessRule(Deny(false));
      var hard = HardenFor(s);
      if (hard)
        s.AddAccessRule(OwnerRule(false));
      else
        s.RemoveAccessRule(OwnerRule(false));
      fi.SetAccessControl(s);
      Label(p, false, hard);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  static string HidState => System.IO.Path.Combine(Config.Dir, "var", "hidstate.txt");

  // מסתיר או מחזיר לתצוגה קבצים שכבר חסומים, כשמתג "נסתר" של החוק שלהם השתנה
  static void SyncHidden(Dictionary<string, Rule> map, List<string> keep, ParallelOptions po)
  {
    try
    {
      var old = new Dictionary<string, string>();
      try
      {
        if (File.Exists(HidState))
          foreach (var ln in File.ReadAllLines(HidState))
          {
            var z = ln.Split('|');
            if (z.Length == 2)
              old[z[0]] = z[1];
          }
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
      var cur = new Dictionary<string, string>();
      foreach (var rl in map.Values.Distinct())
        cur[rl.Id] = rl.Hidden && rl.Mode == Mode.Full ? "1" : "0";
      var todo = keep.Where(l =>
        {
          var i = l.LastIndexOf('|');
          return i >= 0
            && map.TryGetValue(System.IO.Path.GetExtension(l[..i]).TrimStart('.').ToLowerInvariant(), out var rr)
            && (!old.TryGetValue(rr.Id, out var ov) || ov != cur[rr.Id]);
        })
        .ToList();
      var hs = FileAttributes.Hidden | FileAttributes.System;
      if (todo.Count > 0)
        ParBg(
          todo,
          po,
          l =>
          {
            var i = l.LastIndexOf('|');
            var p = l[..i];
            try
            {
              if (!map.TryGetValue(System.IO.Path.GetExtension(p).TrimStart('.').ToLowerInvariant(), out var rr) || !File.Exists(p))
                return;
              var orig = (FileAttributes)int.Parse(l[(i + 1)..]);
              var now = File.GetAttributes(p);
              var next = (now & ~hs) | (cur[rr.Id] == "1" ? hs : (orig & hs));
              if (next == now)
                return;
              try
              {
                File.SetAttributes(p, next);
              }
              catch
              {
                SetLock(l, false);
                try
                {
                  File.SetAttributes(p, next);
                }
                finally
                {
                  SetLock(l, true);
                }
              }
            }
            catch (Exception __e)
            {
              Diag.Log(__e);
            }
          }
        );
      File.WriteAllLines(HidState, cur.Select(x => x.Key + "|" + x.Value));
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  // משחרר קבצים שנחסמו על ידי השירות ושהסיומת שלהם כבר לא חסומה (נקרא בכל טעינה מחדש של ההגדרות)
  public static void ReleaseStale(Dictionary<string, Rule> map)
  {
    lock (LogLock)
    {
      try
      {
        DrainLog();
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
      known.Clear();
      var want = Harden ? "2" : "0";
      var have = "0"; // "2" = חיזוק כולל תווית שלמות (קבצים שנחסמו בגרסה קודמת מקבלים אותה פעם אחת)
      try
      {
        if (File.Exists(HardFlag))
          have = File.ReadAllText(HardFlag).Trim();
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
      var keep = new List<string>();
      var rel = new List<string>();
      removableRoots.Clear();
      var lines = File.Exists(WatchLog) ? File.ReadAllLines(WatchLog).ToList() : new List<string>();
      // יומנים שהועברו הצידה לשחרור ולא הושלמו (למשל החלון נסגר באמצע): מצטרפים לטיפול
      var orphans = new List<string>();
      try
      {
        foreach (var f in Directory.GetFiles(System.IO.Path.GetDirectoryName(WatchLog)!, System.IO.Path.GetFileName(WatchLog) + ".*.rel"))
        {
          // שם הקובץ: watched.log.<זמן ההעברה>_<מזהה>.rel. רק קובץ שהועבר לפני יותר מ-10 דקות (שחרור שנקטע), ולא אחד שהחלון מטפל בו עכשיו
          var mid = System.IO.Path.GetFileName(f)[(System.IO.Path.GetFileName(WatchLog).Length + 1)..];
          var us = mid.IndexOf('_');
          if (us > 0 && long.TryParse(mid[..us], out var tk) && (DateTime.UtcNow - new DateTime(tk, DateTimeKind.Utc)).TotalMinutes > 10)
          {
            lines.AddRange(File.ReadAllLines(f));
            orphans.Add(f);
          }
        }
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
      bool dirty = orphans.Count > 0;
      foreach (var l in lines.Distinct(StringComparer.OrdinalIgnoreCase))
        {
          var i = l.LastIndexOf('|');
          if (i < 0)
            continue;
          var p = l[..i];
          bool inMap = map.ContainsKey(System.IO.Path.GetExtension(p).TrimStart('.').ToLowerInvariant());
          if (!File.Exists(p))
          {
            if (!DriveUp(p))
              keep.Add(l);
            else
              rel.Add(l);
            continue;
          } // כונן שאינו זמין כרגע (נשלף / נעול) – שומרים ביומן כדי שהקובץ ישוחרר בהמשך; קובץ שנמחק מוסר מהיומן
          if (inMap && !InSkipped(p, true) && !RemovableExcluded(p) && !InstallerOwned(p)) // true: קובץ ב-AppData שננעל כשהוכנס לשם – נשאר נעול
          {
            keep.Add(l);
            known[p] = 0;
          }
          else
            rel.Add(l); // סיומת שכבר לא חסומה, תיקייה שהוחרגה או כונן נשלף – משחררים
        }
      var po = new ParallelOptions { MaxDegreeOfParallelism = ParSvc };
      if (rel.Count > 0 || dirty)
      {
        var failed = new ConcurrentBag<string>();
        ParBg(
          rel,
          po,
          l =>
          {
            if (!UnblockLine(l))
              failed.Add(l); // לא שוחרר (שגיאה): נשאר ביומן לניסיון נוסף
          }
        );
        keep.AddRange(failed);
        File.WriteAllLines(WatchLog, keep);
        foreach (var f in orphans)
          try
          {
            File.Delete(f);
          }
          catch (Exception __e)
          {
            Diag.Log(__e);
          }
      }
      logged.Clear();
      foreach (var l in keep)
      {
        var i = l.LastIndexOf('|');
        if (i > 0)
          logged[l[..i]] = 0;
      }
      if (have != want && keep.Count > 0)
        ParBg(keep, po, l => SetOwner(l, Harden));
      // היקף הנעילה השתנה (כל המשתמשים ↔ רק החשבון שנבחר): קבצים שכבר נעולים עוברים להיקף החדש.
      // חוק שפתוח עכשיו בקוד – הקבצים שלו משוחררים כרגע, וכשהחלון ייסגר הם יינעלו בהיקף החדש
      var wantTo = DenyTo.Value;
      var haveTo = "S-1-1-0";
      try
      {
        if (File.Exists(DenyFlag))
          haveTo = File.ReadAllText(DenyFlag).Trim();
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
      if (haveTo != wantTo && keep.Count > 0)
        ParBg(
          keep,
          po,
          l =>
          {
            var i = l.LastIndexOf('|');
            if (i > 0 && map.TryGetValue(System.IO.Path.GetExtension(l[..i]).TrimStart('.').ToLowerInvariant(), out var rr) && openIds.ContainsKey(rr.Id))
              return;
            ReDeny(l);
          }
        );
      SyncHidden(map, keep, po);
      try
      {
        File.WriteAllText(HardFlag, want);
        File.WriteAllText(DenyFlag, wantTo);
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
  }

  // ---- ניקוי מטמוני צפייה (נקרא מהחלון אחרי שהסריקה הסתיימה) ----
  static DateTime lastClear = DateTime.MinValue;

  // מוחק רק קובצי תמונה/וידאו (עותקים שמורים של מה שנחסם) בתוך תיקיית מטמון. שום קובץ אחר (מסדי נתונים, הגדרות) ושום תיקייה לא נמחקים
  static void ClearDir(string d, HashSet<string> exts)
  {
    try
    {
      if (!Directory.Exists(d))
        return;
      foreach (
        var f in Directory.EnumerateFiles(
          d,
          "*",
          new EnumerationOptions
          {
            RecurseSubdirectories = true,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint,
          }
        )
      )
      {
        if (!exts.Contains(System.IO.Path.GetExtension(f).TrimStart('.')))
          continue;
        try
        {
          File.SetAttributes(f, FileAttributes.Normal);
          File.Delete(f);
        }
        catch (Exception __e)
        {
          Diag.Log(__e);
        }
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  // אחרי שהסריקה נעלה תמונות/סרטים: עותקים שמורים שלהם במטמון של אפליקציית התמונות/הסרטים ובמטמון התמונות הממוזערות היו עדיין מוצגים.
  // אפליקציה שפתוחה עכשיו לא נסגרת (עבודה שלא נשמרה הייתה הולכת לאיבוד) – המטמון שלה ינוקה בפעם הבאה
  public static void ClearViewerCaches(Config c)
  {
    if (!(c.Master && (c.Images.On || c.Movies.On)))
      return;
    if ((DateTime.UtcNow - lastClear).TotalMinutes < 10)
      return;
    lastClear = DateTime.UtcNow;
    var exts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    if (c.Images.On)
      exts.UnionWith(Config.Img);
    if (c.Movies.On)
      exts.UnionWith(Config.Vid);
    bool Running(string n)
    {
      try
      {
        var ps = Process.GetProcessesByName(n);
        foreach (var p in ps)
          p.Dispose();
        return ps.Length > 0;
      }
      catch
      {
        return true;
      }
    }
    try
    {
      var pkgs = new List<string>();
      if (!Running("Microsoft.Photos"))
        pkgs.Add("Microsoft.Windows.Photos_*");
      if (c.Movies.On && !Running("Video.UI"))
        pkgs.Add("Microsoft.ZuneVideo_*");
      foreach (var u in Directory.GetDirectories(UsersDir))
      {
        var pk = System.IO.Path.Combine(u, @"AppData\Local\Packages");
        if (!Directory.Exists(pk))
          continue;
        foreach (var pat in pkgs)
        foreach (var pkg in Directory.GetDirectories(pk, pat))
        foreach (var sub in new[] { "TempState", "LocalCache" })
          ClearDir(System.IO.Path.Combine(pkg, sub), exts);
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    try
    {
      const string VCS = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches";
      const string VC = VCS + @"\Thumbnail Cache";
      // ניקוי הדיסק מריץ כל קטגוריה שמסומנת במספר 777. מורידים זמנית סימון כזה מכל שאר הקטגוריות (למשל "הורדות"), כדי שרק מטמון התמונות הממוזערות יימחק,
      // ובסוף מחזירים את הסימונים הקודמים בדיוק כמו שהיו (אם המשתמש שמר הגדרת ניקוי משלו במספר הזה, היא לא נמחקת)
      var saved = new Dictionary<string, object>();
      using (var all = Registry.LocalMachine.OpenSubKey(VCS))
        if (all != null)
          foreach (var n in all.GetSubKeyNames())
            try
            {
              using var sk = Registry.LocalMachine.OpenSubKey(VCS + "\\" + n, true);
              if (sk?.GetValue("StateFlags0777") is object v)
              {
                saved[n] = v;
                sk.DeleteValue("StateFlags0777", false);
              }
            }
            catch (Exception __e)
            {
              Diag.Log(__e);
            }
      try
      {
        using (var k = Registry.LocalMachine.OpenSubKey(VC, true))
          k?.SetValue("StateFlags0777", 2, RegistryValueKind.DWord);
        using (new InternalScope())
        {
          using var p = Process.Start(
            new ProcessStartInfo("cleanmgr.exe", "/sagerun:777") { UseShellExecute = false, CreateNoWindow = true }
          );
          p?.WaitForExit(60000);
        }
      }
      finally
      {
        try
        {
          using (var k = Registry.LocalMachine.OpenSubKey(VC, true))
            k?.DeleteValue("StateFlags0777", false);
          foreach (var kv in saved)
          {
            using var sk = Registry.LocalMachine.OpenSubKey(VCS + "\\" + kv.Key, true);
            sk?.SetValue("StateFlags0777", kv.Value, RegistryValueKind.DWord);
          }
        }
        catch (Exception __e)
        {
          Diag.Log(__e);
        }
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  // מטמון התמונות הממוזערות שייך לכל משתמש בנפרד, והניקוי שבחלון (למעלה) רץ בחשבון המנהל – ולכן ניקה רק את המטמון של המנהל.
  // כאן (בשירות, אחרי הסריקה) ניקוי הדיסק רץ בחשבון של המשתמש שמחובר עכשיו למחשב, בסשן שלו ובלי חלון.
  // מספר פרופיל ניקוי נפרד (778, בחלון 777), כדי ששני הניקויים לא יפריעו זה לזה. כמו בחלון: רק מטמון התמונות הממוזערות מסומן, ושאר הסימונים מוחזרים
  public static void ClearUserThumbs()
  {
    if (!InService)
      return;
    const string VCS = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches";
    const string VC = VCS + @"\Thumbnail Cache";
    var saved = new Dictionary<string, object>();
    try
    {
      using (var all = Registry.LocalMachine.OpenSubKey(VCS))
        if (all != null)
          foreach (var n in all.GetSubKeyNames())
            try
            {
              using var sk = Registry.LocalMachine.OpenSubKey(VCS + "\\" + n, true);
              if (sk?.GetValue("StateFlags0778") is object v)
              {
                saved[n] = v;
                sk.DeleteValue("StateFlags0778", false);
              }
            }
            catch (Exception __e)
            {
              Diag.Log(__e);
            }
      using (var k = Registry.LocalMachine.OpenSubKey(VC, true))
        k?.SetValue("StateFlags0778", 2, RegistryValueKind.DWord);
      var exe = System.IO.Path.Combine(Environment.SystemDirectory, "cleanmgr.exe");
      if (File.Exists(exe) && UserSession.Launch(exe, "/sagerun:778", -1, true))
        Thread.Sleep(60_000); // ניקוי הדיסק קורא את הסימונים כשהוא עולה; מחכים לפני שמחזירים אותם
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    finally
    {
      try
      {
        using (var k = Registry.LocalMachine.OpenSubKey(VC, true))
          k?.DeleteValue("StateFlags0778", false);
        foreach (var kv in saved)
        {
          using var sk = Registry.LocalMachine.OpenSubKey(VCS + "\\" + kv.Key, true);
          sk?.SetValue("StateFlags0778", kv.Value, RegistryValueKind.DWord);
        }
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
  }

  // ---- חסימת חיבור לרשת לפי תוכנה ----
  [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
  static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);

  [DllImport("advapi32.dll")]
  static extern IntPtr FreeSid(IntPtr sid);

  static string? PkgSid(string family)
  {
    try
    {
      if (DeriveAppContainerSidFromAppContainerName(family, out var p) != 0)
        return null;
      try
      {
        return new SecurityIdentifier(p).Value;
      }
      finally
      {
        FreeSid(p);
      }
    }
    catch
    {
      return null;
    }
  }

  // white/list: המצב והרשימה שהוחלו בפועל (רשומת fwcfg). null = לפי ההגדרות הנוכחיות (בזמן ההחלה)
  static List<string> NetAppsRules(Config c, List<string> names, bool? white = null, List<string>? list = null)
  {
    var res = new List<string>();
    var isWhite = white ?? c.NetAppsWhite;
    var apps = (list ?? c.NetApps.White).Where(w => !string.IsNullOrWhiteSpace(w)).ToList();
    if (isWhite && !string.IsNullOrWhiteSpace(c.AlertUrl))
      apps.Add(GateExe); // ברשימה לבנה השירות עצמו חייב להיות מותר, כדי שההתראות (Webhook) יישלחו
    if (isWhite) // עדכוני אבטחה של Windows ושל Windows Defender, בדיקת תעודות וסנכרון שעון ממשיכים לעבוד גם ברשימה לבנה
      apps.AddRange(new[] { "svc:wuauserv", "svc:UsoSvc", "svc:DoSvc", "svc:CryptSvc", "svc:W32Time", "svc:WinDefend" });
    foreach (var a in apps.Distinct(StringComparer.OrdinalIgnoreCase))
    {
      string target,
        label;
      if (a.StartsWith("pkg:"))
      {
        var sid = PkgSid(a[4..]);
        if (sid == null)
          continue;
        target = $"-Package '{sid}'";
        label = a[4..];
      }
      else if (a.StartsWith("svc:"))
      {
        target = $"-Service '{Q(a[4..])}'";
        label = a[4..];
      }
      else
      {
        target = $"-Program '{Q(a)}'";
        label = System.IO.Path.GetFileName(a);
      }
      foreach (var dr in isWhite ? new[] { "Outbound" } : new[] { "Outbound", "Inbound" })
      {
        var nm = $"DeviceGuard {(isWhite ? "Allow" : "Block")} {dr} {label}".Replace("|", "_");
        names.Add(nm);
        res.Add(
          $"New-NetFirewallRule -DisplayName '{Q(nm)}' -Group 'DeviceGuardNet' -Direction {dr} {target} -Action {(isWhite ? "Allow" : "Block")} -Profile Any | Out-Null"
        );
      }
    }
    return res;
  }

  const string FWPOL = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\";

  static bool NetOk(Config c, bool white, List<string> list)
  {
    var names = new List<string>();
    NetAppsRules(c, names, white, list);
    var have = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    using (var k = Registry.LocalMachine.OpenSubKey(FWPOL + "FirewallRules"))
      if (k != null)
        foreach (var n in k.GetValueNames())
        {
          if (k.GetValue(n) is not string v)
            continue;
          var i = v.IndexOf("|Name=", StringComparison.Ordinal);
          if (i < 0)
            continue;
          var j = v.IndexOf('|', i + 6);
          if (j < 0)
            continue;
          have.Add(v.Substring(i + 6, j - i - 6));
        }
    if (names.Any(x => !have.Contains(x)))
      return false;
    foreach (var pf in new[] { "DomainProfile", "StandardProfile", "PublicProfile" })
    {
      using var pk = Registry.LocalMachine.OpenSubKey(FWPOL + pf);
      if (pk?.GetValue("EnableFirewall") is int en && en == 0)
        return false;
      if (white && !(pk?.GetValue("DefaultOutboundAction") is int oa && oa == 1))
        return false;
    }
    return true;
  }

  static int healBusy;
  static DateTime healBackoff = DateTime.MinValue;

  // המצב והרשימה שהוחלו בפועל: fwcfg|1/0|רשימה (Base64 של JSON). null = חסימת רשת לפי תוכנה לא הוחלה.
  // רשומת fwrules בלי fwcfg (החלה מגרסה קודמת): לפי ההגדרות הנוכחיות, כמו קודם
  static (bool White, List<string> List)? FwApplied(Config c)
  {
    List<string> ap;
    lock (c.Applied)
      ap = c.Applied.Where(x => x == "fwrules" || x.StartsWith("fwcfg|")).ToList();
    var cfg = ap.FirstOrDefault(x => x.StartsWith("fwcfg|"));
    if (cfg != null)
    {
      var q = cfg.Split('|', 3);
      try
      {
        var l = q.Length > 2 ? System.Text.Json.JsonSerializer.Deserialize<List<string>>(Encoding.UTF8.GetString(Convert.FromBase64String(q[2]))) : null;
        return (q.Length > 1 && q[1] == "1", l ?? new List<string>());
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
    return ap.Contains("fwrules") ? (c.NetAppsWhite, c.NetApps.White.ToList()) : null;
  }

  static string FwCfg(Config c) =>
    "fwcfg|" + (c.NetAppsWhite ? "1" : "0") + "|" + Convert.ToBase64String(Encoding.UTF8.GetBytes(System.Text.Json.JsonSerializer.Serialize(c.NetApps.White)));

  // נקרא מהשירות כל כמה שניות: אם מישהו מחק את כללי החומה או שינה את ברירת המחדל – יוצר אותם מחדש.
  // משחזרים רק את מה שההחלה רשמה (מצב ורשימה): סימון "חסימת רשת לפי תוכנה" או שינוי הרשימה בלי "החל שינויים" לא נוגע בחומת האש
  // (אחרת השינוי לא היה נרשם, לא היה מבוטל בביטול החסימה, והאינטרנט היה עלול להישאר חסום לכל התוכנות)
  public static void NetHeal(Config c)
  {
    if (!c.Master || DateTime.UtcNow < healBackoff || Applying())
      return;
    var fw = FwApplied(c);
    if (fw == null)
      return;
    var (white, list) = fw.Value;
    if (Interlocked.Exchange(ref healBusy, 1) == 1)
      return;
    try
    {
      // רשימה לבנה: כלל היתר שהופעל מחדש או נוסף בזמן החסימה (תוכנה שהותקנה, מנהל שהפעיל כלל) – מושבת שוב
      var nOff = white ? FwLeakOff() : 0;
      if (nOff > 0)
        Alerts.Log($"הושבתו {nOff} כללי היתר של חומת האש שעקפו את הרשימה הלבנה");
      if (NetOk(c, white, list))
        return;
      Alerts.Log("כללי חומת האש שונו או נמחקו – משחזר");
      var cmds = new List<string>
      {
        "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True",
        "Remove-NetFirewallRule -Group 'DeviceGuardNet' -ErrorAction SilentlyContinue",
      };
      cmds.AddRange(NetAppsRules(c, new List<string>(), white, list));
      if (white)
        cmds.Add("Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block");
      PSAll(cmds);
      if (!NetOk(c, white, list))
        healBackoff = DateTime.UtcNow.AddMinutes(10);
    }
    catch
    {
      healBackoff = DateTime.UtcNow.AddMinutes(10);
    }
    finally
    {
      Interlocked.Exchange(ref healBusy, 0);
    }
  }

  // ---- חסימת הרשת של חשבון אחד: עדכון הכלל בכל שינוי ברשת (רשימה לבנה), ושחזור כלל שנמחק / שונה או חומת אש שכובתה ----
  static DateTime nuBackoff = DateTime.MinValue;
  static int nuBusy;
  static string? nuSig, // מצב הרשת שלפיו נבנה הכלל (מתאמים קיימים ומה מותר)
    nuSnap; // הכלל כפי שנשמר ברישום אחרי הבנייה – כל שינוי בו (מחיקה, השבתה, שינוי מתאמים/משתמש) מזוהה
  static object? nuCfg; // ההגדרות שבזמנן נבנה הכלל: אחרי החלה (הגדרות חדשות) – בנייה מחדש בלי התראה

  static string NetUserSnap()
  {
    var l = new List<string>();
    using (var k = Registry.LocalMachine.OpenSubKey(FWPOL + "FirewallRules"))
      if (k != null)
        foreach (var n in k.GetValueNames())
          if (k.GetValue(n) is string v && string.Equals(FwField(v, "EmbedCtxt"), NetUserGroup, StringComparison.OrdinalIgnoreCase))
            l.Add(n + "=" + v);
    l.Sort(StringComparer.Ordinal);
    return string.Join("\n", l);
  }

  static bool FwProfilesOn()
  {
    foreach (var pf in new[] { "DomainProfile", "StandardProfile", "PublicProfile" })
    {
      using var pk = Registry.LocalMachine.OpenSubKey(FWPOL + pf);
      if (pk?.GetValue("EnableFirewall") is int en && en == 0)
        return false;
    }
    return true;
  }

  static string NetUserSig(string sid, List<string> white)
  {
    if (white.Count == 0)
      return sid + "|all";
    var names = new List<string>();
    try
    {
      names = NetworkInterface.GetAllNetworkInterfaces().Select(n => n.Name + "/" + n.Id).ToList();
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    names.Sort(StringComparer.Ordinal);
    var allow = NetUserAllowed(white);
    allow.Sort(StringComparer.OrdinalIgnoreCase);
    return sid + "|" + string.Join("\n", allow) + "#" + string.Join("\n", names);
  }

  // נקרא מהשירות כל כמה שניות ומיד בשינוי ברשת: רק אחרי שחסימת הרשת של החשבון הוחלה בפועל (רשומת netuser)
  public static void NetUserHeal(Config c)
  {
    if (!c.Master || !c.Net.On || DateTime.UtcNow < nuBackoff || Applying())
      return;
    var ap = NetUserApplied(c);
    if (ap == null)
      return;
    var (sid, white) = ap.Value;
    if (Interlocked.Exchange(ref nuBusy, 1) == 1)
      return;
    try
    {
      var sig = NetUserSig(sid, white);
      bool on = FwProfilesOn();
      var snap = NetUserSnap();
      if (on && sig == nuSig && snap == nuSnap && ReferenceEquals(c, nuCfg))
        return;
      // אותן הגדרות ואותו מצב רשת, אבל הכלל או חומת האש השתנו מבחוץ
      if (ReferenceEquals(c, nuCfg) && sig == nuSig && nuSnap != null)
        Alerts.Log("חסימת הרשת של החשבון שנבחר הוסרה או שונתה בחומת האש – משחזר");
      var cmds = new List<string> { "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True" };
      cmds.AddRange(NetUserCmds(sid, white));
      var res = Lines(PS(string.Join("\n", cmds))).LastOrDefault(l => l.StartsWith('#'));
      nuSig = sig;
      nuCfg = c;
      nuSnap = NetUserSnap();
      bool want = res != "#0"; // "#0" = כל המתאמים מותרים כרגע, ואין כלל
      if (!FwProfilesOn() || res == null || (want && nuSnap.Length == 0))
      {
        nuSnap = null;
        nuBackoff = DateTime.UtcNow.AddMinutes(10); // לא הצליח: לא מנסים (ולא מתריעים) שוב כל כמה שניות
        Alerts.Log("לא ניתן היה להחיל את חסימת הרשת של החשבון שנבחר בחומת האש (ניסיון נוסף בעוד 10 דקות)");
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
      nuBackoff = DateTime.UtcNow.AddMinutes(10);
    }
    finally
    {
      Interlocked.Exchange(ref nuBusy, 0);
    }
  }

  // ---- רשימה לבנה בחומת האש: כללי "אפשר" יוצאים שכבר קיימים במחשב ----
  // ברירת מחדל "חסום" לא מבטלת כללי היתר קיימים: אפליקציות מהחנות (דואר, Xbox, החנות עצמה...) ותוכנות שהוסיפו לעצמן כלל היתר היו ממשיכות להתחבר.
  // בזמן הרשימה הלבנה הכללים האלה מושבתים: נרשמים בקובץ לפני ההשבתה, וחוזרים לפעול בביטול (גם אם ההשבתה נקטעה באמצע).
  // לא נוגעים ב"רשת ליבה" (DNS, DHCP...), בכללים של שירותי Windows, ברכיבי Windows עצמו (תיקיית Windows ואפליקציות המערכת) ובכללים שלנו –
  // בלעדיהם גם התוכנות המותרות לא היו מתחברות
  static string FwOffFile => System.IO.Path.Combine(Config.Dir, "var", "fwoff.txt");
  static HashSet<string>? sysPkgSids;

  // אפליקציות המערכת (C:\Windows\SystemApps – למשל רכיב הכניסה לחשבון Microsoft): לא מושבתות
  static HashSet<string> SysPkgSids()
  {
    if (sysPkgSids != null)
      return sysPkgSids;
    var s = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    try
    {
      var d = System.IO.Path.Combine(WinDir, "SystemApps");
      if (Directory.Exists(d))
        foreach (var f in Directory.GetDirectories(d))
          if (PkgSid(System.IO.Path.GetFileName(f)) is string sid)
            s.Add(sid);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    return sysPkgSids = s;
  }

  static string? FwField(string v, string key)
  {
    var f = "|" + v + "|";
    var i = f.IndexOf("|" + key + "=", StringComparison.OrdinalIgnoreCase);
    if (i < 0)
      return null;
    var st = i + key.Length + 2;
    var j = f.IndexOf('|', st);
    return j < 0 ? f[st..] : f[st..j];
  }

  // כלל (כפי שהוא שמור ברישום) שעוקף את הרשימה הלבנה: היתר, פעיל, יוצא – של אפליקציה מהחנות או של תוכנה מחוץ לתיקיית Windows,
  // או כלל לכל התוכנות שאינו של Windows. sysPkg = אפליקציות המערכת שלא נוגעים בהן
  public static bool FwLeakRule(string v, ICollection<string> sysPkg, string winDir)
  {
    if (
      !string.Equals(FwField(v, "Action"), "Allow", StringComparison.OrdinalIgnoreCase)
      || !string.Equals(FwField(v, "Active"), "TRUE", StringComparison.OrdinalIgnoreCase)
      || !string.Equals(FwField(v, "Dir"), "Out", StringComparison.OrdinalIgnoreCase)
    )
      return false;
    var ctx = FwField(v, "EmbedCtxt");
    if (ctx != null && (ctx.Equals("DeviceGuardNet", StringComparison.OrdinalIgnoreCase) || ctx.Equals("@FirewallAPI.dll,-25000", StringComparison.OrdinalIgnoreCase)))
      return false; // הכללים שלנו / רשת ליבה
    if (FwField(v, "Svc") != null)
      return false; // שירות של Windows
    var pkg = FwField(v, "AppPkgId");
    if (pkg != null)
      return !sysPkg.Contains(pkg);
    var app = FwField(v, "App")?.Trim().Trim('"');
    if (app != null)
      return !(
        app.Equals("System", StringComparison.OrdinalIgnoreCase)
        || app.StartsWith("%SystemRoot%", StringComparison.OrdinalIgnoreCase)
        || app.StartsWith("%windir%", StringComparison.OrdinalIgnoreCase)
        || app.StartsWith(winDir.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase)
      );
    return ctx == null || !ctx.StartsWith('@'); // כלל לכל התוכנות: רק אם אינו של Windows
  }

  static List<string> FwLeakNames()
  {
    var res = new List<string>();
    try
    {
      using var k = Registry.LocalMachine.OpenSubKey(FWPOL + "FirewallRules");
      if (k == null)
        return res;
      var sys = SysPkgSids();
      foreach (var n in k.GetValueNames())
        if (k.GetValue(n) is string v && FwLeakRule(v, sys, WinDir))
          res.Add(n);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    return res;
  }

  static List<string> FwRuleCmds(string verb, List<string> names)
  {
    var cmds = new List<string>();
    for (int i = 0; i < names.Count; i += 40)
      cmds.Add($"{verb}-NetFirewallRule -Name {string.Join(",", names.Skip(i).Take(40).Select(n => "'" + Q(n) + "'"))} -ErrorAction SilentlyContinue");
    return cmds;
  }

  static readonly object FwOffLock = new();

  // משבית את כללי ההיתר שעוקפים את הרשימה הלבנה. מחזיר כמה הושבתו
  static int FwLeakOff()
  {
    lock (FwOffLock)
    {
      var names = FwLeakNames();
      if (names.Count == 0)
        return 0;
      try
      {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(FwOffFile)!);
        File.AppendAllLines(FwOffFile, names); // לפני ההשבתה: גם אם התהליך נקטע, הביטול יחזיר אותם
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
        return 0; // בלי רישום לא משביתים – אחרת לא היו חוזרים לפעול בביטול
      }
      PSAll(FwRuleCmds("Disable", names));
      return names.Count;
    }
  }

  static bool FwOffHeld(string name)
  {
    try
    {
      lock (FwOffLock)
        return File.Exists(FwOffFile) && File.ReadAllLines(FwOffFile).Contains(name, StringComparer.OrdinalIgnoreCase);
    }
    catch
    {
      return false;
    }
  }

  // מתאמי רשת חדשים (מתאם USB, שיתוף אינטרנט מהטלפון) שחוברו אחרי ההחלה: נחסמים אוטומטית. הבדיקה זולה (ללא PowerShell כשאין חדש)
  static string NetHealFile => System.IO.Path.Combine(Config.Dir, "var", "netheal.txt");
  static string NetHealPnpFile => System.IO.Path.Combine(Config.Dir, "var", "netheal.pnp"); // מזהה|שם
  static readonly ConcurrentDictionary<string, DateTime> adBackoff = new(StringComparer.OrdinalIgnoreCase);

  static List<string> WlanArgs(List<string> ssidWhite)
  {
    var l = new List<string> { "wlan add filter permission=denyall networktype=infrastructure" };
    foreach (var ssid in ssidWhite)
      l.Add($"wlan add filter permission=allow ssid=\"{ssid.Replace("\"", "")}\" networktype=infrastructure");
    return l;
  }

  // מתאמי Wi-Fi שכבר טופלו (המסנן הוסף אחרי שהופיעו). מתאם חדש – למשל ב-USB – גורם להוספה חוזרת של המסנן (אם שירות ה-WLAN לא רץ בזמן ההחלה, המסנן לא נוסף אז)
  static readonly ConcurrentDictionary<string, byte> wlanSeen = new(StringComparer.OrdinalIgnoreCase);
  static DateTime wlanRefresh = DateTime.MinValue;

  public static void NetAdapterHeal(Config c)
  {
    if (!c.Master || !c.Net.On || Applying())
    {
      wlanSeen.Clear();
      return;
    }
    // כל 2 דקות מוסיפים את המסנן מחדש (מנהל יכול למחוק אותו ב-netsh). מחיקה והוספה – לא נוצר עותק כפול.
    // רק מסנן שההחלה רשמה (wlanfilter), עם רשימת הרשתות המותרות שנרשמה: סימון "חסימת רשת" בלי "החל שינויים" לא מוסיף מסנן
    // (אחרת הוא לא היה נמחק בביטול, וה-Wi-Fi היה נשאר חסום)
    List<string> applied;
    lock (c.Applied)
      applied = c.Applied.Where(x => x.StartsWith("wlanfilter|")).ToList();
    if ((DateTime.UtcNow - wlanRefresh).TotalMinutes >= 2)
    {
      wlanRefresh = DateTime.UtcNow;
      wlanSeen.Clear();
    }
    try
    {
      var wifiNew = NetworkInterface
        .GetAllNetworkInterfaces()
        .Where(n => n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 && wlanSeen.TryAdd(n.Id, 0))
        .ToList();
      if (wifiNew.Count > 0 && applied.Contains("wlanfilter|denyall"))
        foreach (var a in WlanArgs(applied.Where(x => x.StartsWith("wlanfilter|allow|")).Select(x => x[17..]).ToList()))
        {
          Netsh(a.Replace("wlan add filter", "wlan delete filter")); // קודם מוחקים, כדי שלא ייווצר מסנן כפול (ביטול מוחק עותק אחד בלבד)
          Netsh(a);
        }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    // מתאמים שאינם Wi-Fi: רק אחרי שחסימת הרשת הוחלה בפועל. סימון "חסימת רשת" בלי "החל שינויים" לא מנתק את הרשת הקווית
    // (רשומה מגרסה קודמת: wlanfilter|denyall נרשם בכל החלה של חסימת רשת)
    if (!applied.Contains("wlanfilter|denyall") && !AppliedHas(c, "netapplied"))
      return;
    try
    {
      var wl = c.Net.White.Where(w => !w.StartsWith("ssid:")).ToHashSet(StringComparer.OrdinalIgnoreCase);
      var now = DateTime.UtcNow;
      var bad = NetworkInterface
        .GetAllNetworkInterfaces()
        .Where(n =>
          n.OperationalStatus == OperationalStatus.Up
          && n.NetworkInterfaceType != NetworkInterfaceType.Loopback
          && n.NetworkInterfaceType != NetworkInterfaceType.Wireless80211
          && n.NetworkInterfaceType != NetworkInterfaceType.Tunnel
          && !wl.Contains(n.Name)
          && !(adBackoff.TryGetValue(n.Name, out var until) && now < until)
        )
        .Select(n => n.Name)
        .ToList();
      if (bad.Count == 0)
        return;
      // לפני ההשבתה נרשם גם מזהה ההתקן (netheal.pnp): מתאם USB שינותק עד הביטול יקבל בחזרה את מצבו לפי המזהה
      var outp = PS(
        string.Join(
          "\n",
          bad.Select(n =>
            $"$a = Get-NetAdapter -Name '{Q(n)}' -ErrorAction SilentlyContinue; if ($a) {{ 'P|' + $a.PnPDeviceID + '|' + $a.Name; Disable-NetAdapter -Name '{Q(n)}' -Confirm:$false }}"
          )
        )
      );
      try
      {
        var pl = Lines(outp).Where(l => l.StartsWith("P|")).Select(l => l[2..]).Where(l => l.Contains('|') && !l.StartsWith("|")).ToList();
        if (pl.Count > 0)
        {
          Directory.CreateDirectory(System.IO.Path.GetDirectoryName(NetHealPnpFile)!);
          File.AppendAllLines(NetHealPnpFile, pl);
        }
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
      Directory.CreateDirectory(System.IO.Path.GetDirectoryName(NetHealFile)!);
      File.AppendAllLines(NetHealFile, bad);
      // מתאם שלא הצליח להיחסם: לא מנסים (ולא מתריעים) שוב כל 15 שניות, אלא רק בעוד 10 דקות
      var still = NetworkInterface
        .GetAllNetworkInterfaces()
        .Where(n => n.OperationalStatus == OperationalStatus.Up && bad.Contains(n.Name))
        .Select(n => n.Name)
        .ToList();
      foreach (var n in still)
        adBackoff[n] = now.AddMinutes(10);
      var done = bad.Except(still).ToList();
      if (done.Count > 0)
        Alerts.Log("מתאם רשת חדש נחסם: " + string.Join(", ", done));
      if (still.Count > 0)
        Alerts.Log("לא ניתן היה לחסום מתאם רשת (ניסיון נוסף בעוד 10 דקות): " + string.Join(", ", still));
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  // ---------- שחזור חסימות שהוסרו מבחוץ (הקשחה) ----------

  // קבצים חסומים שההרשאות שלהם שונו מבחוץ: נבדקים ונועלים שוב (חוץ מחוק שפתוח כרגע בקוד)
  public static void RecheckLocks(Dictionary<string, Rule> map, List<string> files)
  {
    int n = 0;
    foreach (var p in files)
    {
      try
      {
        if (!map.TryGetValue(System.IO.Path.GetExtension(p).TrimStart('.').ToLowerInvariant(), out var r) || openIds.ContainsKey(r.Id))
          continue;
        var fi = new FileInfo(p);
        if (!fi.Exists)
          continue;
        if (HasOurDeny(fi.GetAccessControl()))
        {
          known[p] = 0;
          continue;
        }
        bool was = logged.ContainsKey(p);
        known.TryRemove(p, out _);
        BlockNewFile(r, p, was); // was: קובץ שננעל על ידינו (גם ב-AppData) – נועלים שוב
        if (was)
          n++;
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
    if (n > 0)
      Alerts.Log($"זוהתה הסרה של חסימה מ-{n} קבצים – ננעלו שוב");
  }

  // פריט חסום בחלון "קבצים ותיקיות" (שרשום ב-Applied) שהנעילה שלו הוסרה מבחוץ
  public static bool PathUnlocked(Config c, Rule r)
  {
    try
    {
      var p = r.Path?.TrimEnd('\\');
      if (string.IsNullOrWhiteSpace(p) || ProtectedPath(p) || !AclOk(p))
        return false;
      bool applied;
      lock (c.Applied)
        applied = c.Applied.Any(x => x == "acl|" + p || x.StartsWith("acl|" + p + "|", StringComparison.Ordinal) || x == "acl|" + r.Path || x.StartsWith("acl|" + r.Path + "|", StringComparison.Ordinal));
      if (!applied)
        return false; // לא נחסם בהחלה (למשל לא היה קיים) – לא נועלים בלי רישום, אחרת לא היה משתחרר בביטול
      var cur = CurPath(c, p);
      if (Directory.Exists(cur))
        return !HasDeny(cur, false);
      if (File.Exists(cur))
        return !HasOurDeny(new FileInfo(cur).GetAccessControl());
      return false;
    }
    catch
    {
      return false;
    }
  }

  public static void HostsHeal(Config c)
  {
    try
    {
      string? want;
      lock (c.Applied)
        want = c.Applied.FirstOrDefault(x => x == "hostslock" || x.StartsWith("hostslock|"));
      if (want == null)
        return;
      var who = want.Length > 10 ? want[10..] : null; // "hostslock|SID"
      var fi = new FileInfo(HostsPath);
      if (!fi.Exists)
        return;
      var sec = fi.GetAccessControl();
      if (HasHostsDeny(sec, who))
        return;
      sec.AddAccessRule(HostsDenyFor(who));
      fi.SetAccessControl(sec);
      Alerts.Log("הנעילה של קובץ hosts הוסרה – שוחזרה");
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  // מפתחות Safe Mode של השירות (השירות רץ גם ב-Safe Mode). true = היו חסרים ונוצרו מחדש
  public static bool SafeBootHeal()
  {
    bool fixedAny = false;
    foreach (var m in new[] { "Minimal", "Network" })
      try
      {
        var path = $@"SYSTEM\CurrentControlSet\Control\SafeBoot\{m}\DeviceGuard";
        using var k = Registry.LocalMachine.OpenSubKey(path);
        if (k?.GetValue("") is string v && v == "Service")
          continue;
        using var w = Registry.LocalMachine.CreateSubKey(path);
        w.SetValue("", "Service");
        fixedAny = true;
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    return fixedAny;
  }

  // התקני USB שהושבתו על ידינו והופעלו מחדש מבחוץ (מנהל ההתקנים / PowerShell): מושבתים שוב. בדיקה זולה (בלי PowerShell כשאין שינוי)
  static int usbTBusy;
  static readonly ConcurrentDictionary<string, DateTime> usbBackoff = new(StringComparer.OrdinalIgnoreCase);

  public static void UsbTamperHeal(Config c)
  {
    if (!c.Master || !c.Usb.On || Applying())
      return;
    if (Interlocked.Exchange(ref usbTBusy, 1) == 1)
      return;
    try
    {
      List<string> ids;
      lock (c.Applied)
        ids = c.Applied.Where(x => x.StartsWith("usb|")).Select(x => x[4..]).ToList();
      try
      {
        if (File.Exists(UsbHealFile))
          ids.AddRange(File.ReadAllLines(UsbHealFile).Where(l => l.Length > 0));
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
      var now = DateTime.UtcNow;
      var bad = ids.Distinct(StringComparer.OrdinalIgnoreCase)
        .Where(id =>
          !c.Usb.White.Contains(id) && !(usbBackoff.TryGetValue(id, out var u) && now < u) && Native.DevState(id) == 0
        )
        .ToList();
      if (bad.Count == 0)
        return;
      PSAll(bad.Select(id => $"Disable-PnpDevice -InstanceId '{Q(id)}' -Confirm:$false").ToList());
      foreach (var id in bad)
        if (Native.DevState(id) == 0)
          usbBackoff[id] = now.AddMinutes(10); // לא הצליח: לא מנסים שוב כל כמה שניות
      Alerts.Log("התקן USB חסום הופעל מחדש – הושבת שוב: " + string.Join(", ", bad));
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    finally
    {
      Interlocked.Exchange(ref usbTBusy, 0);
    }
  }

  // כונן USB שחובר אחרי ההחלה ובכל זאת עלה (למשל כונן UASP שכבר הותקן בעבר, ולכן חסימת התקנה חדשה לא חלה עליו): נחסם אוטומטית.
  // נקרא מהשירות כשמופיע כונן חדש. מה שנחסם כאן נרשם בקובץ וחוזר לפעול בביטול
  static string UsbHealFile => System.IO.Path.Combine(Config.Dir, "var", "usbheal.txt");
  static int usbHealBusy;

  static bool AppliedHas(Config c, string e)
  {
    lock (c.Applied)
      return c.Applied.Contains(e);
  }

  // רק אחרי שחסימת ה-USB הוחלה בפועל: סימון USB בלי "החל שינויים" לא משבית כוננים שמחברים.
  // (רשומה מגרסה קודמת: מדיניות DenyRemovableDevices נרשמת בכל החלה של חסימת USB)
  static bool UsbApplied(Config c)
  {
    lock (c.Applied)
      return c.Applied.Contains("usbapplied") || c.Applied.Any(x => x.StartsWith("reg|") && x.Contains(@"DeviceInstall\Restrictions|DenyRemovableDevices|"));
  }

  public static void UsbDiskHeal(Config c)
  {
    if (!c.Master || !c.Usb.On || !UsbApplied(c) || Applying())
      return;
    if (Interlocked.Exchange(ref usbHealBusy, 1) == 1)
      return;
    try
    {
      var bad = new List<string>();
      foreach (var l in Lines(PS(UsbQuery)))
      {
        var q = l.Split('|', 3);
        if (q.Length < 2 || c.Usb.White.Contains(q[0]) || c.Usb.White.Contains(q[1]))
          continue;
        bad.Add(q[0]);
      }
      if (bad.Count == 0)
        return;
      // נרשם לפני ההשבתה: גם אם השירות נעצר באמצע, הביטול יחזיר אותם לפעול
      Directory.CreateDirectory(System.IO.Path.GetDirectoryName(UsbHealFile)!);
      File.AppendAllLines(UsbHealFile, bad);
      PSAll(bad.Select(id => $"Disable-PnpDevice -InstanceId '{Q(id)}' -Confirm:$false").ToList());
      Alerts.Log("התקן אחסון USB שחובר נחסם: " + string.Join(", ", bad));
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    finally
    {
      Interlocked.Exchange(ref usbHealBusy, 0);
    }
  }

  // ---- מתאמי רשת והתקני USB שהיו אמורים לחזור לפעול בביטול ולא חזרו (PowerShell נכשל / התקן לא מחובר) ----
  static string DevPendFile => System.IO.Path.Combine(Config.Dir, "var", "devpending.txt");
  static readonly object DevPendLock = new();

  // מקבל רשומות net|שם / usb|מזהה, ומחזיר את אלה שעדיין מושבתות. אם אי אפשר לבדוק – מחזיר את כולן (עדיף לנסות שוב מאשר לשכוח)
  static List<string> StillDisabled(List<string> want)
  {
    if (want.Count == 0)
      return want;
    var o = PS(
      "Get-NetAdapter -ErrorAction SilentlyContinue | ? Status -eq 'Disabled' | % { 'net|' + $_.Name }\n"
        + "Get-PnpDevice -ErrorAction SilentlyContinue | ? ConfigManagerErrorCode -eq 'CM_PROB_DISABLED' | % { 'usb|' + $_.InstanceId; 'pnp|' + $_.InstanceId }\n"
        + "'#OK'"
    );
    var l = Lines(o);
    if (!l.Contains("#OK"))
      return want.Distinct().ToList();
    var dis = new HashSet<string>(l, StringComparer.OrdinalIgnoreCase);
    return want.Where(dis.Contains).Distinct().ToList();
  }

  static void AddDevPending(List<string> items)
  {
    if (items.Count == 0)
      return;
    lock (DevPendLock)
    {
      try
      {
        var cur = File.Exists(DevPendFile) ? File.ReadAllLines(DevPendFile).ToList() : new List<string>();
        foreach (var i in items)
          if (!cur.Any(x => x.StartsWith(i + "|", StringComparison.OrdinalIgnoreCase)))
            cur.Add(i + "|0");
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(DevPendFile)!);
        File.WriteAllLines(DevPendFile, cur);
        Alerts.Log("לא כל מתאמי הרשת/התקני ה-USB חזרו לפעול בביטול – השירות ינסה שוב: " + string.Join(", ", items), false);
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
  }

  static DateTime lastDevPend = DateTime.MinValue;

  // נקרא מהשירות: מנסה שוב להפעיל מה שלא חזר לפעול – אבל לא מתאם/התקן שהחסימה הנוכחית אמורה להשאיר חסום
  public static void ProcessDevPending(Config c, bool blocking)
  {
    if ((DateTime.UtcNow - lastDevPend).TotalMinutes < 5 || !File.Exists(DevPendFile))
      return;
    lastDevPend = DateTime.UtcNow;
    lock (DevPendLock)
    {
      try
      {
        var items = File.ReadAllLines(DevPendFile)
          .Select(x => x.Split('|'))
          .Where(p => p.Length >= 3)
          .Select(p => (Key: p[0] + "|" + string.Join("|", p[1..^1]), Tries: int.TryParse(p[^1], out var t) ? t : 0))
          .ToList();
        bool netWide = AppliedHas(c, "netapplied") || AppliedHas(c, "wlanfilter|denyall");
        bool Hold(string key)
        {
          if (!blocking || !c.Master)
            return false;
          // רק כשחסימת רשת לכל המחשב הוחלה בפועל. חסימת רשת של חשבון אחד (חומת האש) לא משביתה מתאמים: מה שהושבת קודם חוזר לפעול
          if (key.StartsWith("net|"))
            return c.Net.On && netWide && !c.Net.White.Contains(key[4..]);
          if (key.StartsWith("pnp|"))
            return c.Net.On && netWide; // מתאם רשת לפי מזהה: בזמן חסימת רשת לא מחזירים
          return c.Usb.On && !UsbUser(c) && !c.Usb.White.Contains(key[4..]); // חסימה של חשבון אחד לא משביתה התקנים
        }
        // אחרי יום של ניסיונות (288) ממשיכים, אבל פעם בשעה (כל 12 סבבים) – לא מוותרים: התקן שנשאר מושבת לא היה חוזר לעבוד אף פעם
        var now = items.Where(x => !Hold(x.Key) && (x.Tries < 288 || x.Tries % 12 == 0)).ToList();
        var skipped = items.Where(x => !Hold(x.Key) && !now.Contains(x)).ToList();
        if (now.Count == 0 && skipped.Count == 0)
          return;
        var cmds = now.Select(x =>
            x.Key.StartsWith("net|")
              ? $"Enable-NetAdapter -Name '{Q(x.Key[4..])}' -Confirm:$false"
              : $"Enable-PnpDevice -InstanceId '{Q(x.Key[4..])}' -Confirm:$false"
          )
          .ToList();
        if (cmds.Count > 0)
          PSAll(cmds);
        var still = new HashSet<string>(StillDisabled(now.Select(x => x.Key).ToList()), StringComparer.OrdinalIgnoreCase);
        var res = new List<string>();
        foreach (var x in items)
        {
          bool tried = now.Contains(x);
          // התקן USB / מתאם רשת שלא מחובר: מנקים את סימון ההשבתה ברישום, וכשיחובר שוב הוא יעבוד (התקן מושבת לא "מופיע", ולכן אין הזדמנות אחרת להפעיל אותו).
          // הבדיקה הזו קודמת: התקן לא מחובר לא מופיע כ"מושבת" בשאילתת PowerShell, ולכן היה נחשב בטעות כאילו חזר לפעול
          if (tried && (x.Key.StartsWith("usb|") || x.Key.StartsWith("pnp|")) && Native.DevState(x.Key[4..]) == -1)
          {
            if (Native.ClearDisabledFlag(x.Key[4..]))
              continue;
          }
          else if (tried && !still.Contains(x.Key))
            continue; // חזר לפעול
          var n = tried || skipped.Contains(x) ? x.Tries + 1 : x.Tries;
          if (n == 288)
            Alerts.Log("עדיין לא חזר לפעולה: " + x.Key[4..] + " – ממשיך לנסות פעם בשעה. אפשר להפעיל אותו ידנית במנהל ההתקנים");
          res.Add(x.Key + "|" + n);
        }
        if (res.Count == 0)
          File.Delete(DevPendFile);
        else
          File.WriteAllLines(DevPendFile, res);
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
  }

  // הסרת התוכנה (נקרא מהשירות, SYSTEM, רגע לפני שהוא מסיר את עצמו): אחרי ההסרה אין מי שינסה שוב, ולכן כל התקן/מתאם שעדיין ממתין
  // חוזר לפעול עכשיו. התקן שלא מחובר – מנקים את סימון ההשבתה שלו ברישום, כדי שיעבוד כשיחובר שוב
  public static void FlushDevPending()
  {
    lock (DevPendLock)
    {
      try
      {
        if (!File.Exists(DevPendFile))
          return;
        var keys = File.ReadAllLines(DevPendFile)
          .Select(x => x.Split('|'))
          .Where(p => p.Length >= 3)
          .Select(p => p[0] + "|" + string.Join("|", p[1..^1]))
          .Distinct(StringComparer.OrdinalIgnoreCase)
          .ToList();
        var cmds = new List<string>();
        foreach (var k in keys)
        {
          if (k.StartsWith("net|"))
            cmds.Add($"Enable-NetAdapter -Name '{Q(k[4..])}' -Confirm:$false");
          else if (Native.DevState(k[4..]) == -1)
            Native.ClearDisabledFlag(k[4..]);
          else
            cmds.Add($"Enable-PnpDevice -InstanceId '{Q(k[4..])}' -Confirm:$false");
        }
        if (cmds.Count > 0)
          PSAll(cmds);
        File.Delete(DevPendFile);
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
  }

  // ---- חומת אש, מסנן Wi-Fi ונעילת hosts שהיו אמורים להשתחרר בביטול ----
  // הביטול מריץ את הפקודות פעם אחת. אם הן נכשלו (למשל בהפעלת המחשב, כששירות ה-Wi-Fi או חומת האש עוד לא עלו), או שבדיקת השחזור התקופתית
  // הוסיפה אותם שוב בדיוק ברגע הביטול – ה-Wi-Fi או האינטרנט היו נשארים חסומים גם אחרי הפתיחה. לכן כל פריט נרשם כאן, נבדק מול המצב
  // האמיתי ומבוצע שוב עד שהוא באמת שוחרר (ולפחות דקה אחרי הביטול, כדי לתפוס גם מרוץ כזה). שורה: רשומה<TAB>זמן הביטול (ticks)
  static string NetPendFile => System.IO.Path.Combine(Config.Dir, "var", "netpending.txt");
  static readonly object NetPendLock = new();

  static void AddNetPending(List<string> items)
  {
    if (items.Count == 0)
      return;
    lock (NetPendLock)
      try
      {
        var now = DateTime.UtcNow.Ticks;
        var cur = File.Exists(NetPendFile) ? File.ReadAllLines(NetPendFile).Where(l => l.Length > 0).ToList() : new List<string>();
        foreach (var i in items.Distinct())
        {
          cur.RemoveAll(l => l.Split('\t')[0] == i);
          cur.Add(i + "\t" + now);
        }
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(NetPendFile)!);
        File.WriteAllLines(NetPendFile, cur);
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
  }

  public static bool HasNetPending() => File.Exists(NetPendFile);

  static string FwProfileKey(string profile) =>
    profile.Equals("Domain", StringComparison.OrdinalIgnoreCase) ? "DomainProfile"
    : profile.Equals("Private", StringComparison.OrdinalIgnoreCase) ? "StandardProfile"
    : "PublicProfile";

  static int? FwValue(string profile, string name)
  {
    using var k = Registry.LocalMachine.OpenSubKey(FWPOL + FwProfileKey(profile));
    return k?.GetValue(name) is int v ? v : null;
  }

  static bool FwRulesLeft(string group = "DeviceGuardNet")
  {
    using var k = Registry.LocalMachine.OpenSubKey(FWPOL + "FirewallRules");
    if (k == null)
      return false;
    foreach (var n in k.GetValueNames())
      if (
        k.GetValue(n) is string v
        && (
          v.Contains("|EmbedCtxt=" + group + "|", StringComparison.OrdinalIgnoreCase)
          || v.EndsWith("|EmbedCtxt=" + group, StringComparison.OrdinalIgnoreCase)
        )
      )
        return true;
    return false;
  }

  // מצב שירות Windows: null = לא קיים במחשב
  static bool? SvcRunning(string name)
  {
    try
    {
      using var sc = new System.ServiceProcess.ServiceController(name);
      return sc.Status == System.ServiceProcess.ServiceControllerStatus.Running;
    }
    catch (InvalidOperationException)
    {
      return null;
    }
    catch
    {
      return false;
    }
  }

  // true = הפריט שוחרר באמת (אחרי ביצוע חוזר אם צריך). false = עדיין לא – לנסות שוב
  static bool NetRelease(string e)
  {
    var p = e.Split('|');
    switch (p[0])
    {
      case "fwpolicy":
        if (p.Length < 3 || p[2].Equals("Block", StringComparison.OrdinalIgnoreCase))
          return true;
        if (FwValue(p[1], "DefaultOutboundAction") != 1)
          return true;
        PS($"Set-NetFirewallProfile -Profile {p[1]} -DefaultOutboundAction {p[2]}");
        return FwValue(p[1], "DefaultOutboundAction") != 1;
      case "fwenabled":
        if (p.Length < 3 || !p[2].Equals("False", StringComparison.OrdinalIgnoreCase) || FwValue(p[1], "EnableFirewall") == 0)
          return true;
        PS($"Set-NetFirewallProfile -Profile {p[1]} -Enabled False");
        return FwValue(p[1], "EnableFirewall") == 0;
      case "fwrules":
        if (!FwRulesLeft())
          return true;
        PS("Remove-NetFirewallRule -Group 'DeviceGuardNet' -ErrorAction SilentlyContinue");
        return !FwRulesLeft();
      case "wlanfilter":
      {
        // אין דרך אמינה לקרוא את המסננים (הפלט של netsh מתורגם לשפת Windows): מוחקים שוב כשהשירות של ה-Wi-Fi רץ. בלי השירות במחשב – אין Wi-Fi ואין מה לשחרר
        var run = SvcRunning("WlanSvc");
        if (run == null)
          return true;
        if (run == false)
          return false;
        if (p.Length > 1 && p[1] == "denyall")
          for (int i = 0; i < 2; i++)
            Netsh("wlan delete filter permission=denyall networktype=infrastructure");
        else if (p.Length > 2 && p[1] == "allow")
          Netsh($"wlan delete filter permission=allow ssid=\"{string.Join("|", p[2..]).Replace("\"", "")}\" networktype=infrastructure");
        return true;
      }
      case "ruleoff": // כלל היתר שהושבת ברשימה הלבנה: פעיל שוב (או נמחק בינתיים) = שוחרר
      {
        var nm = string.Join("|", p[1..]);
        bool Off()
        {
          using var k = Registry.LocalMachine.OpenSubKey(FWPOL + "FirewallRules");
          return k?.GetValue(nm) is string v && !string.Equals(FwField(v, "Active"), "TRUE", StringComparison.OrdinalIgnoreCase);
        }
        if (p.Length < 2 || !Off())
          return true;
        PSAll(FwRuleCmds("Enable", new List<string> { nm }));
        return !Off();
      }
      case "hostslock":
      {
        var fi = new FileInfo(HostsPath);
        if (!fi.Exists)
          return true;
        var who = p.Length > 1 ? p[1] : null;
        var sec = fi.GetAccessControl();
        if (!HasHostsDeny(sec, who))
          return true;
        sec.RemoveAccessRule(HostsDenyFor(who));
        fi.SetAccessControl(sec);
        return true;
      }
      case "netuser":
        if (!FwRulesLeft(NetUserGroup))
          return true;
        PS($"Remove-NetFirewallRule -Group '{NetUserGroup}' -ErrorAction SilentlyContinue");
        return !FwRulesLeft(NetUserGroup);
    }
    return true;
  }

  static DateTime lastNetPend = DateTime.MinValue;

  // נקרא מהשירות (כל 15 שניות, לא בזמן החלה) ומההסרה (force: בלי המתנה של דקה). פריט שהחסימה הנוכחית שוב מחזיקה (הוחל מחדש) – יורד מהרשימה.
  // מחזיר את מה שעדיין לא שוחרר
  public static List<string> ProcessNetPending(Config c, bool blocking, bool force = false)
  {
    var left = new List<string>();
    lock (NetPendLock)
    {
      try
      {
        if (!File.Exists(NetPendFile))
          return left;
        if (!force && (DateTime.UtcNow - lastNetPend).TotalSeconds < 15)
          return File.ReadAllLines(NetPendFile).Where(l => l.Length > 0).Select(l => l.Split('\t')[0]).ToList();
        lastNetPend = DateTime.UtcNow;
        bool fwOwned,
          netUserOwned,
          wlanOwned;
        HashSet<string> hostsHeld;
        lock (c.Applied)
        {
          fwOwned = blocking && c.Master && c.Applied.Any(x => x == "fwrules" || x.StartsWith("fwcfg|"));
          netUserOwned = blocking && c.Master && c.Applied.Any(x => x.StartsWith("netuser|"));
          wlanOwned = blocking && c.Master && c.Applied.Contains("wlanfilter|denyall");
          hostsHeld = blocking && c.Master ? c.Applied.Where(x => x == "hostslock" || x.StartsWith("hostslock|")).ToHashSet() : new HashSet<string>();
        }
        var keep = new List<string>();
        var now = DateTime.UtcNow.Ticks;
        foreach (var l in File.ReadAllLines(NetPendFile).Where(l => l.Length > 0).Distinct())
        {
          var t = l.Split('\t', 2);
          var e = t[0];
          long at = t.Length > 1 && long.TryParse(t[1], out var v) ? v : 0;
          if (
            (e.StartsWith("fw") && fwOwned)
            || (e.StartsWith("fwenabled|") && netUserOwned) // חומת האש נדרשת גם לחסימת הרשת של חשבון אחד
            || (e.StartsWith("netuser|") && netUserOwned)
            || (e.StartsWith("wlanfilter|") && wlanOwned)
            || hostsHeld.Contains(e)
            || (e.StartsWith("ruleoff|") && blocking && c.Master && FwOffHeld(e[8..])) // הושבת שוב ברשימה לבנה שהוחלה מחדש
          )
            continue; // החסימה הנוכחית מחזיקה אותו (ותבטל אותו בביטול הבא)
          bool ok;
          try
          {
            ok = NetRelease(e);
          }
          catch (Exception __e)
          {
            Diag.Log(__e);
            ok = false;
          }
          if (ok && (force || new TimeSpan(now - at).TotalSeconds >= 60))
            continue;
          keep.Add(l);
          if (!ok)
            left.Add(e);
        }
        if (keep.Count == 0)
          File.Delete(NetPendFile);
        else
          File.WriteAllLines(NetPendFile, keep);
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
    return left;
  }

  // שחזור חסימות שנמחקו מהרישום
  public static List<(string Exe, string Id)> IfeoList(Config c)
  {
    List<string> snap;
    lock (c.Applied)
      snap = c.Applied.Where(x => x.StartsWith("ifeo|")).ToList();
    return snap.Select(x => x.Split('|')).Where(p => p.Length >= 3).Select(p => (p[1], p[2])).ToList();
  }

  public static int Heal(List<(string Exe, string Id)> list)
  {
    int n = 0;
    foreach (var (exe, id) in list)
    {
      var want = GateCmd(id);
      foreach (var v in Views)
      {
        try
        {
          using var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, v);
          using var k = b.CreateSubKey(IFEO + exe);
          if (!want.Equals(k.GetValue("Debugger") as string))
          {
            k.SetValue("Debugger", want);
            n++;
          }
        }
        catch (Exception __e)
        {
          Diag.Log(__e);
        }
      }
    }
    return n;
  }

  // ---- חסימת סיומות (תמונות/שירים/סרטים/סיומות נוספות) בקוד ----
  public static bool IsExt(Config c, Rule r) =>
    ReferenceEquals(r, c.Movies) || ReferenceEquals(r, c.Songs) || ReferenceEquals(r, c.Images) || c.Exts.Contains(r);

  static readonly object ExtLock = new();
  static string OpenMark => System.IO.Path.Combine(Config.Dir, "var", "unlocked.txt");

  // חוקי סיומות שפתוחים כרגע בקוד (בזיכרון): קבצים שלהם משוחררים בכוונה, ולכן לא נועלים אותם שוב כשמזוהה שינוי הרשאות
  static readonly ConcurrentDictionary<string, byte> openIds = new();

  static void Mark(string id, bool add)
  {
    if (add)
      openIds[id] = 0;
    else
      openIds.TryRemove(id, out _);
    try
    {
      var ids = File.Exists(OpenMark) ? File.ReadAllLines(OpenMark).ToList() : new List<string>();
      if (add)
      {
        if (!ids.Contains(id))
          ids.Add(id);
      }
      else
        ids.Remove(id);
      if (ids.Count == 0)
      {
        if (File.Exists(OpenMark))
          File.Delete(OpenMark);
      }
      else
        File.WriteAllLines(OpenMark, ids);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  static List<string> ExtFiles(Config c, Rule r)
  {
    var res = new List<string>();
    var map = ExtMap(c);
    lock (LogLock)
    {
      try
      {
        DrainLog();
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
      if (!File.Exists(WatchLog))
        return res;
      foreach (var l in File.ReadAllLines(WatchLog))
      {
        var i = l.LastIndexOf('|');
        if (i < 0)
          continue;
        if (map.TryGetValue(System.IO.Path.GetExtension(l[..i]).TrimStart('.').ToLowerInvariant(), out var rr) && ReferenceEquals(rr, r))
          res.Add(l);
      }
    }
    return res;
  }

  static void SetLock(string l, bool on)
  {
    var i = l.LastIndexOf('|');
    if (i < 0)
      return;
    try
    {
      var fi = new FileInfo(l[..i]);
      if (!fi.Exists)
        return;
      if (on)
        AclOn(fi, false);
      else
        AclOff(fi, false);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  static void UnlockExt(Config c, Rule r)
  {
    lock (ExtLock)
    {
      Mark(r.Id, true);
      Parallel.ForEach(ExtFiles(c, r), new ParallelOptions { MaxDegreeOfParallelism = Par }, l => SetLock(l, false));
    }
  }

  static void RelockExt(Config c, Rule r)
  {
    List<string> files;
    lock (ExtLock)
    {
      files = ExtFiles(c, r);
      Parallel.ForEach(files, new ParallelOptions { MaxDegreeOfParallelism = Par }, l => SetLock(l, true));
      Mark(r.Id, false);
    }
    // מרוץ: ביטול החסימה רץ בדיוק בזמן הנעילה מחדש (חלון "פתיחה בקוד" נסגר ברגע שהחסימה הסתיימה). הביטול כבר שחרר ומחק את היומן,
    // ואז הנעילה כאן נעלה שוב קבצים שאינם רשומים – והם היו נשארים נעולים. מחכים שהביטול יסתיים, ואם החסימה כבר לא פעילה – משחררים אותם
    if (!InService || files.Count == 0)
      return;
    try
    {
      for (int i = 0; i < 2400 && Applying(); i++)
        Thread.Sleep(250);
      var now = Config.TryLoad();
      var nr = now?.Find(r.Id);
      if (now != null && (nr == null || !nr.On || !IsExt(now, nr) || !Program.Blocking(now)))
        Parallel.ForEach(files, new ParallelOptions { MaxDegreeOfParallelism = Par }, l => SetLock(l, false));
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  // אחרי הפעלה מחדש של השירות: חוקים שנשארו פתוחים (השירות נסגר בזמן שהחלון היה פתוח) ננעלים שוב
  public static void RelockPending(Config c)
  {
    try
    {
      if (!File.Exists(OpenMark))
        return;
      foreach (var id in File.ReadAllLines(OpenMark))
      {
        var r = c.Find(id);
        if (r != null && Program.Blocking(c) && r.On && IsExt(c, r))
        {
          var rr = r;
          Task.Run(() => RelockExt(c, rr));
        }
        else
          Mark(id, false);
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  static void MakeExtLnk(Config c, Rule r)
  {
    try
    {
      var dir = Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory);
      if (string.IsNullOrEmpty(dir))
        return;
      var nm = string.IsNullOrWhiteSpace(r.Name) ? r.Path : r.Name;
      nm = nm.StartsWith("חסימת ") ? "פתיחת " + nm[6..] : "פתיחת " + nm;
      foreach (var ch in System.IO.Path.GetInvalidFileNameChars())
        nm = nm.Replace(ch, '_');
      var lnk = FreeLnk(System.IO.Path.Combine(dir, nm + " (קוד)"));
      if (lnk == null)
        return;
      dynamic sh = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell")!)!;
      dynamic l = sh.CreateShortcut(lnk);
      l.TargetPath = GateExe;
      l.Arguments = "--openext " + r.Id;
      l.IconLocation = GateExe + ",0";
      AddA(c, "lnk|" + lnk); // לפני היצירה (יומן ההחלה). הנתיב פנוי או של קיצור שלנו – ביטול מוחק רק אותו
      l.Save();
      AddFid(c, lnk);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  // הנתיב הנוכחי של פריט שנחסם: אם לא קיים בנתיב המקורי (שם התיקייה או תיקייה מעליה שונה) – לפי המזהה שנרשם בהחלה
  static string CurPath(Config? c, string path)
  {
    try
    {
      if (c == null || File.Exists(path) || Directory.Exists(path))
        return path;
      string? id;
      lock (c.Applied)
        id = c.Applied.Where(x => x.StartsWith("fid|")).Select(x => x.Split('|', 3)).FirstOrDefault(q => q.Length == 3 && q[2].TrimEnd('\\').Equals(path.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))?[1];
      return id != null && Native.PathById(id).Path is { } np ? np : path;
    }
    catch
    {
      return path;
    }
  }

  public static void Unlock(Rule r, Config? c = null)
  {
    if (c != null && IsExt(c, r))
    {
      UnlockExt(c, r);
      return;
    }
    try
    {
      var path = CurPath(c, r.Path);
      if (Directory.Exists(path))
        UnwalkDir(path);
      else
        AclOff(new FileInfo(path), false);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  public static void Relock(Rule r, Config? c = null)
  {
    if (c != null && IsExt(c, r))
    {
      Task.Run(() => RelockExt(c, r));
      return;
    }
    try
    {
      var path = CurPath(c, r.Path);
      if (Directory.Exists(path))
      {
        var subs = ListDirs(path);
        AclOn(new DirectoryInfo(path), true);
        DenySubs(subs);
      }
      else if (File.Exists(path))
        AclOn(new FileInfo(path), false);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  // ---------- שירות ההגנה: התקנה ועדכון ----------
  static void Sc(string a) => RunExe("sc.exe", a);

  static bool ServiceExists() => RunExe2("sc.exe", "query DeviceGuard").Code == 0;

  static bool WaitUp(int sec)
  {
    for (int i = 0; i < sec * 2; i++)
    {
      if (Config.Up())
        return true;
      Thread.Sleep(500);
    }
    return false;
  }

  // מחליף קובץ הפעלה שאולי רץ כרגע (שער שממתין לתוכנה שהפעיל, חלון "פתיחה בקוד", השירות הישן שעוד נסגר). Windows לא מאפשר לדרוס קובץ שרץ,
  // אבל כן לשנות את שמו: אחרי כמה ניסיונות הקובץ הישן מקבל שם זמני (‎.old-…) ונמחק בהזדמנות הבאה. קודם, קובץ תפוס הכשיל את העדכון –
  // אחרי שהשירות הישן כבר הוסר – והחסימות נשארו בלי שירות עד "החל שינויים" נוסף
  static void ReplaceExe(string src, string dest)
  {
    for (int i = 0; ; i++)
    {
      try
      {
        File.Move(src, dest, true);
        return;
      }
      catch (Exception ex) when ((ex is IOException || ex is UnauthorizedAccessException) && i < 20)
      {
        if (i >= 2 && File.Exists(dest))
          try
          {
            File.Move(dest, dest + ".old-" + Guid.NewGuid().ToString("N"));
          }
          catch (Exception __e)
          {
            Diag.Log(__e);
          }
        Thread.Sleep(500);
      }
    }
  }

  // מחיקת קבצי הפעלה ישנים שהוחלפו בזמן שרצו (מה שעדיין רץ – יימחק בפעם הבאה)
  public static void CleanOldExes()
  {
    try
    {
      if (!Directory.Exists(Config.Dir))
        return;
      foreach (var f in Directory.GetFiles(Config.Dir, "*.old-*"))
        try
        {
          File.Delete(f);
        }
        catch (Exception __e)
        {
          Diag.Log(__e);
        }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  static void CopyGate(string wd)
  {
    CleanOldExes();
    var tmp = wd + ".new";
    for (int i = 0; ; i++)
    {
      try
      {
        File.Copy(Environment.ProcessPath!, tmp, true);
        break;
      }
      catch (Exception ex) when ((ex is IOException || ex is UnauthorizedAccessException) && i < 20)
      {
        Thread.Sleep(500);
      }
    }
    ReplaceExe(tmp, wd);
  }

  // שער קל (NativeAOT): מוטמע בתוך הקובץ הראשי ומופרד לדיסק. מטפל במסלול המהיר של כל הפעלה חסומה ופונה לשער המלא רק כשצריך חלון
  static void DeployLightGate()
  {
    try
    {
      using var s = typeof(Enforcer).Assembly.GetManifestResourceStream("DeviceGuardGate.exe");
      if (s == null)
      {
        try
        {
          if (File.Exists(LightGateExe))
            File.Delete(LightGateExe);
        }
        catch (Exception __e)
        {
          Diag.Log(__e);
        }
        return;
      }
      var tmp = LightGateExe + ".new";
      using (var o = File.Create(tmp))
        s.CopyTo(o);
      ReplaceExe(tmp, LightGateExe); // שער קל שממתין לתוכנה שהפעיל – הקובץ שלו תפוס
    }
    catch
    {
      try
      {
        if (File.Exists(LightGateExe))
          File.Delete(LightGateExe);
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    } // כישלון בפריסה → חוזרים לשער המלא (GateCmd בודק אם הקובץ קיים)
  }

  static DateTime lastStart = DateTime.MinValue;

  // מנסה להפעיל את השירות אם הוא מותקן אך לא רץ (מוגבל בקצב, כדי שלא יתקע את הממשק)
  public static bool TryStartService()
  {
    if (Config.Up(300))
      return true;
    if ((DateTime.UtcNow - lastStart).TotalSeconds < 20)
      return false;
    lastStart = DateTime.UtcNow;
    try
    {
      if (!ServiceExists())
        return false;
      Sc("start DeviceGuard");
      return WaitUp(10);
    }
    catch
    {
      return false;
    }
  }

  // התקנה חד-פעמית של שירות מערכת מוגן; אם הוא מגרסה ישנה מעדכנים אותו ב-EnsureService
  static void InstallService()
  {
    Directory.CreateDirectory(Config.Dir);
    var wd = GateExe;
    CopyGate(wd);
    DeployLightGate();
    var ex = RunExe2(
      "sc.exe",
      $"create DeviceGuard binPath= \"\\\"{wd}\\\" --service\" start= auto obj= LocalSystem DisplayName= \"DeviceGuard Protection\""
    );
    if (ex.Code != 0 && !ServiceExists())
      throw new IOException("יצירת שירות ההגנה נכשלה (קוד " + ex.Code + "). ודא שהתוכנה רצה כמנהל.");
    // ספריית החילוץ של .NET (קובץ יחיד) מוגדרת לתיקייה קבועה של השירות, כדי שלא יחולצו קבצים מחדש בכל הפעלה
    try
    {
      var xd = System.IO.Path.Combine(Config.Dir, "var", "net");
      Directory.CreateDirectory(xd);
      using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\DeviceGuard", true);
      k?.SetValue("Environment", new[] { "DOTNET_BUNDLE_EXTRACT_BASE_DIR=" + xd }, RegistryValueKind.MultiString);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    Sc("failure DeviceGuard reset= 0 actions= restart/1000/restart/1000/restart/1000");
    Sc("failureflag DeviceGuard 1");
    Sc("start DeviceGuard");
    for (int i = 0; i < 20 && !Config.Up(); i++)
      Thread.Sleep(500);
    Sc("sdset DeviceGuard D:(A;;GA;;;SY)(A;;CCLCSWRPLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)");
    Config.Token = null;
    if (Program.Code != null)
      Config.Auth(Program.Code); // הטוקן הישן לא תקף אחרי התקנה/עדכון
    ApplyingFlag.Resend();
  }

  // עדכון: ההרשאות של השירות לא מאפשרות עצירה/מחיקה למנהל, ולכן מבקשים מהשירות עצמו (בעזרת טוקן תקף) להסיר את עצמו, ואז מתקינים את הגרסה החדשה
  static void UpdateService()
  {
    var r = Config.Token != null ? Config.Pipe("UNREG|" + Config.Token, 5000) : null;
    if (r != "OK" && Config.Token != null)
      r = Config.Pipe("UNINSTALL|" + Config.Token, 5000); // שירות מגרסה ישנה (שלא מכיר UNREG) מסיר את עצמו דרך הפקודה הישנה
    if (r != "OK")
    {
      Sc("stop DeviceGuard");
      Sc("delete DeviceGuard");
    }
    for (int i = 0; i < 60 && ServiceExists(); i++)
      Thread.Sleep(500);
    if (ServiceExists())
      throw new IOException("לא ניתן היה להסיר את שירות ההגנה הישן לצורך עדכון. הפעל מחדש את המחשב ונסה שוב.");
    foreach (var pr in Process.GetProcessesByName("DeviceGuardWatch"))
    {
      try
      {
        pr.Kill();
        pr.WaitForExit(3000);
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
    Thread.Sleep(1000);
    InstallService();
  }

  // ייתכן שאנטי-וירוס הסיר את קובץ השירות (קובץ לא חתום שמתקין שירות). המנהל לא יכול לעצור/למחוק את השירות (בכוונה), ולכן ההודעה מסבירה איך לשחזר
  static string ServiceDeadMsg =>
    "שירות ההגנה אינו מגיב. הפעל מחדש את המחשב ונסה שוב.\n\n"
    + "אם זה חוזר: ייתכן שתוכנת אנטי-וירוס הסירה את הקובץ " + GateExe + ". שחזר אותו מההסגר (Quarantine) של האנטי-וירוס, "
    + "הוסף החרגה לתיקייה " + Config.Dir + " והפעל מחדש את המחשב.\n"
    + "בינתיים אפשר לבטל את כל החסימות בכפתור 'הסרת שירות ההגנה' (בחלון הגדרות כלליות).";

  // מתקין את השירות אם אינו קיים, ומעדכן אותו אוטומטית אם הוא מגרסה אחרת (הגרסה נקבעת לפי תוכן הקובץ, בלי מספר ידני)
  public static void EnsureService()
  {
    if (!Config.Up())
    {
      if (ServiceExists())
      {
        Sc("start DeviceGuard");
        if (!WaitUp(15))
        {
          Sc("stop DeviceGuard");
          Sc("delete DeviceGuard");
          Thread.Sleep(2000);
          if (ServiceExists())
            throw new IOException(ServiceDeadMsg);
          InstallService();
          return;
        }
      }
      else
      {
        InstallService();
        return;
      }
    }
    if (Config.Pipe("VER", 5000) == Program.Ver)
      return;
    UpdateService();
  }

  // שם פנוי לקיצור הדרך: קיצור קיים של המשתמש באותו שם לא נדרס (בביטול הקיצור שלנו נמחק, ואז גם של המשתמש היה נמחק). null = אין שם פנוי
  // קיצור קיים שמפנה לשער שלנו (נשאר מהחלה קודמת שלא הצליחה למחוק אותו) – נדרס, כדי שלא יישאר יתום
  static string? FreeLnk(string baseNoExt)
  {
    foreach (var cand in new[] { baseNoExt + ".lnk", baseNoExt + " (DeviceGuard).lnk", baseNoExt + " (DeviceGuard 2).lnk" })
      if (!File.Exists(cand) || LnkIsOurs(cand))
        return cand;
    return null;
  }

  static bool LnkIsOurs(string lnk)
  {
    try
    {
      dynamic sh = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell")!)!;
      string t = sh.CreateShortcut(lnk).TargetPath;
      return string.Equals(t, GateExe, StringComparison.OrdinalIgnoreCase);
    }
    catch
    {
      return false;
    }
  }

  // קיצור דרך עם אותו שם, שפותח חלון קוד (הפריט עצמו נעול ומוסתר)
  static void MakeLnk(Config c, Rule r)
  {
    try
    {
      var path = r.Path.TrimEnd('\\');
      var parent = System.IO.Path.GetDirectoryName(path);
      if (parent == null)
        return;
      var lnk = FreeLnk(System.IO.Path.Combine(parent, System.IO.Path.GetFileName(path)));
      if (lnk == null)
        return;
      dynamic sh = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell")!)!;
      dynamic l = sh.CreateShortcut(lnk);
      l.TargetPath = GateExe;
      l.Arguments = "--open " + r.Id;
      l.IconLocation = Directory.Exists(path) ? Environment.SystemDirectory + @"\shell32.dll,3" : path + ",0";
      AddA(c, "lnk|" + lnk); // לפני היצירה (יומן ההחלה)
      l.Save();
      AddFid(c, lnk);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  // ---------- ביטול ----------
  // מזהה NTFS של כל נתיב שנחסם/הוסתר (רשומת fid|מזהה|נתיב). תיקייה חסומה שהשם שלה (או של תיקייה מעליה) שונה בזמן החסימה,
  // או שהועברה באותו כונן, נמצאת בביטול לפי המזהה – ולא נשארת נעולה ומוסתרת לתמיד
  static readonly ConcurrentDictionary<string, string> fids = new(StringComparer.OrdinalIgnoreCase);

  static void AddFid(Config c, string p)
  {
    var id = Native.FileId(p);
    if (id == null)
      return;
    var e = $"fid|{id}|{p}";
    lock (c.Applied)
    {
      if (c.Applied.Contains(e))
        return;
      c.Applied.Add(e);
    }
    JournalAdd(e);
  }

  static void LoadFids(IEnumerable<string> all)
  {
    fids.Clear();
    foreach (var e in all)
      if (e.StartsWith("fid|"))
      {
        var q = e.Split('|', 3);
        if (q.Length == 3)
          fids[q[2]] = q[1];
      }
  }

  // התוצאה: 0 = שוחרר, 1 = לא נמצא כרגע (כונן לא מחובר / לא ניתן לבדוק) – לנסות שוב מאוחר יותר, 2 = הפריט כבר לא קיים
  static int RevertFileCore(string e, string? id)
  {
    var p = e.Split('|');
    var path = p[1];
    bool exists = File.Exists(path) || Directory.Exists(path);
    // יש מזהה: בודקים שזה אותו פריט (אולי הפריט המקורי הועבר ובנתיב הישן נוצר פריט אחר באותו שם)
    if (id != null ? Native.FileId(path) != id : !exists)
    {
      if (id != null)
      {
        var (np, present) = Native.PathById(id);
        if (np == null)
          return present ? 2 : 1;
        if (!np.Equals(path, StringComparison.OrdinalIgnoreCase))
          Alerts.Log($"פריט חסום הועבר או ששמו שונה בזמן החסימה – שוחרר במיקומו החדש: {np}", false);
        path = np;
      }
      else
      {
        // אין מזהה (רשומה מגרסה קודמת): אם הכונן לא מחובר – מנסים שוב כשיחובר; אחרת אין דרך למצוא את הפריט
        var root = System.IO.Path.GetPathRoot(path);
        return string.IsNullOrEmpty(root) || Directory.Exists(root) ? 2 : 1;
      }
    }
    switch (p[0])
    {
      case "acl":
        if (Directory.Exists(path))
          UnwalkDir(path);
        else
          AclOff(new FileInfo(path), false);
        break;
      case "hid":
        File.SetAttributes(path, (FileAttributes)int.Parse(p[2]));
        break;
      case "lnk":
        if (path.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
          File.Delete(path);
        break;
    }
    return 0;
  }

  static void RevertFile(string e)
  {
    var p = e.Split('|');
    fids.TryGetValue(p[1], out var id);
    if (RevertFileCore(e, id) == 1)
      AddPathPending(e, id);
  }

  // ---- שחרורים שממתינים לכונן שלא מחובר כרגע (pathpending.txt: רשומה<TAB>מזהה) ----
  static string PathPendFile => System.IO.Path.Combine(Config.Dir, "var", "pathpending.txt");
  static readonly object PathPendLock = new();

  static void AddPathPending(string e, string? id)
  {
    lock (PathPendLock)
      try
      {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(PathPendFile)!);
        File.AppendAllLines(PathPendFile, new[] { e + "\t" + (id ?? "") });
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
  }

  // נקרא מהשירות (וגם לפני הסרה). פריט שנחסם שוב בינתיים (מופיע במה שהוחל עכשיו) – לא משוחרר
  public static int ProcessPathPending(Config c)
  {
    lock (PathPendLock)
    {
      try
      {
        if (!File.Exists(PathPendFile))
          return 0;
        var lines = File.ReadAllLines(PathPendFile).Where(l => l.Length > 0).Distinct().ToList();
        List<string> cur;
        lock (c.Applied)
          cur = c.Applied.ToList();
        // נתיבים שחסומים עכשיו (לפי הנתיב בלבד, בלי סימון החיזוק): הקובץ הזה נמצא בתיקייה var שמנהלים יכולים לכתוב אליה,
        // ושורה מזויפת לפריט חסום (למשל בלי "|h2") לא תשחרר אותו
        var curPaths = new HashSet<string>(
          cur.Where(x => x.StartsWith("acl|") || x.StartsWith("hid|") || x.StartsWith("lnk|")).Select(x => x.Split('|')[1].TrimEnd('\\')),
          StringComparer.OrdinalIgnoreCase
        );
        var keep = new List<string>();
        int done = 0;
        foreach (var l in lines)
        {
          var t = l.Split('\t', 2);
          var e = t[0];
          var id = t.Length > 1 && t[1].Length > 0 ? t[1] : null;
          var ep = e.Split('|');
          if (ep.Length < 2 || !(ep[0] == "acl" || ep[0] == "hid" || ep[0] == "lnk"))
            continue; // לא רשומה שהתוכנה כותבת לקובץ הזה
          var epath = ep[1].TrimEnd('\\');
          if (
            cur.Contains(e)
            || curPaths.Contains(epath)
            || (InService && ep[0] == "acl" && logged.ContainsKey(epath)) // בשירות: קובץ שנעול עכשיו בחסימת סוגי קבצים – השחרור שלו שייך לביטול של החסימה הזו
            || (id != null && cur.Any(x => x.StartsWith("fid|" + id + "|", StringComparison.Ordinal)))
          )
            continue; // נחסם מחדש בהחלה מאוחרת יותר – הביטול הבא יטפל בו
          try
          {
            var r = RevertFileCore(e, id);
            if (r == 1)
              keep.Add(l);
            else if (r == 0)
              done++;
          }
          catch (Exception __e)
          {
            Diag.Log(__e);
            keep.Add(l);
          }
        }
        if (keep.Count == 0)
          File.Delete(PathPendFile);
        else if (keep.Count != lines.Count)
          File.WriteAllLines(PathPendFile, keep);
        return done;
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
        return 0;
      }
    }
  }

  // משחרר חסימות שהיו בהחלה הקודמת ולא נדרשו מחדש
  static void FinishRevert(Config c)
  {
    var ps = new List<string>();
    var usbBack = prevUsb.Keys.Select(id => "usb|" + id).ToList();
    foreach (var id in prevUsb.Keys)
      ps.Add($"Enable-PnpDevice -InstanceId '{Q(id)}' -Confirm:$false");
    var accs = prevAcl.Keys.ToList();
    var hids = prevHid.Values.ToList();
    prevUsb.Clear();
    prevAcl.Clear();
    prevHid.Clear();
    prevNet.Clear();
    Task? t = ps.Count > 0 ? Task.Run(() => PSAll(ps)) : null;
    try
    {
      var po = new ParallelOptions { MaxDegreeOfParallelism = Par };
      Parallel.ForEach(
        accs,
        po,
        p =>
        {
          try
          {
            RevertFile("acl|" + p);
          }
          catch (Exception __e)
          {
            Diag.Log(__e);
          }
        }
      );
      Parallel.ForEach(
        hids,
        po,
        e =>
        {
          try
          {
            RevertFile(e);
          }
          catch (Exception __e)
          {
            Diag.Log(__e);
          }
        }
      );
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    try
    {
      t?.Wait();
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    // התקני USB שהיו חסומים ונשארו מושבתים (או לא מחוברים כרגע): לניסיון חוזר בשירות, כמו בביטול
    try
    {
      if (usbBack.Count > 0)
        AddDevPending(
          StillDisabled(usbBack)
            .Concat(usbBack.Where(e => Native.DevState(e[4..]) == -1))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList()
        );
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  // soft = קריאה מתוך Apply: מתאמי רשת שעתידים להישאר חסומים לא מופעלים ונחסמים מחדש
  public static void Revert(Config c, bool soft = false)
  {
    // מתאמים ומסנן Wi-Fi נשארים רק אם ההחלה החדשה חוסמת את הרשת לכל המחשב. במעבר לחסימה של חשבון אחד (חומת האש) – הם חוזרים לפעול
    var keepNet = soft && c.Master && c.Net.On && !NetUser(c);
    var keepAd = keepNet ? c.Net.White.Where(w => !w.StartsWith("ssid:")).ToHashSet() : null;
    var ps = new List<string>();
    var enDev = new List<string>(); // מתאמים/התקנים שאמורים לחזור לפעול: נבדק אחרי הביצוע, ומה שלא חזר נשמר לניסיון חוזר
    var pnpPend = new List<string>(); // מתאמי רשת שלא מחוברים כרגע (לפי מזהה התקן)
    // חומת אש, מסנן Wi-Fi ונעילת hosts: נבדקים שוב בשירות אחרי הביטול (netpending.txt). בהחלה מחדש – רק מה שלא יוחל שוב
    var netPend = new List<string>();
    bool keepFw = soft && c.Master && c.NetApps.On,
      keepNetUser = soft && c.Master && c.Net.On && NetUser(c),
      keepFwOn = keepFw || keepNetUser, // חומת האש עצמה נשארת פעילה גם בשביל חסימת הרשת של חשבון אחד
      keepWlan = keepNet,
      keepHosts = soft && c.Master && c.Adv.On && c.AdvOpts.LockHosts;
    List<string> all;
    lock (c.Applied)
      all = c.Applied.ToList();
    LoadFids(all);
    if (soft && c.Master)
    { // חסימות קבצים והתקני USB שכבר קיימות נשארות כמו שהן; FinishRevert ישחרר רק את מה שכבר לא נדרש
      // היקף נעילת הקבצים (כל המשתמשים / רק החשבון שנבחר) השתנה מאז ההחלה הקודמת: קבצים נעולים משתחררים וננעלים מחדש בהיקף החדש
      var prevTo = all.Where(x => x.StartsWith("denyto|")).Select(x => x.Substring(7)).FirstOrDefault() ?? "S-1-1-0";
      bool sameScope = prevTo == DenyTo.Value;
      var rest = new List<string>();
      foreach (var e in all)
      {
        var q = e.Split('|');
        if (q[0] == "usb" && q.Length > 1)
          prevUsb[q[1]] = 0;
        else if (q[0] == "acl" && q.Length > 1 && sameScope && ((q.Length > 2 && q[2] == "h2") == Harden) && !Directory.Exists(q[1]))
          prevAcl[q[1]] = 0;
        else if (q[0] == "hid" && q.Length > 2 && !Directory.Exists(q[1]))
          prevHid[q[1]] = e;
        else
          rest.Add(e);
      }
      all = rest;
    }
    var regs = all.Where(x => x.StartsWith("reg|")).ToList();
    var rkeys = all.Where(x => x.StartsWith("regkey|")).ToList();
    var others = all.Where(x => !(x.StartsWith("reg|") || x.StartsWith("regkey|") || x.StartsWith("acl|") || x.StartsWith("hid|")))
      .OrderBy(x =>
        x.StartsWith("task") ? 0
        : x.StartsWith("ifeoprev|") ? 2 // אחרי מחיקת השער: אחרת הערך המקורי לא הוחזר (השער עוד היה שם), ואז נמחק יחד איתו
        : x.StartsWith("ifeo") ? 1
        : 3
      )
      .ToList();
    foreach (var e in others)
    {
      var p = e.Split('|');
      try
      {
        switch (p[0])
        {
          case "ifeo":
            foreach (var v in Views)
            {
              using var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, v);
              using var parent = b.OpenSubKey(IFEO.TrimEnd('\\'), true);
              if (parent == null)
                continue;
              using (var k = parent.OpenSubKey(p[1], true))
                // רק השער שלנו. ערך של תוכנה אחרת שנכתב בזמן החסימה (למשל Process Explorer שהותקן בינתיים) נשאר
                if (k?.GetValue("Debugger") is string dv && LooksOurGate(dv))
                  k.DeleteValue("Debugger", false);
              using (var k2 = parent.OpenSubKey(p[1]))
              {
                if (k2 != null && k2.ValueCount == 0 && k2.SubKeyCount == 0)
                {
                  k2.Close();
                  parent.DeleteSubKey(p[1], false);
                }
              }
            }
            break;
          case "ifeoprev": // אחרי "ifeo" (מיון): השער כבר נמחק, ומחזירים את הערך המקורי
            if (p.Length >= 4 && int.TryParse(p[2], out var vw))
            {
              using var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, (RegistryView)vw);
              using var k = b.CreateSubKey(IFEO + p[1]);
              if (k.GetValue("Debugger") == null)
                k.SetValue("Debugger", Encoding.UTF8.GetString(Convert.FromBase64String(p[3])));
            }
            break;
          case "netpnp": // netpnp|מזהה|שם: מתאם שלא מחובר עכשיו – השירות ינקה את סימון ההשבתה שלו (כמו בהתקן USB)
            if (p.Length >= 3)
            {
              var nm = string.Join("|", p[2..]);
              if (keepAd != null && !keepAd.Contains(nm))
                break; // נשאר חסום
              if (Native.DevState(p[1]) == -1)
                pnpPend.Add("pnp|" + p[1]);
            }
            break;
          case "net":
            if (keepAd != null && !keepAd.Contains(p[1]))
            {
              prevNet[p[1]] = 0;
              break;
            }
            ps.Add($"Enable-NetAdapter -Name '{Q(p[1])}' -Confirm:$false");
            enDev.Add("net|" + p[1]);
            break;
          case "usb":
            ps.Add($"Enable-PnpDevice -InstanceId '{Q(p[1])}' -Confirm:$false");
            enDev.Add("usb|" + p[1]);
            break;
          case "fwenabled":
            if (p.Length > 2)
            {
              ps.Add($"Set-NetFirewallProfile -Profile {p[1]} -Enabled {p[2]}");
              if (!keepFwOn)
                netPend.Add(e);
            }
            break;
          case "netuser": // חסימת הרשת של חשבון אחד (כלל בחומת האש)
            ps.Add($"Remove-NetFirewallRule -Group '{NetUserGroup}' -ErrorAction SilentlyContinue");
            if (!keepNetUser)
              netPend.Add(e);
            break;
          case "usbstor":
          {
            using var k = Registry.LocalMachine.OpenSubKey(USBSTOR, true);
            k?.SetValue("Start", 3);
            break;
          } // רשומה ישנה (גרסאות קודמות)
          case "lnk":
            RevertFile(e); // קיצור הדרך נמצא גם אם שם התיקייה שמעליו שונה
            break;
          case "task":
            Schtasks("/End /TN DeviceGuardWatch");
            Schtasks("/Delete /TN DeviceGuardWatch /F");
            break;
          case "lsaright": // lsaright|SID|זכות: מחזירים זכות שהוסרה בהקשחה החזקה. נכשל – נשמר לניסיון חוזר בשירות
            if (p.Length >= 3 && !Lsa.Change(p[1], p[2], true))
              AddLsaPending(p[1] + "|" + p[2]);
            break;
          case "hostslock": // hostslock (כל המשתמשים) או hostslock|SID (רק החשבון שנבחר)
          {
            if (!keepHosts)
              netPend.Add(e);
            var fi = new FileInfo(HostsPath);
            if (fi.Exists)
            {
              var sec = fi.GetAccessControl();
              sec.RemoveAccessRule(HostsDenyFor(p.Length > 1 ? p[1] : null));
              fi.SetAccessControl(sec);
            }
            break;
          }
          case "hideui":
          { // רשומה ישנה
            using (
              var k = Registry.LocalMachine.CreateSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL"
              )
            )
              k.SetValue("CheckedValue", 1);
            using (var k = Registry.LocalMachine.OpenSubKey(EXP, true))
              k?.DeleteValue("NoFolderOptions", false);
            using (var k = Registry.CurrentUser.OpenSubKey(EXP, true))
              k?.DeleteValue("NoFolderOptions", false);
            break;
          }
          case "safer":
            Registry.LocalMachine.DeleteSubKeyTree(SAFER, false);
            break; // רשומות ישנות
          case "devrestrict":
            Registry.LocalMachine.DeleteSubKeyTree(DEVREST, false);
            break;
          case "rsd":
            Registry.LocalMachine.DeleteSubKeyTree(RSD, false);
            break;
          case "fwpolicy":
            if (p.Length > 2)
            {
              ps.Add($"Set-NetFirewallProfile -Profile {p[1]} -DefaultOutboundAction {p[2]}");
              if (!keepFw)
                netPend.Add(e);
            }
            break;
          case "fwrules":
            ps.Add("Remove-NetFirewallRule -Group 'DeviceGuardNet' -ErrorAction SilentlyContinue");
            if (!keepFw)
              netPend.Add(e);
            break;
          case "wlanfilter":
            if (!keepWlan)
              netPend.Add(e);
            if (p.Length > 1 && p[1] == "denyall")
              for (int wi = 0; wi < 2; wi++) // פעמיים: אם בכל זאת נוצר עותק כפול, שלא יישאר Wi-Fi חסום אחרי הביטול
                Netsh("wlan delete filter permission=denyall networktype=infrastructure");
            else if (p.Length > 2 && p[1] == "allow")
              Netsh($"wlan delete filter permission=allow ssid=\"{p[2].Replace("\"", "")}\" networktype=infrastructure");
            break;
        }
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
    var regPend = new List<string>(); // ביטולים שלא הצליחו עכשיו (משתמש לא מחובר / שגיאה): נשמרים ומבוצעים מאוחר יותר, ולא הולכים לאיבוד
    foreach (var e in Enumerable.Reverse(regs))
    {
      try
      {
        if (!RevertReg(e))
          regPend.Insert(0, e);
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
        regPend.Insert(0, e);
      }
    } // בסדר הפוך: הערך המקורי ביותר משוחזר אחרון
    // מפתח שנוצר על ידינו נמחק רק אם לא נשארו בו (או מתחתיו) ערכים – כדי לא למחוק ערכים שתוכנה/מדיניות אחרת הוסיפה בינתיים
    foreach (var e in rkeys.OrderByDescending(x => x.Length))
    {
      try
      {
        if (!RevertRegKey(e))
          regPend.Add(e);
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
    AddRegPending(regPend);
    try
    {
      if (File.Exists(NetHealFile))
      {
        // מתאמים שנחסמו אוטומטית: בביטול מלא כולם חוזרים לפעול; בהחלה מחדש – רק מה שנוסף בינתיים לרשימה הלבנה
        var lines = File.ReadAllLines(NetHealFile).Where(n => n.Length > 0).Distinct().ToList();
        var back = keepNet ? lines.Where(n => keepAd!.Contains(n)).ToList() : lines;
        foreach (var n in back)
        {
          ps.Add($"Enable-NetAdapter -Name '{Q(n)}' -Confirm:$false");
          enDev.Add("net|" + n);
        }
        var rest = lines.Except(back).ToList();
        if (rest.Count == 0)
          File.Delete(NetHealFile);
        else if (back.Count > 0)
          File.WriteAllLines(NetHealFile, rest);
        // מתאמים שחוזרים לפעול אבל לא מחוברים עכשיו: לפי מזהה ההתקן (השירות ינקה את סימון ההשבתה)
        if (File.Exists(NetHealPnpFile))
        {
          var pl = File.ReadAllLines(NetHealPnpFile).Where(l => l.Contains('|')).Distinct().ToList();
          var backSet = back.ToHashSet(StringComparer.OrdinalIgnoreCase);
          var done = pl.Where(l => backSet.Contains(l[(l.IndexOf('|') + 1)..])).ToList();
          foreach (var l in done)
          {
            var id = l[..l.IndexOf('|')];
            if (Native.DevState(id) == -1)
              pnpPend.Add("pnp|" + id);
          }
          var keepPl = pl.Except(done).ToList();
          if (keepPl.Count == 0)
            File.Delete(NetHealPnpFile);
          else
            File.WriteAllLines(NetHealPnpFile, keepPl);
        }
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    try
    {
      // התקני USB שנחסמו אוטומטית: בביטול מלא חוזרים לפעול; בהחלה מחדש (USB עדיין חסום) – רק מה שנוסף לרשימה הלבנה
      if (File.Exists(UsbHealFile))
      {
        var lines = File.ReadAllLines(UsbHealFile).Where(n => n.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var keepUsb = soft && c.Master && c.Usb.On && !UsbUser(c); // חסימה של חשבון אחד לא משביתה התקנים: מה שהושבת קודם חוזר לפעול
        var back = keepUsb ? lines.Where(n => c.Usb.White.Contains(n)).ToList() : lines;
        foreach (var n in back)
        {
          ps.Add($"Enable-PnpDevice -InstanceId '{Q(n)}' -Confirm:$false");
          enDev.Add("usb|" + n);
        }
        var rest = lines.Except(back, StringComparer.OrdinalIgnoreCase).ToList();
        if (rest.Count == 0)
          File.Delete(UsbHealFile);
        else if (back.Count > 0)
          File.WriteAllLines(UsbHealFile, rest);
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    try
    {
      // כללי היתר של חומת האש שהושבתו ברשימה הלבנה: חוזרים לפעול. בהחלה מחדש שעדיין עם רשימה לבנה – נשארים מושבתים.
      // נרשמים לבדיקה חוזרת (netpending) לפני מחיקת הקובץ: אם ההפעלה נכשלה, השירות ינסה שוב
      if (!(soft && c.Master && c.NetApps.On && c.NetAppsWhite))
      {
        List<string> names;
        lock (FwOffLock)
          names = File.Exists(FwOffFile) ? File.ReadAllLines(FwOffFile).Where(n => n.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList() : new List<string>();
        if (names.Count > 0)
        {
          AddNetPending(names.Select(n => "ruleoff|" + n).ToList()); // מחוץ לנעילה של הקובץ (סדר נעילות קבוע מול ProcessNetPending)
          ps.AddRange(FwRuleCmds("Enable", names));
          lock (FwOffLock)
            File.Delete(FwOffFile);
        }
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    try
    {
      PSAll(ps);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    AddNetPending(netPend);
    // גם התקני USB שלא מחוברים כרגע: הם לא מופיעים כ"מושבתים", אבל יישארו מושבתים כשיחוברו – השירות ינקה את הסימון שלהם
    AddDevPending(
      StillDisabled(enDev)
        .Concat(enDev.Where(e => e.StartsWith("usb|") && Native.DevState(e[4..]) == -1))
        .Concat(pnpPend)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToList()
    );
    try
    { // שחרור קבצים ותיקיות במקביל (כל נתיב בנפרד, לפי הסדר שבו נחסם)
      Parallel.ForEach(
        all.Where(x => x.StartsWith("acl|") || x.StartsWith("hid|")).GroupBy(x => x.Split('|')[1]),
        new ParallelOptions { MaxDegreeOfParallelism = Par },
        g =>
        {
          foreach (var e in g)
          {
            try
            {
              RevertFile(e);
            }
            catch (Exception __e)
            {
              Diag.Log(__e);
            }
          }
        }
      );
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    if (!(soft && c.Master))
      try
      { // קבצים שנחסמו אוטומטית על ידי שירות הרקע
        ReleaseWatchLogAll();
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    lock (c.Applied)
      c.Applied.Clear();
    if (!soft)
      c.State = 0;
  }
}

// ---------- Wi-Fi: לאיזו רשת מחובר כל כרטיס כרגע (WLAN API – בלי פלט מתורגם של netsh) ----------
static class Wlan
{
  [DllImport("wlanapi.dll")]
  static extern uint WlanOpenHandle(uint ver, IntPtr res, out uint neg, out IntPtr h);

  [DllImport("wlanapi.dll")]
  static extern uint WlanCloseHandle(IntPtr h, IntPtr res);

  [DllImport("wlanapi.dll")]
  static extern uint WlanEnumInterfaces(IntPtr h, IntPtr res, out IntPtr list);

  [DllImport("wlanapi.dll")]
  static extern uint WlanQueryInterface(IntPtr h, ref Guid g, int op, IntPtr res, out int size, out IntPtr data, IntPtr type);

  [DllImport("wlanapi.dll")]
  static extern void WlanFreeMemory(IntPtr p);

  // מזהה הכרטיס -> שם הרשת (SSID) ושם הפרופיל. כרטיס שלא מחובר לא מופיע. אין Wi-Fi במחשב – רשימה ריקה
  public static Dictionary<Guid, (string Ssid, string Profile)> Connected()
  {
    var res = new Dictionary<Guid, (string Ssid, string Profile)>();
    var h = IntPtr.Zero;
    try
    {
      if (WlanOpenHandle(2, IntPtr.Zero, out _, out h) != 0)
        return res;
      if (WlanEnumInterfaces(h, IntPtr.Zero, out var list) != 0)
        return res;
      try
      {
        // WLAN_INTERFACE_INFO_LIST: מספר (4), אינדקס (4), ואז פריטים של 532 בתים: GUID (16), תיאור (512), מצב (4)
        int n = Marshal.ReadInt32(list, 0);
        for (int i = 0; i < n && i < 64; i++)
        {
          var item = list + 8 + i * 532;
          var g = Marshal.PtrToStructure<Guid>(item);
          if (Marshal.ReadInt32(item, 528) != 1) // wlan_interface_state_connected
            continue;
          // wlan_intf_opcode_current_connection: מצב (4), סוג חיבור (4), שם הפרופיל (512), ואז אורך ה-SSID (4) והבתים שלו (32)
          if (WlanQueryInterface(h, ref g, 7, IntPtr.Zero, out var size, out var data, IntPtr.Zero) != 0)
            continue;
          try
          {
            if (size < 556)
              continue;
            var profile = (Marshal.PtrToStringUni(data + 8, 256) ?? "").Split('\0')[0];
            int len = Math.Clamp(Marshal.ReadInt32(data, 520), 0, 32);
            var b = new byte[len];
            Marshal.Copy(data + 524, b, 0, len);
            res[g] = (Encoding.UTF8.GetString(b), profile);
          }
          finally
          {
            WlanFreeMemory(data);
          }
        }
      }
      finally
      {
        WlanFreeMemory(list);
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    finally
    {
      if (h != IntPtr.Zero)
        WlanCloseHandle(h, IntPtr.Zero);
    }
    return res;
  }
}
