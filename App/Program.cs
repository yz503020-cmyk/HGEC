using System.Collections.Concurrent; using System.Diagnostics; using System.IO; using System.IO.Pipes; using System.Management; using System.Security.AccessControl; using System.Security.Principal; using System.Text; using System.Text.Json; using System.Threading; using System.Threading.Tasks; using System.Windows;
namespace DG;
public static class Program {
  public static string? Code;   // קוד הכניסה של התוכנה (בזיכרון בלבד, לאימות מחדש מול השירות)
  static string? ver;
  // גרסת השירות = גיבוב של קובץ ההפעלה. כשמעדכנים את התוכנה, השירות מתעדכן אוטומטית (בלי מספר גרסה ידני)
  public static string Ver {
    get { if (ver == null) { try { using var s = File.OpenRead(Environment.ProcessPath!); ver = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(s))[..16]; } catch { ver = "0"; } } return ver; }
  }

  // ---------- מצב השירות ----------
  static volatile Config cur = new();
  static volatile Dictionary<string, Rule> curMap = new();
  static volatile HashSet<string> killSet = new(StringComparer.OrdinalIgnoreCase);
  static volatile Dictionary<string, string> codeKillMap = new(StringComparer.OrdinalIgnoreCase);
  static readonly ConcurrentDictionary<string, DateTime> tokens = new(), lease = new(), ruleAuth = new();
  static readonly ConcurrentDictionary<int, (string Rule, DateTime Start)> authPid = new();   // תהליכים שאושרו בקוד (או בנו של תהליך מאושר)
  static readonly ConcurrentDictionary<int, string> promptedPid = new();
  static readonly ConcurrentDictionary<int, int> internalPids = new();                       // תהליכים של DeviceGuard עצמו שמריצים כלי מערכת
  static readonly object lk = new();
  static readonly Dictionary<string, (int N, int Level, DateTime Until)> fails = new();
  static int authFails, authLevel; static DateTime authLock = DateTime.MinValue;
  static int applyBusy; static DateTime reconBackoff = DateTime.MinValue;
  static volatile bool overflow;
  static ManagementEventWatcher? pw;
  static readonly Dictionary<string, string[]> alias = new(StringComparer.OrdinalIgnoreCase) { ["calc"] = new[] { "CalculatorApp", "Calculator" }, ["SystemSettings"] = new[] { "SystemSettings" } };

  // האם החסימות אמורות להיות פעילות כרגע (מתג ראשי, פתיחה זמנית, תזמון)
  public static bool Blocking(Config c) => c.Master && c.TempOpenUntil <= DateTime.UtcNow.Ticks && (!c.Sched.On || c.Sched.Active(DateTime.Now));
  public static void InternalAdd(int pid, int d) {
    internalPids.AddOrUpdate(pid, d > 0 ? 1 : 0, (k, v) => Math.Max(0, v + d));
    if (internalPids.TryGetValue(pid, out var v2) && v2 <= 0) internalPids.TryRemove(pid, out _);
  }
  static bool Locked(string key) { lock (lk) return fails.TryGetValue(key, out var f) && DateTime.UtcNow < f.Until; }
  static void Fail(string key, string what) {
    lock (lk) {
      fails.TryGetValue(key, out var f); var n = f.N + 1; var lvl = f.Level; var until = f.Until;
      Alerts.Log("קוד שגוי: " + what, false);
      if (n >= 5) { n = 0; lvl = Math.Min(lvl + 1, 5); until = DateTime.UtcNow.AddSeconds(30 << lvl); Alerts.Log("נעילה זמנית אחרי ניסיונות קוד שגויים: " + what); }
      fails[key] = (n, lvl, until);
    }
  }
  static void Ok(string key) { lock (lk) fails.Remove(key); }
  static bool TokenOk(string t) { if (tokens.TryGetValue(t, out var d) && (DateTime.UtcNow - d).TotalHours < 8) return true; tokens.TryRemove(t, out _); return false; }
  static bool IsAuth(int pid, string rid) => authPid.TryGetValue(pid, out var a) && a.Rule == rid && Native.SameStart(pid, a.Start);
  static bool FromGate(int pid) { var ip = pid > 0 ? Native.ImagePath(pid) : null; return ip != null && string.Equals(System.IO.Path.GetFullPath(ip), System.IO.Path.GetFullPath(Enforcer.GateExe), StringComparison.OrdinalIgnoreCase); }
  static void RegisterAuth(int pid, string rule) { try { using var pr = Process.GetProcessById(pid); authPid[pid] = (rule, pr.StartTime); ruleAuth[rule] = DateTime.UtcNow; } catch { } }
  static string ExtOf(string p) => System.IO.Path.GetExtension(p).TrimStart('.').ToLowerInvariant();

  // ---------- שירות ----------
  class GuardService : System.ServiceProcess.ServiceBase {
    public GuardService() { ServiceName = "DeviceGuard"; }
    protected override void OnStart(string[] a) { new Thread(Watch) { IsBackground = true }.Start(); }
    protected override void OnStop() { Alerts.Log("שירות ההגנה נעצר", false); }
  }
  static void LockDir() {   // תיקיית ההגדרות: רק SYSTEM כותב; מנהלים וקבצי ההפעלה לקריאה. קובץ ההגדרות עצמו נעול גם בפני משתמשים רגילים
    try {
      Directory.CreateDirectory(Config.Dir); Directory.CreateDirectory(System.IO.Path.Combine(Config.Dir, "var"));
      Enforcer.RunExe("icacls", $"\"{Config.Dir}\" /inheritance:r /grant *S-1-5-18:(OI)(CI)F /grant *S-1-5-32-544:(OI)(CI)RX /grant *S-1-5-32-545:(OI)(CI)RX");
      Enforcer.RunExe("icacls", $"\"{System.IO.Path.Combine(Config.Dir, "var")}\" /inheritance:r /grant *S-1-5-18:(OI)(CI)F /grant *S-1-5-32-544:(OI)(CI)F");
      Config.SecureFile(Config.CfgPath); Config.SecureFile(Config.BakPath);
    } catch { }
  }

  // ---------- הפעלה / סגירה אוטומטית (תזמון ופתיחה זמנית) ----------
  static void Reconcile(Config c) {
    if (Interlocked.CompareExchange(ref applyBusy, 0, 0) != 0 || DateTime.UtcNow < reconBackoff) return;
    bool need = Blocking(c), applied = c.State == 1 || c.Applied.Count > 0;
    if (need && !applied && c.AnyOn() && (c.Sched.On || c.TempOpenUntil != 0)) Job(true);
    else if (!need && applied) Job(false);
  }
  static void Job(bool apply) {
    if (Interlocked.Exchange(ref applyBusy, 1) == 1) return;
    Task.Factory.StartNew(() => {
      try {
        var cfg = Config.TryLoad(); if (cfg == null) return;
        Enforcer.SetSkip(cfg);
        if (apply) { cfg.TempOpenUntil = 0; Alerts.Log(cfg.Sched.On ? "תחילת חלון הזמנים: החסימות מופעלות" : "הפתיחה הזמנית הסתיימה: החסימות מופעלות", false); Enforcer.Apply(cfg); }
        else { Alerts.Log("מחוץ לחלון הזמנים: החסימות הוסרו", false); Enforcer.Release(cfg); }
      } catch (Exception x) { Alerts.Log("שגיאה בהפעלה/הסרה אוטומטית: " + x.Message); reconBackoff = DateTime.UtcNow.AddMinutes(2); }
      finally { Interlocked.Exchange(ref applyBusy, 0); }
    }, CancellationToken.None, TaskCreationOptions.None, Enforcer.Sta);
  }

  // ---------- ניטור תהליכים ----------
  static void StartWmi() {
    try {
      pw = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
      pw.EventArrived += (s, e) => { try { var n = (string)e.NewEvent["ProcessName"]; int pid = Convert.ToInt32(e.NewEvent["ProcessID"]); HandleProc(n.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? n[..^4] : n, pid); } catch { } };
      pw.Start();
    } catch { pw = null; }
  }
  static bool OwnerApplies(Config c, int pid) => c.AllUsers || string.IsNullOrEmpty(c.OwnerSid) || string.Equals(Native.ProcSid(pid), c.OwnerSid, StringComparison.OrdinalIgnoreCase);
  static void KillPid(int pid) { try { using var p = Process.GetProcessById(pid); p.Kill(); } catch { } }
  static void HandleProc(string n, int pid) {
    var c = cur; if (!Blocking(c)) return;
    if (killSet.Contains(n)) { if (OwnerApplies(c, pid)) { KillPid(pid); Alerts.Log("נסגרה תוכנה חסומה: " + n, false); } return; }
    if (codeKillMap.TryGetValue(n, out var rid) && !IsAuth(pid, rid) && promptedPid.TryAdd(pid, rid)) {
      int sess = 0; try { using var p = Process.GetProcessById(pid); sess = p.SessionId; } catch { return; }
      // ממתינים רגע: אם התוכנה הופעלה דרך השער, הקוד כבר הוקש והאישור מגיע בעוד מילישניות
      Task.Run(async () => {
        await Task.Delay(2500);
        try { if (IsAuth(pid, rid) || !Native.Alive(pid) || !OwnerApplies(c, pid)) return; UserSession.Launch(Enforcer.GateExe, $"--promptkill {rid} {pid}", sess); } catch { }
      });
    }
  }
  static void Reload(Config c) {
    var blocking = Blocking(c);
    var ks = new HashSet<string>(StringComparer.OrdinalIgnoreCase); var ck = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    void Names(Rule r, bool full) {
      var n = System.IO.Path.GetFileNameWithoutExtension(r.Path); if (n.Length == 0 || Enforcer.IsCritical(n)) return;
      var all = new List<string> { n }; if (alias.TryGetValue(n, out var al)) all.AddRange(al);
      foreach (var x in all) { if (full) ks.Add(x); else ck[x] = r.Id; }
    }
    if (blocking) {
      foreach (var r in c.Programs.Where(r => r.On)) Names(r, r.Mode == Mode.Full);
      if (c.Settings.On && c.Settings.Mode == Mode.Code) ck["SystemSettings"] = c.Settings.Id;   // רשת ביטחון: אפליקציית ההגדרות של Windows לא תמיד נתפסת ב-IFEO
    }
    killSet = ks; codeKillMap = ck;
    curMap = blocking ? Enforcer.ExtMap(c) : new Dictionary<string, Rule>();
    Enforcer.SetSkip(c); Alerts.SetUrl(c.AlertUrl);
  }

  // ---------- הפקודות של ה-Pipe ----------
  static string RuleInfo(string id, string sid) {
    var c = cur; var r = c.Find(id); if (r == null) return "NONE";
    bool applies = Blocking(c) && r.On && (c.AllUsers || string.IsNullOrEmpty(c.OwnerSid) || string.Equals(sid, c.OwnerSid, StringComparison.OrdinalIgnoreCase));
    var kind = c.Paths.Contains(r) ? "path" : Enforcer.IsExt(c, r) ? "ext" : "other";
    return string.Join("|", "OK", r.Name.Replace('|', '/'), (int)r.Mode, r.OwnCode != null ? 1 : 0, applies ? 1 : 0, kind, r.Path ?? "");
  }
  static string Auth(string code) {
    lock (lk) { if (DateTime.UtcNow < authLock) return "LOCK"; }
    if (Config.Check(code, cur.AppCode)) {
      lock (lk) { authFails = 0; authLevel = 0; }
      var t = Guid.NewGuid().ToString("N"); tokens[t] = DateTime.UtcNow; return "TOKEN|" + t;
    }
    lock (lk) {
      Alerts.Log("קוד כניסה שגוי לתוכנה", false);
      if (++authFails >= 5) { authFails = 0; authLevel = Math.Min(authLevel + 1, 5); authLock = DateTime.UtcNow.AddSeconds(30 << authLevel); Alerts.Log("נעילה זמנית אחרי ניסיונות כניסה שגויים לתוכנה"); }
    }
    return "BAD";
  }
  static string Handle(string line, int clientPid) {
    try {
      var p = line.Split('|', 4);
      switch (p[0]) {
        case "HELLO": return "OK";
        case "VER": return Ver;
        case "AUTH": return Auth(string.Join("|", p.Skip(1)));
        case "SAVE": {
            if (p.Length < 3 || !TokenOk(p[1])) return "DENY";
            var json = Encoding.UTF8.GetString(Convert.FromBase64String(p[2]));
            if (json.Length > 8_000_000 || JsonSerializer.Deserialize<Config>(json, Config.O) == null) return "ERR";
            Config.WriteSecure(json); return "OK";
          }
        case "RULE": return RuleInfo(p[1], p.Length > 2 ? string.Join("|", p.Skip(2)) : "");
        case "VERIFY": {
            var c = cur; var r = c.Find(p[1]); if (r == null) return "ERR";
            var k = "r|" + p[1]; if (Locked(k)) return "LOCK";
            if (c.CodeOk(r, string.Join("|", p.Skip(2)))) { Ok(k); return "OK"; }
            Fail(k, r.Name); return "BAD";
          }
        case "OPEN": {
            var c = cur; var r = c.Find(p[1]);
            if (r == null || !r.On || !Blocking(c) || r.Mode != Mode.Code || !(c.Paths.Contains(r) || Enforcer.IsExt(c, r))) return "ERR";
            var k = "r|" + p[1]; if (Locked(k)) return "LOCK";
            if (!c.CodeOk(r, string.Join("|", p.Skip(2)))) { Fail(k, r.Name); return "BAD"; }
            Ok(k); Enforcer.Unlock(r, c); lease[p[1]] = DateTime.UtcNow; Alerts.Log("נפתח בקוד: " + r.Name, false); return "OK";
          }
        case "ISAUTH": {   // ISAUTH|ruleId|parentPid[|SYS]: האם ההפעלה הזו מאושרת בלי קוד (הורה מאושר / הפעלה פנימית של DeviceGuard / שירות מערכת אחרי אישור)
            if (p.Length < 3 || !int.TryParse(p[2], out var pp)) return "NO";
            if (internalPids.ContainsKey(pp) || IsAuth(pp, p[1])) return "OK";
            if (p.Length > 3 && p[3] == "SYS") { var r = cur.Find(p[1]); if (r != null && r.Mode == Mode.Code && ruleAuth.TryGetValue(p[1], out var t) && (DateTime.UtcNow - t).TotalMinutes < 15) return "OK"; }
            return "NO";
          }
        case "INTERNAL": {
            if (p.Length < 4 || !TokenOk(p[1]) || !int.TryParse(p[2], out var ip)) return "DENY";
            InternalAdd(ip, p[3] == "1" ? 1 : -1); return "OK";
          }
        case "AUTHPID": { if (!FromGate(clientPid) || p.Length < 3 || !int.TryParse(p[1], out var ap)) return "DENY"; RegisterAuth(ap, p[2]); return "OK"; }
        case "KILL": {
            if (!FromGate(clientPid) || p.Length < 3 || !int.TryParse(p[1], out var kp)) return "DENY";
            if (promptedPid.TryGetValue(kp, out var rr) && rr == p[2] && !IsAuth(kp, rr)) { KillPid(kp); Alerts.Log("תוכנה חסומה נסגרה (לא הוקש קוד)", false); }
            return "OK";
          }
        case "PING": lease[p[1]] = DateTime.UtcNow; return "OK";
        case "RELOCK": {
            lease.TryRemove(p[1], out _); var c = cur; var r = c.Find(p[1]);
            if (r != null && Blocking(c) && r.On) Enforcer.Relock(r, c); return "OK";
          }
        case "SCAN": return $"{Enforcer.ScanId}|{Enforcer.ScanStartTicks}|{Enforcer.ScanDone}|{Enforcer.ScanTotal}|{(Enforcer.ScanRunning ? 1 : 0)}|{(Enforcer.ScanFinished ? 1 : 0)}|{string.Join(",", Enforcer.NoAclDrives.Keys)}";
        case "UNREG":   // הסרת השירות לצורך עדכון (נקרא מהחלון בעדכון גרסה)
        case "UNINSTALL": {
            if (p.Length < 2 || !TokenOk(p[1])) return "DENY";
            bool full = p[0] == "UNINSTALL"; Alerts.Log(full ? "התוכנה הוסרה" : "השירות מתעדכן");
            var cmd = $"sc sdset DeviceGuard \"D:(A;;GA;;;SY)(A;;GA;;;BA)\" & ping -n 3 127.0.0.1 >nul & sc stop DeviceGuard & sc delete DeviceGuard & icacls \"{Config.Dir}\" /grant *S-1-5-32-544:(OI)(CI)F";
            if (full) cmd += " & reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\DeviceGuard\" /f & reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\DeviceGuard\" /f & ping -n 3 127.0.0.1 >nul & del /f /q \"" + Enforcer.GateExe + "\"";
            Process.Start(new ProcessStartInfo("cmd.exe", "/c " + cmd) { CreateNoWindow = true, UseShellExecute = false }); return "OK";
          }
      }
    } catch { }
    return "ERR";
  }
  static void PipeServer() {
    var ps = new PipeSecurity();
    ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null), PipeAccessRights.ReadWrite, AccessControlType.Allow));
    ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
    ps.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
    while (true) {
      NamedPipeServerStream? st = null;
      try {
        st = NamedPipeServerStreamAcl.Create("DeviceGuard.Unlock", PipeDirection.InOut, 64, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 0, 0, ps);
        st.WaitForConnection(); var s2 = st; st = null; _ = Task.Run(() => Serve(s2));
      } catch { try { st?.Dispose(); } catch { } Thread.Sleep(500); }
    }
  }
  // כל חיבור מוגבל ל-5 שניות קריאה: אי אפשר לתפוס את השרת בחיבור שלא שולח כלום
  static async Task Serve(NamedPipeServerStream st) {
    try {
      using (st) {
        string? l;
        try { using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5)); var rd = new StreamReader(st, new UTF8Encoding(false), false, 4096, true); l = await rd.ReadLineAsync(cts.Token); } catch { return; }
        if (l == null) return;
        int cpid = 0; try { if (Native.GetNamedPipeClientProcessId(st.SafePipeHandle.DangerousGetHandle(), out var u)) cpid = (int)u; } catch { }
        var resp = await Task.Run(() => Handle(l, cpid));
        var wr = new StreamWriter(st, new UTF8Encoding(false)) { AutoFlush = true }; await wr.WriteLineAsync(resp);
      }
    } catch { }
  }

  // ---------- הלולאה הראשית של השירות ----------
  public static void Watch() {
    Config.InService = true; Enforcer.InService = true;
    LockDir(); new Thread(PipeServer) { IsBackground = true }.Start();
    Alerts.Log("שירות ההגנה הופעל", false);
    StartWmi();
    var q = new ConcurrentQueue<(string P, int T, DateTime At)>();
    var fsw = new List<FileSystemWatcher>(); var watched = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    void Add(string p) { if (curMap.ContainsKey(ExtOf(p))) q.Enqueue((p, 0, DateTime.UtcNow.AddSeconds(2))); }
    void Watch1(string root) {
      if (!watched.Add(root)) return;
      try {
        var w = new FileSystemWatcher(root) { IncludeSubdirectories = true, NotifyFilter = NotifyFilters.FileName, InternalBufferSize = 65536 };
        w.Created += (s, e) => Add(e.FullPath); w.Renamed += (s, e) => Add(e.FullPath); w.Error += (s, e) => overflow = true;
        w.EnableRaisingEvents = true; fsw.Add(w);
      } catch { }
    }
    IEnumerable<string> Drives() => DriveInfo.GetDrives().Where(x => (x.DriveType == DriveType.Fixed || x.DriveType == DriveType.Removable) && x.IsReady).Select(x => x.RootDirectory.FullName);
    foreach (var d in Drives()) Watch1(d);

    var stamp = DateTime.MinValue; var c = new Config();
    var ifeo = new List<(string Exe, string Id)>(); var regs = new List<RegWant>();
    var lastScan = DateTime.MinValue; var lastIfeo = DateTime.UtcNow; var lastReg = DateTime.UtcNow; var lastFw = DateTime.UtcNow; var lastAd = DateTime.UtcNow;
    var lastPoll = DateTime.MinValue; var lastRec = DateTime.UtcNow; var lastSweep = DateTime.UtcNow; var lastOverflow = DateTime.MinValue;
    bool pendingDone = false; Task scanTask = Task.CompletedTask; CancellationTokenSource? scanCts = null;
    void StartScan(Dictionary<string, Rule> map, bool release, string? root = null) {
      if (release) scanCts?.Cancel();
      var cts = release || scanCts == null ? (scanCts = new CancellationTokenSource()) : scanCts;
      var prev = scanTask;
      scanTask = Task.Run(() => { try { prev.Wait(); } catch { } try { if (release) Enforcer.ReleaseStale(map); Enforcer.ScanNew(map, cts.Token, root); } catch { } });
    }
    while (true) {
      try {
        try { foreach (var d in Drives()) { if (watched.Contains(d)) continue; Enforcer.ResetDriveCache(); Watch1(d); if (curMap.Count > 0) StartScan(curMap, false, d); } } catch { }
        var ts = File.GetLastWriteTimeUtc(Config.CfgPath);
        if (ts != stamp) {
          var nc = Config.TryLoad();   // null = קריאה נכשלה: נשארים עם ההגדרות הקודמות ומנסים שוב (לא מתאפסים להגדרות ריקות)
          if (nc != null) {
            stamp = ts; c = nc; cur = nc; Reload(nc); var bl = Blocking(nc);
            ifeo = bl ? Enforcer.IfeoList(nc) : new(); regs = bl ? Enforcer.RegWants(nc) : new();
            if (!pendingDone) { pendingDone = true; Enforcer.RelockPending(nc); }
            StartScan(curMap, true); lastScan = DateTime.UtcNow;
          }
        }
        var blocking = Blocking(c); var now = DateTime.UtcNow;
        foreach (var kv in lease.ToArray()) if ((now - kv.Value).TotalSeconds > 15 && lease.TryRemove(kv.Key, out _)) { var lr = c.Find(kv.Key); if (lr != null && blocking && lr.On) Enforcer.Relock(lr, c); }
        if ((now - lastRec).TotalSeconds >= 5) { lastRec = now; Reconcile(c); }
        if (blocking) {
          if ((now - lastPoll).TotalSeconds >= 3 && (killSet.Count > 0 || codeKillMap.Count > 0)) {   // גיבוי לאירועי ה-WMI
            lastPoll = now;
            foreach (var pr in Process.GetProcesses()) { try { HandleProc(pr.ProcessName, pr.Id); } catch { } finally { pr.Dispose(); } }
          }
          for (int n = q.Count; n > 0 && q.TryDequeue(out var it); n--) {
            if (it.At > DateTime.UtcNow) { q.Enqueue(it); continue; }
            if (curMap.TryGetValue(ExtOf(it.P), out var rule) && !Enforcer.BlockNewFile(rule, it.P) && it.T < 5) q.Enqueue((it.P, it.T + 1, DateTime.UtcNow.AddSeconds(3)));
          }
          if (scanTask.IsCompleted && curMap.Count > 0) {
            if (overflow && (now - lastOverflow).TotalMinutes >= 5) { overflow = false; lastOverflow = now; StartScan(curMap, false); lastScan = now; }
            else if ((now - lastScan).TotalMinutes >= 60) { StartScan(curMap, false); lastScan = now; }
          }
          bool quiet = !Enforcer.Applying() && Interlocked.CompareExchange(ref applyBusy, 0, 0) == 0 && (now - stamp).TotalSeconds > 5;
          if (quiet && (now - lastIfeo).TotalSeconds >= 5) { lastIfeo = now; var n = Enforcer.Heal(ifeo); if (n > 0) Alerts.Log($"זוהה שינוי בחסימות תוכנות ({n}) – שוחזר"); }
          if (quiet && (now - lastReg).TotalSeconds >= 10) { lastReg = now; var n = Enforcer.HealReg(regs); if (n > 0) Alerts.Log($"זוהה שינוי במדיניות מערכת ({n}) – שוחזר"); }
          if ((now - lastFw).TotalSeconds >= 30) { lastFw = now; Enforcer.NetHeal(c); }
          if ((now - lastAd).TotalSeconds >= 15) { lastAd = now; Enforcer.NetAdapterHeal(c); }
        } else while (q.TryDequeue(out _)) { }
        if ((now - lastSweep).TotalSeconds >= 30) {
          lastSweep = now;
          foreach (var k in authPid.Keys.ToArray()) if (!Native.Alive(k)) authPid.TryRemove(k, out _);
          foreach (var k in promptedPid.Keys.ToArray()) if (!Native.Alive(k)) promptedPid.TryRemove(k, out _);
          foreach (var k in internalPids.Keys.ToArray()) if (!Native.Alive(k)) internalPids.TryRemove(k, out _);
          foreach (var kv in tokens.ToArray()) if ((now - kv.Value).TotalHours >= 8) tokens.TryRemove(kv.Key, out _);
          foreach (var kv in ruleAuth.ToArray()) if ((now - kv.Value).TotalHours >= 1) ruleAuth.TryRemove(kv.Key, out _);
        }
      } catch { }
      Thread.Sleep(1000);
    }
  }

  // ---------- נקודת כניסה ----------
  static bool IsAdmin() { using var id = WindowsIdentity.GetCurrent(); return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator); }
  [STAThread]
  public static void Main(string[] args) {
    if (args.Contains("--service")) { Config.InService = true; System.ServiceProcess.ServiceBase.Run(new GuardService()); return; }
    if (args.Contains("--watch")) { Watch(); return; }
    if (args.Length >= 2 && args[0] == "--gate") { GateMode.RunGate(args); return; }
    if (args.Length >= 3 && args[0] == "--promptkill") { GateMode.PromptKill(args); return; }
    if (args.Length >= 2 && args[0] == "--open") { GateMode.OpenFlow(args[1]); return; }
    if (args.Length >= 2 && args[0] == "--openext") { GateMode.OpenExt(args[1]); return; }
    if (!IsAdmin()) {
      try { Process.Start(new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true, Verb = "runas" }); } catch { }
      return;
    }
    RunUi();
  }
  static void RunUi() {
    try {
      var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown }; Theme.Apply(app);
      app.DispatcherUnhandledException += (s, e) => { MessageBox.Show(e.Exception.Message, "DeviceGuard"); e.Handled = true; };
      var c = Config.Load();
      bool dirty = false;
      if (c.AppCode == null) {
        var k = MainWin.Ask("הגדר קוד כניסה לתוכנה", true); if (k == null) return;
        Code = k; c.AppCode = Config.Hash(k); dirty = true;
        c.Save(); dirty = false;
      } else {
        while (true) {
          var k = MainWin.Ask("הזן קוד כניסה"); if (k == null) return;
          if (Config.Check(k, c.AppCode)) { Code = k; break; }
          MessageBox.Show("קוד שגוי");
        }
      }
      if (Code != null && Config.Up() && !Config.Auth(Code)) MessageBox.Show("האימות מול שירות ההגנה נכשל (ייתכן שיש נעילה זמנית אחרי ניסיונות שגויים)");
      if (string.IsNullOrEmpty(c.OwnerSid)) { c.OwnerSid = Native.InteractiveUserSid(); c.OwnerUser = Native.AccountName(c.OwnerSid) ?? Environment.UserName; dirty = true; }
      if (!string.Equals(c.UiExe, Environment.ProcessPath, StringComparison.OrdinalIgnoreCase)) { c.UiExe = Environment.ProcessPath; dirty = true; }
      if (!c.Terms) { if (!MainWin.TermsDialog()) return; c.Terms = true; dirty = true; }
      if (dirty) { try { c.Save(); } catch { } }
      var w = new MainWin(c); app.MainWindow = w; app.ShutdownMode = ShutdownMode.OnMainWindowClose; app.Run(w);
    } catch (Exception x) { MessageBox.Show(x.ToString(), "DeviceGuard – שגיאה"); }
  }
}
