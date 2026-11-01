using System.Diagnostics; using System.IO; using System.Security.AccessControl; using System.Security.Principal; using System.Text; using System.Threading; using Microsoft.Win32;
namespace DG;
public static class Enforcer {
  const string IFEO = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\";
  const string EXP = @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";
  const string SAFER = @"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers";
  const string DEVREST = @"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions";
  public static int Blocked, Failed; public static string? LastErr;   // תוצאת החסימה האחרונה (לחיווי בחלון)
  static string GateExe => System.IO.Path.Combine(Config.Dir, "DeviceGuardWatch.exe");
  static void AddA(Config c, string e) { lock (c.Applied) c.Applied.Add(e); }
  static readonly int Par = Math.Min(16, Math.Max(4, Environment.ProcessorCount * 2));
  // חסימות קבצים שכבר קיימות מההחלה הקודמת: לא משחררים ונועלים מחדש, רק מדלגים (מה שלא נדרש יותר משוחרר בסוף)
  static readonly System.Collections.Concurrent.ConcurrentDictionary<string, byte> prevAcl = new(StringComparer.OrdinalIgnoreCase), prevUsb = new();
  static readonly System.Collections.Concurrent.ConcurrentDictionary<string, string> prevHid = new(StringComparer.OrdinalIgnoreCase);
  static readonly string CdT = Config.Dir.TrimEnd('\\'), BdT = AppContext.BaseDirectory.TrimEnd('\\');
  static readonly RegistryView[] Views = { RegistryView.Registry64, RegistryView.Registry32 };

  static string PS(string cmd) {
    var p = Process.Start(new ProcessStartInfo("powershell.exe", "-NoLogo -NoProfile -NonInteractive -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(cmd))) { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true })!;
    var o = p.StandardOutput.ReadToEnd(); p.WaitForExit(); return o;
  }
  static void PSAll(List<string> cmds) { if (cmds.Count > 0) PS(string.Join("\n", cmds)); }
  static void Schtasks(string a) { Process.Start(new ProcessStartInfo("schtasks.exe", a) { CreateNoWindow = true, UseShellExecute = false })!.WaitForExit(); }
  static string[] Lines(string s) => s.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

  public static void Apply(Config c) {
    Harden = c.Harden; Revert(c, true); Blocked = 0; Failed = 0; LastErr = null;
    try {
      if (!c.Master) { FinishRevert(c); c.Save(); return; }
      ApplyCore(c);
      FinishRevert(c);   // משחרר רק מה שכבר לא נדרש
      c.Save();
    } catch { try { FinishRevert(c); } catch { } throw; }
  }
  static void ApplyCore(Config c) {
    EnsureService();
    var self = Environment.ProcessPath ?? "";
    // שאילתות PowerShell רצות במקביל. חסימת סיומות (תמונות/שירים/סרטים) נעשית ברקע בשירות, ולכן ההחלה חוזרת מיד
    Task<string>? netT = c.Net.On ? Task.Run(() => PS("Get-NetAdapter | % { $w = ($_.PhysicalMediaType -like '*802.11*' -or $_.InterfaceDescription -match 'Wireless|Wi-Fi'); $(if ($w) { 'W' } else { 'E' }) + '|' + $_.Status + '|' + $_.Name }")) : null;
    Task<string>? usbT = c.Usb.On ? Task.Run(() => PS("Get-PnpDevice -PresentOnly | ? InstanceId -like 'USBSTOR*' | % { $_.InstanceId + '|' + $_.FriendlyName }")) : null;
    Task<string>? hwT = c.Usb.On && c.Usb.White.Count > 0 ? Task.Run(() => PS("Get-PnpDevice -PresentOnly | ? InstanceId -like 'USBSTOR*' | % { $hw = (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName DEVPKEY_Device_HardwareIds -ErrorAction SilentlyContinue).Data -join ';'; $_.FriendlyName + '|' + $hw }")) : null;
    var netCmds = new List<string>(); var usbCmds = new List<string>();

    // 1) פעולות PowerShell (לפני חסימת powershell עצמו)
    if (c.Net.On) {
      var ssidWhite = c.Net.White.Where(w => w.StartsWith("ssid:")).Select(w => w[5..]).ToList();
      var adapterWhite = c.Net.White.Where(w => !w.StartsWith("ssid:")).ToList();
      // שאילתה אחת לכל המתאמים, וכל הפקודות רצות יחד בהפעלת PowerShell אחת (מהיר בהרבה)
      var nl = Lines(netT!.Result);
      // מתאמי רשת שאינם Wi-Fi (Ethernet וכדומה): נחסמים כולם חוץ מהרשימה הלבנה; מתאם שכבר מושבת לא נוגעים בו שוב
      foreach (var l in nl) { var q = l.Split('|', 3); if (q.Length < 3 || q[0] != "E" || adapterWhite.Contains(q[2])) continue; if (q[1] != "Disabled") netCmds.Add($"Disable-NetAdapter -Name '{q[2]}' -Confirm:$false"); AddA(c, "net|" + q[2]); }
      // Wi-Fi: חסימה לפי שם הרשת (SSID). חוסם את כל הרשתות, כולל כאלה שלא היו זמינות בזמן ההחלה, חוץ מהרשימה הלבנה
      if (nl.Any(l => l.StartsWith("W|"))) {
        netCmds.Add("netsh wlan add filter permission=denyall networktype=infrastructure"); AddA(c, "wlanfilter|denyall");
        foreach (var ssid in ssidWhite) { netCmds.Add($"netsh wlan add filter permission=allow ssid=\"{ssid.Replace("\"", "")}\" networktype=infrastructure"); AddA(c, "wlanfilter|allow|" + ssid); }
      }
    }
    if (c.Usb.On) {
      foreach (var l in Lines(usbT!.Result)) {
        var q = l.Split('|', 2); if (q.Length < 2 || c.Usb.White.Contains(q[1])) continue;
        if (!prevUsb.TryRemove(q[0], out _)) usbCmds.Add($"Disable-PnpDevice -InstanceId '{q[0]}' -Confirm:$false"); AddA(c, "usb|" + q[0]);
      }
      if (c.Usb.White.Count == 0) { using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\USBSTOR", true); k?.SetValue("Start", 4); AddA(c, "usbstor"); }
      // חסימה ברמת המדיניות: חלה גם על התקנים שעדיין לא חוברו למחשב (לא רק מה שמחובר כרגע)
      using (var k = Registry.LocalMachine.CreateSubKey(DEVREST)) {
        k.SetValue("DenyRemovableDevices", 1, RegistryValueKind.DWord); AddA(c, "devrestrict");
        if (c.Usb.White.Count > 0) {
          k.SetValue("AllowDeviceIDs", 1, RegistryValueKind.DWord); k.SetValue("AllowDeviceIDsRetroactive", 1, RegistryValueKind.DWord);
          using var ak = k.CreateSubKey("AllowDeviceIDs"); int ai = 1;
          foreach (var l in Lines(hwT!.Result)) {
            var q = l.Split('|', 2); if (q.Length < 2 || !c.Usb.White.Contains(q[0])) continue;
            foreach (var hw in q[1].Split(';', StringSplitOptions.RemoveEmptyEntries)) ak.SetValue((ai++).ToString(), hw);
          }
        }
      }
    }
    Task.WaitAll(Task.Run(() => PSAll(netCmds)), Task.Run(() => PSAll(usbCmds)));
    // 2) הגדרות מחשב
    var s = c.Settings;
    if (s.On) {
      if (s.Mode == Mode.Code) { Ifeo(c, "control.exe", s); Ifeo(c, "SystemSettings.exe", s); }
      else {
        var h = c.AllUsers ? "HKLM" : "HKCU";
        using var k = (c.AllUsers ? Registry.LocalMachine : Registry.CurrentUser).CreateSubKey(EXP);
        var v = s.White.Count > 0 ? "SettingsPageVisibility" : "NoControlPanel";
        if (s.White.Count > 0) k.SetValue(v, "showonly:" + string.Join(";", s.White)); else k.SetValue(v, 1, RegistryValueKind.DWord);
        AddA(c, $"reg|{h}|{EXP}|{v}");
        if (s.White.Count > 0) Ifeo(c, "control.exe", s);   // עם רשימה לבנה נחסמת רק אפליקציית ההגדרות החדשה, ולכן לוח הבקרה הישן נחסם בנפרד
      }
    }
    if (c.Install.On) Ifeo(c, "msiexec.exe", c.Install);
    // 3) תוכנות
    foreach (var r in c.Programs.Where(r => r.On && File.Exists(r.Path))) {
      var f = System.IO.Path.GetFileName(r.Path);
      if (f.Equals("DeviceGuard.exe", StringComparison.OrdinalIgnoreCase)) continue;
      Ifeo(c, f, r); if (r.Hidden && r.Mode == Mode.Full) Hide(c, r.Path);
    }
    // 4) תוכנות ניידות (Software Restriction Policies: ברירת מחדל = חסום, מותר: מערכת + רשימה לבנה)
    if (c.Portable.On) {
      using var k = Registry.LocalMachine.CreateSubKey(SAFER);
      k.SetValue("DefaultLevel", 0, RegistryValueKind.DWord); k.SetValue("PolicyScope", 0, RegistryValueKind.DWord); k.SetValue("TransparentEnabled", 1, RegistryValueKind.DWord);
      var allow = new List<string> { Environment.GetFolderPath(Environment.SpecialFolder.Windows), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), Config.Dir, AppContext.BaseDirectory };
      allow.AddRange(c.Portable.White);
      foreach (var a in allow) { using var pk = k.CreateSubKey(@"262144\Paths\{" + Guid.NewGuid() + "}"); pk.SetValue("ItemData", a); pk.SetValue("SaferFlags", 0, RegistryValueKind.DWord); }
      AddA(c, "safer");
    }
    // 5) קבצים, תיקיות וסיומות (קבצים לפי סיומת נחסמים ברקע בשירות; כאן נוצר רק קיצור הדרך לפתיחה בקוד)
    foreach (var r in c.Paths.Where(r => r.On)) if (!Protected(r.Path)) { Block(c, r, r.Path); if (r.Mode == Mode.Code) MakeLnk(c, r); }
    foreach (var r in new[] { c.Movies, c.Songs, c.Images }.Concat(c.Exts).Where(r => r.On && r.Mode == Mode.Code)) MakeExtLnk(c, r);
    if (c.Applied.Any(x => x.StartsWith("hid|"))) {   // מונע הצגת קבצים מוסתרים בסייר הקבצים
      try {
        using (var k = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) { k.SetValue("Hidden", 2); k.SetValue("ShowSuperHidden", 0); }
        using (var k = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL")) k.SetValue("CheckedValue", 0);
        using (var k = (c.AllUsers ? Registry.LocalMachine : Registry.CurrentUser).CreateSubKey(EXP)) k.SetValue("NoFolderOptions", 1);
        AddA(c, "hideui");
      } catch { }
    }
  }

  // מגן על התוכנה עצמה: אי אפשר לחסום את תיקיית ההגדרות, את תיקיית ההרצה, תיקייה שמכילה אותן, או קובץ בשם התוכנה בכל מיקום
  static bool Protected(string p) {
    var t = p.TrimEnd('\\'); var cd = CdT; var bd = BdT;
    bool Covers(string a, string b) => a.Equals(b, StringComparison.OrdinalIgnoreCase) || a.StartsWith(b + "\\", StringComparison.OrdinalIgnoreCase) || b.StartsWith(a + "\\", StringComparison.OrdinalIgnoreCase);
    return Covers(t, cd) || Covers(t, bd)
      || System.IO.Path.GetFileName(t).Equals("DeviceGuard.exe", StringComparison.OrdinalIgnoreCase)
      || System.IO.Path.GetFileName(t).Equals("DeviceGuardWatch.exe", StringComparison.OrdinalIgnoreCase);
  }
  static void Ifeo(Config c, string exe, Rule r) {
    if (exe.Equals("DeviceGuard.exe", StringComparison.OrdinalIgnoreCase) || exe.Equals("DeviceGuardWatch.exe", StringComparison.OrdinalIgnoreCase)) return;
    foreach (var v in Views) { using var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, v); using var k = b.CreateSubKey(IFEO + exe); k.SetValue("Debugger", $"\"{GateExe}\" --gate {r.Id}"); }
    AddA(c, "ifeo|" + exe + "|" + r.Id);
  }
  static void Hide(Config c, string p) { try { if (prevHid.TryRemove(p, out var old)) { AddA(c, old); return; } var a = File.GetAttributes(p); File.SetAttributes(p, a | FileAttributes.Hidden | FileAttributes.System); lock (c.Applied) AddA(c, $"hid|{p}|{(int)a}"); } catch { } }
  // חיזוק: כלל OWNER RIGHTS (S-1-3-4) מבטל לבעל הקובץ את הזכות המובנית לשנות הרשאות, כך שמשתמש רגיל לא יכול להסיר את החסימה בעצמו.
  // SYSTEM והמנהלים ממשיכים לשנות הרשאות דרך ההרשאות הרגילות שלהם, ולכן השחרור על ידי השירות או החלון לא נפגע
  public static bool Harden = true;
  static readonly SecurityIdentifier OwnerSid = new("S-1-3-4");
  static FileSystemAccessRule OwnerRule(bool dir) => new(OwnerSid, FileSystemRights.ReadAttributes | FileSystemRights.ReadPermissions | FileSystemRights.Synchronize,
    dir ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit : InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow);
  static void Own(FileSystemSecurity s, bool dir) { if (Harden) s.AddAccessRule(OwnerRule(dir)); }
  static void Unown(FileSystemSecurity s, bool dir) { s.RemoveAccessRule(OwnerRule(dir)); }
  static FileSystemAccessRule Deny(bool dir) => new(new SecurityIdentifier(WellKnownSidType.WorldSid, null),
    FileSystemRights.ReadData | FileSystemRights.ExecuteFile | FileSystemRights.Delete,
    dir ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit : InheritanceFlags.None, PropagationFlags.None, AccessControlType.Deny);
  // ---- חסימת תיקייה כולל כל התיקיות שבתוכה (גם כאלה שלא ירשו את החסימה, למשל כשהירושה בהן כבויה) ----
  static List<string> ListDirs(string root) {   // חייב לרוץ לפני החסימה, כי אחריה אי אפשר לרשום את תוכן התיקייה
    var all = new List<string>();
    void Walk(string d) { string[] subs; try { subs = Directory.GetDirectories(d); } catch { return; } foreach (var x in subs) { try { if ((File.GetAttributes(x) & FileAttributes.ReparsePoint) != 0) continue; } catch { continue; } all.Add(x); Walk(x); } }
    Walk(root); return all;
  }
  static bool HasDeny(string d, bool inherited) {
    try { return new DirectoryInfo(d).GetAccessControl().GetAccessRules(true, inherited, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().Any(x => x.AccessControlType == AccessControlType.Deny && x.IdentityReference.Value == "S-1-1-0" && (x.FileSystemRights & FileSystemRights.ListDirectory) != 0); } catch { return false; }
  }
  static void DenySubs(List<string> subs) {
    Parallel.ForEach(subs, new ParallelOptions { MaxDegreeOfParallelism = Par }, d => { try { if (HasDeny(d, true)) return; var i = new DirectoryInfo(d); var s = i.GetAccessControl(); s.AddAccessRule(Deny(true)); Own(s, true); i.SetAccessControl(s); } catch { } });
  }
  static void UnwalkDir(string d, bool root = true) {   // משחרר מלמעלה למטה: קודם התיקייה עצמה, ואז אפשר לרשום את מה שבתוכה
    try { if (root || HasDeny(d, false)) { var i = new DirectoryInfo(d); var s = i.GetAccessControl(); s.RemoveAccessRule(Deny(true)); Unown(s, true); i.SetAccessControl(s); } } catch { }
    string[] subs; try { subs = Directory.GetDirectories(d); } catch { return; }
    foreach (var x in subs) { try { if ((File.GetAttributes(x) & FileAttributes.ReparsePoint) == 0) UnwalkDir(x, false); } catch { } }
  }
  static void Block(Config c, Rule r, string p) {
    try {
      bool dir = Directory.Exists(p); if (!dir && !File.Exists(p)) return;
      if ((r.Hidden && r.Mode == Mode.Full) || (r.Mode == Mode.Code && c.Paths.Contains(r))) Hide(c, p);
      if (dir) { var subs = ListDirs(p); var i = new DirectoryInfo(p); var s = i.GetAccessControl(); s.AddAccessRule(Deny(true)); Own(s, true); i.SetAccessControl(s); DenySubs(subs); }
      else if (!prevAcl.TryRemove(p, out _)) { var i = new FileInfo(p); var s = i.GetAccessControl(); s.AddAccessRule(Deny(false)); Own(s, false); i.SetAccessControl(s); }
      lock (c.Applied) AddA(c, "acl|" + p + (Harden ? "|h" : "")); Interlocked.Increment(ref Blocked);
    } catch (Exception x) { Interlocked.Increment(ref Failed); LastErr = x.Message; }
  }
  static string WatchLog => System.IO.Path.Combine(Config.Dir, "var", "watched.log");
  static readonly string[] SkipDirs = { "Windows", "Program Files", "Program Files (x86)", "ProgramData", "$Recycle.Bin", "System Volume Information" };
  public static Dictionary<string, Rule> ExtMap(Config c) {
    var map = new Dictionary<string, Rule>();
    void M(Rule r, string[] x) { if (r.On) foreach (var y in x) map[y] = r; }
    M(c.Movies, Config.Vid); M(c.Songs, Config.Aud); M(c.Images, Config.Img);
    foreach (var r in c.Exts.Where(r => r.On)) map[r.Path.TrimStart('.').ToLowerInvariant()] = r;
    return map;
  }
  static readonly object LogLock = new();
  static readonly System.Collections.Concurrent.ConcurrentDictionary<string, byte> known = new(StringComparer.OrdinalIgnoreCase);   // קבצים שכבר נחסמו על ידי השירות (חוסך קריאת הרשאות בכל סריקה)
  static readonly int ParSvc = Math.Max(2, Environment.ProcessorCount / 2);   // השירות רץ ברקע ולכן משתמש בפחות ליבות
  // חוסם קובץ (נקרא משירות הרקע: קבצים חדשים וגם קבצים קיימים). מחזיר false אם צריך לנסות שוב
  public static bool BlockNewFile(Rule r, string p) {
    try {
      if (known.ContainsKey(p)) return true;
      var fi = new FileInfo(p); if (!fi.Exists || Protected(p)) return true;
      var s = fi.GetAccessControl();
      if (s.GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().Any(x => x.AccessControlType == AccessControlType.Deny && x.IdentityReference.Value == "S-1-1-0")) return true;
      var a = File.GetAttributes(p);
      if (r.Hidden && r.Mode == Mode.Full) File.SetAttributes(p, a | FileAttributes.Hidden | FileAttributes.System);
      s.AddAccessRule(Deny(false)); Own(s, false); fi.SetAccessControl(s);
      lock (LogLock) File.AppendAllText(WatchLog, $"{p}|{(int)a}\n");
      known[p] = 0; return true;
    } catch { return false; }
  }
  // סריקה ברקע של כל הכוננים (או כונן אחד): חוסמת קבצים קיימים לפי הסיומות, באותה דרך שבה נחסמים קבצים חדשים
  public static void ScanNew(Dictionary<string, Rule> map, CancellationToken ct = default, string? only = null) {
    var roots = only != null ? new[] { only } : DriveInfo.GetDrives().Where(d => (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable) && d.IsReady).Select(d => d.RootDirectory.FullName).ToArray();
    Parallel.ForEach(roots, new ParallelOptions { MaxDegreeOfParallelism = ParSvc, CancellationToken = ct }, d => ScanN(d, map, ct, 0));
  }
  static void ScanN(string dir, Dictionary<string, Rule> map, CancellationToken ct, int depth) {
    if (ct.IsCancellationRequested) return;
    try {
      foreach (var f in Directory.EnumerateFiles(dir)) { if (ct.IsCancellationRequested) return; if (map.TryGetValue(System.IO.Path.GetExtension(f).TrimStart('.').ToLowerInvariant(), out var r)) BlockNewFile(r, f); }
      var subs = new List<string>();
      foreach (var d in Directory.EnumerateDirectories(dir)) {
        if (SkipDirs.Contains(System.IO.Path.GetFileName(d), StringComparer.OrdinalIgnoreCase)) continue;
        try { if ((File.GetAttributes(d) & FileAttributes.ReparsePoint) != 0) continue; } catch { continue; }
        subs.Add(d);
      }
      if (depth < 2 && subs.Count > 1) Parallel.ForEach(subs, new ParallelOptions { MaxDegreeOfParallelism = ParSvc, CancellationToken = ct }, d => ScanN(d, map, ct, depth + 1));
      else foreach (var d in subs) ScanN(d, map, ct, depth + 1);
    } catch (OperationCanceledException) { } catch { }
  }
  static void UnblockLine(string l) {
    var i = l.LastIndexOf('|'); if (i < 0) return; var p = l[..i];
    try { var fi = new FileInfo(p); if (!fi.Exists) return; var s = fi.GetAccessControl(); s.RemoveAccessRule(Deny(false)); Unown(s, false); fi.SetAccessControl(s); File.SetAttributes(p, (FileAttributes)int.Parse(l[(i + 1)..])); } catch { }
  }
  // משחרר קבצים שנחסמו על ידי השירות ושהסיומת שלהם כבר לא חסומה (נקרא בכל טעינה מחדש של ההגדרות)
  static string HardFlag => System.IO.Path.Combine(Config.Dir, "var", "harden.flag");
  static void SetOwner(string l, bool on) {
    var i = l.LastIndexOf('|'); if (i < 0) return; var p = l[..i];
    try { var fi = new FileInfo(p); if (!fi.Exists) return; var s = fi.GetAccessControl(); if (on) s.AddAccessRule(OwnerRule(false)); else s.RemoveAccessRule(OwnerRule(false)); fi.SetAccessControl(s); } catch { }
  }
  public static void ReleaseStale(Dictionary<string, Rule> map) {
    lock (LogLock) {
      known.Clear();
      var want = Harden ? "1" : "0"; var have = "0";
      try { if (File.Exists(HardFlag)) have = File.ReadAllText(HardFlag).Trim(); } catch { }
      var keep = new List<string>(); var rel = new List<string>();
      if (File.Exists(WatchLog)) foreach (var l in File.ReadAllLines(WatchLog)) {
        var i = l.LastIndexOf('|'); if (i < 0) continue; var p = l[..i];
        if (map.ContainsKey(System.IO.Path.GetExtension(p).TrimStart('.').ToLowerInvariant())) { keep.Add(l); known[p] = 0; } else rel.Add(l);
      }
      var po = new ParallelOptions { MaxDegreeOfParallelism = ParSvc };
      if (rel.Count > 0) { Parallel.ForEach(rel, po, UnblockLine); File.WriteAllLines(WatchLog, keep); }
      if (have != want && keep.Count > 0) Parallel.ForEach(keep, po, l => SetOwner(l, Harden));   // מתג החיזוק שונה: מעדכנים גם קבצים שכבר נחסמו
      try { File.WriteAllText(HardFlag, want); } catch { }
    }
  }
  // שחזור חסימות שנמחקו מהרישום
  public static List<(string Exe, string Id)> IfeoList(Config c) {
    List<string> snap; lock (c.Applied) snap = c.Applied.Where(x => x.StartsWith("ifeo|")).ToList();
    return snap.Select(x => x.Split('|')).Where(p => p.Length >= 3).Select(p => (p[1], p[2])).ToList();
  }
  public static void Heal(Config c) => Heal(IfeoList(c));
  public static void Heal(List<(string Exe, string Id)> list) {
    foreach (var (exe, id) in list) {
      var want = $"\"{GateExe}\" --gate {id}";
      foreach (var v in Views) { try { using var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, v); using var k = b.CreateSubKey(IFEO + exe); if (!want.Equals(k.GetValue("Debugger") as string)) k.SetValue("Debugger", want); } catch { } }
    }
  }
  // פתיחה / נעילה מחדש של פריט בודד (חסימה בקוד)
  // ---- חסימת סיומות (תמונות/שירים/סרטים/סיומות נוספות) בקוד: הקבצים חסומים לגמרי, וקיצור דרך פותח חלון קוד; כל זמן שהחלון פתוח הקבצים משוחררים ---
  public static bool IsExt(Config c, Rule r) => ReferenceEquals(r, c.Movies) || ReferenceEquals(r, c.Songs) || ReferenceEquals(r, c.Images) || c.Exts.Contains(r);
  static readonly object ExtLock = new();
  static string OpenMark => System.IO.Path.Combine(Config.Dir, "var", "unlocked.txt");
  static void Mark(string id, bool add) {
    try {
      var ids = File.Exists(OpenMark) ? File.ReadAllLines(OpenMark).ToList() : new List<string>();
      if (add) { if (!ids.Contains(id)) ids.Add(id); } else ids.Remove(id);
      if (ids.Count == 0) { if (File.Exists(OpenMark)) File.Delete(OpenMark); } else File.WriteAllLines(OpenMark, ids);
    } catch { }
  }
  static List<string> ExtFiles(Config c, Rule r) {   // הקבצים שהשירות חסם עבור החוק הזה
    var res = new List<string>(); var map = ExtMap(c);
    lock (LogLock) {
      if (!File.Exists(WatchLog)) return res;
      foreach (var l in File.ReadAllLines(WatchLog)) {
        var i = l.LastIndexOf('|'); if (i < 0) continue;
        if (map.TryGetValue(System.IO.Path.GetExtension(l[..i]).TrimStart('.').ToLowerInvariant(), out var rr) && ReferenceEquals(rr, r)) res.Add(l);
      }
    }
    return res;
  }
  static void SetLock(string l, bool on) {
    var i = l.LastIndexOf('|'); if (i < 0) return;
    try {
      var fi = new FileInfo(l[..i]); if (!fi.Exists) return; var s = fi.GetAccessControl();
      if (on) { s.AddAccessRule(Deny(false)); Own(s, false); } else { s.RemoveAccessRule(Deny(false)); Unown(s, false); }
      fi.SetAccessControl(s);
    } catch { }
  }
  static void UnlockExt(Config c, Rule r) {
    lock (ExtLock) { Mark(r.Id, true); Parallel.ForEach(ExtFiles(c, r), new ParallelOptions { MaxDegreeOfParallelism = Par }, l => SetLock(l, false)); }
  }
  static void RelockExt(Config c, Rule r) {
    lock (ExtLock) { Parallel.ForEach(ExtFiles(c, r), new ParallelOptions { MaxDegreeOfParallelism = Par }, l => SetLock(l, true)); Mark(r.Id, false); }
  }
  // אחרי הפעלה מחדש של השירות: חוקים שנשארו פתוחים (השירות נסגר בזמן שהחלון היה פתוח) ננעלים שוב
  public static void RelockPending(Config c) {
    try {
      if (!File.Exists(OpenMark)) return;
      foreach (var id in File.ReadAllLines(OpenMark)) {
        var r = c.Find(id);
        if (r != null && c.Master && r.On && IsExt(c, r)) { var rr = r; Task.Run(() => RelockExt(c, rr)); } else Mark(id, false);
      }
    } catch { }
  }
  // קיצור דרך בשולחן העבודה (לכל המשתמשים) שפותח חלון קוד עבור סיומות בחסימה בקוד
  static void MakeExtLnk(Config c, Rule r) {
    try {
      var dir = Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory); if (string.IsNullOrEmpty(dir)) return;
      var nm = string.IsNullOrWhiteSpace(r.Name) ? r.Path : r.Name;
      nm = nm.StartsWith("חסימת ") ? "פתיחת " + nm[6..] : "פתיחת " + nm;
      foreach (var ch in System.IO.Path.GetInvalidFileNameChars()) nm = nm.Replace(ch, '_');
      var lnk = System.IO.Path.Combine(dir, nm + " (קוד).lnk");
      dynamic sh = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell")!)!; dynamic l = sh.CreateShortcut(lnk);
      l.TargetPath = GateExe; l.Arguments = "--openext " + r.Id; l.IconLocation = GateExe + ",0";
      l.Save(); AddA(c, "lnk|" + lnk);
    } catch { }
  }

  public static void Unlock(Rule r, Config? c = null) { if (c != null && IsExt(c, r)) { UnlockExt(c, r); return; } try { if (Directory.Exists(r.Path)) UnwalkDir(r.Path); else { var i = new FileInfo(r.Path); var s = i.GetAccessControl(); s.RemoveAccessRule(Deny(false)); Unown(s, false); i.SetAccessControl(s); } } catch { } }
  public static void Relock(Rule r, Config? c = null) { if (c != null && IsExt(c, r)) { Task.Run(() => RelockExt(c, r)); return; } try { if (Directory.Exists(r.Path)) { var subs = ListDirs(r.Path); var i = new DirectoryInfo(r.Path); var s = i.GetAccessControl(); s.AddAccessRule(Deny(true)); Own(s, true); i.SetAccessControl(s); DenySubs(subs); } else if (File.Exists(r.Path)) { var i = new FileInfo(r.Path); var s = i.GetAccessControl(); s.AddAccessRule(Deny(false)); Own(s, false); i.SetAccessControl(s); } } catch { } }

  static void Sc(string a) { Process.Start(new ProcessStartInfo("sc.exe", a) { CreateNoWindow = true, UseShellExecute = false })!.WaitForExit(); }
  static bool ServiceExists() {
    var p = Process.Start(new ProcessStartInfo("sc.exe", "query DeviceGuard") { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true })!;
    p.StandardOutput.ReadToEnd(); p.WaitForExit(); return p.ExitCode == 0;
  }
  static bool WaitUp(int sec) { for (int i = 0; i < sec * 2; i++) { if (Config.Up()) return true; Thread.Sleep(500); } return false; }
  // עוצר את השירות וסוגר כל תהליך שרץ מ-DeviceGuardWatch.exe (שער, חלון קוד וכו'), כדי לשחרר את הקובץ
  static void StopAndFree() {
    Sc("stop DeviceGuard");
    for (int i = 0; i < 20 && Config.Up(); i++) Thread.Sleep(500);
    foreach (var pr in Process.GetProcessesByName("DeviceGuardWatch")) { try { pr.Kill(); pr.WaitForExit(3000); } catch { } finally { pr.Dispose(); } }
  }
  static void CopyGate(string wd) {
    for (int i = 0; ; i++) {
      try { File.Copy(Environment.ProcessPath!, wd, true); return; }
      catch (IOException) when (i < 10) { Thread.Sleep(500); }
    }
  }
  // התקנה חד-פעמית של שירות מערכת מוגן; אם הוא מגרסה ישנה מעדכנים אותו ב-EnsureService
  static void InstallService() {
    Directory.CreateDirectory(Config.Dir);
    var wd = GateExe; CopyGate(wd);
    Sc($"create DeviceGuard binPath= \"\\\"{wd}\\\" --service\" start= auto obj= LocalSystem DisplayName= \"DeviceGuard Protection\"");
    Sc("failure DeviceGuard reset= 0 actions= restart/1000/restart/1000/restart/1000");
    Sc("start DeviceGuard");
    for (int i = 0; i < 20 && !Config.Up(); i++) Thread.Sleep(500);
    Sc("sdset DeviceGuard D:(A;;GA;;;SY)(A;;CCLCSWRPLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)");
    if (Config.Token == null && Program.Code != null) Config.Auth(Program.Code);
  }
  // מתקין את השירות אם אינו קיים, ומעדכן אותו אוטומטית אם הוא מגרסה ישנה (בלי צורך בפעולה ידנית)
  public static void EnsureService() {
    if (!Config.Up()) {
      // השירות קיים אבל עסוק או כבוי: לא מתקינים מחדש, נותנים לו זמן
      if (ServiceExists()) {
        Sc("start DeviceGuard");
        if (!WaitUp(15)) { StopAndFree(); Sc("delete DeviceGuard"); Thread.Sleep(1000); InstallService(); return; }
      } else { InstallService(); return; }
    }
    if (Config.Pipe("VER", 5000) == "3") return;
    StopAndFree();
    Sc("delete DeviceGuard"); Thread.Sleep(1000);
    InstallService();
  }
  // קיצור דרך עם אותו שם, שפותח חלון קוד (הפריט עצמו נעול ומוסתר)
  static void MakeLnk(Config c, Rule r) {
    try {
      var path = r.Path.TrimEnd('\\'); var parent = System.IO.Path.GetDirectoryName(path); if (parent == null) return;
      var lnk = System.IO.Path.Combine(parent, System.IO.Path.GetFileName(path) + ".lnk");
      dynamic sh = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell")!)!; dynamic l = sh.CreateShortcut(lnk);
      l.TargetPath = GateExe; l.Arguments = "--open " + r.Id;
      l.IconLocation = Directory.Exists(path) ? Environment.SystemDirectory + @"\shell32.dll,3" : path + ",0";
      l.Save(); AddA(c, "lnk|" + lnk);
    } catch { }
  }

  static void RevertFile(string e) {
    var p = e.Split('|');
    if (p[0] == "acl") {
      bool dir = Directory.Exists(p[1]);
      if (dir) UnwalkDir(p[1]);
      else { var i = new FileInfo(p[1]); var s = i.GetAccessControl(); s.RemoveAccessRule(Deny(false)); Unown(s, false); i.SetAccessControl(s); }
    } else File.SetAttributes(p[1], (FileAttributes)int.Parse(p[2]));
  }
  // משחרר חסימות שהיו בהחלה הקודמת ולא נדרשו מחדש
  static void FinishRevert(Config c) {
    var ps = new List<string>(); foreach (var id in prevUsb.Keys) ps.Add($"Enable-PnpDevice -InstanceId '{id}' -Confirm:$false");
    var accs = prevAcl.Keys.ToList(); var hids = prevHid.Values.ToList(); prevUsb.Clear(); prevAcl.Clear(); prevHid.Clear();
    Task? t = ps.Count > 0 ? Task.Run(() => PSAll(ps)) : null;
    try {
      var po = new ParallelOptions { MaxDegreeOfParallelism = Par };
      Parallel.ForEach(accs, po, p => { try { RevertFile("acl|" + p); } catch { } });
      Parallel.ForEach(hids, po, e => { try { RevertFile(e); } catch { } });
    } catch { }
    try { t?.Wait(); } catch { }
  }
  // soft = קריאה מתוך Apply: מתאמי רשת שעתידים להישאר חסומים לא מופעלים ונחסמים מחדש (חוסך ניתוק וחיבור מיותרים)
  public static void Revert(Config c, bool soft = false) {
    var keepAd = soft && c.Master && c.Net.On ? c.Net.White.Where(w => !w.StartsWith("ssid:")).ToHashSet() : null;
    var ps = new List<string>();
    var all = c.Applied.OrderBy(x => x.StartsWith("task") ? 0 : x.StartsWith("ifeo") ? 1 : 2).ToList();
    if (soft && c.Master) {   // חסימות קבצים והתקני USB שכבר קיימות נשארות כמו שהן; FinishRevert ישחרר רק את מה שכבר לא נדרש
      var rest = new List<string>();
      foreach (var e in all) {
        var q = e.Split('|');
        if (q[0] == "usb" && q.Length > 1) prevUsb[q[1]] = 0;
        else if (q[0] == "acl" && q.Length > 1 && ((q.Length > 2 && q[2] == "h") == Harden) && !Directory.Exists(q[1])) prevAcl[q[1]] = 0;   // חסימה שנעשתה במצב חיזוק אחר נשחררת ונחסמת מחדש
        else if (q[0] == "hid" && q.Length > 2 && !Directory.Exists(q[1])) prevHid[q[1]] = e;
        else rest.Add(e);
      }
      all = rest;
    }
    foreach (var e in all) {
      var p = e.Split('|');
      if (p[0] == "acl" || p[0] == "hid") continue;
      try {
        switch (p[0]) {
          case "ifeo": foreach (var v in Views) { using var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, v); using var k = b.OpenSubKey(IFEO + p[1], true); k?.DeleteValue("Debugger", false); } break;
          case "reg": { using var k = (p[1] == "HKLM" ? Registry.LocalMachine : Registry.CurrentUser).OpenSubKey(p[2], true); k?.DeleteValue(p[3], false); break; }
          case "net": if (keepAd != null && !keepAd.Contains(p[1])) break; ps.Add($"Enable-NetAdapter -Name '{p[1]}' -Confirm:$false"); break;
          case "usb": ps.Add($"Enable-PnpDevice -InstanceId '{p[1]}' -Confirm:$false"); break;
          case "usbstor": { using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\USBSTOR", true); k?.SetValue("Start", 3); break; }
          case "lnk": File.Delete(p[1]); break;
          case "task": Schtasks("/End /TN DeviceGuardWatch"); Schtasks("/Delete /TN DeviceGuardWatch /F"); break;
          case "hideui": {
              using (var k = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL")) k.SetValue("CheckedValue", 1);
              using (var k = Registry.LocalMachine.OpenSubKey(EXP, true)) k?.DeleteValue("NoFolderOptions", false);
              using (var k = Registry.CurrentUser.OpenSubKey(EXP, true)) k?.DeleteValue("NoFolderOptions", false);
              break; }
          case "safer": Registry.LocalMachine.DeleteSubKeyTree(SAFER, false); break;
          case "devrestrict": Registry.LocalMachine.DeleteSubKeyTree(DEVREST, false); break;
          case "wlanfilter":
            if (p.Length > 1 && p[1] == "denyall") ps.Add("netsh wlan delete filter permission=denyall networktype=infrastructure");
            else if (p.Length > 2 && p[1] == "allow") ps.Add($"netsh wlan delete filter permission=allow ssid=\"{p[2].Replace("\"", "")}\" networktype=infrastructure");
            break;
        }
      } catch { }
    }
    try { PSAll(ps); } catch { }
    try {   // שחרור קבצים ותיקיות במקביל (כל נתיב בנפרד, לפי הסדר שבו נחסם)
      Parallel.ForEach(all.Where(x => x.StartsWith("acl|") || x.StartsWith("hid|")).GroupBy(x => x.Split('|')[1]), new ParallelOptions { MaxDegreeOfParallelism = Par }, g => { foreach (var e in g) { try { RevertFile(e); } catch { } } });
    } catch { }
    if (!(soft && c.Master)) try {   // קבצים שנחסמו אוטומטית על ידי שירות הרקע (בהחלה רגילה השירות עצמו משחרר מה שכבר לא נדרש)
      lock (LogLock) if (File.Exists(WatchLog)) {
        Parallel.ForEach(File.ReadAllLines(WatchLog), new ParallelOptions { MaxDegreeOfParallelism = Par }, UnblockLine);
        File.Delete(WatchLog);
      }
    } catch { }
    c.Applied.Clear();
  }
}
