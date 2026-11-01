using System.Diagnostics; using System.IO; using System.Security.AccessControl; using System.Security.Principal; using System.Text; using System.Threading; using Microsoft.Win32;
namespace DG;
public static class Enforcer {
  const string IFEO = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\";
  const string EXP = @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";
  const string SAFER = @"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers";
  const string DEVREST = @"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions";
  public static int Blocked, Failed; public static string? LastErr;   // תוצאת החסימה האחרונה (לחיווי בחלון)
  static string GateExe => System.IO.Path.Combine(Config.Dir, "DeviceGuardWatch.exe");
  static readonly RegistryView[] Views = { RegistryView.Registry64, RegistryView.Registry32 };

  static string PS(string cmd) {
    var p = Process.Start(new ProcessStartInfo("powershell.exe", "-NoProfile -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(cmd))) { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true })!;
    var o = p.StandardOutput.ReadToEnd(); p.WaitForExit(); return o;
  }
  static void PSAll(List<string> cmds) { if (cmds.Count > 0) PS(string.Join("\n", cmds)); }
  static void Schtasks(string a) { Process.Start(new ProcessStartInfo("schtasks.exe", a) { CreateNoWindow = true, UseShellExecute = false })!.WaitForExit(); }
  static string[] Lines(string s) => s.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

  public static void Apply(Config c) {
    Revert(c, true); Blocked = 0; Failed = 0; LastErr = null;
    if (!c.Master) { c.Save(); return; }
    EnsureService();
    var self = Environment.ProcessPath ?? "";

    // 1) פעולות PowerShell (לפני חסימת powershell עצמו)
    if (c.Net.On) {
      var ssidWhite = c.Net.White.Where(w => w.StartsWith("ssid:")).Select(w => w[5..]).ToList();
      var adapterWhite = c.Net.White.Where(w => !w.StartsWith("ssid:")).ToList();
      // שאילתה אחת לכל המתאמים, וכל הפקודות רצות יחד בהפעלת PowerShell אחת (מהיר בהרבה)
      var nl = Lines(PS("Get-NetAdapter | % { $w = ($_.PhysicalMediaType -like '*802.11*' -or $_.InterfaceDescription -match 'Wireless|Wi-Fi'); $(if ($w) { 'W' } else { 'E' }) + '|' + $_.Status + '|' + $_.Name }"));
      var netCmds = new List<string>();
      // מתאמי רשת שאינם Wi-Fi (Ethernet וכדומה): נחסמים כולם חוץ מהרשימה הלבנה; מתאם שכבר מושבת לא נוגעים בו שוב
      foreach (var l in nl) { var q = l.Split('|', 3); if (q.Length < 3 || q[0] != "E" || adapterWhite.Contains(q[2])) continue; if (q[1] != "Disabled") netCmds.Add($"Disable-NetAdapter -Name '{q[2]}' -Confirm:$false"); c.Applied.Add("net|" + q[2]); }
      // Wi-Fi: חסימה לפי שם הרשת (SSID). חוסם את כל הרשתות, כולל כאלה שלא היו זמינות בזמן ההחלה, חוץ מהרשימה הלבנה
      if (nl.Any(l => l.StartsWith("W|"))) {
        netCmds.Add("netsh wlan add filter permission=denyall networktype=infrastructure"); c.Applied.Add("wlanfilter|denyall");
        foreach (var ssid in ssidWhite) { netCmds.Add($"netsh wlan add filter permission=allow ssid=\"{ssid.Replace("\"", "")}\" networktype=infrastructure"); c.Applied.Add("wlanfilter|allow|" + ssid); }
      }
      PSAll(netCmds);
    }
    if (c.Usb.On) {
      var usbCmds = new List<string>();
      foreach (var l in Lines(PS("Get-PnpDevice -PresentOnly | ? InstanceId -like 'USBSTOR*' | % { $_.InstanceId + '|' + $_.FriendlyName }"))) {
        var q = l.Split('|', 2); if (q.Length < 2 || c.Usb.White.Contains(q[1])) continue;
        usbCmds.Add($"Disable-PnpDevice -InstanceId '{q[0]}' -Confirm:$false"); c.Applied.Add("usb|" + q[0]);
      }
      PSAll(usbCmds);
      if (c.Usb.White.Count == 0) { using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\USBSTOR", true); k?.SetValue("Start", 4); c.Applied.Add("usbstor"); }
      // חסימה ברמת המדיניות: חלה גם על התקנים שעדיין לא חוברו למחשב (לא רק מה שמחובר כרגע)
      using (var k = Registry.LocalMachine.CreateSubKey(DEVREST)) {
        k.SetValue("DenyRemovableDevices", 1, RegistryValueKind.DWord); c.Applied.Add("devrestrict");
        if (c.Usb.White.Count > 0) {
          k.SetValue("AllowDeviceIDs", 1, RegistryValueKind.DWord); k.SetValue("AllowDeviceIDsRetroactive", 1, RegistryValueKind.DWord);
          using var ak = k.CreateSubKey("AllowDeviceIDs"); int ai = 1;
          foreach (var l in Lines(PS("Get-PnpDevice -PresentOnly | ? InstanceId -like 'USBSTOR*' | % { $hw = (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName DEVPKEY_Device_HardwareIds -ErrorAction SilentlyContinue).Data -join ';'; $_.FriendlyName + '|' + $hw }"))) {
            var q = l.Split('|', 2); if (q.Length < 2 || !c.Usb.White.Contains(q[0])) continue;
            foreach (var hw in q[1].Split(';', StringSplitOptions.RemoveEmptyEntries)) ak.SetValue((ai++).ToString(), hw);
          }
        }
      }
    }
    // 2) הגדרות מחשב
    var s = c.Settings;
    if (s.On) {
      if (s.Mode == Mode.Code) { Ifeo(c, "control.exe", s); Ifeo(c, "SystemSettings.exe", s); }
      else {
        var h = c.AllUsers ? "HKLM" : "HKCU";
        using var k = (c.AllUsers ? Registry.LocalMachine : Registry.CurrentUser).CreateSubKey(EXP);
        var v = s.White.Count > 0 ? "SettingsPageVisibility" : "NoControlPanel";
        if (s.White.Count > 0) k.SetValue(v, "showonly:" + string.Join(";", s.White)); else k.SetValue(v, 1, RegistryValueKind.DWord);
        c.Applied.Add($"reg|{h}|{EXP}|{v}");
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
      c.Applied.Add("safer");
    }
    // 5) קבצים, תיקיות וסיומות
    foreach (var r in c.Paths.Where(r => r.On)) if (!Protected(r.Path)) { Block(c, r, r.Path); if (r.Mode == Mode.Code) MakeLnk(c, r); }
    var map = new Dictionary<string, Rule>();
    void M(Rule r, string[] e) { if (r.On) foreach (var x in e) map[x] = r; }
    M(c.Movies, Config.Vid); M(c.Songs, Config.Aud); M(c.Images, Config.Img);
    foreach (var r in c.Exts.Where(r => r.On)) map[r.Path.TrimStart('.').ToLowerInvariant()] = r;
    if (map.Count > 0) foreach (var d in DriveInfo.GetDrives().Where(d => (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable) && d.IsReady)) ScanRoot(d.RootDirectory.FullName, map, c);
    if (c.Applied.Any(x => x.StartsWith("hid|"))) {   // מונע הצגת קבצים מוסתרים בסייר הקבצים
      try {
        using (var k = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced")) { k.SetValue("Hidden", 2); k.SetValue("ShowSuperHidden", 0); }
        using (var k = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL")) k.SetValue("CheckedValue", 0);
        using (var k = (c.AllUsers ? Registry.LocalMachine : Registry.CurrentUser).CreateSubKey(EXP)) k.SetValue("NoFolderOptions", 1);
        c.Applied.Add("hideui");
      } catch { }
    }
    c.Save();
  }

  // מגן על התוכנה עצמה: אי אפשר לחסום את תיקיית ההגדרות, את תיקיית ההרצה, תיקייה שמכילה אותן, או קובץ בשם התוכנה בכל מיקום
  static bool Protected(string p) {
    var t = p.TrimEnd('\\'); var cd = Config.Dir.TrimEnd('\\'); var bd = AppContext.BaseDirectory.TrimEnd('\\');
    bool Covers(string a, string b) => a.Equals(b, StringComparison.OrdinalIgnoreCase) || a.StartsWith(b + "\\", StringComparison.OrdinalIgnoreCase) || b.StartsWith(a + "\\", StringComparison.OrdinalIgnoreCase);
    return Covers(t, cd) || Covers(t, bd)
      || System.IO.Path.GetFileName(t).Equals("DeviceGuard.exe", StringComparison.OrdinalIgnoreCase)
      || System.IO.Path.GetFileName(t).Equals("DeviceGuardWatch.exe", StringComparison.OrdinalIgnoreCase);
  }
  static void Ifeo(Config c, string exe, Rule r) {
    if (exe.Equals("DeviceGuard.exe", StringComparison.OrdinalIgnoreCase) || exe.Equals("DeviceGuardWatch.exe", StringComparison.OrdinalIgnoreCase)) return;
    foreach (var v in Views) { using var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, v); using var k = b.CreateSubKey(IFEO + exe); k.SetValue("Debugger", $"\"{GateExe}\" --gate {r.Id}"); }
    c.Applied.Add("ifeo|" + exe + "|" + r.Id);
  }
  static void Hide(Config c, string p) { try { var a = File.GetAttributes(p); File.SetAttributes(p, a | FileAttributes.Hidden | FileAttributes.System); lock (c.Applied) c.Applied.Add($"hid|{p}|{(int)a}"); } catch { } }
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
    Parallel.ForEach(subs, new ParallelOptions { MaxDegreeOfParallelism = 8 }, d => { try { if (HasDeny(d, true)) return; var i = new DirectoryInfo(d); var s = i.GetAccessControl(); s.AddAccessRule(Deny(true)); i.SetAccessControl(s); } catch { } });
  }
  static void UnwalkDir(string d, bool root = true) {   // משחרר מלמעלה למטה: קודם התיקייה עצמה, ואז אפשר לרשום את מה שבתוכה
    try { if (root || HasDeny(d, false)) { var i = new DirectoryInfo(d); var s = i.GetAccessControl(); s.RemoveAccessRule(Deny(true)); i.SetAccessControl(s); } } catch { }
    string[] subs; try { subs = Directory.GetDirectories(d); } catch { return; }
    foreach (var x in subs) { try { if ((File.GetAttributes(x) & FileAttributes.ReparsePoint) == 0) UnwalkDir(x, false); } catch { } }
  }
  static void Block(Config c, Rule r, string p) {
    try {
      bool dir = Directory.Exists(p); if (!dir && !File.Exists(p)) return;
      if ((r.Hidden && r.Mode == Mode.Full) || (r.Mode == Mode.Code && c.Paths.Contains(r))) Hide(c, p);
      if (dir) { var subs = ListDirs(p); var i = new DirectoryInfo(p); var s = i.GetAccessControl(); s.AddAccessRule(Deny(true)); i.SetAccessControl(s); DenySubs(subs); }
      else { var i = new FileInfo(p); var s = i.GetAccessControl(); s.AddAccessRule(Deny(false)); i.SetAccessControl(s); }
      lock (c.Applied) c.Applied.Add("acl|" + p); Interlocked.Increment(ref Blocked);
    } catch (Exception x) { Interlocked.Increment(ref Failed); LastErr = x.Message; }
  }
  static void Scan(string dir, Dictionary<string, Rule> map, Config c) {
    try {
      foreach (var f in Directory.EnumerateFiles(dir))
        if (map.TryGetValue(System.IO.Path.GetExtension(f).TrimStart('.').ToLowerInvariant(), out var r) && !Protected(f)) Block(c, r, f);
      foreach (var d in Directory.EnumerateDirectories(dir)) {
        var n = System.IO.Path.GetFileName(d);
        if (new[] { "Windows", "Program Files", "Program Files (x86)", "ProgramData", "$Recycle.Bin", "System Volume Information" }.Contains(n, StringComparer.OrdinalIgnoreCase)) continue;
        if ((File.GetAttributes(d) & FileAttributes.ReparsePoint) != 0) continue;
        Scan(d, map, c);
      }
    } catch { }
  }

  // סריקה מקבילית של תיקיות הדיסק (מהירה בהרבה מסריקה רציפה)
  static void ScanRoot(string dir, Dictionary<string, Rule> map, Config c) {
    try {
      foreach (var f in Directory.EnumerateFiles(dir))
        if (map.TryGetValue(System.IO.Path.GetExtension(f).TrimStart('.').ToLowerInvariant(), out var r) && !Protected(f)) Block(c, r, f);
      bool Ok(string d) { try { return !SkipDirs.Contains(System.IO.Path.GetFileName(d), StringComparer.OrdinalIgnoreCase) && (File.GetAttributes(d) & FileAttributes.ReparsePoint) == 0; } catch { return false; } }
      var subs = Directory.EnumerateDirectories(dir).Where(Ok).ToList();
      Parallel.ForEach(subs, new ParallelOptions { MaxDegreeOfParallelism = 8 }, d => Scan(d, map, c));
    } catch { }
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
  // חוסם קובץ חדש (נקרא משירות הרקע). מחזיר false אם צריך לנסות שוב
  public static bool BlockNewFile(Rule r, string p) {
    try {
      var fi = new FileInfo(p); if (!fi.Exists || Protected(p)) return true;
      var s = fi.GetAccessControl();
      if (s.GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().Any(x => x.AccessControlType == AccessControlType.Deny && x.IdentityReference.Value == "S-1-1-0")) return true;
      var a = File.GetAttributes(p);
      if (r.Hidden && r.Mode == Mode.Full) File.SetAttributes(p, a | FileAttributes.Hidden | FileAttributes.System);
      s.AddAccessRule(Deny(false)); fi.SetAccessControl(s);
      File.AppendAllText(WatchLog, $"{p}|{(int)a}\n"); return true;
    } catch { return false; }
  }
  public static void ScanNew(Dictionary<string, Rule> map) { foreach (var d in DriveInfo.GetDrives().Where(d => (d.DriveType == DriveType.Fixed || d.DriveType == DriveType.Removable) && d.IsReady)) ScanN(d.RootDirectory.FullName, map); }
  static void ScanN(string dir, Dictionary<string, Rule> map) {
    try {
      foreach (var f in Directory.EnumerateFiles(dir)) if (map.TryGetValue(System.IO.Path.GetExtension(f).TrimStart('.').ToLowerInvariant(), out var r)) BlockNewFile(r, f);
      foreach (var d in Directory.EnumerateDirectories(dir)) {
        if (SkipDirs.Contains(System.IO.Path.GetFileName(d), StringComparer.OrdinalIgnoreCase) || (File.GetAttributes(d) & FileAttributes.ReparsePoint) != 0) continue;
        ScanN(d, map);
      }
    } catch { }
  }
  // שחזור חסימות שנמחקו מהרישום
  public static void Heal(Config c) {
    foreach (var en in c.Applied.Where(x => x.StartsWith("ifeo|"))) {
      var p = en.Split('|'); if (p.Length < 3) continue; var want = $"\"{GateExe}\" --gate {p[2]}";
      foreach (var v in Views) { try { using var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, v); using var k = b.CreateSubKey(IFEO + p[1]); if (!want.Equals(k.GetValue("Debugger") as string)) k.SetValue("Debugger", want); } catch { } }
    }
  }
  // פתיחה / נעילה מחדש של פריט בודד (חסימה בקוד)
  public static void Unlock(Rule r) { try { if (Directory.Exists(r.Path)) UnwalkDir(r.Path); else { var i = new FileInfo(r.Path); var s = i.GetAccessControl(); s.RemoveAccessRule(Deny(false)); i.SetAccessControl(s); } } catch { } }
  public static void Relock(Rule r) { try { if (Directory.Exists(r.Path)) { var subs = ListDirs(r.Path); var i = new DirectoryInfo(r.Path); var s = i.GetAccessControl(); s.AddAccessRule(Deny(true)); i.SetAccessControl(s); DenySubs(subs); } else if (File.Exists(r.Path)) { var i = new FileInfo(r.Path); var s = i.GetAccessControl(); s.AddAccessRule(Deny(false)); i.SetAccessControl(s); } } catch { } }

  static void Sc(string a) { Process.Start(new ProcessStartInfo("sc.exe", a) { CreateNoWindow = true, UseShellExecute = false })!.WaitForExit(); }
  // התקנה חד-פעמית של שירות מערכת מוגן; בהמשך הוא רק מקבל עדכון של Gate.exe
  static void InstallService() {
    Directory.CreateDirectory(Config.Dir);
    var wd = GateExe; File.Copy(Environment.ProcessPath!, wd, true);
    Sc($"create DeviceGuard binPath= \"\\\"{wd}\\\" --service\" start= auto obj= LocalSystem DisplayName= \"DeviceGuard Protection\"");
    Sc("failure DeviceGuard reset= 0 actions= restart/1000/restart/1000/restart/1000");
    Sc("start DeviceGuard");
    for (int i = 0; i < 20 && !Config.Up(); i++) Thread.Sleep(500);
    Sc("sdset DeviceGuard D:(A;;GA;;;SY)(A;;CCLCSWRPLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)");
    if (Config.Token == null && Program.Code != null) Config.Auth(Program.Code);
  }
  // מתקין את השירות אם אינו קיים, ומעדכן אותו אוטומטית אם הוא מגרסה ישנה (בלי צורך בפעולה ידנית)
  public static void EnsureService() {
    if (!Config.Up()) { InstallService(); return; }
    if (Config.Pipe("VER") == "3") return;
    Sc("stop DeviceGuard"); for (int i = 0; i < 10 && Config.Up(); i++) Thread.Sleep(500);
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
      l.Save(); c.Applied.Add("lnk|" + lnk);
    } catch { }
  }

  static void RevertFile(string e) {
    var p = e.Split('|');
    if (p[0] == "acl") {
      bool dir = Directory.Exists(p[1]);
      if (dir) UnwalkDir(p[1]);
      else { var i = new FileInfo(p[1]); var s = i.GetAccessControl(); s.RemoveAccessRule(Deny(false)); i.SetAccessControl(s); }
    } else File.SetAttributes(p[1], (FileAttributes)int.Parse(p[2]));
  }
  // soft = קריאה מתוך Apply: מתאמי רשת שעתידים להישאר חסומים לא מופעלים ונחסמים מחדש (חוסך ניתוק וחיבור מיותרים)
  public static void Revert(Config c, bool soft = false) {
    var keepAd = soft && c.Master && c.Net.On ? c.Net.White.Where(w => !w.StartsWith("ssid:")).ToHashSet() : null;
    var ps = new List<string>();
    var all = c.Applied.OrderBy(x => x.StartsWith("task") ? 0 : x.StartsWith("ifeo") ? 1 : 2).ToList();
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
      Parallel.ForEach(all.Where(x => x.StartsWith("acl|") || x.StartsWith("hid|")).GroupBy(x => x.Split('|')[1]), new ParallelOptions { MaxDegreeOfParallelism = 8 }, g => { foreach (var e in g) { try { RevertFile(e); } catch { } } });
    } catch { }
    try {   // קבצים שנחסמו אוטומטית על ידי שירות הרקע
      if (File.Exists(WatchLog)) {
        Parallel.ForEach(File.ReadAllLines(WatchLog), new ParallelOptions { MaxDegreeOfParallelism = 8 }, l => {
          var i = l.LastIndexOf('|'); if (i < 0) return; var p = l[..i];
          try { var fi = new FileInfo(p); if (!fi.Exists) return; var s = fi.GetAccessControl(); s.RemoveAccessRule(Deny(false)); fi.SetAccessControl(s); File.SetAttributes(p, (FileAttributes)int.Parse(l[(i + 1)..])); } catch { }
        });
        File.Delete(WatchLog);
      }
    } catch { }
    c.Applied.Clear();
  }
}
