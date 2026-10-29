using System.Diagnostics; using System.IO; using System.Security.AccessControl; using System.Security.Principal; using System.Text; using Microsoft.Win32;
namespace DG;
public static class Enforcer {
  const string IFEO = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\";
  const string EXP = @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";
  const string SAFER = @"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers";
  static string GateExe => System.IO.Path.Combine(Config.Dir, "Gate.exe");
  static readonly RegistryView[] Views = { RegistryView.Registry64, RegistryView.Registry32 };

  static string PS(string cmd) {
    var p = Process.Start(new ProcessStartInfo("powershell.exe", "-NoProfile -EncodedCommand " + Convert.ToBase64String(Encoding.Unicode.GetBytes(cmd))) { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true })!;
    var o = p.StandardOutput.ReadToEnd(); p.WaitForExit(); return o;
  }
  static void Schtasks(string a) { Process.Start(new ProcessStartInfo("schtasks.exe", a) { CreateNoWindow = true, UseShellExecute = false })!.WaitForExit(); }
  static string[] Lines(string s) => s.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

  public static void Apply(Config c) {
    Revert(c);
    if (!c.Master) { c.Save(); return; }
    EnsureService();
    var self = Environment.ProcessPath ?? "";

    // 1) פעולות PowerShell (לפני חסימת powershell עצמו)
    if (c.Net.On)
      foreach (var n in Lines(PS("(Get-NetAdapter | ? Status -eq 'Up').Name")).Where(n => !c.Net.White.Contains(n))) {
        PS($"Disable-NetAdapter -Name '{n}' -Confirm:$false"); c.Applied.Add("net|" + n);
      }
    if (c.Usb.On) {
      foreach (var l in Lines(PS("Get-PnpDevice -PresentOnly | ? InstanceId -like 'USBSTOR*' | % { $_.InstanceId + '|' + $_.FriendlyName }"))) {
        var q = l.Split('|', 2); if (q.Length < 2 || c.Usb.White.Contains(q[1])) continue;
        PS($"Disable-PnpDevice -InstanceId '{q[0]}' -Confirm:$false"); c.Applied.Add("usb|" + q[0]);
      }
      if (c.Usb.White.Count == 0) { using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\USBSTOR", true); k?.SetValue("Start", 4); c.Applied.Add("usbstor"); }
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
    if (map.Count > 0) foreach (var d in DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady)) Scan(d.RootDirectory.FullName, map, c);
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

  static bool Protected(string p) => p.StartsWith(Config.Dir, StringComparison.OrdinalIgnoreCase) || p.StartsWith(AppContext.BaseDirectory, StringComparison.OrdinalIgnoreCase);
  static void Ifeo(Config c, string exe, Rule r) {
    if (exe.Equals("DeviceGuard.exe", StringComparison.OrdinalIgnoreCase) || exe.Equals("Gate.exe", StringComparison.OrdinalIgnoreCase)) return;
    foreach (var v in Views) { using var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, v); using var k = b.CreateSubKey(IFEO + exe); k.SetValue("Debugger", $"\"{GateExe}\" {r.Id}"); }
    c.Applied.Add("ifeo|" + exe + "|" + r.Id);
  }
  static void Hide(Config c, string p) { try { var a = File.GetAttributes(p); File.SetAttributes(p, a | FileAttributes.Hidden | FileAttributes.System); c.Applied.Add($"hid|{p}|{(int)a}"); } catch { } }
  static FileSystemAccessRule Deny(bool dir) => new(new SecurityIdentifier(WellKnownSidType.WorldSid, null),
    FileSystemRights.ReadData | FileSystemRights.ExecuteFile | FileSystemRights.Delete,
    dir ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit : InheritanceFlags.None, PropagationFlags.None, AccessControlType.Deny);
  static void Block(Config c, Rule r, string p) {
    try {
      bool dir = Directory.Exists(p); if (!dir && !File.Exists(p)) return;
      if ((r.Hidden && r.Mode == Mode.Full) || (r.Mode == Mode.Code && c.Paths.Contains(r))) Hide(c, p);
      if (dir) { var i = new DirectoryInfo(p); var s = i.GetAccessControl(); s.AddAccessRule(Deny(true)); i.SetAccessControl(s); }
      else { var i = new FileInfo(p); var s = i.GetAccessControl(); s.AddAccessRule(Deny(false)); i.SetAccessControl(s); }
      c.Applied.Add("acl|" + p);
    } catch { }
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
  public static void ScanNew(Dictionary<string, Rule> map) { foreach (var d in DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady)) ScanN(d.RootDirectory.FullName, map); }
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
      var p = en.Split('|'); if (p.Length < 3) continue; var want = $"\"{GateExe}\" {p[2]}";
      foreach (var v in Views) { try { using var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, v); using var k = b.CreateSubKey(IFEO + p[1]); if (!want.Equals(k.GetValue("Debugger") as string)) k.SetValue("Debugger", want); } catch { } }
    }
  }
  // פתיחה / נעילה מחדש של פריט בודד (חסימה בקוד)
  public static void Unlock(Rule r) { try { if (Directory.Exists(r.Path)) { var i = new DirectoryInfo(r.Path); var s = i.GetAccessControl(); s.RemoveAccessRule(Deny(true)); i.SetAccessControl(s); } else { var i = new FileInfo(r.Path); var s = i.GetAccessControl(); s.RemoveAccessRule(Deny(false)); i.SetAccessControl(s); } } catch { } }
  public static void Relock(Rule r) { try { if (Directory.Exists(r.Path)) { var i = new DirectoryInfo(r.Path); var s = i.GetAccessControl(); s.AddAccessRule(Deny(true)); i.SetAccessControl(s); } else if (File.Exists(r.Path)) { var i = new FileInfo(r.Path); var s = i.GetAccessControl(); s.AddAccessRule(Deny(false)); i.SetAccessControl(s); } } catch { } }

  static void Sc(string a) { Process.Start(new ProcessStartInfo("sc.exe", a) { CreateNoWindow = true, UseShellExecute = false })!.WaitForExit(); }
  // התקנה חד-פעמית של שירות מערכת מוגן; בהמשך הוא רק מקבל עדכון של Gate.exe
  public static void EnsureService() {
    var gate = System.IO.Path.Combine(AppContext.BaseDirectory, "Gate.exe");
    if (!Config.Up()) {
      Directory.CreateDirectory(Config.Dir);
      var wd = System.IO.Path.Combine(Config.Dir, "DeviceGuardWatch.exe"); File.Copy(Environment.ProcessPath!, wd, true);
      if (File.Exists(gate)) File.Copy(gate, GateExe, true);
      Sc($"create DeviceGuard binPath= \"\\\"{wd}\\\" --service\" start= auto obj= LocalSystem DisplayName= \"DeviceGuard Protection\"");
      Sc("failure DeviceGuard reset= 0 actions= restart/1000/restart/1000/restart/1000");
      Sc("start DeviceGuard");
      for (int i = 0; i < 20 && !Config.Up(); i++) Thread.Sleep(500);
      Sc("sdset DeviceGuard D:(A;;GA;;;SY)(A;;CCLCSWRPLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)");
      if (Config.Token == null && Program.Code != null) Config.Auth(Program.Code);
    } else if (File.Exists(gate) && Config.Token != null) Config.Pipe($"COPY|{Config.Token}|{gate}|Gate.exe");
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

  public static void Revert(Config c) {
    foreach (var e in c.Applied.OrderBy(x => x.StartsWith("task") ? 0 : x.StartsWith("ifeo") ? 1 : 2).ToList()) {
      var p = e.Split('|');
      try {
        switch (p[0]) {
          case "ifeo": foreach (var v in Views) { using var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, v); using var k = b.OpenSubKey(IFEO + p[1], true); k?.DeleteValue("Debugger", false); } break;
          case "acl": { bool dir = Directory.Exists(p[1]);
              if (dir) { var i = new DirectoryInfo(p[1]); var s = i.GetAccessControl(); s.RemoveAccessRule(Deny(true)); i.SetAccessControl(s); }
              else { var i = new FileInfo(p[1]); var s = i.GetAccessControl(); s.RemoveAccessRule(Deny(false)); i.SetAccessControl(s); } break; }
          case "hid": File.SetAttributes(p[1], (FileAttributes)int.Parse(p[2])); break;
          case "reg": { using var k = (p[1] == "HKLM" ? Registry.LocalMachine : Registry.CurrentUser).OpenSubKey(p[2], true); k?.DeleteValue(p[3], false); break; }
          case "net": PS($"Enable-NetAdapter -Name '{p[1]}' -Confirm:$false"); break;
          case "usb": PS($"Enable-PnpDevice -InstanceId '{p[1]}' -Confirm:$false"); break;
          case "usbstor": { using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\USBSTOR", true); k?.SetValue("Start", 3); break; }
          case "lnk": File.Delete(p[1]); break;
          case "task": Schtasks("/End /TN DeviceGuardWatch"); Schtasks("/Delete /TN DeviceGuardWatch /F"); break;
          case "hideui": {
              using (var k = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL")) k.SetValue("CheckedValue", 1);
              using (var k = Registry.LocalMachine.OpenSubKey(EXP, true)) k?.DeleteValue("NoFolderOptions", false);
              using (var k = Registry.CurrentUser.OpenSubKey(EXP, true)) k?.DeleteValue("NoFolderOptions", false);
              break; }
          case "safer": Registry.LocalMachine.DeleteSubKeyTree(SAFER, false); break;
        }
      } catch { }
    }
    try {   // קבצים שנחסמו אוטומטית על ידי שירות הרקע
      if (File.Exists(WatchLog)) {
        foreach (var l in File.ReadAllLines(WatchLog)) {
          var i = l.LastIndexOf('|'); if (i < 0) continue; var p = l[..i];
          try { var fi = new FileInfo(p); if (!fi.Exists) continue; var s = fi.GetAccessControl(); s.RemoveAccessRule(Deny(false)); fi.SetAccessControl(s); File.SetAttributes(p, (FileAttributes)int.Parse(l[(i + 1)..])); } catch { }
        }
        File.Delete(WatchLog);
      }
    } catch { }
    c.Applied.Clear();
  }
}
