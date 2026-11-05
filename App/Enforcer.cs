using System.Collections.Concurrent; using System.Diagnostics; using System.IO; using System.Net.NetworkInformation; using System.Security.AccessControl; using System.Security.Principal; using System.Text; using System.Threading; using System.Runtime.InteropServices; using Microsoft.Win32;
namespace DG;
public readonly record struct RegWant(string Hive, string Path, string Name, string Kind, string Enc);
public static class Enforcer {
  const string IFEO = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\";
  const string EXP = @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";
  const string SYSPOL = @"Software\Microsoft\Windows\CurrentVersion\Policies\System";
  const string SAFER = @"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers";
  const string DEVREST = @"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions";
  const string RSD = @"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices";
  const string INS = @"SOFTWARE\Policies\Microsoft\Windows\Installer";
  const string USBSTOR = @"SYSTEM\CurrentControlSet\Services\USBSTOR";
  const string ADV = @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced";
  public static int Blocked, Failed; public static string? LastErr;   // תוצאת החסימה האחרונה (לחיווי בחלון)
  public static bool InService;   // true כשרצים בתוך השירות (SYSTEM)
  public static readonly StaTaskScheduler Sta = new();   // תהליכון STA יחיד (יצירת קיצורים ב-COM, שימוש חוזר בין החלות)
  public static string GateExe => System.IO.Path.Combine(Config.Dir, "DeviceGuardWatch.exe");
  // שער קל (NativeAOT) שמוטמע בקובץ הראשי: מכריע מהר אם להפעיל, ומפעיל את השער המלא רק כשצריך חלון קוד. אם הוא חסר – משתמשים בשער המלא
  public static string LightGateExe => System.IO.Path.Combine(Config.Dir, "DeviceGuardGate.exe");
  public static string GateCmd(string id) => $"\"{(File.Exists(LightGateExe) ? LightGateExe : GateExe)}\" --gate {id}";
  static void AddA(Config c, string e) { lock (c.Applied) c.Applied.Add(e); }
  static readonly int Par = Math.Min(16, Math.Max(4, Environment.ProcessorCount * 2));
  // חסימות קבצים שכבר קיימות מההחלה הקודמת: לא משחררים ונועלים מחדש, רק מדלגים (מה שלא נדרש יותר משוחרר בסוף)
  static readonly ConcurrentDictionary<string, byte> prevAcl = new(StringComparer.OrdinalIgnoreCase), prevUsb = new();
  static readonly ConcurrentDictionary<string, string> prevHid = new(StringComparer.OrdinalIgnoreCase);
  static readonly ConcurrentDictionary<string, byte> prevNet = new(StringComparer.OrdinalIgnoreCase);   // מתאמי רשת שהושבתו על ידינו בהחלה הקודמת ונשארים מושבתים (שומרים שייכות לביטול)
  static readonly string CdT = Config.Dir.TrimEnd('\\'), BdT = AppContext.BaseDirectory.TrimEnd('\\');
  static readonly RegistryView[] Views = { RegistryView.Registry64, RegistryView.Registry32 };
  // תהליכי מערכת שלעולם לא חוסמים ולא סוגרים (חסימה שלהם מקריסה את המחשב)
  static readonly HashSet<string> Critical = new(StringComparer.OrdinalIgnoreCase) { "csrss", "wininit", "winlogon", "lsass", "services", "smss", "system", "svchost", "dwm", "fontdrvhost", "explorer", "sihost", "ctfmon", "taskhostw", "runtimebroker", "startmenuexperiencehost", "searchhost", "shellexperiencehost", "audiodg", "dllhost", "conhost", "wmiprvse", "DeviceGuard", "DeviceGuardWatch" };
  public static bool IsCritical(string name) => Critical.Contains(System.IO.Path.GetFileNameWithoutExtension(name));

  // ---------- הרצת תהליכים עזר ----------
  // כשהשירות/החלון מריצים כלי מערכת (PowerShell, sc, netsh...) שייתכן שחסום בשער – הם מסומנים כ"פנימיים" והשער מאפשר אותם
  sealed class InternalScope : IDisposable {
    public InternalScope() => Adjust(1); public void Dispose() => Adjust(0);
    static void Adjust(int on) {
      try {
        if (Config.InService) Program.InternalAdd(Environment.ProcessId, on == 1 ? 1 : -1);
        else if (Config.Token != null) Config.Pipe($"INTERNAL|{Config.Token}|{Environment.ProcessId}|{on}", 2000);
      } catch { }
    }
  }
  // זמן קצוב: כלי שנתקע (למשל PowerShell ב-Get-PnpDevice) נסגר, כדי שההחלה והתזמון האוטומטי לא ייתקעו לתמיד
  const int ExeTimeoutMs = 180_000;
  public static (int Code, string Out) RunExe2(string exe, string args) {
    using var _ = new InternalScope();
    try {
      using var p = Process.Start(new ProcessStartInfo(exe, args) { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true })!;
      var ot = p.StandardOutput.ReadToEndAsync();
      if (!p.WaitForExit(ExeTimeoutMs)) {
        try { p.Kill(true); } catch { }
        Alerts.Log($"פעולת מערכת נתקעה ונעצרה אחרי {ExeTimeoutMs / 1000} שניות: {System.IO.Path.GetFileName(exe)}", false);
        return (-1, ot.Wait(2000) ? ot.Result : "");
      }
      p.WaitForExit(); return (p.ExitCode, ot.Wait(5000) ? ot.Result : "");
    } catch { return (-1, ""); }
  }
  public static string RunExe(string exe, string args) => RunExe2(exe, args).Out;
  // מרכאות בודדות בתוך מחרוזת PowerShell. PowerShell מתייחס גם לגרשיים החכמים ‘ ’ ‚ ‛ כגרש, ולכן מכפילים גם אותם (אחרת שם כמו "John’s" שובר את הפקודה)
  static string Q(string s) => s.Replace("'", "''").Replace("\u2018", "\u2018\u2018").Replace("\u2019", "\u2019\u2019").Replace("\u201A", "\u201A\u201A").Replace("\u201B", "\u201B\u201B");
  static string PS(string cmd) {
    var enc = Convert.ToBase64String(Encoding.Unicode.GetBytes(cmd));
    if (enc.Length < 24000) return RunExe("powershell.exe", "-NoLogo -NoProfile -NonInteractive -EncodedCommand " + enc);
    // סקריפט ארוך חורג ממגבלת שורת הפקודה של Windows (32K תווים), ולכן מועבר דרך קובץ זמני בתיקייה המוגנת
    string? file = null;
    try {
      var dir = System.IO.Path.Combine(Config.Dir, "var"); Directory.CreateDirectory(dir);
      file = System.IO.Path.Combine(dir, "ps-" + Guid.NewGuid().ToString("N") + ".ps1");
      File.WriteAllText(file, cmd, new UTF8Encoding(true));
      return RunExe("powershell.exe", "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"" + file + "\"");
    } catch { return ""; } finally { try { if (file != null) File.Delete(file); } catch { } }
  }
  static void PSAll(List<string> cmds) { if (cmds.Count > 0) PS(string.Join("\n", cmds)); }
  static void Schtasks(string a) => RunExe("schtasks.exe", a);
  static void Netsh(string a) => RunExe("netsh.exe", a);
  static string[] Lines(string s) => s.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

  // ---------- רישום: כתיבה עם שמירת הערך הקודם (לשחזור מדויק בביטול) ----------
  // רשומות ב-Applied:  reg|hive|path|name|prevKind|prevB64|wantKind|wantB64   (prevKind='-' = לא היה ערך)   ,   regkey|hive|path  (מפתח שנוצר על ידינו)
  public static string UserHive(Config c) => c.AllUsers ? "HKLM" : string.IsNullOrEmpty(c.OwnerSid) ? "HKCU" : "HKU:" + c.OwnerSid;
  static RegistryKey? Root(string hive) {
    if (hive == "HKLM") return Registry.LocalMachine; if (hive == "HKCU") return Registry.CurrentUser;
    if (hive.StartsWith("HKU:")) { try { return Registry.Users.OpenSubKey(hive[4..], true); } catch { return null; } }
    return null;
  }
  static string Enc(object v, RegistryValueKind k) => k == RegistryValueKind.DWord ? Convert.ToInt32(v).ToString() : Convert.ToBase64String(Encoding.UTF8.GetBytes(v?.ToString() ?? ""));
  static object Dec(string s, RegistryValueKind k) => k == RegistryValueKind.DWord ? int.Parse(s) : Encoding.UTF8.GetString(Convert.FromBase64String(s));
  static void SetReg(Config c, string hive, string path, string name, object value, RegistryValueKind kind = RegistryValueKind.DWord) {
    var root = Root(hive); if (root == null) return;
    bool existed; using (var t = root.OpenSubKey(path)) existed = t != null;
    using var k = root.CreateSubKey(path, true); if (k == null) return;
    if (!existed) AddA(c, $"regkey|{hive}|{path}");
    string pk = "-", pv = "";
    var old = k.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
    if (old != null) { var ok = k.GetValueKind(name); if (ok == RegistryValueKind.DWord || ok == RegistryValueKind.String || ok == RegistryValueKind.ExpandString) { pk = ok.ToString(); pv = Enc(old, ok); } }
    k.SetValue(name, value, kind);
    AddA(c, $"reg|{hive}|{path}|{name}|{pk}|{pv}|{kind}|{Enc(value, kind)}");
  }
  static bool HasValues(RegistryKey k, int depth = 0) {
    if (k.ValueCount > 0 || depth > 16) return true;
    foreach (var n in k.GetSubKeyNames()) { using var sk = k.OpenSubKey(n); if (sk != null && HasValues(sk, depth + 1)) return true; }
    return false;
  }
  static void RevertReg(string e) {
    var p = e.Split('|');
    if (p.Length < 4) return;
    var root = Root(p[1]); if (root == null) return;
    using var k = root.OpenSubKey(p[2], true); if (k == null) return;
    if (p.Length >= 8 && p[4] != "-") k.SetValue(p[3], Dec(p[5], Enum.Parse<RegistryValueKind>(p[4])), Enum.Parse<RegistryValueKind>(p[4]));
    else k.DeleteValue(p[3], false);
  }
  public static List<RegWant> RegWants(Config c) {
    List<string> snap; lock (c.Applied) snap = c.Applied.Where(x => x.StartsWith("reg|")).ToList();
    return snap.Select(x => x.Split('|')).Where(p => p.Length >= 8).Select(p => new RegWant(p[1], p[2], p[3], p[6], p[7])).ToList();
  }
  // שחזור מדיניות רישום שנמחקה/שונתה (נקרא מהשירות)
  public static int HealReg(List<RegWant> list) {
    int n = 0;
    foreach (var w in list) {
      try {
        var root = Root(w.Hive); if (root == null) continue;
        using var k = root.CreateSubKey(w.Path, true); if (k == null) continue;
        var kind = Enum.Parse<RegistryValueKind>(w.Kind); var want = Dec(w.Enc, kind);
        var have = k.GetValue(w.Name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        bool same = have != null && (kind == RegistryValueKind.DWord ? have is int hi && hi == (int)want : string.Equals(have as string, want as string, StringComparison.Ordinal));
        if (!same) { k.SetValue(w.Name, want, kind); n++; }
      } catch { }
    }
    return n;
  }

  // ---------- החלה ----------
  static string ApplyFlag => System.IO.Path.Combine(Config.Dir, "var", "applying.flag");
  public static bool Applying() { try { var f = ApplyFlag; return File.Exists(f) && (DateTime.UtcNow - File.GetLastWriteTimeUtc(f)).TotalMinutes < 5; } catch { return false; } }
  public static void Apply(Config c) {
    try { Directory.CreateDirectory(System.IO.Path.GetDirectoryName(ApplyFlag)!); File.WriteAllText(ApplyFlag, "1"); } catch { }
    try { ApplyInner(c); } finally { try { File.Delete(ApplyFlag); } catch { } }
  }
  public static void Release(Config c) { Revert(c); c.State = 0; c.Save(true); }
  // פתיחה זמנית מהחלון: הדגל מסמן לשירות לא "לשחזר" חסימות בזמן הביטול. הדגל נשאר עוד רגע אחרי השמירה, כדי שהשירות יטען את ההגדרות החדשות לפני שהוא בודק שוב
  public static void TempOpen(Config c, long until) {
    try { Directory.CreateDirectory(System.IO.Path.GetDirectoryName(ApplyFlag)!); File.WriteAllText(ApplyFlag, "1"); } catch { }
    try { Revert(c); c.TempOpenUntil = until; c.Save(true); Thread.Sleep(3000); }
    finally { try { File.Delete(ApplyFlag); } catch { } }
  }
  static void ApplyInner(Config c) {
    SetSkip(c); Revert(c, true); Blocked = 0; Failed = 0; LastErr = null;
    try {
      PurgeIfeo();   // מנקה שערים יתומים שנשארו מהחלה שנכשלה
      if (!c.Master) { FinishRevert(c); c.State = 0; c.Save(true); return; }
      ApplyCore(c);
      FinishRevert(c);   // משחרר רק מה שכבר לא נדרש
      c.State = 1; c.Save(true);
      Alerts.Log("הוחלו חסימות", false);
    } catch { try { FinishRevert(c); } catch { } try { c.Save(true); } catch { } throw; }   // שומרים את מה שכבר הוחל, כדי שאפשר יהיה לבטל אותו
  }
  public static void SetSkip(Config c) { Harden = c.Harden; SkipAppData = c.SkipAppData; Exclude = c.Exclude.ToArray(); IncludeRemovable = c.IncludeRemovable; SkipProgramDirs = c.SkipProgramDirs; }
  // סיכום קצר של מה שעומד להיות מוחל (לחלון האישור)
  public static string Describe(Config c) {
    if (!c.Master) return "החסימות מושבתות: כל החסימות הקיימות יוסרו.";
    var l = new List<string>();
    foreach (var r in new[] { c.Settings, c.Install, c.Net, c.Usb, c.Portable, c.Movies, c.Songs, c.Images }.Where(r => r.On)) l.Add("• " + r.Name + (r.Mode == Mode.Code ? " (בקוד)" : ""));
    int pr = c.Programs.Count(r => r.On), ex = c.Exts.Count(r => r.On), pa = c.Paths.Count(r => r.On);
    if (pr > 0) l.Add($"• חסימת {pr} תוכנות"); if (ex > 0) l.Add($"• חסימת {ex} סיומות נוספות"); if (pa > 0) l.Add($"• חסימת {pa} קבצים/תיקיות");
    if (c.NetApps.On) l.Add("• חסימת רשת לפי תוכנה" + (c.NetAppsWhite ? " (רשימה לבנה)" : ""));
    if (c.Adv.On) l.Add("• הגנה מתקדמת");
    if (c.Sched.On) l.Add($"• תזמון: פעיל בין {c.Sched.From} ל-{c.Sched.To}");
    return l.Count == 0 ? "לא מסומנת אף חסימה." : "יוחלו החסימות הבאות:\n" + string.Join("\n", l);
  }
  static void SafeBootSet(bool on) {
    foreach (var m in new[] { "Minimal", "Network" }) {
      var path = $@"SYSTEM\CurrentControlSet\Control\SafeBoot\{m}\DeviceGuard";
      try { if (on) { using var k = Registry.LocalMachine.CreateSubKey(path); k.SetValue("", "Service"); } else Registry.LocalMachine.DeleteSubKeyTree(path, false); } catch { }
    }
  }
  static void ApplyCore(Config c) {
    if (!InService) EnsureService();
    SafeBootSet(c.AdvOpts.SafeBoot);
    var uh = UserHive(c);
    // שאילתות PowerShell רצות במקביל. חסימת סיומות (תמונות/שירים/סרטים) נעשית ברקע בשירות, ולכן ההחלה חוזרת מיד
    Task<string>? netT = c.Net.On ? Task.Run(() => PS("Get-NetAdapter | % { $w = ($_.PhysicalMediaType -like '*802.11*' -or $_.InterfaceDescription -match 'Wireless|Wi-Fi'); $(if ($w) { 'W' } else { 'E' }) + '|' + $_.Status + '|' + $_.Name }")) : null;
    Task<string>? usbT = c.Usb.On ? Task.Run(() => PS("Get-PnpDevice -PresentOnly | ? InstanceId -like 'USBSTOR*' | % { $p = (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName 'DEVPKEY_Device_Parent' -ErrorAction SilentlyContinue).Data; $_.InstanceId + '|' + $_.FriendlyName + '|' + $p }")) : null;
    Task<string>? fwT = c.NetApps.On && c.NetAppsWhite ? Task.Run(() => PS("Get-NetFirewallProfile | % { [string]$_.Name + '|' + [string]$_.DefaultOutboundAction }")) : null;
    var netCmds = new List<string>(); var usbCmds = new List<string>(); var fwCmds = new List<string>(); var wlanArgs = new List<string>();

    // 1) פעולות PowerShell / netsh
    if (c.Net.On) {
      var ssidWhite = c.Net.White.Where(w => w.StartsWith("ssid:")).Select(w => w[5..]).ToList();
      var adapterWhite = c.Net.White.Where(w => !w.StartsWith("ssid:")).ToList();
      var nl = Lines(netT!.Result);
      // מתאמי רשת שאינם Wi-Fi (Ethernet וכדומה): נחסמים כולם חוץ מהרשימה הלבנה; מתאם שכבר מושבת לא נוגעים בו שוב
      foreach (var l in nl) { var q = l.Split('|', 3); if (q.Length < 3 || q[0] != "E" || adapterWhite.Contains(q[2])) continue; if (q[1] != "Disabled") { netCmds.Add($"Disable-NetAdapter -Name '{Q(q[2])}' -Confirm:$false"); AddA(c, "net|" + q[2]); } else if (prevNet.ContainsKey(q[2])) AddA(c, "net|" + q[2]); }   // מתאם שהיה מושבת לפני כן (לא על ידינו) לא יופעל בביטול
      // Wi-Fi: חסימה לפי שם הרשת (SSID). נשלח ישירות ל-netsh (בלי PowerShell), כדי ששם רשת זדוני לא יוכל להריץ פקודות
      if (nl.Any(l => l.StartsWith("W|"))) {
        wlanArgs.Add("wlan add filter permission=denyall networktype=infrastructure"); AddA(c, "wlanfilter|denyall");
        foreach (var ssid in ssidWhite) { wlanArgs.Add($"wlan add filter permission=allow ssid=\"{ssid.Replace("\"", "")}\" networktype=infrastructure"); AddA(c, "wlanfilter|allow|" + ssid); }
      }
    }
    // חסימת חיבור לרשת לפי תוכנה (חומת האש של Windows)
    if (c.NetApps.On) {
      fwCmds.Add("Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True");
      fwCmds.AddRange(NetAppsRules(c, new List<string>()));
      if (c.NetAppsWhite) {
        foreach (var l in Lines(fwT!.Result)) { var q = l.Split('|', 2); if (q.Length < 2 || q[1] == "Block") continue; AddA(c, "fwpolicy|" + q[0] + "|" + q[1]); }
        fwCmds.Add("Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block");
      }
      AddA(c, "fwrules");
    }
    if (c.Usb.On) {
      // רשימה לבנה לפי מזהה מופע (כולל מספר סידורי): כונן אחר מאותו דגם לא יאושר. ערכים ישנים (שם ידידותי) עדיין נתמכים
      var allow = new List<string>();
      foreach (var l in Lines(usbT!.Result)) {
        var q = l.Split('|', 3); if (q.Length < 2) continue;
        var parent = q.Length > 2 ? q[2].Trim() : "";
        if (c.Usb.White.Contains(q[0]) || c.Usb.White.Contains(q[1])) {
          allow.Add(q[0]);
          if (parent.Length > 0) { allow.Add(parent); var pw = "usbparent:" + parent; if (!c.Usb.White.Contains(pw)) c.Usb.White.Add(pw); }   // גם התקן ה-USB האב חייב להיות מותר, אחרת הכונן לא יותקן
          continue;
        }
        if (!prevUsb.TryRemove(q[0], out _)) usbCmds.Add($"Disable-PnpDevice -InstanceId '{Q(q[0])}' -Confirm:$false"); AddA(c, "usb|" + q[0]);
      }
      foreach (var w in c.Usb.White.ToList()) { var wv = w.StartsWith("usbparent:") ? w[10..] : w; if (wv.Contains('\\') && !allow.Contains(wv)) allow.Add(wv); }
      bool hasWhite = c.Usb.White.Any(w => !w.StartsWith("usbparent:"));
      if (!hasWhite) { SetReg(c, "HKLM", USBSTOR, "Start", 4); SetReg(c, "HKLM", RSD, "Deny_All", 1); }   // חוסם גם אמצעי אחסון שכבר הותקנו
      SetReg(c, "HKLM", DEVREST, "DenyRemovableDevices", 1);   // חסימה ברמת המדיניות: חלה גם על התקנים עתידיים
      if (hasWhite) {
        SetReg(c, "HKLM", DEVREST, "AllowDenyLayered", 1); SetReg(c, "HKLM", DEVREST, "AllowInstanceIDs", 1);
        int ai = 1; foreach (var id in allow) SetReg(c, "HKLM", DEVREST + @"\AllowInstanceIDs", (ai++).ToString(), id, RegistryValueKind.String);
      }
    }
    Task.WaitAll(Task.Run(() => PSAll(netCmds)), Task.Run(() => PSAll(usbCmds)), Task.Run(() => PSAll(fwCmds)), Task.Run(() => { foreach (var a in wlanArgs) Netsh(a); }));
    // 2) הגדרות מחשב
    var s = c.Settings;
    if (s.On) {
      if (s.Mode == Mode.Code) { Ifeo(c, "control.exe", s); Ifeo(c, "SystemSettings.exe", s); }
      else {
        if (s.White.Count > 0) SetReg(c, uh, EXP, "SettingsPageVisibility", "showonly:" + string.Join(";", s.White), RegistryValueKind.String);
        else SetReg(c, uh, EXP, "NoControlPanel", 1);
        if (s.White.Count > 0) Ifeo(c, "control.exe", s);   // עם רשימה לבנה נחסמת רק אפליקציית ההגדרות החדשה, ולכן לוח הבקרה הישן נחסם בנפרד
      }
    }
    if (c.Install.On) {
      Ifeo(c, "msiexec.exe", c.Install);
      if (c.Install.Mode == Mode.Full) SetReg(c, uh, INS, "DisableMSI", 2);   // חסימה גמורה: גם מדיניות Windows Installer, שתופסת כל הפעלה של התקנת MSI
    }
    // 3) תוכנות
    foreach (var r in c.Programs.Where(r => r.On && File.Exists(r.Path))) {
      var f = System.IO.Path.GetFileName(r.Path);
      if (IsCritical(f)) continue;
      Ifeo(c, f, r); if (r.Hidden && r.Mode == Mode.Full) Hide(c, r.Path);
    }
    // 4) תוכנות ניידות (Software Restriction Policies: ברירת מחדל = חסום, מותר: מערכת + רשימה לבנה). מותר רק קובץ ההפעלה של התוכנה עצמה, לא כל התיקייה שלו
    if (c.Portable.On) {
      SetReg(c, "HKLM", SAFER, "DefaultLevel", 0); SetReg(c, "HKLM", SAFER, "PolicyScope", 0); SetReg(c, "HKLM", SAFER, "TransparentEnabled", 1);
      var allow = new List<string> { Environment.GetFolderPath(Environment.SpecialFolder.Windows), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), Config.Dir };
      if (!string.IsNullOrEmpty(c.UiExe)) allow.Add(c.UiExe); else if (!InService && Environment.ProcessPath != null) allow.Add(Environment.ProcessPath);
      allow.AddRange(c.Portable.White);
      foreach (var a in allow.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.OrdinalIgnoreCase)) {
        var pp = SAFER + @"\262144\Paths\{" + Guid.NewGuid() + "}";
        SetReg(c, "HKLM", pp, "ItemData", a, RegistryValueKind.String); SetReg(c, "HKLM", pp, "SaferFlags", 0);
      }
      // תיקיות שמשתמש רגיל יכול לכתוב אליהן בתוך Windows: חוסמים הרצה מהן (כלל מפורש גובר על הכלל הכללי של Windows)
      foreach (var wd in new[] { @"\Temp", @"\Tasks", @"\tracing", @"\Registration\CRMLog", @"\System32\Tasks", @"\System32\spool\drivers\color", @"\System32\spool\PRINTERS" }) {
        var dp = SAFER + @"\0\Paths\{" + Guid.NewGuid() + "}";
        SetReg(c, "HKLM", dp, "ItemData", WinDir + wd, RegistryValueKind.String); SetReg(c, "HKLM", dp, "SaferFlags", 0);
      }
    }
    // 5) קבצים, תיקיות וסיומות
    foreach (var r in c.Paths.Where(r => r.On)) if (!ProtectedPath(r.Path)) { Block(c, r, r.Path); if (r.Mode == Mode.Code) MakeLnk(c, r); }
    foreach (var r in new[] { c.Movies, c.Songs, c.Images }.Concat(c.Exts).Where(r => r.On && r.Mode == Mode.Code)) MakeExtLnk(c, r);
    if (c.Applied.Any(x => x.StartsWith("hid|"))) {   // מונע הצגת קבצים מוסתרים בסייר הקבצים
      try {
        SetReg(c, uh, ADV, "Hidden", 2); SetReg(c, uh, ADV, "ShowSuperHidden", 0);
        SetReg(c, "HKLM", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL", "CheckedValue", 0);
        SetReg(c, uh, EXP, "NoFolderOptions", 1);
      } catch { }
    }
    // 6) הגנה מתקדמת (חלון 7)
    if (c.Adv.On) ApplyAdv(c, uh);
  }
  static void ApplyAdv(Config c, string uh) {
    var a = c.AdvOpts;
    if (a.BlockBoot) foreach (var e in new[] { "bcdedit.exe", "msconfig.exe", "reagentc.exe" }) Ifeo(c, e, c.Adv);
    if (a.NoVirt) foreach (var e in new[] { "wsl.exe", "bash.exe", "WindowsSandbox.exe", "vmconnect.exe" }) Ifeo(c, e, c.Adv);
    if (a.NoTaskMgr) SetReg(c, uh, SYSPOL, "DisableTaskMgr", 1);
    if (a.NoRegedit) SetReg(c, uh, SYSPOL, "DisableRegistryTools", 1);
    if (a.NoStore) SetReg(c, "HKLM", @"SOFTWARE\Policies\Microsoft\WindowsStore", "RemoveWindowsStore", 1);
    if (a.NoWinget) SetReg(c, "HKLM", @"SOFTWARE\Policies\Microsoft\Windows\AppInstaller", "EnableAppInstaller", 0);
    if (a.Browsers) {   // מונע עקיפת סינון: DNS מוצפן בדפדפן וגלישה פרטית
      SetReg(c, "HKLM", @"SOFTWARE\Policies\Google\Chrome", "IncognitoModeAvailability", 1); SetReg(c, "HKLM", @"SOFTWARE\Policies\Google\Chrome", "DnsOverHttpsMode", "off", RegistryValueKind.String);
      SetReg(c, "HKLM", @"SOFTWARE\Policies\Microsoft\Edge", "InPrivateModeAvailability", 1); SetReg(c, "HKLM", @"SOFTWARE\Policies\Microsoft\Edge", "DnsOverHttpsMode", "off", RegistryValueKind.String);
      SetReg(c, "HKLM", @"SOFTWARE\Policies\Google\Chrome", "BrowserGuestModeEnabled", 0); SetReg(c, "HKLM", @"SOFTWARE\Policies\Microsoft\Edge", "BrowserGuestModeEnabled", 0);   // מצב אורח עוקף פרופיל מסונן
      SetReg(c, "HKLM", @"SOFTWARE\Policies\Mozilla\Firefox", "DisablePrivateBrowsing", 1);
      SetReg(c, "HKLM", @"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS", "Enabled", 0); SetReg(c, "HKLM", @"SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS", "Locked", 1);
    }
    if (a.NoTether) SetReg(c, "HKLM", @"SOFTWARE\Policies\Microsoft\Windows\Network Connections", "NC_ShowSharedAccessUI", 0);
    if (a.NoTcpip) SetReg(c, "HKLM", @"SOFTWARE\Policies\Microsoft\Windows\Network Connections", "NC_AllowAdvancedTCPIPConfig", 0);
    if (a.NoProxy) SetReg(c, "HKLM", @"SOFTWARE\Policies\Microsoft\Internet Explorer\Control Panel", "Proxy", 1);   // מונע הגדרת Proxy (עקיפת סינון) בהגדרות המערכת, שמשפיעות גם על Chrome ו-Edge
    if (a.LockHosts) {
      try { var fi = new FileInfo(HostsPath); if (fi.Exists) { var sec = fi.GetAccessControl(); sec.AddAccessRule(HostsDeny); fi.SetAccessControl(sec); AddA(c, "hostslock"); } } catch { }
    }
  }
  static string HostsPath => System.IO.Path.Combine(Environment.SystemDirectory, @"drivers\etc\hosts");
  static FileSystemAccessRule HostsDeny => new(new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.Delete, AccessControlType.Deny);

  // ---------- הגנה על נתיבי מערכת ותוכנה עצמה ----------
  static string UsersDir => System.IO.Path.Combine(Environment.GetEnvironmentVariable("SystemDrive") ?? "C:", "Users");
  static readonly string WinDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\'), PF = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).TrimEnd('\\'),
    PF86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86).TrimEnd('\\'), PData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData).TrimEnd('\\');
  static bool Under(string p, string d) => p.Equals(d, StringComparison.OrdinalIgnoreCase) || p.StartsWith(d + "\\", StringComparison.OrdinalIgnoreCase);
  // נתיבים שחסימתם עלולה להקריס את המחשב (שורש כונן, Windows, Program Files, ProgramData, Users, ותיקיית הבית של כל משתמש)
  public static bool IsDangerous(string p) {
    var t = p.TrimEnd('\\'); if (t.Length <= 2) return true;
    var root = System.IO.Path.GetPathRoot(p); if (root != null && t.Equals(root.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) return true;
    if (Under(t, WinDir)) return true;
    foreach (var d in new[] { PF, PF86, PData, UsersDir }) if (t.Equals(d, StringComparison.OrdinalIgnoreCase) || d.StartsWith(t + "\\", StringComparison.OrdinalIgnoreCase)) return true;
    try { foreach (var u in Directory.GetDirectories(UsersDir)) if (t.Equals(u, StringComparison.OrdinalIgnoreCase)) return true; } catch { }
    return false;
  }
  // מגן על התוכנה עצמה: אי אפשר לחסום את תיקיית ההגדרות, את תיקיית ההרצה, תיקייה שמכילה אותן, או קובץ בשם התוכנה בכל מיקום
  static bool Protected(string p) {
    var t = p.TrimEnd('\\'); var cd = CdT; var bd = BdT;
    bool Covers(string a, string b) => a.Equals(b, StringComparison.OrdinalIgnoreCase) || a.StartsWith(b + "\\", StringComparison.OrdinalIgnoreCase) || b.StartsWith(a + "\\", StringComparison.OrdinalIgnoreCase);
    return Covers(t, cd) || Covers(t, bd)
      || System.IO.Path.GetFileName(t).Equals("DeviceGuard.exe", StringComparison.OrdinalIgnoreCase)
      || System.IO.Path.GetFileName(t).Equals("DeviceGuardWatch.exe", StringComparison.OrdinalIgnoreCase);
  }
  static bool ProtectedPath(string p) => IsDangerous(p) || Protected(p);

  // ---------- IFEO (שער חסימה) ----------
  static void Ifeo(Config c, string exe, Rule r) {
    if (IsCritical(exe)) return;
    foreach (var v in Views) { using var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, v); using var k = b.CreateSubKey(IFEO + exe); k.SetValue("Debugger", GateCmd(r.Id)); }
    AddA(c, "ifeo|" + exe + "|" + r.Id);
  }
  // מוחק כל שער של DeviceGuard מהרישום (גם יתומים שאינם רשומים ב-Applied)
  public static void PurgeIfeo() {
    var mark = "\"" + GateExe + "\" --gate"; var mark2 = "\"" + LightGateExe + "\" --gate";
    foreach (var v in Views) {
      try {
        using var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, v); using var ifeo = b.OpenSubKey(IFEO.TrimEnd('\\'), true); if (ifeo == null) continue;
        foreach (var n in ifeo.GetSubKeyNames()) {
          try { using var k = ifeo.OpenSubKey(n, true); if (k?.GetValue("Debugger") is string d && (d.StartsWith(mark, StringComparison.OrdinalIgnoreCase) || d.StartsWith(mark2, StringComparison.OrdinalIgnoreCase))) k.DeleteValue("Debugger", false); } catch { }
        }
      } catch { }
    }
  }
  // ניקוי מלא בהסרת התוכנה: שערים, כללי חומת אש, נעילת קובץ hosts
  public static void PurgeAll() {
    PurgeIfeo();
    try { PSAll(new List<string> { "Remove-NetFirewallRule -Group 'DeviceGuardNet' -ErrorAction SilentlyContinue" }); } catch { }
    try { var fi = new FileInfo(HostsPath); if (fi.Exists) { var sec = fi.GetAccessControl(); sec.RemoveAccessRule(HostsDeny); fi.SetAccessControl(sec); } } catch { }
  }
  static void Hide(Config c, string p) { try { if (prevHid.TryRemove(p, out var old)) { AddA(c, old); return; } var a = File.GetAttributes(p); File.SetAttributes(p, a | FileAttributes.Hidden | FileAttributes.System); AddA(c, $"hid|{p}|{(int)a}"); } catch { } }

  // ---------- חסימת קבצים ותיקיות (ACL) ----------
  // חיזוק: כלל OWNER RIGHTS (S-1-3-4) מבטל לבעל הקובץ את הזכות המובנית לשנות הרשאות, כך שמשתמש רגיל לא יכול להסיר את החסימה בעצמו.
  public static bool Harden = true, SkipAppData = true, IncludeRemovable, SkipProgramDirs = true; public static string[] Exclude = Array.Empty<string>();
  static readonly SecurityIdentifier OwnerSid = new("S-1-3-4");
  static FileSystemAccessRule OwnerRule(bool dir) => new(OwnerSid, FileSystemRights.ReadAttributes | FileSystemRights.ReadPermissions | FileSystemRights.Synchronize,
    dir ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit : InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow);
  // תווית שלמות High עם No-Write-Up: תהליך לא מורם (משתמש רגיל, או מנהל בלי אישור UAC) לא יכול לשנות הרשאות/בעלות של הקובץ,
  // גם כשיש לו "שליטה מלאה" מפורשת (כמו בכל קובץ בתיקיות המשתמש). השירות (SYSTEM) והחלון המורם (High) לא מושפעים
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint rev, out IntPtr sd, IntPtr size);
  [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetSecurityDescriptorSacl(IntPtr sd, out bool present, out IntPtr sacl, out bool defaulted);
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode)] static extern uint SetNamedSecurityInfoW(string name, int type, uint info, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr h);
  static readonly byte[] EmptyAcl = MakeEmptyAcl();
  static byte[] MakeEmptyAcl() { var a = new RawAcl(GenericAcl.AclRevision, 0); var b = new byte[a.BinaryLength]; a.GetBinaryForm(b, 0); return b; }
  static void Label(string p, bool dir, bool on) {
    const int SE_FILE_OBJECT = 1; const uint LABEL_SECURITY_INFORMATION = 0x10;
    try {
      if (on) {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(dir ? "S:(ML;OICI;NW;;;HI)" : "S:(ML;;NW;;;HI)", 1, out var sd, IntPtr.Zero)) return;
        try { if (GetSecurityDescriptorSacl(sd, out var present, out var sacl, out _) && present) SetNamedSecurityInfoW(p, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, sacl); }
        finally { LocalFree(sd); }
      } else {
        var h = GCHandle.Alloc(EmptyAcl, GCHandleType.Pinned);
        try { SetNamedSecurityInfoW(p, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, h.AddrOfPinnedObject()); } finally { h.Free(); }
      }
    } catch { }
  }
  // נעילה/שחרור של קובץ או תיקייה: כלל הדחייה + (בחיזוק) כלל OWNER RIGHTS ותווית השלמות
  static void AclOn(FileSystemInfo i, bool dir) {
    var s = i is DirectoryInfo d ? (FileSystemSecurity)d.GetAccessControl() : ((FileInfo)i).GetAccessControl();
    s.AddAccessRule(Deny(dir)); Own(s, dir);
    if (i is DirectoryInfo d2) d2.SetAccessControl((DirectorySecurity)s); else ((FileInfo)i).SetAccessControl((FileSecurity)s);
    if (Harden) Label(i.FullName, dir, true);
  }
  static void AclOff(FileSystemInfo i, bool dir) {
    Label(i.FullName, dir, false);
    var s = i is DirectoryInfo d ? (FileSystemSecurity)d.GetAccessControl() : ((FileInfo)i).GetAccessControl();
    s.RemoveAccessRule(Deny(dir)); Unown(s, dir);
    if (i is DirectoryInfo d2) d2.SetAccessControl((DirectorySecurity)s); else ((FileInfo)i).SetAccessControl((FileSecurity)s);
  }
  static void Own(FileSystemSecurity s, bool dir) { if (Harden) s.AddAccessRule(OwnerRule(dir)); }
  static void Unown(FileSystemSecurity s, bool dir) { s.RemoveAccessRule(OwnerRule(dir)); }
  static FileSystemAccessRule Deny(bool dir) => new(new SecurityIdentifier(WellKnownSidType.WorldSid, null),
    FileSystemRights.ReadData | FileSystemRights.ExecuteFile | FileSystemRights.Delete,
    dir ? InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit : InheritanceFlags.None, PropagationFlags.None, AccessControlType.Deny);
  static List<string> ListDirs(string root) {   // חייב לרוץ לפני החסימה, כי אחריה אי אפשר לרשום את תוכן התיקייה
    var all = new List<string>();
    void Walk(string d) { string[] subs; try { subs = Directory.GetDirectories(d); } catch { return; } foreach (var x in subs) { try { if ((File.GetAttributes(x) & FileAttributes.ReparsePoint) != 0) continue; } catch { continue; } all.Add(x); Walk(x); } }
    Walk(root); return all;
  }
  static bool HasDeny(string d, bool inherited) {
    try { return new DirectoryInfo(d).GetAccessControl().GetAccessRules(true, inherited, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().Any(x => x.AccessControlType == AccessControlType.Deny && x.IdentityReference.Value == "S-1-1-0" && (x.FileSystemRights & FileSystemRights.ListDirectory) != 0); } catch { return false; }
  }
  static void DenySubs(List<string> subs) {
    Parallel.ForEach(subs, new ParallelOptions { MaxDegreeOfParallelism = Par }, d => { try { if (HasDeny(d, true)) return; AclOn(new DirectoryInfo(d), true); } catch { } });
  }
  static void UnwalkDir(string d, bool root = true) {   // משחרר מלמעלה למטה: קודם התיקייה עצמה, ואז אפשר לרשום את מה שבתוכה
    try { if (root || HasDeny(d, false)) { AclOff(new DirectoryInfo(d), true); } } catch { }
    string[] subs; try { subs = Directory.GetDirectories(d); } catch { return; }
    foreach (var x in subs) { try { if ((File.GetAttributes(x) & FileAttributes.ReparsePoint) == 0) UnwalkDir(x, false); } catch { } }
  }
  static void Block(Config c, Rule r, string p) {
    try {
      bool dir = Directory.Exists(p); if (!dir && !File.Exists(p)) return;
      if ((r.Hidden && r.Mode == Mode.Full) || (r.Mode == Mode.Code && c.Paths.Contains(r))) Hide(c, p);
      if (dir) { var subs = ListDirs(p); AclOn(new DirectoryInfo(p), true); DenySubs(subs); }
      else if (!prevAcl.TryRemove(p, out _)) AclOn(new FileInfo(p), false);
      AddA(c, "acl|" + p + (Harden ? "|h2" : "")); Interlocked.Increment(ref Blocked);
    } catch (Exception x) { Interlocked.Increment(ref Failed); LastErr = x.Message; }
  }

  // ---------- חסימת סיומות ברקע (השירות) ----------
  static string WatchLog => System.IO.Path.Combine(Config.Dir, "var", "watched.log");
  // דילוג לפי נתיב מלא (ולא לפי שם תיקייה, שאפשר לעקוף בקלות): Windows (חוץ מ-Temp), Program Files, חלק מ-ProgramData, AppData של משתמשים (אופציונלי) וההחרגות שהוגדרו
  static readonly string[] SkipFull = { PF, PF86, System.IO.Path.Combine(PData, "Microsoft"), System.IO.Path.Combine(PData, "Packages") };
  // תיקיית תוכנה: תיקייה (או אחת מהתיקיות שמעליה) שיש בה קובצי dll, וכן תיקיות נקודה, node_modules ו-site-packages. חסימת תמונות/סרטים שם שוברת תוכנות
  static readonly ConcurrentDictionary<string, (bool V, DateTime T)> dllDirs = new(StringComparer.OrdinalIgnoreCase);
  static bool HasDll(string d) {
    var now = DateTime.UtcNow;
    if (dllDirs.TryGetValue(d, out var e) && (now - e.T).TotalMinutes < 10) return e.V;
    bool v; try { v = Directory.EnumerateFiles(d, "*.dll").Any(); } catch { v = false; }
    if (dllDirs.Count > 20000) dllDirs.Clear();
    dllDirs[d] = (v, now); return v;
  }
  static bool IsProgramPath(string p) {
    var root = System.IO.Path.GetPathRoot(p) ?? "";
    if (p.Length > root.Length) {
      var parts = p[root.Length..].Split('\\');
      for (int i = 0; i < parts.Length - 1; i++) { var s = parts[i]; if ((s.Length > 1 && s[0] == '.') || s.Equals("node_modules", StringComparison.OrdinalIgnoreCase) || s.Equals("site-packages", StringComparison.OrdinalIgnoreCase)) return true; }
    }
    var d = System.IO.Path.GetDirectoryName(p);
    for (int depth = 0; d != null && depth < 12; depth++, d = System.IO.Path.GetDirectoryName(d)) if (HasDll(d)) return true;
    return false;
  }
  static readonly ConcurrentDictionary<string, bool> removableRoots = new(StringComparer.OrdinalIgnoreCase);
  static bool RemovableExcluded(string p) {
    if (IncludeRemovable) return false;
    try { var r = System.IO.Path.GetPathRoot(p); if (string.IsNullOrEmpty(r)) return false; return removableRoots.GetOrAdd(r, x => { try { return new DriveInfo(x).DriveType == DriveType.Removable; } catch { return false; } }); } catch { return false; }
  }
  public static bool ScanDrive(DriveInfo d) => d.DriveType == DriveType.Fixed || (d.DriveType == DriveType.Removable && IncludeRemovable);
  static bool DriveUp(string p) { try { var r = System.IO.Path.GetPathRoot(p); return !string.IsNullOrEmpty(r) && Directory.Exists(r); } catch { return false; } }
  public static bool InSkipped(string p) {
    if (Under(p, WinDir) && !Under(p, WinDir + @"\Temp")) return true;
    foreach (var s in SkipFull) if (Under(p, s)) return true;
    var root = System.IO.Path.GetPathRoot(p) ?? "";
    if (p.Length > root.Length) { var first = p[root.Length..].Split('\\')[0]; if (first.Equals("$Recycle.Bin", StringComparison.OrdinalIgnoreCase) || first.Equals("System Volume Information", StringComparison.OrdinalIgnoreCase)) return true; }
    if (SkipAppData && p.StartsWith(UsersDir + "\\", StringComparison.OrdinalIgnoreCase)) { var parts = p[(UsersDir.Length + 1)..].Split('\\'); if (parts.Length >= 2 && parts[1].Equals("AppData", StringComparison.OrdinalIgnoreCase)) return true; }
    foreach (var e in Exclude) if (!string.IsNullOrWhiteSpace(e) && Under(p, e.TrimEnd('\\'))) return true;
    if (SkipProgramDirs && IsProgramPath(p)) return true;
    return false;
  }
  // כוננים שאינם NTFS/ReFS (FAT, exFAT) לא תומכים בהרשאות, ולכן אי אפשר לחסום בהם קבצים
  static readonly ConcurrentDictionary<string, bool> aclRoots = new(StringComparer.OrdinalIgnoreCase);
  public static readonly ConcurrentDictionary<string, byte> NoAclDrives = new(StringComparer.OrdinalIgnoreCase);
  public static void ResetDriveCache() { aclRoots.Clear(); NoAclDrives.Clear(); removableRoots.Clear(); }
  static bool AclOk(string p) {
    var root = System.IO.Path.GetPathRoot(p); if (string.IsNullOrEmpty(root)) return true;
    return aclRoots.GetOrAdd(root, r => {
      try { var f = new DriveInfo(r).DriveFormat; bool ok = f.Equals("NTFS", StringComparison.OrdinalIgnoreCase) || f.Equals("ReFS", StringComparison.OrdinalIgnoreCase); if (!ok) NoAclDrives[r] = 0; return ok; } catch { return true; }
    });
  }
  static readonly string[] DangerExt = Config.Danger.ToArray();
  public static Dictionary<string, Rule> ExtMap(Config c) {
    var map = new Dictionary<string, Rule>();
    void M(Rule r, string[] x) { if (r.On) foreach (var y in x) map[y] = r; }
    M(c.Movies, Config.Vid); M(c.Songs, Config.Aud); M(c.Images, Config.Img);
    foreach (var r in c.Exts.Where(r => r.On)) { var x = r.Path.TrimStart('.').ToLowerInvariant(); if (x.Length > 0 && !Config.Danger.Contains(x)) map[x] = r; }
    return map;
  }
  static readonly object LogLock = new(), logInit = new();
  static readonly ConcurrentQueue<string> pendingLog = new();
  static Thread? logThread;
  static readonly ConcurrentDictionary<string, byte> known = new(StringComparer.OrdinalIgnoreCase);   // קבצים שכבר נחסמו על ידי השירות (חוסך קריאת הרשאות בכל סריקה)
  static readonly int ParSvc = Math.Max(2, Environment.ProcessorCount / 2);   // השירות רץ ברקע ולכן משתמש בפחות ליבות
  // כתיבת היומן נעשית באצוות בתהליכון נפרד: הלולאה הראשית של השירות אף פעם לא ממתינה לנעילה
  static void EnqueueLog(string line) {
    pendingLog.Enqueue(line);
    if (logThread != null) return;
    lock (logInit) if (logThread == null) { logThread = new Thread(() => { while (true) { Thread.Sleep(700); try { lock (LogLock) DrainLog(); } catch { } } }) { IsBackground = true }; logThread.Start(); }
  }
  static void DrainLog() {   // חייב לרוץ בתוך LogLock
    if (pendingLog.IsEmpty) return;
    var lines = new List<string>(); while (pendingLog.TryDequeue(out var l)) lines.Add(l);
    Directory.CreateDirectory(System.IO.Path.GetDirectoryName(WatchLog)!); File.AppendAllLines(WatchLog, lines);
  }
  // חוסם קובץ (נקרא משירות הרקע: קבצים חדשים וגם קבצים קיימים). מחזיר false אם צריך לנסות שוב
  // הסריקה התקופתית בודקת מחדש כל קובץ (ולא סומכת על המטמון), כדי שחסימה שהוסרה תחזור
  public static void ForgetKnown() { lock (LogLock) known.Clear(); }
  public static bool BlockNewFile(Rule r, string p) {
    try {
      if (known.ContainsKey(p)) return true;
      if (RemovableExcluded(p) || InSkipped(p) || !AclOk(p)) return true;
      var fi = new FileInfo(p); if (!fi.Exists || Protected(p)) return true;
      var s = fi.GetAccessControl();
      if (s.GetAccessRules(true, false, typeof(SecurityIdentifier)).Cast<FileSystemAccessRule>().Any(x => x.AccessControlType == AccessControlType.Deny && x.IdentityReference.Value == "S-1-1-0")) return true;
      var a = File.GetAttributes(p);
      if (r.Hidden && r.Mode == Mode.Full) File.SetAttributes(p, a | FileAttributes.Hidden | FileAttributes.System);
      s.AddAccessRule(Deny(false)); Own(s, false); fi.SetAccessControl(s); if (Harden) Label(p, false, true);
      EnqueueLog($"{p}|{(int)a}"); known[p] = 0; return true;
    } catch { return false; }
  }
  // התקדמות הסריקה המלאה (נקראת מהחלון דרך הפקודה SCAN): כל תיקייה עד עומק 2 היא "יחידה", ותיקיות עמוקות יותר נספרות בתוך היחידה שלהן
  public static long ScanId, ScanStartTicks; public static int ScanDone, ScanTotal; public static volatile bool ScanRunning, ScanFinished;
  static List<string> SubDirs(string dir) {
    var subs = new List<string>();
    try { foreach (var d in Directory.EnumerateDirectories(dir)) { if (InSkipped(d)) continue; try { if ((File.GetAttributes(d) & FileAttributes.ReparsePoint) != 0) continue; } catch { continue; } subs.Add(d); } } catch { }
    return subs;
  }
  static int CountUnits(string root) { int n = 1; foreach (var d1 in SubDirs(root)) { n++; n += SubDirs(d1).Count; } return n; }
  public static void ScanNew(Dictionary<string, Rule> map, CancellationToken ct = default, string? only = null) {
    if (map.Count == 0) return;   // אין סיומות חסומות – אין מה לסרוק
    var roots = (only != null ? new[] { only } : DriveInfo.GetDrives().Where(d => ScanDrive(d) && d.IsReady).Select(d => d.RootDirectory.FullName).ToArray()).Where(AclOk).ToArray();
    bool track = only == null;
    if (track) { ScanFinished = false; ScanDone = 0; ScanTotal = 0; ScanStartTicks = DateTime.UtcNow.Ticks; ScanId++; ScanRunning = true; }
    try {
      // סריקה מהירה דרך יומן ה-USN (קריאת ה-MFT) כשאפשר; אחרת – מעבר על התיקיות כמו קודם
      var usn = new List<(string Root, List<string> Files)>(); var crawl = new List<string>();
      foreach (var r in roots) { if (ct.IsCancellationRequested) break; var l = UsnScan.TryList(r, map.Keys, ct); if (l != null) usn.Add((r, l)); else crawl.Add(r); }
      if (track) ScanTotal = Math.Max(1, usn.Sum(u => u.Files.Count) + crawl.Sum(CountUnits));
      var po = new ParallelOptions { MaxDegreeOfParallelism = ParSvc, CancellationToken = ct };
      foreach (var u in usn) Parallel.ForEach(u.Files, po, f => { if (map.TryGetValue(System.IO.Path.GetExtension(f).TrimStart('.').ToLowerInvariant(), out var rl)) BlockNewFile(rl, f); if (track) Interlocked.Increment(ref ScanDone); });
      Parallel.ForEach(crawl, po, d => ScanN(d, map, ct, 0));
      if (track && !ct.IsCancellationRequested) { ScanDone = ScanTotal; ScanFinished = true; }
    } finally { if (track) ScanRunning = false; }
  }
  static void ScanN(string dir, Dictionary<string, Rule> map, CancellationToken ct, int depth) {
    if (ct.IsCancellationRequested) return;
    try {
      foreach (var f in Directory.EnumerateFiles(dir)) { if (ct.IsCancellationRequested) return; if (map.TryGetValue(System.IO.Path.GetExtension(f).TrimStart('.').ToLowerInvariant(), out var r)) BlockNewFile(r, f); }
      var subs = SubDirs(dir);
      if (depth < 2 && subs.Count > 1) Parallel.ForEach(subs, new ParallelOptions { MaxDegreeOfParallelism = ParSvc, CancellationToken = ct }, d => ScanN(d, map, ct, depth + 1));
      else foreach (var d in subs) ScanN(d, map, ct, depth + 1);
    } catch (OperationCanceledException) { } catch { }
    finally { if (depth <= 2 && !ct.IsCancellationRequested) Interlocked.Increment(ref ScanDone); }
  }
  static void UnblockLine(string l) {
    var i = l.LastIndexOf('|'); if (i < 0) return; var p = l[..i];
    try { var fi = new FileInfo(p); if (!fi.Exists) return; AclOff(fi, false); File.SetAttributes(p, (FileAttributes)int.Parse(l[(i + 1)..])); } catch { }
  }
  static string HardFlag => System.IO.Path.Combine(Config.Dir, "var", "harden.flag");
  static void SetOwner(string l, bool on) {
    var i = l.LastIndexOf('|'); if (i < 0) return; var p = l[..i];
    try { var fi = new FileInfo(p); if (!fi.Exists) return; var s = fi.GetAccessControl(); if (on) s.AddAccessRule(OwnerRule(false)); else s.RemoveAccessRule(OwnerRule(false)); fi.SetAccessControl(s); Label(p, false, on); } catch { }
  }
  static string HidState => System.IO.Path.Combine(Config.Dir, "var", "hidstate.txt");
  // מסתיר או מחזיר לתצוגה קבצים שכבר חסומים, כשמתג "נסתר" של החוק שלהם השתנה
  static void SyncHidden(Dictionary<string, Rule> map, List<string> keep, ParallelOptions po) {
    try {
      var old = new Dictionary<string, string>();
      try { if (File.Exists(HidState)) foreach (var ln in File.ReadAllLines(HidState)) { var z = ln.Split('|'); if (z.Length == 2) old[z[0]] = z[1]; } } catch { }
      var cur = new Dictionary<string, string>();
      foreach (var rl in map.Values.Distinct()) cur[rl.Id] = rl.Hidden && rl.Mode == Mode.Full ? "1" : "0";
      var todo = keep.Where(l => { var i = l.LastIndexOf('|'); return i >= 0 && map.TryGetValue(System.IO.Path.GetExtension(l[..i]).TrimStart('.').ToLowerInvariant(), out var rr) && (!old.TryGetValue(rr.Id, out var ov) || ov != cur[rr.Id]); }).ToList();
      var hs = FileAttributes.Hidden | FileAttributes.System;
      if (todo.Count > 0) Parallel.ForEach(todo, po, l => {
        var i = l.LastIndexOf('|'); var p = l[..i];
        try {
          if (!map.TryGetValue(System.IO.Path.GetExtension(p).TrimStart('.').ToLowerInvariant(), out var rr) || !File.Exists(p)) return;
          var orig = (FileAttributes)int.Parse(l[(i + 1)..]); var now = File.GetAttributes(p);
          var next = (now & ~hs) | (cur[rr.Id] == "1" ? hs : (orig & hs));
          if (next == now) return;
          try { File.SetAttributes(p, next); } catch { SetLock(l, false); try { File.SetAttributes(p, next); } finally { SetLock(l, true); } }
        } catch { }
      });
      File.WriteAllLines(HidState, cur.Select(x => x.Key + "|" + x.Value));
    } catch { }
  }
  // משחרר קבצים שנחסמו על ידי השירות ושהסיומת שלהם כבר לא חסומה (נקרא בכל טעינה מחדש של ההגדרות)
  public static void ReleaseStale(Dictionary<string, Rule> map) {
    lock (LogLock) {
      DrainLog(); known.Clear();
      var want = Harden ? "2" : "0"; var have = "0";   // "2" = חיזוק כולל תווית שלמות (קבצים שנחסמו בגרסה קודמת מקבלים אותה פעם אחת)
      try { if (File.Exists(HardFlag)) have = File.ReadAllText(HardFlag).Trim(); } catch { }
      var keep = new List<string>(); var rel = new List<string>();
      removableRoots.Clear();
      if (File.Exists(WatchLog)) foreach (var l in File.ReadAllLines(WatchLog)) {
        var i = l.LastIndexOf('|'); if (i < 0) continue; var p = l[..i];
        bool inMap = map.ContainsKey(System.IO.Path.GetExtension(p).TrimStart('.').ToLowerInvariant());
        if (!File.Exists(p)) { if (!DriveUp(p)) keep.Add(l); else rel.Add(l); continue; }   // כונן שאינו זמין כרגע (נשלף / נעול) – שומרים ביומן כדי שהקובץ ישוחרר בהמשך; קובץ שנמחק מוסר מהיומן
        if (inMap && !InSkipped(p) && !RemovableExcluded(p)) { keep.Add(l); known[p] = 0; } else rel.Add(l);   // סיומת שכבר לא חסומה, תיקייה שהוחרגה או כונן נשלף – משחררים
      }
      var po = new ParallelOptions { MaxDegreeOfParallelism = ParSvc };
      if (rel.Count > 0) { Parallel.ForEach(rel, po, UnblockLine); File.WriteAllLines(WatchLog, keep); }
      if (have != want && keep.Count > 0) Parallel.ForEach(keep, po, l => SetOwner(l, Harden));
      SyncHidden(map, keep, po);
      try { File.WriteAllText(HardFlag, want); } catch { }
    }
  }
  // ---- ניקוי מטמוני צפייה (נקרא מהחלון אחרי שהסריקה הסתיימה) ----
  static DateTime lastClear = DateTime.MinValue;
  static void ClearDir(string d) {
    try {
      foreach (var f in Directory.GetFiles(d)) { try { File.SetAttributes(f, FileAttributes.Normal); File.Delete(f); } catch { } }
      foreach (var s in Directory.GetDirectories(d)) { try { Directory.Delete(s, true); } catch { } }
    } catch { }
  }
  public static void ClearViewerCaches(Config c) {
    if (!(c.Master && (c.Images.On || c.Movies.On))) return;
    if ((DateTime.UtcNow - lastClear).TotalMinutes < 10) return;   // לא סוגרים את אפליקציית התמונות שוב ושוב
    lastClear = DateTime.UtcNow;
    try {
      var names = new List<string> { "Microsoft.Photos" }; if (c.Movies.On) names.Add("Video.UI");
      foreach (var n in names) foreach (var pr in Process.GetProcessesByName(n)) { try { pr.Kill(); pr.WaitForExit(3000); } catch { } finally { pr.Dispose(); } }
    } catch { }
    try {
      foreach (var u in Directory.GetDirectories(UsersDir)) {
        var pk = System.IO.Path.Combine(u, @"AppData\Local\Packages"); if (!Directory.Exists(pk)) continue;
        foreach (var pkg in Directory.GetDirectories(pk, "Microsoft.Windows.Photos_*").Concat(Directory.GetDirectories(pk, "Microsoft.ZuneVideo_*")))
          foreach (var sub in new[] { "TempState", "LocalCache" }) ClearDir(System.IO.Path.Combine(pkg, sub));
      }
    } catch { }
    try {
      const string VC = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache";
      using (var k = Registry.LocalMachine.OpenSubKey(VC, true)) k?.SetValue("StateFlags0777", 2, RegistryValueKind.DWord);
      using (new InternalScope()) { using var p = Process.Start(new ProcessStartInfo("cleanmgr.exe", "/sagerun:777") { UseShellExecute = false, CreateNoWindow = true }); p?.WaitForExit(60000); }
      using (var k = Registry.LocalMachine.OpenSubKey(VC, true)) k?.DeleteValue("StateFlags0777", false);
    } catch { }
  }
  // ---- חסימת חיבור לרשת לפי תוכנה ----
  [DllImport("userenv.dll", CharSet = CharSet.Unicode)] static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);
  [DllImport("advapi32.dll")] static extern IntPtr FreeSid(IntPtr sid);
  static string? PkgSid(string family) {
    try { if (DeriveAppContainerSidFromAppContainerName(family, out var p) != 0) return null; try { return new SecurityIdentifier(p).Value; } finally { FreeSid(p); } } catch { return null; }
  }
  static List<string> NetAppsRules(Config c, List<string> names) {
    var res = new List<string>();
    var apps = c.NetApps.White.Where(w => !string.IsNullOrWhiteSpace(w)).ToList();
    if (c.NetAppsWhite && !string.IsNullOrWhiteSpace(c.AlertUrl)) apps.Add(GateExe);   // ברשימה לבנה השירות עצמו חייב להיות מותר, כדי שההתראות (Webhook) יישלחו
    foreach (var a in apps.Distinct(StringComparer.OrdinalIgnoreCase)) {
      string target, label;
      if (a.StartsWith("pkg:")) { var sid = PkgSid(a[4..]); if (sid == null) continue; target = $"-Package '{sid}'"; label = a[4..]; }
      else if (a.StartsWith("svc:")) { target = $"-Service '{Q(a[4..])}'"; label = a[4..]; }
      else { target = $"-Program '{Q(a)}'"; label = System.IO.Path.GetFileName(a); }
      foreach (var dr in c.NetAppsWhite ? new[] { "Outbound" } : new[] { "Outbound", "Inbound" }) {
        var nm = $"DeviceGuard {(c.NetAppsWhite ? "Allow" : "Block")} {dr} {label}".Replace("|", "_"); names.Add(nm);
        res.Add($"New-NetFirewallRule -DisplayName '{Q(nm)}' -Group 'DeviceGuardNet' -Direction {dr} {target} -Action {(c.NetAppsWhite ? "Allow" : "Block")} -Profile Any | Out-Null");
      }
    }
    return res;
  }
  const string FWPOL = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\";
  static bool NetOk(Config c) {
    var names = new List<string>(); NetAppsRules(c, names);
    var have = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    using (var k = Registry.LocalMachine.OpenSubKey(FWPOL + "FirewallRules")) if (k != null) foreach (var n in k.GetValueNames()) {
      if (k.GetValue(n) is not string v) continue; var i = v.IndexOf("|Name=", StringComparison.Ordinal); if (i < 0) continue; var j = v.IndexOf('|', i + 6); if (j < 0) continue; have.Add(v.Substring(i + 6, j - i - 6));
    }
    if (names.Any(x => !have.Contains(x))) return false;
    foreach (var pf in new[] { "DomainProfile", "StandardProfile", "PublicProfile" }) {
      using var pk = Registry.LocalMachine.OpenSubKey(FWPOL + pf);
      if (pk?.GetValue("EnableFirewall") is int en && en == 0) return false;
      if (c.NetAppsWhite && !(pk?.GetValue("DefaultOutboundAction") is int oa && oa == 1)) return false;
    }
    return true;
  }
  static int healBusy; static DateTime healBackoff = DateTime.MinValue;
  // נקרא מהשירות כל כמה שניות: אם מישהו מחק את כללי החומה או שינה את ברירת המחדל – יוצר אותם מחדש
  public static void NetHeal(Config c) {
    if (!c.Master || !c.NetApps.On || DateTime.UtcNow < healBackoff || Applying()) return;
    if (Interlocked.Exchange(ref healBusy, 1) == 1) return;
    try {
      if (NetOk(c)) return;
      Alerts.Log("כללי חומת האש שונו או נמחקו – משחזר");
      var cmds = new List<string> { "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True", "Remove-NetFirewallRule -Group 'DeviceGuardNet' -ErrorAction SilentlyContinue" };
      cmds.AddRange(NetAppsRules(c, new List<string>()));
      if (c.NetAppsWhite) cmds.Add("Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block");
      PSAll(cmds);
      if (!NetOk(c)) healBackoff = DateTime.UtcNow.AddMinutes(10);
    } catch { healBackoff = DateTime.UtcNow.AddMinutes(10); } finally { Interlocked.Exchange(ref healBusy, 0); }
  }
  // מתאמי רשת חדשים (מתאם USB, שיתוף אינטרנט מהטלפון) שחוברו אחרי ההחלה: נחסמים אוטומטית. הבדיקה זולה (ללא PowerShell כשאין חדש)
  static string NetHealFile => System.IO.Path.Combine(Config.Dir, "var", "netheal.txt");
  static readonly ConcurrentDictionary<string, DateTime> adBackoff = new(StringComparer.OrdinalIgnoreCase);
  public static void NetAdapterHeal(Config c) {
    if (!c.Master || !c.Net.On || Applying()) return;
    try {
      var wl = c.Net.White.Where(w => !w.StartsWith("ssid:")).ToHashSet(StringComparer.OrdinalIgnoreCase);
      var now = DateTime.UtcNow;
      var bad = NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback
        && n.NetworkInterfaceType != NetworkInterfaceType.Wireless80211 && n.NetworkInterfaceType != NetworkInterfaceType.Tunnel && !wl.Contains(n.Name)
        && !(adBackoff.TryGetValue(n.Name, out var until) && now < until)).Select(n => n.Name).ToList();
      if (bad.Count == 0) return;
      PSAll(bad.Select(n => $"Disable-NetAdapter -Name '{Q(n)}' -Confirm:$false").ToList());
      Directory.CreateDirectory(System.IO.Path.GetDirectoryName(NetHealFile)!); File.AppendAllLines(NetHealFile, bad);
      // מתאם שלא הצליח להיחסם: לא מנסים (ולא מתריעים) שוב כל 15 שניות, אלא רק בעוד 10 דקות
      var still = NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up && bad.Contains(n.Name)).Select(n => n.Name).ToList();
      foreach (var n in still) adBackoff[n] = now.AddMinutes(10);
      var done = bad.Except(still).ToList();
      if (done.Count > 0) Alerts.Log("מתאם רשת חדש נחסם: " + string.Join(", ", done));
      if (still.Count > 0) Alerts.Log("לא ניתן היה לחסום מתאם רשת (ניסיון נוסף בעוד 10 דקות): " + string.Join(", ", still));
    } catch { }
  }
  // שחזור חסימות שנמחקו מהרישום
  public static List<(string Exe, string Id)> IfeoList(Config c) {
    List<string> snap; lock (c.Applied) snap = c.Applied.Where(x => x.StartsWith("ifeo|")).ToList();
    return snap.Select(x => x.Split('|')).Where(p => p.Length >= 3).Select(p => (p[1], p[2])).ToList();
  }
  public static int Heal(List<(string Exe, string Id)> list) {
    int n = 0;
    foreach (var (exe, id) in list) {
      var want = GateCmd(id);
      foreach (var v in Views) { try { using var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, v); using var k = b.CreateSubKey(IFEO + exe); if (!want.Equals(k.GetValue("Debugger") as string)) { k.SetValue("Debugger", want); n++; } } catch { } }
    }
    return n;
  }
  // ---- חסימת סיומות (תמונות/שירים/סרטים/סיומות נוספות) בקוד ----
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
  static List<string> ExtFiles(Config c, Rule r) {
    var res = new List<string>(); var map = ExtMap(c);
    lock (LogLock) {
      DrainLog();
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
      var fi = new FileInfo(l[..i]); if (!fi.Exists) return;
      if (on) AclOn(fi, false); else AclOff(fi, false);
    } catch { }
  }
  static void UnlockExt(Config c, Rule r) { lock (ExtLock) { Mark(r.Id, true); Parallel.ForEach(ExtFiles(c, r), new ParallelOptions { MaxDegreeOfParallelism = Par }, l => SetLock(l, false)); } }
  static void RelockExt(Config c, Rule r) { lock (ExtLock) { Parallel.ForEach(ExtFiles(c, r), new ParallelOptions { MaxDegreeOfParallelism = Par }, l => SetLock(l, true)); Mark(r.Id, false); } }
  // אחרי הפעלה מחדש של השירות: חוקים שנשארו פתוחים (השירות נסגר בזמן שהחלון היה פתוח) ננעלים שוב
  public static void RelockPending(Config c) {
    try {
      if (!File.Exists(OpenMark)) return;
      foreach (var id in File.ReadAllLines(OpenMark)) {
        var r = c.Find(id);
        if (r != null && Program.Blocking(c) && r.On && IsExt(c, r)) { var rr = r; Task.Run(() => RelockExt(c, rr)); } else Mark(id, false);
      }
    } catch { }
  }
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
  public static void Unlock(Rule r, Config? c = null) { if (c != null && IsExt(c, r)) { UnlockExt(c, r); return; } try { if (Directory.Exists(r.Path)) UnwalkDir(r.Path); else AclOff(new FileInfo(r.Path), false); } catch { } }
  public static void Relock(Rule r, Config? c = null) { if (c != null && IsExt(c, r)) { Task.Run(() => RelockExt(c, r)); return; } try { if (Directory.Exists(r.Path)) { var subs = ListDirs(r.Path); AclOn(new DirectoryInfo(r.Path), true); DenySubs(subs); } else if (File.Exists(r.Path)) AclOn(new FileInfo(r.Path), false); } catch { } }

  // ---------- שירות ההגנה: התקנה ועדכון ----------
  static void Sc(string a) => RunExe("sc.exe", a);
  static bool ServiceExists() => RunExe2("sc.exe", "query DeviceGuard").Code == 0;
  static bool WaitUp(int sec) { for (int i = 0; i < sec * 2; i++) { if (Config.Up()) return true; Thread.Sleep(500); } return false; }
  static void CopyGate(string wd) {
    for (int i = 0; ; i++) {
      try { File.Copy(Environment.ProcessPath!, wd, true); return; }
      catch (Exception ex) when ((ex is IOException || ex is UnauthorizedAccessException) && i < 20) { Thread.Sleep(500); }
    }
  }
  // שער קל (NativeAOT): מוטמע בתוך הקובץ הראשי ומופרד לדיסק. מטפל במסלול המהיר של כל הפעלה חסומה ופונה לשער המלא רק כשצריך חלון
  static void DeployLightGate() {
    try {
      using var s = typeof(Enforcer).Assembly.GetManifestResourceStream("DeviceGuardGate.exe");
      if (s == null) { try { if (File.Exists(LightGateExe)) File.Delete(LightGateExe); } catch { } return; }
      var tmp = LightGateExe + ".new";
      using (var o = File.Create(tmp)) s.CopyTo(o);
      File.Move(tmp, LightGateExe, true);
    } catch { try { if (File.Exists(LightGateExe)) File.Delete(LightGateExe); } catch { } }   // כישלון בפריסה → חוזרים לשער המלא (GateCmd בודק אם הקובץ קיים)
  }
  static DateTime lastStart = DateTime.MinValue;
  // מנסה להפעיל את השירות אם הוא מותקן אך לא רץ (מוגבל בקצב, כדי שלא יתקע את הממשק)
  public static bool TryStartService() {
    if (Config.Up(300)) return true;
    if ((DateTime.UtcNow - lastStart).TotalSeconds < 20) return false;
    lastStart = DateTime.UtcNow;
    try { if (!ServiceExists()) return false; Sc("start DeviceGuard"); return WaitUp(10); } catch { return false; }
  }
  // התקנה חד-פעמית של שירות מערכת מוגן; אם הוא מגרסה ישנה מעדכנים אותו ב-EnsureService
  static void InstallService() {
    Directory.CreateDirectory(Config.Dir);
    var wd = GateExe; CopyGate(wd); DeployLightGate();
    var ex = RunExe2("sc.exe", $"create DeviceGuard binPath= \"\\\"{wd}\\\" --service\" start= auto obj= LocalSystem DisplayName= \"DeviceGuard Protection\"");
    if (ex.Code != 0 && !ServiceExists()) throw new IOException("יצירת שירות ההגנה נכשלה (קוד " + ex.Code + "). ודא שהתוכנה רצה כמנהל.");
    // ספריית החילוץ של .NET (קובץ יחיד) מוגדרת לתיקייה קבועה של השירות, כדי שלא יחולצו קבצים מחדש בכל הפעלה
    try {
      var xd = System.IO.Path.Combine(Config.Dir, "var", "net"); Directory.CreateDirectory(xd);
      using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\DeviceGuard", true);
      k?.SetValue("Environment", new[] { "DOTNET_BUNDLE_EXTRACT_BASE_DIR=" + xd }, RegistryValueKind.MultiString);
    } catch { }
    Sc("failure DeviceGuard reset= 0 actions= restart/1000/restart/1000/restart/1000"); Sc("failureflag DeviceGuard 1");
    SafeBootSet(true);
    Sc("start DeviceGuard");
    for (int i = 0; i < 20 && !Config.Up(); i++) Thread.Sleep(500);
    Sc("sdset DeviceGuard D:(A;;GA;;;SY)(A;;CCLCSWRPLOCRRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)");
    Config.Token = null; if (Program.Code != null) Config.Auth(Program.Code);   // הטוקן הישן לא תקף אחרי התקנה/עדכון
  }
  // עדכון: ההרשאות של השירות לא מאפשרות עצירה/מחיקה למנהל, ולכן מבקשים מהשירות עצמו (בעזרת טוקן תקף) להסיר את עצמו, ואז מתקינים את הגרסה החדשה
  static void UpdateService() {
    var r = Config.Token != null ? Config.Pipe("UNREG|" + Config.Token, 5000) : null;
    if (r != "OK" && Config.Token != null) r = Config.Pipe("UNINSTALL|" + Config.Token, 5000);   // שירות מגרסה ישנה (שלא מכיר UNREG) מסיר את עצמו דרך הפקודה הישנה
    if (r != "OK") { Sc("stop DeviceGuard"); Sc("delete DeviceGuard"); }
    for (int i = 0; i < 60 && ServiceExists(); i++) Thread.Sleep(500);
    if (ServiceExists()) throw new IOException("לא ניתן היה להסיר את שירות ההגנה הישן לצורך עדכון. הפעל מחדש את המחשב ונסה שוב.");
    foreach (var pr in Process.GetProcessesByName("DeviceGuardWatch")) { try { pr.Kill(); pr.WaitForExit(3000); } catch { } finally { pr.Dispose(); } }
    Thread.Sleep(1000); InstallService();
  }
  // מתקין את השירות אם אינו קיים, ומעדכן אותו אוטומטית אם הוא מגרסה אחרת (הגרסה נקבעת לפי תוכן הקובץ, בלי מספר ידני)
  public static void EnsureService() {
    if (!Config.Up()) {
      if (ServiceExists()) {
        Sc("start DeviceGuard");
        if (!WaitUp(15)) {
          Sc("stop DeviceGuard"); Sc("delete DeviceGuard"); Thread.Sleep(2000);
          if (ServiceExists()) throw new IOException("שירות ההגנה אינו מגיב. הפעל מחדש את המחשב ונסה שוב.");
          InstallService(); return;
        }
      } else { InstallService(); return; }
    }
    if (Config.Pipe("VER", 5000) == Program.Ver) return;
    UpdateService();
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

  // ---------- ביטול ----------
  static void RevertFile(string e) {
    var p = e.Split('|');
    if (p[0] == "acl") {
      bool dir = Directory.Exists(p[1]);
      if (dir) UnwalkDir(p[1]);
      else AclOff(new FileInfo(p[1]), false);
    } else File.SetAttributes(p[1], (FileAttributes)int.Parse(p[2]));
  }
  // משחרר חסימות שהיו בהחלה הקודמת ולא נדרשו מחדש
  static void FinishRevert(Config c) {
    var ps = new List<string>(); foreach (var id in prevUsb.Keys) ps.Add($"Enable-PnpDevice -InstanceId '{Q(id)}' -Confirm:$false");
    var accs = prevAcl.Keys.ToList(); var hids = prevHid.Values.ToList(); prevUsb.Clear(); prevAcl.Clear(); prevHid.Clear(); prevNet.Clear();
    Task? t = ps.Count > 0 ? Task.Run(() => PSAll(ps)) : null;
    try {
      var po = new ParallelOptions { MaxDegreeOfParallelism = Par };
      Parallel.ForEach(accs, po, p => { try { RevertFile("acl|" + p); } catch { } });
      Parallel.ForEach(hids, po, e => { try { RevertFile(e); } catch { } });
    } catch { }
    try { t?.Wait(); } catch { }
  }
  // soft = קריאה מתוך Apply: מתאמי רשת שעתידים להישאר חסומים לא מופעלים ונחסמים מחדש
  public static void Revert(Config c, bool soft = false) {
    var keepNet = soft && c.Master && c.Net.On;
    var keepAd = keepNet ? c.Net.White.Where(w => !w.StartsWith("ssid:")).ToHashSet() : null;
    var ps = new List<string>();
    List<string> all; lock (c.Applied) all = c.Applied.ToList();
    if (soft && c.Master) {   // חסימות קבצים והתקני USB שכבר קיימות נשארות כמו שהן; FinishRevert ישחרר רק את מה שכבר לא נדרש
      var rest = new List<string>();
      foreach (var e in all) {
        var q = e.Split('|');
        if (q[0] == "usb" && q.Length > 1) prevUsb[q[1]] = 0;
        else if (q[0] == "acl" && q.Length > 1 && ((q.Length > 2 && q[2] == "h2") == Harden) && !Directory.Exists(q[1])) prevAcl[q[1]] = 0;
        else if (q[0] == "hid" && q.Length > 2 && !Directory.Exists(q[1])) prevHid[q[1]] = e;
        else rest.Add(e);
      }
      all = rest;
    }
    var regs = all.Where(x => x.StartsWith("reg|")).ToList(); var rkeys = all.Where(x => x.StartsWith("regkey|")).ToList();
    var others = all.Where(x => !(x.StartsWith("reg|") || x.StartsWith("regkey|") || x.StartsWith("acl|") || x.StartsWith("hid|"))).OrderBy(x => x.StartsWith("task") ? 0 : x.StartsWith("ifeo") ? 1 : 2).ToList();
    foreach (var e in others) {
      var p = e.Split('|');
      try {
        switch (p[0]) {
          case "ifeo":
            foreach (var v in Views) {
              using var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, v); using var parent = b.OpenSubKey(IFEO.TrimEnd('\\'), true); if (parent == null) continue;
              using (var k = parent.OpenSubKey(p[1], true)) k?.DeleteValue("Debugger", false);
              using (var k2 = parent.OpenSubKey(p[1])) { if (k2 != null && k2.ValueCount == 0 && k2.SubKeyCount == 0) { k2.Close(); parent.DeleteSubKey(p[1], false); } }
            }
            break;
          case "net": if (keepAd != null && !keepAd.Contains(p[1])) { prevNet[p[1]] = 0; break; } ps.Add($"Enable-NetAdapter -Name '{Q(p[1])}' -Confirm:$false"); break;
          case "usb": ps.Add($"Enable-PnpDevice -InstanceId '{Q(p[1])}' -Confirm:$false"); break;
          case "usbstor": { using var k = Registry.LocalMachine.OpenSubKey(USBSTOR, true); k?.SetValue("Start", 3); break; }   // רשומה ישנה (גרסאות קודמות)
          case "lnk": File.Delete(p[1]); break;
          case "task": Schtasks("/End /TN DeviceGuardWatch"); Schtasks("/Delete /TN DeviceGuardWatch /F"); break;
          case "hostslock": { var fi = new FileInfo(HostsPath); if (fi.Exists) { var sec = fi.GetAccessControl(); sec.RemoveAccessRule(HostsDeny); fi.SetAccessControl(sec); } break; }
          case "hideui": {   // רשומה ישנה
              using (var k = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL")) k.SetValue("CheckedValue", 1);
              using (var k = Registry.LocalMachine.OpenSubKey(EXP, true)) k?.DeleteValue("NoFolderOptions", false);
              using (var k = Registry.CurrentUser.OpenSubKey(EXP, true)) k?.DeleteValue("NoFolderOptions", false);
              break; }
          case "safer": Registry.LocalMachine.DeleteSubKeyTree(SAFER, false); break;   // רשומות ישנות
          case "devrestrict": Registry.LocalMachine.DeleteSubKeyTree(DEVREST, false); break;
          case "rsd": Registry.LocalMachine.DeleteSubKeyTree(RSD, false); break;
          case "fwpolicy": if (p.Length > 2) ps.Add($"Set-NetFirewallProfile -Profile {p[1]} -DefaultOutboundAction {p[2]}"); break;
          case "fwrules": ps.Add("Remove-NetFirewallRule -Group 'DeviceGuardNet' -ErrorAction SilentlyContinue"); break;
          case "wlanfilter":
            if (p.Length > 1 && p[1] == "denyall") Netsh("wlan delete filter permission=denyall networktype=infrastructure");
            else if (p.Length > 2 && p[1] == "allow") Netsh($"wlan delete filter permission=allow ssid=\"{p[2].Replace("\"", "")}\" networktype=infrastructure");
            break;
        }
      } catch { }
    }
    foreach (var e in Enumerable.Reverse(regs)) { try { RevertReg(e); } catch { } }   // בסדר הפוך: הערך המקורי ביותר משוחזר אחרון
    // מפתח שנוצר על ידינו נמחק רק אם לא נשארו בו (או מתחתיו) ערכים – כדי לא למחוק ערכים שתוכנה/מדיניות אחרת הוסיפה בינתיים
    foreach (var e in rkeys.OrderByDescending(x => x.Length)) {
      try {
        var p = e.Split('|'); var root = Root(p[1]); if (root == null) continue;
        bool empty; using (var k = root.OpenSubKey(p[2])) { if (k == null) continue; empty = !HasValues(k); }
        if (empty) root.DeleteSubKeyTree(p[2], false);
      } catch { }
    }
    if (!keepNet) { try { if (File.Exists(NetHealFile)) { foreach (var n in File.ReadAllLines(NetHealFile).Distinct()) ps.Add($"Enable-NetAdapter -Name '{Q(n)}' -Confirm:$false"); File.Delete(NetHealFile); } } catch { } }
    try { PSAll(ps); } catch { }
    try {   // שחרור קבצים ותיקיות במקביל (כל נתיב בנפרד, לפי הסדר שבו נחסם)
      Parallel.ForEach(all.Where(x => x.StartsWith("acl|") || x.StartsWith("hid|")).GroupBy(x => x.Split('|')[1]), new ParallelOptions { MaxDegreeOfParallelism = Par }, g => { foreach (var e in g) { try { RevertFile(e); } catch { } } });
    } catch { }
    if (!(soft && c.Master)) try {   // קבצים שנחסמו אוטומטית על ידי שירות הרקע
      lock (LogLock) { DrainLog(); if (File.Exists(WatchLog)) { Parallel.ForEach(File.ReadAllLines(WatchLog), new ParallelOptions { MaxDegreeOfParallelism = Par }, UnblockLine); File.Delete(WatchLog); } }
      known.Clear();
    } catch { }
    lock (c.Applied) c.Applied.Clear();
    if (!soft) c.State = 0;
  }
}
