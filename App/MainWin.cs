using System.Collections.Concurrent; using System.Diagnostics; using System.IO; using System.Text.Json; using System.Threading; using System.Threading.Tasks; using System.Windows; using System.Windows.Controls; using System.Windows.Controls.Primitives;
using System.Windows.Interop; using System.Windows.Media; using System.Windows.Media.Imaging; using System.Windows.Threading; using Microsoft.Win32;
namespace DG;
// מריץ את Enforcer.Apply על תהליכון STA ייעודי, כדי שיצירת קיצורי דרך (COM) תהיה אמינה בוודאות
public class StaTaskScheduler : TaskScheduler, IDisposable {
  readonly BlockingCollection<Task> q = new(); readonly Thread t;
  public StaTaskScheduler() { t = new Thread(() => { foreach (var task in q.GetConsumingEnumerable()) TryExecuteTask(task); }); t.SetApartmentState(ApartmentState.STA); t.IsBackground = true; t.Start(); }
  protected override IEnumerable<Task>? GetScheduledTasks() => null;
  protected override void QueueTask(Task task) => q.Add(task);
  protected override bool TryExecuteTaskInline(Task task, bool prev) => false;
  public void Dispose() => q.CompleteAdding();
}
public static class Theme {
  public static readonly Brush Accent = new SolidColorBrush(Color.FromRgb(37, 99, 235));
  static Style Make(Type t, Color bg, Color? offBg = null) {
    var s = new Style(t);
    s.Setters.Add(new Setter(Control.BackgroundProperty, new SolidColorBrush(bg)));
    s.Setters.Add(new Setter(Control.ForegroundProperty, Brushes.White));
    s.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(14, 7, 14, 7)));
    s.Setters.Add(new Setter(Control.BorderThicknessProperty, new Thickness(0)));
    s.Setters.Add(new Setter(FrameworkElement.CursorProperty, System.Windows.Input.Cursors.Hand));
    var b = new FrameworkElementFactory(typeof(Border), "b");
    b.SetValue(Border.CornerRadiusProperty, new CornerRadius(8));
    b.SetValue(Border.BackgroundProperty, new TemplateBindingExtension(Control.BackgroundProperty));
    b.SetValue(Border.PaddingProperty, new TemplateBindingExtension(Control.PaddingProperty));
    var cp = new FrameworkElementFactory(typeof(ContentPresenter));
    cp.SetValue(FrameworkElement.HorizontalAlignmentProperty, new TemplateBindingExtension(Control.HorizontalContentAlignmentProperty));
    cp.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);
    b.AppendChild(cp);
    var tpl = new ControlTemplate(t) { VisualTree = b };
    var hov = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true }; hov.Setters.Add(new Setter(UIElement.OpacityProperty, 0.85, "b"));
    tpl.Triggers.Add(hov);
    s.Setters.Add(new Setter(Control.TemplateProperty, tpl));
    if (offBg != null) { var off = new Trigger { Property = ToggleButton.IsCheckedProperty, Value = false }; off.Setters.Add(new Setter(Control.BackgroundProperty, new SolidColorBrush(offBg.Value))); s.Triggers.Add(off); }
    return s;
  }
  public static readonly FontFamily IconFont = new FontFamily("Segoe Fluent Icons, Segoe MDL2 Assets");
  public static TextBlock Glyph(string g, double size, Brush fg) => new TextBlock { Text = g, FontFamily = IconFont, FontSize = size, Foreground = fg, VerticalAlignment = VerticalAlignment.Center, HorizontalAlignment = HorizontalAlignment.Center };
  public static UIElement IconText(string g, string text) {
    var sp = new StackPanel { Orientation = Orientation.Horizontal };
    var ic = Glyph(g, 16, Brushes.White); ic.Margin = new Thickness(0, 0, 10, 0); sp.Children.Add(ic);
    sp.Children.Add(new TextBlock { Text = text, VerticalAlignment = VerticalAlignment.Center }); return sp;
  }
  public static UIElement Badge(string g) => new Border { Width = 38, Height = 38, CornerRadius = new CornerRadius(10), Background = new SolidColorBrush(Color.FromRgb(239, 246, 255)), Margin = new Thickness(0, 0, 12, 0), VerticalAlignment = VerticalAlignment.Center, Child = Glyph(g, 18, Accent) };
  static Style Switch() {
    var s = new Style(typeof(CheckBox));
    s.Setters.Add(new Setter(FrameworkElement.CursorProperty, System.Windows.Input.Cursors.Hand));
    s.Setters.Add(new Setter(Control.ForegroundProperty, new SolidColorBrush(Color.FromRgb(31, 41, 55))));
    var root = new FrameworkElementFactory(typeof(StackPanel)); root.SetValue(StackPanel.OrientationProperty, Orientation.Horizontal); root.SetValue(Panel.BackgroundProperty, Brushes.Transparent);
    var track = new FrameworkElementFactory(typeof(Border), "track");
    track.SetValue(FrameworkElement.WidthProperty, 42.0); track.SetValue(FrameworkElement.HeightProperty, 22.0); track.SetValue(Border.CornerRadiusProperty, new CornerRadius(11));
    track.SetValue(Border.BackgroundProperty, new SolidColorBrush(Color.FromRgb(203, 213, 225))); track.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);
    var thumb = new FrameworkElementFactory(typeof(System.Windows.Shapes.Ellipse), "thumb");
    thumb.SetValue(FrameworkElement.WidthProperty, 16.0); thumb.SetValue(FrameworkElement.HeightProperty, 16.0); thumb.SetValue(System.Windows.Shapes.Shape.FillProperty, Brushes.White);
    thumb.SetValue(FrameworkElement.MarginProperty, new Thickness(3)); thumb.SetValue(FrameworkElement.HorizontalAlignmentProperty, HorizontalAlignment.Left);
    track.AppendChild(thumb); root.AppendChild(track);
    var cp = new FrameworkElementFactory(typeof(ContentPresenter)); cp.SetValue(FrameworkElement.MarginProperty, new Thickness(10, 0, 0, 0)); cp.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);
    root.AppendChild(cp);
    var tpl = new ControlTemplate(typeof(CheckBox)) { VisualTree = root };
    var on = new Trigger { Property = ToggleButton.IsCheckedProperty, Value = true };
    on.Setters.Add(new Setter(Border.BackgroundProperty, Accent, "track")); on.Setters.Add(new Setter(FrameworkElement.HorizontalAlignmentProperty, HorizontalAlignment.Right, "thumb"));
    tpl.Triggers.Add(on); s.Setters.Add(new Setter(Control.TemplateProperty, tpl)); return s;
  }
  public static void Apply(Application app) {
    app.Resources[typeof(CheckBox)] = Switch();
    app.Resources[typeof(Button)] = Make(typeof(Button), Color.FromRgb(37, 99, 235));
    app.Resources[typeof(ToggleButton)] = Make(typeof(ToggleButton), Color.FromRgb(22, 163, 74), Color.FromRgb(220, 38, 38));
  }
}
public static class Program {
  static volatile Dictionary<string, Rule> curMap = new();
  public static string? Code;
  static readonly System.Collections.Concurrent.ConcurrentDictionary<string, DateTime> lease = new();
  static readonly System.Collections.Concurrent.ConcurrentDictionary<string, bool> tokens = new();
  static readonly System.Collections.Concurrent.ConcurrentDictionary<string, (int N, DateTime Until)> fails = new();
  static DateTime authLock = DateTime.MinValue; static int authFails;
  static readonly ConcurrentDictionary<int, bool> authPid = new();   // תהליכים שכבר עברו קוד דרך IFEO – לא לבקש מהם קוד שוב
  static readonly ConcurrentDictionary<int, bool> promptedPid = new();   // תהליכים שכבר קיבלו חלון קוד תגובתי – לא לפתוח עוד אחד לאותו תהליך
  class GuardService : System.ServiceProcess.ServiceBase {
    public GuardService() { ServiceName = "DeviceGuard"; }
    protected override void OnStart(string[] a) { new Thread(Watch) { IsBackground = true }.Start(); }
  }
  static void Icacls(string a) { try { Process.Start(new ProcessStartInfo("icacls", a) { CreateNoWindow = true, UseShellExecute = false })!.WaitForExit(); } catch { } }
  static void LockDir() {   // מנהל רגיל לא יכול לשנות את תיקיית ההגנה; רק השירות
    try {
      var v = System.IO.Path.Combine(Config.Dir, "var"); Directory.CreateDirectory(v);
      Icacls($"\"{Config.Dir}\" /inheritance:r /grant *S-1-5-18:(OI)(CI)F /grant *S-1-5-32-544:(OI)(CI)RX /grant *S-1-5-32-545:(OI)(CI)RX");
      Icacls($"\"{v}\" /grant *S-1-5-32-544:(OI)(CI)F");
    } catch { }
  }
  static string Handle(string line) {
    try {
      var p = line.Split('|', 4); var cfgPath = System.IO.Path.Combine(Config.Dir, "config.json");
      switch (p[0]) {
        case "HELLO": return "OK";
        case "VER": return "2";
        case "AUTH": {
            if (DateTime.UtcNow < authLock) return "LOCK";
            if (Config.Check(string.Join("|", p.Skip(1)), Config.Load().AppCode)) { authFails = 0; var t = Guid.NewGuid().ToString("N"); tokens[t] = true; return "TOKEN|" + t; }
            if (++authFails >= 5) { authFails = 0; authLock = DateTime.UtcNow.AddSeconds(60); }
            return "BAD"; }
        case "SAVE": {
            if (p.Length < 3 || !tokens.ContainsKey(p[1])) return "DENY";
            var json = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(p[2]));
            if (System.Text.Json.JsonSerializer.Deserialize<Config>(json, Config.O) == null) return "ERR";
            var tmp = cfgPath + ".tmp"; File.WriteAllText(tmp, json); File.Move(tmp, cfgPath, true); return "OK"; }
        case "COPY": {
            if (p.Length < 4 || !tokens.ContainsKey(p[1]) || p[3] != "Gate.exe") return "DENY";
            File.Copy(p[2], System.IO.Path.Combine(Config.Dir, "Gate.exe"), true); return "OK"; }
        case "OPEN": {
            var c = Config.Load(); var r = c.Find(p[1]);
            if (r == null || !r.On || !c.Master || r.Mode != Mode.Code || !c.Paths.Contains(r)) return "ERR";
            if (fails.TryGetValue(p[1], out var f) && DateTime.UtcNow < f.Until) return "LOCK";
            if (!c.CodeOk(r, string.Join("|", p.Skip(2)))) {
              var n = (fails.TryGetValue(p[1], out var f2) ? f2.N : 0) + 1;
              fails[p[1]] = n >= 5 ? (0, DateTime.UtcNow.AddSeconds(60)) : (n, DateTime.MinValue); return "BAD";
            }
            fails.TryRemove(p[1], out _); Enforcer.Unlock(r); lease[p[1]] = DateTime.UtcNow; return "OK"; }
        case "AUTHPID": if (p.Length > 1 && int.TryParse(p[1], out var apid)) authPid[apid] = true; return "OK";
        case "PING": if (lease.ContainsKey(p[1])) lease[p[1]] = DateTime.UtcNow; return "OK";
        case "RELOCK": {
            if (lease.TryRemove(p[1], out _)) { var c = Config.Load(); var r = c.Find(p[1]); if (r != null && c.Master && r.On) Enforcer.Relock(r); }
            return "OK"; }
        case "UNINSTALL": {
            if (p.Length < 2 || !tokens.ContainsKey(p[1])) return "DENY";
            Process.Start(new ProcessStartInfo("cmd.exe", "/c sc sdset DeviceGuard \"D:(A;;GA;;;SY)(A;;GA;;;BA)\" & ping -n 3 127.0.0.1 >nul & sc stop DeviceGuard & sc delete DeviceGuard & icacls \"" + Config.Dir + "\" /grant *S-1-5-32-544:(OI)(CI)F") { CreateNoWindow = true, UseShellExecute = false });
            return "OK"; }
      }
    } catch { }
    return "ERR";
  }
  static void PipeServer() {
    var ps = new System.IO.Pipes.PipeSecurity();
    var sid = (System.Security.Principal.WellKnownSidType t) => new System.Security.Principal.SecurityIdentifier(t, null);
    ps.AddAccessRule(new System.IO.Pipes.PipeAccessRule(sid(System.Security.Principal.WellKnownSidType.NetworkSid), System.IO.Pipes.PipeAccessRights.FullControl, System.Security.AccessControl.AccessControlType.Deny));
    ps.AddAccessRule(new System.IO.Pipes.PipeAccessRule(sid(System.Security.Principal.WellKnownSidType.AuthenticatedUserSid), System.IO.Pipes.PipeAccessRights.ReadWrite, System.Security.AccessControl.AccessControlType.Allow));
    ps.AddAccessRule(new System.IO.Pipes.PipeAccessRule(sid(System.Security.Principal.WellKnownSidType.LocalSystemSid), System.IO.Pipes.PipeAccessRights.FullControl, System.Security.AccessControl.AccessControlType.Allow));
    while (true) {
      try {
        var st = System.IO.Pipes.NamedPipeServerStreamAcl.Create("DeviceGuard.Unlock", System.IO.Pipes.PipeDirection.InOut, 16, System.IO.Pipes.PipeTransmissionMode.Byte, System.IO.Pipes.PipeOptions.None, 0, 0, ps);
        st.WaitForConnection();
        Task.Run(() => { try { using (st) { var rd = new StreamReader(st); var wr = new StreamWriter(st) { AutoFlush = true }; var l = rd.ReadLine(); if (l != null) wr.WriteLine(Handle(l)); } } catch { } });
      } catch { Thread.Sleep(500); }
    }
  }
  public static void Watch() {
    LockDir(); new Thread(PipeServer) { IsBackground = true }.Start();
    var alias = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase) { ["calc"] = new[] { "CalculatorApp", "Calculator" } };
    var q = new System.Collections.Concurrent.ConcurrentQueue<(string P, int T, DateTime At)>();
    var fsw = new List<FileSystemWatcher>();
    void Add(string p) { if (curMap.ContainsKey(System.IO.Path.GetExtension(p).TrimStart('.').ToLowerInvariant())) q.Enqueue((p, 0, DateTime.UtcNow.AddSeconds(2))); }
    var watched = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    void Watch1(string root) {
      if (!watched.Add(root)) return;
      try {
        var w = new FileSystemWatcher(root) { IncludeSubdirectories = true, NotifyFilter = NotifyFilters.FileName, InternalBufferSize = 65536 };
        w.Created += (s, e) => Add(e.FullPath); w.Renamed += (s, e) => Add(e.FullPath); w.EnableRaisingEvents = true; fsw.Add(w);
      } catch { }
    }
    foreach (var dr in DriveInfo.GetDrives().Where(x => (x.DriveType == DriveType.Fixed || x.DriveType == DriveType.Removable) && x.IsReady)) Watch1(dr.RootDirectory.FullName);
    var cfg = System.IO.Path.Combine(Config.Dir, "config.json"); var stamp = DateTime.MinValue; var c = new Config(); var kill = new HashSet<string>(StringComparer.OrdinalIgnoreCase); var lastScan = DateTime.MinValue;
    var codeKill = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);   // שם תהליך → מזהה חוק, לתוכנות בחסימת קוד (רשת ביטחון לתוכנות שה-IFEO לא תופס, כמו אפליקציות Store)
    var gateExe = System.IO.Path.Combine(Config.Dir, "DeviceGuardWatch.exe");
    while (true) {
      try {
        foreach (var dr in DriveInfo.GetDrives().Where(x => (x.DriveType == DriveType.Fixed || x.DriveType == DriveType.Removable) && x.IsReady)) {   // כונן חיצוני חדש שחובר – להתחיל לעקוב אחריו ולסרוק מיד
          if (watched.Contains(dr.RootDirectory.FullName)) continue;
          Watch1(dr.RootDirectory.FullName);
          if (curMap.Count > 0) Enforcer.ScanNew(curMap);
        }
        var ts = File.GetLastWriteTimeUtc(cfg);
        if (ts != stamp) {   // טוען מחדש רק כשהקובץ השתנה
          stamp = ts; c = Config.Load(); kill.Clear();
          codeKill.Clear();
          if (c.Master) foreach (var r in c.Programs.Where(r => r.On)) {
            var n = System.IO.Path.GetFileNameWithoutExtension(r.Path);
            if (n.Equals("DeviceGuard", StringComparison.OrdinalIgnoreCase) || n.Equals("DeviceGuardWatch", StringComparison.OrdinalIgnoreCase)) continue;
            if (r.Mode == Mode.Full) { kill.Add(n); if (alias.TryGetValue(n, out var al)) foreach (var x in al) kill.Add(x); }
            else { codeKill[n] = r.Id; if (alias.TryGetValue(n, out var al)) foreach (var x in al) codeKill[x] = r.Id; }
          }
          curMap = c.Master ? Enforcer.ExtMap(c) : new();
        }
        foreach (var kv in lease.ToArray()) if ((DateTime.UtcNow - kv.Value).TotalSeconds > 15 && lease.TryRemove(kv.Key, out _)) { var lr = c.Find(kv.Key); if (lr != null && c.Master && lr.On) Enforcer.Relock(lr); }
        if (c.Master) {
          if (kill.Count > 0 || codeKill.Count > 0) foreach (var pr in Process.GetProcesses()) {
            try {
              if (kill.Contains(pr.ProcessName)) { pr.Kill(); continue; }
              // תוכנה בחסימת קוד שרצה בכל זאת (לא נתפסה מראש ב-IFEO, כמו אפליקציות Store): לבקש קוד מהמשתמש המחובר, אחרת לסגור
              if (codeKill.TryGetValue(pr.ProcessName, out var ruleId) && !authPid.ContainsKey(pr.Id) && promptedPid.TryAdd(pr.Id, true))
                UserSession.Launch(gateExe, $"--promptkill {ruleId} {pr.Id}");
            } catch { } finally { pr.Dispose(); }
          }
          int cnt = q.Count;
          for (int i = 0; i < cnt && q.TryDequeue(out var it); i++) {
            if (it.At > DateTime.UtcNow) { q.Enqueue(it); continue; }
            if (curMap.TryGetValue(System.IO.Path.GetExtension(it.P).TrimStart('.').ToLowerInvariant(), out var rr) && !Enforcer.BlockNewFile(rr, it.P) && it.T < 5) q.Enqueue((it.P, it.T + 1, DateTime.UtcNow.AddSeconds(3)));
          }
          if (curMap.Count > 0 && (DateTime.UtcNow - lastScan).TotalMinutes >= 10) { lastScan = DateTime.UtcNow; Enforcer.ScanNew(curMap); }
          if ((DateTime.UtcNow - ts).TotalSeconds > 5) Enforcer.Heal(c);
        } else { while (q.TryDequeue(out _)) { } }
        if (DateTime.UtcNow.Second == 0) {   // ניקוי תקופתי של מזהי תהליכים שכבר לא רצים (כדי שמספר pid לא יישאר מסומן לנצח)
          foreach (var pid in authPid.Keys.ToArray()) if (!Alive(pid)) authPid.TryRemove(pid, out _);
          foreach (var pid in promptedPid.Keys.ToArray()) if (!Alive(pid)) promptedPid.TryRemove(pid, out _);
        }
      } catch { }
      Thread.Sleep(1000);
    }
  }
  static bool Alive(int pid) { try { Process.GetProcessById(pid); return true; } catch { return false; } }
  [STAThread] public static void Main(string[] args) {
    if (args.Contains("--service")) { System.ServiceProcess.ServiceBase.Run(new GuardService()); return; }
    if (args.Contains("--watch")) { Watch(); return; }
    if (args.Length >= 2 && args[0] == "--gate") { GateMode.RunGate(args); return; }
    if (args.Length == 2 && args[0] == "--open") { GateMode.OpenFlow(args[1]); return; }
    if (args.Length == 3 && args[0] == "--promptkill") { GateMode.PromptKill(args); return; }
    if (!IsAdmin()) { try { Process.Start(new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true, Verb = "runas" }); } catch { } return; }
    RunUi();
  }
  static bool IsAdmin() { using var id = System.Security.Principal.WindowsIdentity.GetCurrent(); return new System.Security.Principal.WindowsPrincipal(id).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator); }
  static void RunUi() {
    try {
      var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown }; Theme.Apply(app);
      app.DispatcherUnhandledException += (s, e) => { MessageBox.Show(e.Exception.Message, "DeviceGuard"); e.Handled = true; };
      var c = Config.Load();
      if (c.AppCode == null) {
        var k = MainWin.Ask("הגדר קוד כניסה לתוכנה", true); if (k == null) return;
        Code = k; c.AppCode = Config.Hash(k); c.OwnerUser = Environment.UserName; c.Save();
      } else {
        while (true) { var k = MainWin.Ask("הזן קוד כניסה"); if (k == null) return; if (Config.Check(k, c.AppCode)) { Code = k; break; } MessageBox.Show("קוד שגוי"); }
      }
      if (Code != null && Config.Up() && !Config.Auth(Code)) MessageBox.Show("האימות מול שירות ההגנה נכשל");
      var w = new MainWin(c); app.MainWindow = w; app.ShutdownMode = ShutdownMode.OnMainWindowClose; app.Run(w);
    } catch (Exception x) { MessageBox.Show(x.ToString(), "DeviceGuard – שגיאה"); }
  }
}
public class MainWin : Window {
  Config C; Func<UIElement>? cur; readonly List<Rule> opened = new(); List<(string N, string E)>? inst; ContentControl host = new(); TextBlock status = new(); DispatcherTimer? tmr;
  public MainWin(Config c) {
    C = c; Title = "DeviceGuard – מנהל חסימות"; Width = 1050; Height = 720; FlowDirection = FlowDirection.RightToLeft; FontSize = 14; Background = new SolidColorBrush(Color.FromRgb(243, 244, 246)); FontFamily = new FontFamily("Segoe UI");
    var tg = new ToggleButton { IsChecked = C.Master, Padding = new Thickness(14, 6, 14, 6), Margin = new Thickness(0, 0, 8, 0) };
    void Lbl() => tg.Content = tg.IsChecked == true ? Theme.IconText("\uE72E", "החסימות פעילות – לחץ להשבתה") : Theme.IconText("\uE785", "החסימות מושבתות – לחץ להפעלה");
    Lbl(); tg.Click += async (s, e) => { C.Master = tg.IsChecked == true; Lbl(); await Do(); };
    var ap = Btn("החל שינויים", () => { }, "\uE73E"); ap.Click += async (s, e) => await Do();
    var un = Btn("פתיחה זמנית (30 דק׳)", () => { }, "\uE785");
    un.Click += async (s, e) => {
      var k = Ask("קוד ברירת מחדל"); if (k == null) return; if (!Config.Check(k, C.DefaultCode)) { MessageBox.Show(C.DefaultCode == null ? "לא הוגדר קוד ברירת מחדל (חלון 1)" : "קוד שגוי"); return; }
      IsEnabled = false; await Task.Run(() => Enforcer.Revert(C)); C.Save(); IsEnabled = true;
      tmr?.Stop(); tmr = new DispatcherTimer { Interval = TimeSpan.FromMinutes(30) }; tmr.Tick += async (a, b) => { tmr.Stop(); await Do(); }; tmr.Start(); status.Text = "החסימות פתוחות זמנית";
    };
    var top = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0), Background = Brushes.White };
    top.Children.Add(tg); top.Children.Add(ap); top.Children.Add(un); top.Children.Add(SearchBox()); top.Children.Add(status); foreach (FrameworkElement ch in top.Children) { ch.Margin = new Thickness(8, 10, 0, 10); ch.VerticalAlignment = VerticalAlignment.Center; }
    var side = new StackPanel { Width = 210, Background = new SolidColorBrush(Color.FromRgb(17, 24, 39)) };
    var pages = new (string, string, Func<UIElement>)[] { ("הגדרות כלליות", "\uE713", P1), ("תוכנות מותקנות", "\uE71D", P2), ("תוכנות ניידות", "\uE8A7", P3), ("סוגי קבצים", "\uE8A5", P4), ("קבצים ותיקיות", "\uE8B7", P5) };
    var logo = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(18, 22, 18, 14) };
    logo.Children.Add(Theme.Glyph("\uE72E", 22, Brushes.White)); logo.Children.Add(new TextBlock { Text = "  DeviceGuard", Foreground = Brushes.White, FontSize = 20, FontWeight = FontWeights.Bold });
    side.Children.Add(logo);
    var nav = new List<Button>();
    foreach (var (n, g, f) in pages) { var b = new Button { Content = Theme.IconText(g, n), Padding = new Thickness(14, 13, 14, 13), Margin = new Thickness(10, 4, 10, 0), Background = Brushes.Transparent, FontSize = 15, HorizontalContentAlignment = HorizontalAlignment.Left }; nav.Add(b); b.Click += (s, e) => { foreach (var x in nav) x.Background = Brushes.Transparent; b.Background = Theme.Accent; cur = f; host.Content = f(); }; side.Children.Add(b); }
    nav[0].Background = Theme.Accent;
    var root = new DockPanel(); DockPanel.SetDock(top, Dock.Top); DockPanel.SetDock(side, Dock.Left); // ב-RTL: מופיע מימין
    root.Children.Add(top); root.Children.Add(side); root.Children.Add(host); Content = root; host.Content = P1(); Closing += (s, e) => { foreach (var r in opened) if (C.Master && r.On) Enforcer.Relock(r); };
  }
  async Task Do() {
    if (C.Master && C.DefaultCode == null && C.All().Any(r => r.On && r.Mode == Mode.Code && r.OwnCode == null)) { MessageBox.Show("יש חסימות בקוד שאין להן קוד. הגדר קוד ברירת מחדל (חלון 1) או קוד נפרד לכל חסימה."); return; }
    status.Text = "מחיל..."; IsEnabled = false;
    try {
      await Task.Factory.StartNew(() => Enforcer.Apply(C), CancellationToken.None, TaskCreationOptions.None, new StaTaskScheduler());
      status.Text = "הוחל ✓";
    } catch (Exception x) { status.Text = "שגיאה: " + x.Message; MessageBox.Show("שגיאה בהחלת החסימות: " + x.Message); }
    IsEnabled = true;
  }

  // ---------- דיאלוגים ----------
  public static string? Ask(string title, bool confirm = false) {
    var w = new Window { Title = title, SizeToContent = SizeToContent.WidthAndHeight, WindowStartupLocation = WindowStartupLocation.CenterScreen, FlowDirection = FlowDirection.RightToLeft, ResizeMode = ResizeMode.NoResize, Topmost = true };
    var sp = new StackPanel { Margin = new Thickness(16) }; var a = new PasswordBox { Width = 240, Margin = new Thickness(0, 4, 0, 8) }; var b = new PasswordBox { Width = 240, Margin = new Thickness(0, 4, 0, 8) };
    sp.Children.Add(new TextBlock { Text = title }); sp.Children.Add(a);
    if (confirm) { sp.Children.Add(new TextBlock { Text = "אימות הקוד" }); sp.Children.Add(b); }
    string? res = null; var ok = new Button { Content = "אישור", IsDefault = true, Padding = new Thickness(10, 4, 10, 4) };
    ok.Click += (s, e) => { if (a.Password.Length == 0) return; if (confirm && a.Password != b.Password) { MessageBox.Show("הקודים אינם זהים"); return; } res = a.Password; w.Close(); };
    sp.Children.Add(ok); w.Content = sp; w.ShowDialog(); return res;
  }
  public static List<string>? Pick(string title, IEnumerable<(string L, string V)> opts, IEnumerable<string> sel) {
    var w = new Window { Title = title, Width = 420, Height = 520, WindowStartupLocation = WindowStartupLocation.CenterScreen, FlowDirection = FlowDirection.RightToLeft };
    var lb = new StackPanel(); var boxes = opts.Select(o => new CheckBox { Content = o.L, Tag = o.V, IsChecked = sel.Contains(o.V), Margin = new Thickness(6) }).ToList(); boxes.ForEach(x => lb.Children.Add(x));
    List<string>? res = null; var ok = new Button { Content = "אישור", IsDefault = true, Margin = new Thickness(8), Padding = new Thickness(10, 4, 10, 4) };
    ok.Click += (s, e) => { res = boxes.Where(x => x.IsChecked == true).Select(x => (string)x.Tag).ToList(); w.Close(); };
    var d = new DockPanel(); DockPanel.SetDock(ok, Dock.Bottom); d.Children.Add(ok); d.Children.Add(new ScrollViewer { Content = lb }); w.Content = d; w.ShowDialog(); return res;
  }

  // ---------- רכיבי UI ----------
  static UIElement Segment(string[] labels, int sel, Action<int> changed) {
    var outer = new Border { Background = new SolidColorBrush(Color.FromRgb(229, 231, 235)), CornerRadius = new CornerRadius(8), Padding = new Thickness(2), Margin = new Thickness(0, 4, 12, 4), VerticalAlignment = VerticalAlignment.Center };
    var sp = new StackPanel { Orientation = Orientation.Horizontal }; var items = new List<Border>();
    void Paint() { for (int i = 0; i < items.Count; i++) { items[i].Background = i == sel ? Brushes.White : Brushes.Transparent; ((TextBlock)items[i].Child).Foreground = i == sel ? Brushes.Black : Brushes.Gray; } }
    for (int i = 0; i < labels.Length; i++) {
      int k = i; var bd = new Border { CornerRadius = new CornerRadius(6), Padding = new Thickness(12, 5, 12, 5), Cursor = System.Windows.Input.Cursors.Hand, Background = Brushes.Transparent, Child = new TextBlock { Text = labels[i], FontSize = 13 } };
      bd.MouseLeftButtonUp += (s, e) => { sel = k; Paint(); changed(k); }; items.Add(bd); sp.Children.Add(bd);
    }
    Paint(); outer.Child = sp; return outer;
  }
  UIElement Row(Rule r, Func<IEnumerable<(string, string)>>? wl = null, bool file = true, Action? remove = null, string? glyph = null, bool canOpen = false) {
    if (glyph == null && remove != null) glyph = Directory.Exists(r.Path) ? "\uE8B7" : "\uE8A5";
    var p = new WrapPanel { VerticalAlignment = VerticalAlignment.Center }; var m12 = new Thickness(0, 4, 12, 4);
    if (glyph != null) p.Children.Add(Theme.Badge(glyph));
    var on = new CheckBox { Content = r.Name, IsChecked = r.On, MinWidth = 280, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center, Margin = m12 }; on.Click += (s, e) => { r.On = on.IsChecked == true; C.Save(); };
    var sep = new CheckBox { Content = "קוד נפרד", IsChecked = r.OwnCode != null, VerticalAlignment = VerticalAlignment.Center, Margin = m12 };
    var hid = new CheckBox { Content = "נסתר", IsChecked = r.Hidden, VerticalAlignment = VerticalAlignment.Center, Margin = m12 };
    Button? ob = null;
    void V() { if (ob != null) ob.Visibility = r.Mode == Mode.Code ? Visibility.Visible : Visibility.Collapsed; sep.Visibility = r.Mode == Mode.Code ? Visibility.Visible : Visibility.Collapsed; hid.Visibility = r.Mode == Mode.Full && file ? Visibility.Visible : Visibility.Collapsed; }
    var seg = Segment(new[] { "חסימה גמורה", "חסימה בקוד" }, (int)r.Mode, i => { r.Mode = (Mode)i; V(); C.Save(); });
    sep.Click += (s, e) => { if (sep.IsChecked == true) { var k = Ask("קוד נפרד עבור: " + r.Name, true); if (k == null) { sep.IsChecked = false; return; } r.OwnCode = Config.Hash(k); } else r.OwnCode = null; C.Save(); };
    hid.Click += (s, e) => { r.Hidden = hid.IsChecked == true; C.Save(); };
    p.Children.Add(on); p.Children.Add(seg); p.Children.Add(sep); p.Children.Add(hid); if (canOpen) { ob = Btn("פתח בקוד", () => OpenWithCode(r), "\uE785"); ob.Margin = m12; p.Children.Add(ob); } V();
    if (wl != null) { var b = Btn("רשימה לבנה", () => { var x = Pick("רשימה לבנה – " + r.Name, wl(), r.White); if (x != null) { r.White = x; C.Save(); } }, "\uE8FD"); b.Margin = m12; p.Children.Add(b); }
    if (remove != null) { var d = new Button { Content = Theme.Glyph("\uE74D", 15, Brushes.White), Background = new SolidColorBrush(Color.FromRgb(220, 38, 38)), Padding = new Thickness(10, 7, 10, 7), Margin = new Thickness(0, 4, 0, 4) }; d.Click += (s, e) => remove(); p.Children.Add(d); }
    return new Border { Child = p, Background = Brushes.White, CornerRadius = new CornerRadius(12), Padding = new Thickness(14, 10, 14, 10), Margin = new Thickness(0, 0, 0, 10), Effect = new System.Windows.Media.Effects.DropShadowEffect { BlurRadius = 10, ShadowDepth = 1, Opacity = 0.07 } };
  }
  static ScrollViewer Page(string title, string glyph, params UIElement[] items) {
    var sp = new StackPanel { Margin = new Thickness(28, 22, 28, 22) };
    var h = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 18) };
    h.Children.Add(Theme.Badge(glyph)); h.Children.Add(new TextBlock { Text = title, FontSize = 24, FontWeight = FontWeights.Bold, Foreground = new SolidColorBrush(Color.FromRgb(17, 24, 39)), VerticalAlignment = VerticalAlignment.Center });
    sp.Children.Add(h); foreach (var i in items) sp.Children.Add(i); return new ScrollViewer { Content = sp, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
  }
  static Button Btn(string t, Action a, string? glyph = null) {
    glyph ??= t.Contains("הוסף") ? "\uE710" : t.Contains("ייצוא") ? "\uE898" : t.Contains("ייבוא") ? "\uE896" : t.Contains("קוד") ? "\uE72E" : null;
    var b = new Button { Content = glyph == null ? t : Theme.IconText(glyph, t), Margin = new Thickness(0, 4, 8, 4) }; b.Click += (s, e) => a(); return b;
  }
  static ImageSource? Icon(string exe) { try { using var i = System.Drawing.Icon.ExtractAssociatedIcon(exe); return i == null ? null : Imaging.CreateBitmapSourceFromHIcon(i.Handle, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions()); } catch { return null; } }

  UIElement ProgRow(string n, string e) {
    var r = C.Programs.FirstOrDefault(x => x.Path.Equals(e, StringComparison.OrdinalIgnoreCase)); if (r == null) { r = new Rule { Name = n, Path = e }; C.Programs.Add(r); }
    var d = new DockPanel(); var img = new Image { Source = Icon(e), Width = 32, Height = 32, Margin = new Thickness(0, 0, 10, 0) }; DockPanel.SetDock(img, Dock.Left); d.Children.Add(img); d.Children.Add(Row(r)); return d;
  }
  void OpenWithCode(Rule r) {
    var g = System.IO.Path.Combine(Config.Dir, "DeviceGuardWatch.exe");
    if (!File.Exists(g)) { MessageBox.Show("יש ללחוץ 'החל שינויים' קודם"); return; }
    Process.Start(new ProcessStartInfo(g, "--open " + r.Id) { UseShellExecute = false });
  }
  UIElement SearchBox() {
    var sp = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
    var tb = new TextBox { Width = 220, Padding = new Thickness(8, 6, 8, 6), VerticalContentAlignment = VerticalAlignment.Center, ToolTip = "חיפוש בתוכנה" };
    sp.Children.Add(new Border { Background = new SolidColorBrush(Color.FromRgb(229, 231, 235)), CornerRadius = new CornerRadius(8), Padding = new Thickness(8, 0, 8, 0), Child = Theme.Glyph("\uE721", 15, Brushes.Gray) }); sp.Children.Add(tb);
    tb.TextChanged += (s, e) => { var q = tb.Text.Trim(); host.Content = q.Length == 0 ? (cur ?? (Func<UIElement>)P1)() : Search(q); };
    return sp;
  }
  UIElement Search(string q) {
    bool M(string t) => t.Contains(q, StringComparison.CurrentCultureIgnoreCase);
    var items = new List<UIElement>();
    foreach (var (r, g, f) in new[] { (C.Settings, "\uE713", false), (C.Install, "\uE896", false), (C.Net, "\uE774", false), (C.Usb, "\uE88E", false), (C.Portable, "\uE8A7", false), (C.Movies, "\uE714", true), (C.Songs, "\uE8D6", true), (C.Images, "\uE91B", true) })
      if (M(r.Name)) items.Add(Row(r, null, f, null, g));
    inst ??= Installed();
    foreach (var (n, e) in inst.Where(x => M(x.N) || M(System.IO.Path.GetFileName(x.E)))) items.Add(ProgRow(n, e));
    foreach (var r in C.Exts.Where(x => M(x.Name) || M(x.Path)).ToList()) { var rr = r; items.Add(Row(rr, null, true, () => { C.Exts.Remove(rr); C.Save(); host.Content = Search(q); })); }
    foreach (var r in C.Paths.Where(x => M(x.Name) || M(x.Path)).ToList()) { var rr = r; items.Add(Row(rr, null, true, () => { C.Paths.Remove(rr); C.Save(); host.Content = Search(q); }, null, true)); }
    if (items.Count == 0) items.Add(new TextBlock { Text = "לא נמצאו תוצאות", Foreground = Brushes.Gray, FontSize = 16 });
    return Page("תוצאות חיפוש: " + q, "\uE721", items.ToArray());
  }

  // ---------- חלון 1 ----------
  static readonly (string, string)[] SettingsPages = { ("תצוגה", "display"), ("קול", "sound"), ("התראות", "notifications"), ("אחסון", "storagesense"), ("Bluetooth", "bluetooth"), ("מדפסות", "printers"), ("עכבר", "mousetouchpad"), ("Wi-Fi", "network-wifi"), ("Ethernet", "network-ethernet"), ("פרטיות", "privacy"), ("Windows Update", "windowsupdate"), ("התאמה אישית", "personalization-background"), ("תאריך ושעה", "dateandtime"), ("שפה ואזור", "regionlanguage"), ("נגישות", "easeofaccess-display"), ("אודות", "about"), ("אפליקציות ותכונות", "appsfeatures"), ("אפליקציות ברירת מחדל", "defaultapps") };
  UIElement P1() {
    var all = new CheckBox { Content = "החסימות יחולו על כל המשתמשים במחשב (אחרת – רק על משתמש זה)", IsChecked = C.AllUsers, Margin = new Thickness(0, 8, 0, 8) }; all.Click += (s, e) => { C.AllUsers = all.IsChecked == true; C.Save(); };
    var code = Btn("הגדר / שנה קוד ברירת מחדל לחסימות", () => { var k = Ask("קוד ברירת מחדל", true); if (k != null) { C.DefaultCode = Config.Hash(k); C.Save(); MessageBox.Show("הקוד נשמר"); } });
    var net = () => {
      var items = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces().Where(n => n.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback).Select(n => (n.Name, n.Name)).ToList();
      items.AddRange(WifiSsids());
      return items.AsEnumerable();
    };
    var usb = () => { try { using var s = new System.Management.ManagementObjectSearcher("SELECT Caption FROM Win32_DiskDrive WHERE InterfaceType='USB'"); return s.Get().Cast<System.Management.ManagementBaseObject>().Select(o => ((string)o["Caption"], (string)o["Caption"])).ToList().AsEnumerable(); } catch { return Enumerable.Empty<(string, string)>(); } };
    var exp = Btn("ייצוא הגדרות…", Export); var imp = Btn("ייבוא הגדרות…", Import);
    var un2 = Btn("הסרת שירות ההגנה (בקוד כניסה)", () => {
      if (MessageBox.Show("הפעולה תשבית את כל החסימות ותסיר את שירות ההגנה. להמשיך?", "אישור", MessageBoxButton.YesNo) != MessageBoxResult.Yes) return;
      var k = Ask("קוד כניסה לתוכנה"); if (k == null || !Config.Check(k, C.AppCode)) { MessageBox.Show("קוד שגוי"); return; }
      C.Master = false; Enforcer.Apply(C); Config.Pipe("UNINSTALL|" + Config.Token); Config.Token = null; MessageBox.Show("השירות יוסר בעוד מספר שניות");
    }, "\uE74D");
    var note = new TextBlock { Text = "הערה: רשימה לבנה של הגדרות/רשת/התקנים פועלת בחסימה גמורה.", Foreground = Brushes.Gray, Margin = new Thickness(0, 8, 0, 0), TextWrapping = TextWrapping.Wrap };
    return Page("הגדרות כלליות", "\uE713", code, all, Row(C.Settings, () => SettingsPages, false, null, "\uE713"), Row(C.Install, null, false, null, "\uE896"), Row(C.Net, net, false, null, "\uE774"), Row(C.Usb, usb, false, null, "\uE88E"), new StackPanel { Orientation = Orientation.Horizontal, Children = { exp, imp, un2 } }, note);
  }
  Dictionary<string, object> Sections() => new() { ["1"] = new { C.AllUsers, C.Settings, C.Install, C.Net, C.Usb }, ["2"] = C.Programs, ["3"] = C.Portable, ["4"] = new { C.Movies, C.Songs, C.Images, C.Exts }, ["5"] = C.Paths };
  void Export() {
    var sel = Pick("מה לייצא?", Enumerable.Range(1, 5).Select(i => ($"חלון {i}", i.ToString())), new[] { "1", "2", "3", "4", "5" }); if (sel == null || sel.Count == 0) return;
    var d = new SaveFileDialog { Filter = "DeviceGuard|*.dgcfg", FileName = "settings.dgcfg" }; if (d.ShowDialog() != true) return;
    File.WriteAllText(d.FileName, JsonSerializer.Serialize(Sections().Where(k => sel.Contains(k.Key)).ToDictionary(k => k.Key, k => k.Value), Config.O));
  }
  void Import() {
    var d = new OpenFileDialog { Filter = "DeviceGuard|*.dgcfg" }; if (d.ShowDialog() != true) return;
    try {
      using var doc = JsonDocument.Parse(File.ReadAllText(d.FileName)); var r = doc.RootElement; T D<T>(JsonElement e, string n) => e.GetProperty(n).Deserialize<T>(Config.O)!;
      if (r.TryGetProperty("1", out var a)) { C.AllUsers = a.GetProperty("AllUsers").GetBoolean(); C.Settings = D<Rule>(a, "Settings"); C.Install = D<Rule>(a, "Install"); C.Net = D<Rule>(a, "Net"); C.Usb = D<Rule>(a, "Usb"); }
      if (r.TryGetProperty("2", out var b)) C.Programs = b.Deserialize<List<Rule>>(Config.O)!;
      if (r.TryGetProperty("3", out var c3)) C.Portable = c3.Deserialize<Rule>(Config.O)!;
      if (r.TryGetProperty("4", out var e)) { C.Movies = D<Rule>(e, "Movies"); C.Songs = D<Rule>(e, "Songs"); C.Images = D<Rule>(e, "Images"); C.Exts = D<List<Rule>>(e, "Exts"); }
      if (r.TryGetProperty("5", out var f)) C.Paths = f.Deserialize<List<Rule>>(Config.O)!;
      C.Save(); host.Content = P1(); status.Text = "יובא – לחץ 'החל שינויים'";
    } catch (Exception x) { MessageBox.Show("קובץ לא תקין: " + x.Message); }
  }

  // ---------- חלון 2 ----------
    static string RunCmd(string exe, string args) { try { var p = Process.Start(new ProcessStartInfo(exe, args) { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true })!; var o = p.StandardOutput.ReadToEnd(); p.WaitForExit(); return o; } catch { return ""; } }
  // שמות רשתות Wi-Fi: גם רשתות שבטווח כרגע וגם רשתות ששמורות במחשב (כדי שאפשר יהיה לבחור אותן לרשימה הלבנה גם אם אינן בטווח כרגע)
  static IEnumerable<(string, string)> WifiSsids() {
    var names = new HashSet<string>();
    foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(RunCmd("netsh", "wlan show networks"), @"SSID\s+\d+\s*:\s*(.+)")) { var n = m.Groups[1].Value.Trim(); if (n.Length > 0) names.Add(n); }
    foreach (System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(RunCmd("netsh", "wlan show profiles"), @"All User Profile\s*:\s*(.+)")) { var n = m.Groups[1].Value.Trim(); if (n.Length > 0) names.Add(n); }
    return names.Select(n => ("רשת Wi-Fi: " + n, "ssid:" + n));
  }
  static List<(string N, string E)> Installed() {
    var res = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    foreach (var (h, v) in new[] { (RegistryHive.LocalMachine, RegistryView.Registry64), (RegistryHive.LocalMachine, RegistryView.Registry32), (RegistryHive.CurrentUser, RegistryView.Default) }) {
      try {
        using var b = RegistryKey.OpenBaseKey(h, v); using var u = b.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"); if (u == null) continue;
        foreach (var n in u.GetSubKeyNames()) {
          using var k = u.OpenSubKey(n); var name = k?.GetValue("DisplayName") as string; if (string.IsNullOrWhiteSpace(name)) continue;
          var ic = (k!.GetValue("DisplayIcon") as string)?.Split(',')[0].Trim('"'); string? exe = null;
          if (ic != null && ic.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && File.Exists(ic)) exe = ic;
          else { var loc = (k.GetValue("InstallLocation") as string)?.Trim('"'); if (loc != null && Directory.Exists(loc)) exe = Directory.EnumerateFiles(loc, "*.exe").Where(f => !System.IO.Path.GetFileName(f).StartsWith("unins", StringComparison.OrdinalIgnoreCase)).OrderByDescending(f => new FileInfo(f).Length).FirstOrDefault(); }
          if (exe != null) res.TryAdd(exe, name);
        }
      } catch { }
    }
    var sys = Environment.SystemDirectory;
    foreach (var (n, f) in new[] { ("שורת פקודה (cmd)", "cmd.exe"), ("PowerShell", @"WindowsPowerShell\v1.0\powershell.exe"), ("עורך הרישום (regedit)", @"..\regedit.exe"), ("מנהל המשימות", "taskmgr.exe"), ("לוח הבקרה", "control.exe"), ("פנקס רשימות", @"..\notepad.exe"), ("צייר (Paint)", @"..\System32\mspaint.exe"), ("מחשבון", "calc.exe"), ("Microsoft Management Console", "mmc.exe") }) {
      var p = System.IO.Path.GetFullPath(System.IO.Path.Combine(sys, f)); if (File.Exists(p)) res.TryAdd(p, n);
    }
    var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
    foreach (var (n, f) in new[] { ("Word", "WINWORD.EXE"), ("Excel", "EXCEL.EXE"), ("PowerPoint", "POWERPNT.EXE"), ("Outlook", "OUTLOOK.EXE"), ("Access", "MSACCESS.EXE") }) {
      var p = System.IO.Path.Combine(pf, @"Microsoft Office\root\Office16", f); if (File.Exists(p)) res.TryAdd(p, "Microsoft " + n);
    }
    try {   // תפריט התחל: תופס גם תוכנות שהזיהוי לפי רשימת ההתקנות מפספס
      dynamic sh = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell")!)!;
      foreach (var dir in new[] { Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu), Environment.GetFolderPath(Environment.SpecialFolder.StartMenu) }) {
        if (!Directory.Exists(dir)) continue;
        foreach (var lnk in Directory.EnumerateFiles(dir, "*.lnk", SearchOption.AllDirectories)) {
          string? target = null; try { dynamic l = sh.CreateShortcut(lnk); target = (string)l.TargetPath; } catch { }
          if (string.IsNullOrEmpty(target) || !target.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || !File.Exists(target)) continue;
          res.TryAdd(target, System.IO.Path.GetFileNameWithoutExtension(lnk));
        }
      }
    } catch { }
    return res.Where(x => !x.Key.EndsWith("DeviceGuard.exe", StringComparison.OrdinalIgnoreCase) && !x.Key.EndsWith("DeviceGuardWatch.exe", StringComparison.OrdinalIgnoreCase)).Select(x => (x.Value, x.Key)).OrderBy(x => x.Value).ToList();
  }
  UIElement P2() {
    var items = new List<UIElement>();
    foreach (var (n, e) in Installed()) items.Add(ProgRow(n, e));
    items.Add(new TextBlock { Text = "התוכנה סורקת תוכנות מותקנות ותפריט התחל. יישום שחסר מהרשימה אפשר לחסום ישירות דרך תיקיית הקבצים שלו בחלון 5.", Foreground = Brushes.Gray, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 10, 0, 0) });
    return Page("תוכנות מותקנות", "\uE71D", items.ToArray());
  }

  // ---------- חלון 3 ----------
  UIElement P3() {
    Func<IEnumerable<(string, string)>> opts = () => {
      var l = new List<string>(C.Portable.White);
      foreach (var p in Process.GetProcesses()) { try { var f = p.MainModule?.FileName; if (f != null && !f.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase) && !f.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), StringComparison.OrdinalIgnoreCase) && !f.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), StringComparison.OrdinalIgnoreCase) && !l.Contains(f)) l.Add(f); } catch { } }
      return l.Select(f => (System.IO.Path.GetFileName(f) + "  —  " + f, f));
    };
    var drop = new Border { BorderBrush = Brushes.Gray, BorderThickness = new Thickness(2), Height = 90, Margin = new Thickness(0, 12, 0, 0), AllowDrop = true, Background = Brushes.WhiteSmoke, Child = new TextBlock { Text = "גרור לכאן תוכנה ניידת כדי להוסיפה לרשימה הלבנה", HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center } };
    drop.Drop += (s, e) => { if (e.Data.GetData(DataFormats.FileDrop) is string[] fs) { foreach (var f in fs) if (!C.Portable.White.Contains(f)) C.Portable.White.Add(f); C.Save(); MessageBox.Show($"נוספו {fs.Length} פריטים"); } };
    var warn = new TextBlock { Text = "חסימת ניידות חוסמת הרצה מכל מקום מחוץ ל-Windows ו-Program Files (כולל אפליקציות שמותקנות בתיקיית המשתמש). חסימה זו היא גמורה בלבד.", TextWrapping = TextWrapping.Wrap, Foreground = Brushes.Gray, Margin = new Thickness(0, 8, 0, 0) };
    return Page("תוכנות ניידות", "\uE8A7", Row(C.Portable, opts, false, null, "\uE8A7"), drop, warn);
  }

  // ---------- חלון 4 ----------
  UIElement P4() {
    var ext = new TextBox { Width = 120, Margin = new Thickness(0, 0, 8, 0) }; var list = new StackPanel();
    void Fill() { list.Children.Clear(); foreach (var r in C.Exts.ToList()) { var rr = r; list.Children.Add(Row(rr, null, true, () => { C.Exts.Remove(rr); C.Save(); Fill(); })); } }
    var add = Btn("הוסף סיומת", () => { var x = ext.Text.Trim().TrimStart('.').ToLowerInvariant(); if (x.Length == 0) return; C.Exts.Add(new Rule { Name = "חסימת ." + x, Path = x }); C.Save(); ext.Clear(); Fill(); });
    Fill(); var tip = new TextBlock { Text = "סרטים: " + string.Join(", ", Config.Vid.Take(12)) + "…  |  שירים: " + string.Join(", ", Config.Aud) + "  |  תמונות: " + string.Join(", ", Config.Img), Foreground = Brushes.Gray, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 8) };
    return Page("סוגי קבצים", "\uE8A5", Row(C.Movies, null, true, null, "\uE714"), Row(C.Songs, null, true, null, "\uE8D6"), Row(C.Images, null, true, null, "\uE91B"), tip, new TextBlock { Text = "סיומות נוספות:" }, new StackPanel { Orientation = Orientation.Horizontal, Children = { ext, add } }, list);
  }

  // ---------- חלון 5 ----------
  UIElement P5() {
    var list = new StackPanel();
    void Fill() { list.Children.Clear(); foreach (var r in C.Paths.ToList()) { var rr = r; list.Children.Add(Row(rr, null, true, () => { C.Paths.Remove(rr); C.Save(); Fill(); }, null, true)); } }
    void AddP(string p) { if (C.Paths.Any(x => x.Path.Equals(p, StringComparison.OrdinalIgnoreCase))) return; C.Paths.Add(new Rule { Name = p, Path = p }); C.Save(); Fill(); }
    var f = Btn("הוסף קובץ…", () => { var d = new OpenFileDialog { Multiselect = true }; if (d.ShowDialog() == true) foreach (var x in d.FileNames) AddP(x); });
    var g = Btn("הוסף תיקייה…", () => { var d = new OpenFolderDialog(); if (d.ShowDialog() == true) AddP(d.FolderName); });
    Fill(); return Page("קבצים ותיקיות", "\uE8B7", new StackPanel { Orientation = Orientation.Horizontal, Children = { f, g } }, list);
  }
}
