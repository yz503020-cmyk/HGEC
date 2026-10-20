using System.Diagnostics; using System.IO; using System.Text.Json; using System.Windows; using System.Windows.Controls; using System.Windows.Controls.Primitives;
using System.Windows.Interop; using System.Windows.Media; using System.Windows.Media.Imaging; using System.Windows.Threading; using Microsoft.Win32;
namespace DG;
public static class Program {
  [STAThread] public static void Main() {
    var app = new Application(); var c = Config.Load();
    if (c.AppCode == null) {   // הפעלה ראשונה – הגדרת קוד כניסה
      var k = MainWin.Ask("הגדר קוד כניסה לתוכנה", true); if (k == null) return;
      c.AppCode = Config.Hash(k); c.OwnerUser = Environment.UserName; c.Save();
    } else {
      while (true) { var k = MainWin.Ask("הזן קוד כניסה"); if (k == null) return; if (Config.Check(k, c.AppCode)) break; MessageBox.Show("קוד שגוי"); }
    }
    app.Run(new MainWin(c));
  }
}
public class MainWin : Window {
  Config C; ContentControl host = new(); TextBlock status = new(); DispatcherTimer? tmr;
  public MainWin(Config c) {
    C = c; Title = "DeviceGuard – מנהל חסימות"; Width = 1050; Height = 720; FlowDirection = FlowDirection.RightToLeft; FontSize = 14;
    var tg = new ToggleButton { IsChecked = C.Master, Padding = new Thickness(14, 6, 14, 6), Margin = new Thickness(0, 0, 8, 0) };
    void Lbl() => tg.Content = tg.IsChecked == true ? "החסימות פעילות – לחץ להשבתת הכל" : "החסימות מושבתות – לחץ להפעלה";
    Lbl(); tg.Click += async (s, e) => { C.Master = tg.IsChecked == true; Lbl(); await Do(); };
    var ap = new Button { Content = "החל שינויים", Padding = new Thickness(14, 6, 14, 6), Margin = new Thickness(0, 0, 8, 0) }; ap.Click += async (s, e) => await Do();
    var un = new Button { Content = "פתיחה זמנית (30 דק׳)", Padding = new Thickness(14, 6, 14, 6), Margin = new Thickness(0, 0, 8, 0) };
    un.Click += async (s, e) => {
      var k = Ask("קוד ברירת מחדל"); if (k == null || !Config.Check(k, C.DefaultCode)) return;
      IsEnabled = false; await Task.Run(() => Enforcer.Revert(C)); C.Save(); IsEnabled = true;
      tmr?.Stop(); tmr = new DispatcherTimer { Interval = TimeSpan.FromMinutes(30) }; tmr.Tick += async (a, b) => { tmr.Stop(); await Do(); }; tmr.Start(); status.Text = "החסימות פתוחות זמנית";
    };
    var top = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(8) };
    top.Children.Add(tg); top.Children.Add(ap); top.Children.Add(un); top.Children.Add(status);
    var side = new StackPanel { Width = 150, Background = Brushes.WhiteSmoke };
    var pages = new (string, Func<UIElement>)[] { ("1 · הגדרות כלליות", P1), ("2 · תוכנות מותקנות", P2), ("3 · תוכנות ניידות", P3), ("4 · סוגי קבצים", P4), ("5 · קבצים ותיקיות", P5) };
    foreach (var (n, f) in pages) { var b = new Button { Content = n, Padding = new Thickness(8, 12, 8, 12), Margin = new Thickness(4) }; b.Click += (s, e) => host.Content = f(); side.Children.Add(b); }
    var root = new DockPanel(); DockPanel.SetDock(top, Dock.Top); DockPanel.SetDock(side, Dock.Left); // ב-RTL: מופיע מימין
    root.Children.Add(top); root.Children.Add(side); root.Children.Add(host); Content = root; host.Content = P1();
  }
  async Task Do() { status.Text = "מחיל..."; IsEnabled = false; try { await Task.Run(() => Enforcer.Apply(C)); status.Text = "הוחל ✓"; } catch (Exception x) { status.Text = "שגיאה: " + x.Message; } IsEnabled = true; }

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
  UIElement Row(Rule r, Func<IEnumerable<(string, string)>>? wl = null, bool file = true, Action? remove = null) {
    var p = new WrapPanel { Margin = new Thickness(0, 3, 0, 3) }; var m8 = new Thickness(0, 0, 10, 0);
    var on = new CheckBox { Content = r.Name, IsChecked = r.On, MinWidth = 260, VerticalAlignment = VerticalAlignment.Center, Margin = m8 }; on.Click += (s, e) => { r.On = on.IsChecked == true; C.Save(); };
    var m = new ComboBox { ItemsSource = new[] { "חסימה גמורה", "חסימה בקוד" }, SelectedIndex = (int)r.Mode, Margin = m8 };
    var sep = new CheckBox { Content = "קוד נפרד", IsChecked = r.OwnCode != null, VerticalAlignment = VerticalAlignment.Center, Margin = m8 };
    var hid = new CheckBox { Content = "נסתר", IsChecked = r.Hidden, VerticalAlignment = VerticalAlignment.Center, Margin = m8 };
    void V() { sep.Visibility = r.Mode == Mode.Code ? Visibility.Visible : Visibility.Collapsed; hid.Visibility = r.Mode == Mode.Full && file ? Visibility.Visible : Visibility.Collapsed; }
    m.SelectionChanged += (s, e) => { r.Mode = (Mode)m.SelectedIndex; V(); C.Save(); };
    sep.Click += (s, e) => { if (sep.IsChecked == true) { var k = Ask("קוד נפרד עבור: " + r.Name, true); if (k == null) { sep.IsChecked = false; return; } r.OwnCode = Config.Hash(k); } else r.OwnCode = null; C.Save(); };
    hid.Click += (s, e) => { r.Hidden = hid.IsChecked == true; C.Save(); };
    foreach (UIElement u in new UIElement[] { on, m, sep, hid }) p.Children.Add(u); V();
    if (wl != null) { var b = new Button { Content = "רשימה לבנה…", Padding = new Thickness(8, 2, 8, 2), Margin = m8 }; b.Click += (s, e) => { var x = Pick("רשימה לבנה – " + r.Name, wl(), r.White); if (x != null) { r.White = x; C.Save(); } }; p.Children.Add(b); }
    if (remove != null) { var b = new Button { Content = "הסר", Padding = new Thickness(8, 2, 8, 2) }; b.Click += (s, e) => remove(); p.Children.Add(b); }
    return p;
  }
  static ScrollViewer Page(params UIElement[] items) { var sp = new StackPanel { Margin = new Thickness(14) }; foreach (var i in items) sp.Children.Add(i); return new ScrollViewer { Content = sp }; }
  static Button Btn(string t, Action a) { var b = new Button { Content = t, Padding = new Thickness(10, 4, 10, 4), Margin = new Thickness(0, 4, 8, 4) }; b.Click += (s, e) => a(); return b; }
  static ImageSource? Icon(string exe) { try { using var i = System.Drawing.Icon.ExtractAssociatedIcon(exe); return i == null ? null : Imaging.CreateBitmapSourceFromHIcon(i.Handle, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions()); } catch { return null; } }

  // ---------- חלון 1 ----------
  static readonly (string, string)[] SettingsPages = { ("תצוגה", "display"), ("קול", "sound"), ("התראות", "notifications"), ("אחסון", "storagesense"), ("Bluetooth", "bluetooth"), ("מדפסות", "printers"), ("עכבר", "mousetouchpad"), ("Wi-Fi", "network-wifi"), ("Ethernet", "network-ethernet"), ("פרטיות", "privacy"), ("Windows Update", "windowsupdate"), ("התאמה אישית", "personalization-background"), ("תאריך ושעה", "dateandtime"), ("שפה ואזור", "regionlanguage"), ("נגישות", "easeofaccess-display"), ("אודות", "about"), ("אפליקציות ותכונות", "appsfeatures"), ("אפליקציות ברירת מחדל", "defaultapps") };
  UIElement P1() {
    var all = new CheckBox { Content = "החסימות יחולו על כל המשתמשים במחשב (אחרת – רק על משתמש זה)", IsChecked = C.AllUsers, Margin = new Thickness(0, 8, 0, 8) }; all.Click += (s, e) => { C.AllUsers = all.IsChecked == true; C.Save(); };
    var code = Btn("הגדר / שנה קוד ברירת מחדל לחסימות", () => { var k = Ask("קוד ברירת מחדל", true); if (k != null) { C.DefaultCode = Config.Hash(k); C.Save(); MessageBox.Show("הקוד נשמר"); } });
    var net = () => System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up && n.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback).Select(n => (n.Name, n.Name));
    var usb = () => { try { using var s = new System.Management.ManagementObjectSearcher("SELECT Caption FROM Win32_DiskDrive WHERE InterfaceType='USB'"); return s.Get().Cast<System.Management.ManagementBaseObject>().Select(o => ((string)o["Caption"], (string)o["Caption"])).ToList().AsEnumerable(); } catch { return Enumerable.Empty<(string, string)>(); } };
    var exp = Btn("ייצוא הגדרות…", Export); var imp = Btn("ייבוא הגדרות…", Import);
    var note = new TextBlock { Text = "הערה: רשימה לבנה של הגדרות/רשת/התקנים פועלת בחסימה גמורה.", Foreground = Brushes.Gray, Margin = new Thickness(0, 8, 0, 0), TextWrapping = TextWrapping.Wrap };
    return Page(code, all, Row(C.Settings, () => SettingsPages, false), Row(C.Install, null, false), Row(C.Net, net, false), Row(C.Usb, usb, false), new StackPanel { Orientation = Orientation.Horizontal, Children = { exp, imp } }, note);
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
    return res.Where(x => !x.Key.EndsWith("DeviceGuard.exe", StringComparison.OrdinalIgnoreCase)).Select(x => (x.Value, x.Key)).OrderBy(x => x.Value).ToList();
  }
  UIElement P2() {
    var items = new List<UIElement>();
    foreach (var (n, e) in Installed()) {
      var r = C.Programs.FirstOrDefault(x => x.Path.Equals(e, StringComparison.OrdinalIgnoreCase)); if (r == null) { r = new Rule { Name = n, Path = e }; C.Programs.Add(r); }
      var d = new DockPanel(); var img = new Image { Source = Icon(e), Width = 32, Height = 32, Margin = new Thickness(0, 0, 10, 0) }; DockPanel.SetDock(img, Dock.Left); d.Children.Add(img); d.Children.Add(Row(r)); items.Add(d);
    }
    return Page(items.ToArray());
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
    return Page(Row(C.Portable, opts, false), drop, warn);
  }

  // ---------- חלון 4 ----------
  UIElement P4() {
    var ext = new TextBox { Width = 120, Margin = new Thickness(0, 0, 8, 0) }; var list = new StackPanel();
    void Fill() { list.Children.Clear(); foreach (var r in C.Exts.ToList()) { var rr = r; list.Children.Add(Row(rr, null, true, () => { C.Exts.Remove(rr); C.Save(); Fill(); })); } }
    var add = Btn("הוסף סיומת", () => { var x = ext.Text.Trim().TrimStart('.').ToLowerInvariant(); if (x.Length == 0) return; C.Exts.Add(new Rule { Name = "חסימת ." + x, Path = x }); C.Save(); ext.Clear(); Fill(); });
    Fill(); var tip = new TextBlock { Text = "סרטים: " + string.Join(", ", Config.Vid.Take(12)) + "…  |  שירים: " + string.Join(", ", Config.Aud) + "  |  תמונות: " + string.Join(", ", Config.Img), Foreground = Brushes.Gray, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 8) };
    return Page(Row(C.Movies), Row(C.Songs), Row(C.Images), tip, new TextBlock { Text = "סיומות נוספות:" }, new StackPanel { Orientation = Orientation.Horizontal, Children = { ext, add } }, list);
  }

  // ---------- חלון 5 ----------
  UIElement P5() {
    var list = new StackPanel();
    void Fill() { list.Children.Clear(); foreach (var r in C.Paths.ToList()) { var rr = r; list.Children.Add(Row(rr, null, true, () => { C.Paths.Remove(rr); C.Save(); Fill(); })); } }
    void AddP(string p) { if (C.Paths.Any(x => x.Path.Equals(p, StringComparison.OrdinalIgnoreCase))) return; C.Paths.Add(new Rule { Name = p, Path = p }); C.Save(); Fill(); }
    var f = Btn("הוסף קובץ…", () => { var d = new OpenFileDialog { Multiselect = true }; if (d.ShowDialog() == true) foreach (var x in d.FileNames) AddP(x); });
    var g = Btn("הוסף תיקייה…", () => { var d = new OpenFolderDialog(); if (d.ShowDialog() == true) AddP(d.FolderName); });
    Fill(); return Page(new StackPanel { Orientation = Orientation.Horizontal, Children = { f, g } }, list);
  }
}
