using System.Collections.Concurrent; using System.Diagnostics; using System.IO; using System.Text.Json; using System.Threading; using System.Threading.Tasks; using System.Windows; using System.Windows.Controls; using System.Windows.Controls.Primitives;
using System.Windows.Interop; using System.Windows.Media; using System.Windows.Media.Imaging; using System.Windows.Threading; using Microsoft.Win32;
namespace DG;
public class MainWin : Window {
  Border scanBar = null!, scanFill = null!; TextBlock scanTxt = null!; DispatcherTimer? scanTmr; bool scanBusy; long scanFrom; const double ScanW = 150;
  Config C; Func<UIElement>? cur; List<(string N, string E)>? inst; ContentControl host = new(); TextBlock status = new(); DispatcherTimer? tmr, syncTmr; bool busy, wasTemp; DateTime lastStamp;
  public MainWin(Config c) {
    C = c; Title = "DeviceGuard – מנהל חסימות"; Width = 1050; Height = 720; FlowDirection = FlowDirection.RightToLeft; FontSize = 14; Background = new SolidColorBrush(Color.FromRgb(248, 250, 252)); FontFamily = new FontFamily("Segoe UI"); Foreground = new SolidColorBrush(Color.FromRgb(30, 41, 59));
    var tg = new ToggleButton { IsChecked = C.Master, Padding = new Thickness(14, 6, 14, 6), Margin = new Thickness(0, 0, 8, 0), Style = Theme.Soft(typeof(ToggleButton)) };
    void Lbl() {
      bool on = tg.IsChecked == true; var fg = on ? Color.FromRgb(21, 128, 61) : Color.FromRgb(185, 28, 28);
      Theme.Tint(tg, on ? Color.FromRgb(240, 250, 244) : Color.FromRgb(254, 242, 242), fg, on ? Color.FromRgb(187, 229, 203) : Color.FromRgb(245, 198, 198));
      tg.Content = on ? Theme.IconText("\uE72E", "החסימות פעילות – לחץ להשבתה", new SolidColorBrush(fg)) : Theme.IconText("\uE785", "החסימות מושבתות – לחץ להפעלה", new SolidColorBrush(fg));
    }
    Lbl(); tg.Click += async (s, e) => { C.Master = tg.IsChecked == true; Lbl(); await Do(); };
    var ap = Btn("החל שינויים", () => { }, "\uE73E"); ap.Click += async (s, e) => await Do();
    var un = Btn("פתיחה זמנית (30 דק׳)", () => { }, "\uE785");
    var softFg = Color.FromRgb(52, 90, 158); var softBr = new SolidColorBrush(softFg);
    foreach (var (sb, sg, st) in new[] { (ap, "\uE73E", "החל שינויים"), (un, "\uE785", "פתיחה זמנית (30 דק׳)") }) { sb.Style = Theme.Soft(typeof(Button)); Theme.Tint(sb, Color.FromRgb(238, 243, 252), softFg, Color.FromRgb(206, 220, 242)); sb.Content = Theme.IconText(sg, st, softBr); }
    Theme.Tipped(tg, "המתג הראשי: הפעלה או השבתה של כל החסימות בבת אחת. השינוי מוחל מיד.");
    Theme.Tipped(ap, "מחיל על המחשב את כל החסימות וההגדרות שבחרת. יש ללחוץ עליו אחרי שינוי.");
    Theme.Tipped(un, "פותח את כל החסימות ל-30 דקות אחרי הקשת קוד ברירת המחדל, ואחר כך הן חוזרות אוטומטית.");
    un.Click += async (s, e) => {
      var k = Ask("קוד ברירת מחדל"); if (k == null) return; if (!Config.Check(k, C.DefaultCode)) { MessageBox.Show(C.DefaultCode == null ? "לא הוגדר קוד ברירת מחדל (חלון 1)" : "קוד שגוי"); return; }
      IsEnabled = false; busy = true;
      try { await Task.Run(() => Enforcer.TempOpen(C, DateTime.UtcNow.AddMinutes(30).Ticks)); status.Text = "החסימות פתוחות זמנית (30 דקות)"; }   // השירות מחזיר את החסימות לבד כשהזמן נגמר, גם אם התוכנה נסגרה
      catch (Exception x) { MessageBox.Show("שגיאה: " + x.Message); }
      busy = false; IsEnabled = true;
    };
    InitScanBar();
    var top = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0), Background = Brushes.White };
    top.Children.Add(tg); top.Children.Add(ap); top.Children.Add(un); top.Children.Add(SearchBox()); top.Children.Add(status); top.Children.Add(scanBar); status.Foreground = new SolidColorBrush(Color.FromRgb(100, 116, 139)); status.FontSize = 13; foreach (FrameworkElement ch in top.Children) { ch.Margin = new Thickness(8, 10, 0, 10); ch.VerticalAlignment = VerticalAlignment.Center; }
    var line = new SolidColorBrush(Color.FromRgb(229, 231, 235));
    var side = new Border { Width = 92, Background = Brushes.White, BorderBrush = line, BorderThickness = new Thickness(0, 0, 1, 0) };
    var sideSp = new StackPanel(); side.Child = sideSp;
    var pages = new (string, string, Func<UIElement>)[] { ("הגדרות כלליות", "\uE713", P1), ("תוכנות מותקנות", "\uE71D", P2), ("תוכנות ניידות", "\uE8A7", P3), ("סוגי קבצים", "\uE8A5", P4), ("קבצים ותיקיות", "\uE8B7", P5), ("רשת", "\uE774", P6), ("הגנה מתקדמת", "\uE72E", P7) };
    var logoImg = new Image { Source = Logo.Src, Width = 54, Height = 54, Margin = new Thickness(0, 18, 0, 16), HorizontalAlignment = HorizontalAlignment.Center }; RenderOptions.SetBitmapScalingMode(logoImg, BitmapScalingMode.HighQuality); sideSp.Children.Add(logoImg);
    int selIdx = 0; var paints = new List<Action>();
    var mute = new SolidColorBrush(Color.FromRgb(107, 114, 128)); var selBg = new SolidColorBrush(Color.FromRgb(239, 246, 255)); var hoverBg = new SolidColorBrush(Color.FromRgb(243, 244, 246));
    for (int i = 0; i < pages.Length; i++) {
      int k = i; var (n, g, f) = pages[i];
      var ic = Theme.Glyph(g, 20, mute);
      var tx = new TextBlock { Text = n, FontSize = 11, FontWeight = FontWeights.SemiBold, Foreground = mute, TextAlignment = TextAlignment.Center, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 0) };
      var col = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center }; col.Children.Add(ic); col.Children.Add(tx);
      var item = new Border { CornerRadius = new CornerRadius(12), Padding = new Thickness(4, 10, 4, 10), Margin = new Thickness(8, 2, 8, 2), Background = Brushes.Transparent, Child = col };
      var bar = new Border { Width = 3, CornerRadius = new CornerRadius(2), Background = Theme.SideAccent, HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 14, 0, 14), Visibility = Visibility.Collapsed };
      var cell = new Grid { Background = Brushes.Transparent, Cursor = System.Windows.Input.Cursors.Hand }; cell.Children.Add(item); cell.Children.Add(bar);
      void Paint() { bool sel = selIdx == k; item.Background = sel ? selBg : Brushes.Transparent; ic.Foreground = tx.Foreground = sel ? Theme.SideAccent : mute; bar.Visibility = sel ? Visibility.Visible : Visibility.Collapsed; }
      paints.Add(Paint);
      cell.MouseEnter += (s, e) => { if (selIdx != k) item.Background = hoverBg; };
      cell.MouseLeave += (s, e) => Paint();
      cell.MouseLeftButtonUp += (s, e) => { selIdx = k; foreach (var pt in paints) pt(); cur = f; host.Content = f(); };
      sideSp.Children.Add(cell);
    }
    foreach (var pt in paints) pt();
    PreviewKeyDown += (s, e) => { if (e.Key == System.Windows.Input.Key.F && System.Windows.Input.Keyboard.Modifiers == System.Windows.Input.ModifierKeys.Control) { sbox?.Focus(); sbox?.SelectAll(); e.Handled = true; } };
    var topBar = new Border { Child = top, Background = Brushes.White, BorderBrush = line, BorderThickness = new Thickness(0, 0, 0, 1) };
    var root = new DockPanel(); DockPanel.SetDock(topBar, Dock.Top); DockPanel.SetDock(side, Dock.Left); // ב-RTL: מופיע מימין
    var foot = new TextBlock { Text = "האחריות על המשתמש בלבד, בעז\"ה שישמש לדברים חיוביים.", FontSize = 12, Foreground = new SolidColorBrush(Color.FromRgb(148, 163, 184)), HorizontalAlignment = HorizontalAlignment.Center, TextAlignment = TextAlignment.Center, Margin = new Thickness(0, 7, 0, 9) }; DockPanel.SetDock(foot, Dock.Bottom);
    root.Children.Add(foot); root.Children.Add(topBar); root.Children.Add(side); root.Children.Add(host); Content = root; host.Content = P1(); StartSync(); Closing += (s, e) => { syncTmr?.Stop(); };
  }
  async Task Do() {
    if (C.Master && C.DefaultCode == null && C.All().Any(r => r.On && r.Mode == Mode.Code && r.OwnCode == null)) { MessageBox.Show("יש חסימות בקוד שאין להן קוד. הגדר קוד ברירת מחדל (חלון 1) או קוד נפרד לכל חסימה."); return; }
    C.TempOpenUntil = 0;
    if (C.Master && C.Sched.On && !C.Sched.Active(C.Sched.NowPinned())) {   // מחוץ לחלון הזמנים: שומרים, והשירות יפעיל לבד בתחילת החלון
      try { C.Save(true); } catch (Exception x) { MessageBox.Show(x.Message); }
      status.Text = "מחוץ לחלון הזמנים – החסימות יופעלו אוטומטית בתחילת החלון"; return;
    }
    if (C.PreviewApply && MessageBox.Show(Enforcer.Describe(C) + "\n\nלהחיל?", "סיכום החלה", MessageBoxButton.YesNo) != MessageBoxResult.Yes) return;
    status.Text = "מחיל..."; IsEnabled = false; busy = true;
    try {
      await Task.Factory.StartNew(() => Enforcer.Apply(C), CancellationToken.None, TaskCreationOptions.None, Enforcer.Sta);
      status.Text = "הוחל ✓" + (Enforcer.Blocked > 0 || Enforcer.Failed > 0 ? $" (נחסמו {Enforcer.Blocked} קבצים" + (Enforcer.Failed > 0 ? $", נכשלו {Enforcer.Failed}: {Enforcer.LastErr}" : "") + ")" : "");
      StartScanWatch();
    } catch (Exception x) { status.Text = "שגיאה: " + x.Message; MessageBox.Show("שגיאה בהחלת החסימות: " + x.Message); }
    busy = false; IsEnabled = true;
  }

  // ---------- התקדמות חסימת הקבצים ברקע (הסריקה רצה בשירות, ולכן אפשר להמשיך להשתמש בתוכנה) ----------
  void InitScanBar() {
    scanFill = new Border { Background = new SolidColorBrush(Color.FromRgb(134, 214, 160)), CornerRadius = new CornerRadius(7), HorizontalAlignment = HorizontalAlignment.Left, Width = 0 };
    scanTxt = new TextBlock { FontSize = 12, FontWeight = FontWeights.SemiBold, Foreground = new SolidColorBrush(Color.FromRgb(21, 101, 52)), HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
    var g = new Grid(); g.Children.Add(scanFill); g.Children.Add(scanTxt);
    scanBar = new Border { Width = ScanW, Height = 26, CornerRadius = new CornerRadius(8), Background = new SolidColorBrush(Color.FromRgb(236, 244, 239)), BorderBrush = new SolidColorBrush(Color.FromRgb(206, 228, 214)), BorderThickness = new Thickness(1), Child = g, Visibility = Visibility.Collapsed };
    Theme.Tipped(scanBar, "התקדמות חסימת הקבצים ברקע. אפשר להמשיך להשתמש בתוכנה בזמן הסריקה.");
  }
  void ScanShow(double f, string t) { scanFill.Width = Math.Max(0, (ScanW - 2) * Math.Min(1, f)); scanTxt.Text = t; }
  void StartScanWatch() {
    scanTmr?.Stop();
    if (!(C.Master && Enforcer.ExtMap(C).Count > 0)) { scanBar.Visibility = Visibility.Collapsed; return; }
    try { scanFrom = File.GetLastWriteTimeUtc(System.IO.Path.Combine(Config.Dir, "config.json")).Ticks; } catch { scanFrom = DateTime.UtcNow.Ticks; }
    scanBar.Visibility = Visibility.Visible; ScanShow(0, "מתחיל…"); int miss = 0; var t0 = DateTime.UtcNow;
    var tm = scanTmr = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(700) };
    tm.Tick += async (s, e) => {
      if (scanBusy) return; scanBusy = true;
      try {
        var resp = await Task.Run(() => Config.Pipe("SCAN", 1500)); var q = resp?.Split('|');
        if (q == null || q.Length < 6) { if (++miss >= 10) { tm.Stop(); ScanShow(0, "השירות לא זמין"); } return; }
        miss = 0; if (q.Length > 6 && q[6].Length > 0) status.Text = "אזהרה: אין תמיכה בחסימת קבצים בכוננים " + q[6] + " (FAT/exFAT)"; long st = long.Parse(q[1]); int done = int.Parse(q[2]), total = int.Parse(q[3]);
        if (st < scanFrom) { ScanShow(0, "מתחיל…"); if ((DateTime.UtcNow - t0).TotalMinutes > 3) { tm.Stop(); scanBar.Visibility = Visibility.Collapsed; } return; }
        if (q[5] == "1") { ScanShow(1, "סיים"); tm.Stop(); var cc = C; _ = Task.Run(() => Enforcer.ClearViewerCaches(cc)); return; }
        if (total <= 0) { ScanShow(0, "מכין…"); return; }
        double f = (double)done / total; ScanShow(f, (int)(f * 100) + "%");
      } catch { } finally { scanBusy = false; }
    };
    tm.Start();
  }

  // ---------- דיאלוגים ----------
  const int MinCode = 6;   // אורך מינימלי לקוד חדש (confirm = הגדרת קוד). קודים קיימים ממשיכים לעבוד
  public static string? Ask(string title, bool confirm = false) {
    var w = new Window { Title = title, SizeToContent = SizeToContent.WidthAndHeight, WindowStartupLocation = WindowStartupLocation.CenterScreen, FlowDirection = FlowDirection.RightToLeft, ResizeMode = ResizeMode.NoResize, Topmost = true, Background = new SolidColorBrush(Color.FromRgb(248, 250, 252)), FontFamily = new FontFamily("Segoe UI"), FontSize = 14 };
    var sp = new StackPanel { Margin = new Thickness(16) }; var a = new PasswordBox { Width = 240, Margin = new Thickness(0, 4, 0, 8) }; var b = new PasswordBox { Width = 240, Margin = new Thickness(0, 4, 0, 8) };
    sp.Children.Add(new TextBlock { Text = title }); sp.Children.Add(a);
    if (confirm) { sp.Children.Add(new TextBlock { Text = "אימות הקוד" }); sp.Children.Add(b); }
    string? res = null; var ok = new Button { Content = "אישור", IsDefault = true, Padding = new Thickness(10, 4, 10, 4) };
    ok.Click += (s, e) => { if (a.Password.Length == 0) return; if (confirm && a.Password.Length < MinCode) { MessageBox.Show($"הקוד חייב להכיל לפחות {MinCode} תווים"); return; } if (confirm && a.Password != b.Password) { MessageBox.Show("הקודים אינם זהים"); return; } res = a.Password; w.Close(); };
    sp.Children.Add(ok); w.Content = sp; w.ShowDialog(); return res;
  }
  public static List<string>? Pick(string title, IEnumerable<(string L, string V)> opts, IEnumerable<string> sel) {
    var w = new Window { Title = title, Width = 420, Height = 520, WindowStartupLocation = WindowStartupLocation.CenterScreen, FlowDirection = FlowDirection.RightToLeft, Background = new SolidColorBrush(Color.FromRgb(248, 250, 252)), FontFamily = new FontFamily("Segoe UI"), FontSize = 14 };
    var lb = new StackPanel(); var boxes = opts.Select(o => new CheckBox { Content = o.L, Tag = o.V, IsChecked = sel.Contains(o.V), Margin = new Thickness(6) }).ToList(); boxes.ForEach(x => lb.Children.Add(x));
    List<string>? res = null; var ok = new Button { Content = "אישור", IsDefault = true, Margin = new Thickness(8), Padding = new Thickness(10, 4, 10, 4) };
    ok.Click += (s, e) => { res = boxes.Where(x => x.IsChecked == true).Select(x => (string)x.Tag).ToList(); w.Close(); };
    var d = new DockPanel(); DockPanel.SetDock(ok, Dock.Bottom); d.Children.Add(ok); d.Children.Add(new ScrollViewer { Content = lb }); w.Content = d; w.ShowDialog(); return res;
  }

  // ---------- רכיבי UI ----------
  static UIElement Segment(string[] labels, int sel, Action<int> changed) {
    var outer = new Border { Background = new SolidColorBrush(Color.FromRgb(238, 242, 247)), CornerRadius = new CornerRadius(10), Padding = new Thickness(3), Margin = new Thickness(0, 4, 12, 4), VerticalAlignment = VerticalAlignment.Center };
    var sp = new StackPanel { Orientation = Orientation.Horizontal }; var items = new List<Border>();
    void Paint() { for (int i = 0; i < items.Count; i++) { items[i].Background = i == sel ? Brushes.White : Brushes.Transparent; ((TextBlock)items[i].Child).Foreground = new SolidColorBrush(i == sel ? Color.FromRgb(30, 41, 59) : Color.FromRgb(100, 116, 139)); } }
    for (int i = 0; i < labels.Length; i++) {
      int k = i; var bd = new Border { CornerRadius = new CornerRadius(8), Padding = new Thickness(12, 5, 12, 5), Cursor = System.Windows.Input.Cursors.Hand, Background = Brushes.Transparent, Child = new TextBlock { Text = labels[i], FontSize = 13 } };
      bd.MouseLeftButtonUp += (s, e) => { sel = k; Paint(); changed(k); }; items.Add(bd); sp.Children.Add(bd);
    }
    Paint(); outer.Child = sp; return outer;
  }
  UIElement Row(Rule r, Func<IEnumerable<(string, string)>>? wl = null, bool file = true, Action? remove = null, string? glyph = null, bool canOpen = false, Action? touch = null) {
    void Sv() { touch?.Invoke(); C.Save(); }
    if (glyph == null && remove != null) glyph = Directory.Exists(r.Path) ? "\uE8B7" : "\uE8A5";
    var p = new WrapPanel { VerticalAlignment = VerticalAlignment.Center }; var m12 = new Thickness(0, 4, 12, 4);
    if (glyph != null) p.Children.Add(Theme.Badge(glyph));
    var on = new CheckBox { Content = r.Name, IsChecked = r.On, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center }; on.Click += (s, e) => { if (ReferenceEquals(r, C.Net) && on.IsChecked == true && !NetWarn()) { on.IsChecked = false; return; } r.On = on.IsChecked == true; Sv(); };
    var sep = new CheckBox { Content = "קוד נפרד", IsChecked = r.OwnCode != null, VerticalAlignment = VerticalAlignment.Center, Margin = m12 };
    var hid = new CheckBox { Content = "נסתר", IsChecked = r.Hidden, VerticalAlignment = VerticalAlignment.Center, Margin = m12 };
    Button? ob = null;
    void V() { if (ob != null) ob.Visibility = r.Mode == Mode.Code ? Visibility.Visible : Visibility.Collapsed; sep.Visibility = r.Mode == Mode.Code ? Visibility.Visible : Visibility.Collapsed; hid.Visibility = r.Mode == Mode.Full && file ? Visibility.Visible : Visibility.Collapsed; }
    var seg = Segment(new[] { "חסימה גמורה", "חסימה בקוד" }, (int)r.Mode, i => { r.Mode = (Mode)i; V(); Sv(); });
    sep.Click += (s, e) => { if (sep.IsChecked == true) { var k = Ask("קוד נפרד עבור: " + r.Name, true); if (k == null) { sep.IsChecked = false; return; } r.OwnCode = Config.Hash(k); } else r.OwnCode = null; Sv(); };
    hid.Click += (s, e) => { r.Hidden = hid.IsChecked == true; Sv(); };
    var head = new StackPanel { Orientation = Orientation.Horizontal, MinWidth = 280, Margin = m12, VerticalAlignment = VerticalAlignment.Center }; head.Children.Add(on);
    var rt = RuleTip(r); if (rt != null) { var inf = Theme.Info(rt); inf.Margin = new Thickness(8, 0, 0, 0); head.Children.Add(inf); }
    Theme.Tipped((FrameworkElement)seg, "חסימה גמורה – הפריט חסום לחלוטין ואי אפשר לפתוח אותו.\nחסימה בקוד – מי שמקיש את הקוד הנכון יכול לפתוח אותו.");
    Theme.Tipped(sep, "משתמש בקוד מיוחד לפריט הזה, במקום בקוד ברירת המחדל.");
    Theme.Tipped(hid, "מסתיר את הפריט כך שלא יופיע בסייר הקבצים. פועל בחסימה גמורה.");
    p.Children.Add(head); p.Children.Add(seg); p.Children.Add(sep); p.Children.Add(hid); if (canOpen) { ob = Btn("פתח בקוד", () => OpenWithCode(r), "\uE785"); ob.Margin = m12; Theme.Tipped(ob, "פותח את הפריט אחרי הקשת קוד, ונועל אותו שוב אוטומטית כשסוגרים אותו."); p.Children.Add(ob); } V();
    if (wl != null) { var b = Btn("רשימה לבנה", () => { var x = Pick("רשימה לבנה – " + r.Name, wl(), r.White); if (x != null) { r.White = x; Sv(); } }, "\uE8FD"); b.Margin = m12; Theme.Tipped(b, WlTip(r)); p.Children.Add(b); }
    if (remove != null) { var d = new Button { Content = Theme.Glyph("\uE74D", 15, new SolidColorBrush(Color.FromRgb(185, 28, 28))), Style = Theme.Soft(typeof(Button)), Padding = new Thickness(10, 7, 10, 7), Margin = new Thickness(0, 4, 0, 4) }; Theme.Tint(d, Color.FromRgb(254, 242, 242), Color.FromRgb(185, 28, 28), Color.FromRgb(245, 198, 198)); d.Click += (s, e) => remove(); Theme.Tipped(d, "מסיר את הפריט מהרשימה ומבטל את החסימה שלו."); p.Children.Add(d); }
    return new Border { Child = p, Background = Brushes.White, CornerRadius = new CornerRadius(14), Padding = new Thickness(16, 12, 16, 12), Margin = new Thickness(0, 0, 0, 12), BorderBrush = new SolidColorBrush(Color.FromRgb(230, 235, 242)), BorderThickness = new Thickness(1), Effect = new System.Windows.Media.Effects.DropShadowEffect { BlurRadius = 16, ShadowDepth = 2, Opacity = 0.05, Color = Color.FromRgb(30, 41, 59) } };
  }
  // חלון אישור אחריות – מופיע פעם אחת בלבד, בהפעלה הראשונה אחרי הקשת הקוד
  public static bool TermsDialog() {
    bool ok = false;
    var w = new Window { Title = "DeviceGuard", Topmost = true, WindowStartupLocation = WindowStartupLocation.CenterScreen, ResizeMode = ResizeMode.NoResize, SizeToContent = SizeToContent.Height, Width = 420, FlowDirection = FlowDirection.RightToLeft, Background = new SolidColorBrush(Color.FromRgb(248, 250, 252)), FontFamily = new FontFamily("Segoe UI"), Foreground = new SolidColorBrush(Color.FromRgb(30, 41, 59)) };
    var sp = new StackPanel { Margin = new Thickness(28, 24, 28, 24) };
    sp.Children.Add(new Border { Width = 52, Height = 52, CornerRadius = new CornerRadius(16), Background = new SolidColorBrush(Color.FromRgb(238, 243, 252)), HorizontalAlignment = HorizontalAlignment.Center, Child = Theme.Glyph("\uE72E", 26, Theme.Accent) });
    sp.Children.Add(new TextBlock { Text = "שים לב", FontSize = 20, FontWeight = FontWeights.SemiBold, HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 14, 0, 10) });
    sp.Children.Add(new TextBlock { Text = "השימוש בתוכנה על אחריות המשתמש בלבד", FontSize = 15, LineHeight = 24, TextWrapping = TextWrapping.Wrap, TextAlignment = TextAlignment.Center, Margin = new Thickness(0, 0, 0, 22) });
    var b = new Button { Content = "אני מאשר", IsDefault = true, FontSize = 15, Padding = new Thickness(40, 9, 40, 9), HorizontalAlignment = HorizontalAlignment.Center }; b.Click += (s, e) => { ok = true; w.Close(); };
    sp.Children.Add(b); w.Content = sp; w.ShowDialog(); return ok;
  }
  // אזהרה שמופיעה בהפעלת חסימת חיבור לרשת; מחזיר true רק אחרי שלוחצים "הבנתי"
  bool NetWarn() {
    bool ok = false;
    var w = new Window { Title = "שים לב", Owner = this, WindowStartupLocation = WindowStartupLocation.CenterOwner, ResizeMode = ResizeMode.NoResize, ShowInTaskbar = false, SizeToContent = SizeToContent.Height, Width = 440, FlowDirection = FlowDirection.RightToLeft, Background = new SolidColorBrush(Color.FromRgb(248, 250, 252)), FontFamily = new FontFamily("Segoe UI"), Foreground = new SolidColorBrush(Color.FromRgb(30, 41, 59)) };
    var sp = new StackPanel { Margin = new Thickness(28, 24, 28, 24) };
    sp.Children.Add(new Border { Width = 52, Height = 52, CornerRadius = new CornerRadius(16), Background = new SolidColorBrush(Color.FromRgb(254, 243, 199)), HorizontalAlignment = HorizontalAlignment.Center, Child = Theme.Glyph("\uE7BA", 26, new SolidColorBrush(Color.FromRgb(180, 83, 9))) });
    sp.Children.Add(new TextBlock { Text = "שים לב", FontSize = 20, FontWeight = FontWeights.SemiBold, HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 14, 0, 10) });
    sp.Children.Add(new TextBlock { Text = "חוץ מחסימה זו יש להתקין תעודת אבטחה - נטפרי וכדו' (החוסם את חיבור המחשב לאינטרנט ללא סינון) ואין להסתמך רק על חסימה זו, אינטרנט ללא סינון מסוכן מאוד!", FontSize = 15, LineHeight = 24, TextWrapping = TextWrapping.Wrap, TextAlignment = TextAlignment.Center, Margin = new Thickness(0, 0, 0, 22) });
    var b = new Button { Content = "הבנתי", IsDefault = true, FontSize = 15, Padding = new Thickness(40, 9, 40, 9), HorizontalAlignment = HorizontalAlignment.Center }; b.Click += (s, e) => { ok = true; w.Close(); };
    sp.Children.Add(b); w.Content = sp; w.ShowDialog(); return ok;
  }
  string? RuleTip(Rule r) {
    if (ReferenceEquals(r, C.Settings)) return "חוסם את הגישה להגדרות המחשב וללוח הבקרה. בחסימה גמורה אפשר להשאיר דפי הגדרות מסוימים פתוחים ברשימה הלבנה. בחסימה בקוד נדרש קוד כדי להיכנס להגדרות.";
    if (ReferenceEquals(r, C.Install)) return "חוסם התקנה של תוכנות באמצעות מתקין Windows (קובצי MSI). בחסימה בקוד נדרש קוד כדי להתקין.";
    if (ReferenceEquals(r, C.Net)) return "חוסם חיבור לרשת: מתאמי רשת קוויים מושבתים, ובכרטיס Wi-Fi נחסמות כל הרשתות – גם כאלה שלא היו זמינות בזמן ההחלה. ברשימה הלבנה אפשר להשאיר מתאם או רשת Wi-Fi מסוימת מותרים.";
    if (ReferenceEquals(r, C.Usb)) return "חוסם את כל ההתקנים החיצוניים (דיסק און קי, דיסק נייד) – גם כאלה שעדיין לא חוברו למחשב. ברשימה הלבנה מופיעים ההתקנים המחוברים כרגע: התקן שתבחר ייזכר ויורשה גם בחיבורים הבאים, ושאר ההתקנים יישארו חסומים.";
    if (ReferenceEquals(r, C.Portable)) return "חוסם הרצת תוכנות מכל מקום מחוץ ל-Windows ול-Program Files, כולל אפליקציות שמותקנות בתיקיית המשתמש. אפשר להתיר תוכנות מסוימות ברשימה הלבנה. החסימה היא גמורה בלבד.";
    if (ReferenceEquals(r, C.Movies)) return "חוסם קובצי וידאו (כגון mp4, avi, mkv) בכל הכוננים, וגם קבצים חדשים שיתווספו בהמשך.";
    if (ReferenceEquals(r, C.Songs)) return "חוסם קובצי שמע ושירים (כגון mp3, wav, flac) בכל הכוננים, וגם קבצים חדשים שיתווספו בהמשך.";
    if (ReferenceEquals(r, C.Images)) return "חוסם קובצי תמונות (כגון jpg, png, gif) בכל הכוננים, וגם קבצים חדשים שיתווספו בהמשך.";
    if (C.Paths.Contains(r)) return "חוסם גישה לקובץ או לתיקייה הזו: קריאה, הפעלה ומחיקה. בחסימה בקוד הפריט מוסתר ונפתח רק דרך הכפתור 'פתח בקוד'.";
    if (C.Exts.Contains(r)) return "חוסם את כל הקבצים בסיומת הזו בכל הכוננים, וגם קבצים חדשים שיתווספו בהמשך.";
    if (!string.IsNullOrEmpty(r.Path)) return "חוסם את הפעלת התוכנה הזו. בחסימה גמורה היא לא נפתחת, ובחסימה בקוד נדרש קוד כדי להפעיל אותה.";
    return null;
  }
  string WlTip(Rule r) =>
    ReferenceEquals(r, C.Usb) ? "ההתקנים המחוברים כרגע מוצגים ברשימה. התקן שתסמן ייזכר ויורשה גם בחיבורים הבאים, ושאר ההתקנים יישארו חסומים." :
    ReferenceEquals(r, C.Net) ? "בחר מתאמי רשת או רשתות Wi-Fi שיישארו מותרים. כל השאר ייחסמו." :
    ReferenceEquals(r, C.Settings) ? "בחר דפי הגדרות שיישארו פתוחים. כל השאר ייחסמו." :
    "פריטים שתסמן ברשימה הלבנה לא ייחסמו.";
  static ScrollViewer Page(string title, string glyph, params UIElement[] items) {
    var sp = new StackPanel { Margin = new Thickness(28, 22, 28, 22) };
    var h = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 18) };
    h.Children.Add(Theme.Badge(glyph)); h.Children.Add(new TextBlock { Text = title, FontSize = 22, FontWeight = FontWeights.SemiBold, Foreground = new SolidColorBrush(Color.FromRgb(30, 41, 59)), VerticalAlignment = VerticalAlignment.Center });
    sp.Children.Add(h); foreach (var i in items) sp.Children.Add(i); return new ScrollViewer { Content = sp, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
  }
  static Button Btn(string t, Action a, string? glyph = null) {
    glyph ??= t.Contains("הוסף") ? "\uE710" : t.Contains("ייצוא") ? "\uE898" : t.Contains("ייבוא") ? "\uE896" : t.Contains("קוד") ? "\uE72E" : null;
    var b = new Button { Content = glyph == null ? t : Theme.IconText(glyph, t), Margin = new Thickness(0, 4, 8, 4) }; b.Click += (s, e) => a(); return b;
  }
  static readonly Dictionary<string, ImageSource?> iconCache = new(StringComparer.OrdinalIgnoreCase);
  static new ImageSource? Icon(string exe) {
    if (iconCache.TryGetValue(exe, out var c)) return c;
    ImageSource? r = null;
    try { using var i = System.Drawing.Icon.ExtractAssociatedIcon(exe); if (i != null) { var b = Imaging.CreateBitmapSourceFromHIcon(i.Handle, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions()); b.Freeze(); r = b; } } catch { }
    iconCache[exe] = r; return r;
  }

  UIElement ProgRow(string n, string e) {
    var rule = C.Programs.FirstOrDefault(x => x.Path.Equals(e, StringComparison.OrdinalIgnoreCase)) ?? new Rule { Name = n, Path = e };   // נוסף לרשימה ונשמר רק אחרי שינוי (לא כל תוכנה מותקנת)
    var d = new DockPanel(); var img = new Image { Source = Icon(e), Width = 32, Height = 32, Margin = new Thickness(0, 0, 10, 0) }; DockPanel.SetDock(img, Dock.Left); d.Children.Add(img);
    d.Children.Add(Row(rule, null, true, null, null, false, () => { if (!C.Programs.Contains(rule)) C.Programs.Add(rule); })); return d;
  }
  void OpenWithCode(Rule r) {
    var g = System.IO.Path.Combine(Config.Dir, "DeviceGuardWatch.exe");
    if (!File.Exists(g)) { MessageBox.Show("יש ללחוץ 'החל שינויים' קודם"); return; }
    Process.Start(new ProcessStartInfo(g, "--open " + r.Id) { UseShellExecute = false });
  }
  TextBox? sbox;
  UIElement SearchBox() {
    var tb = new TextBox { Width = 240, BorderThickness = new Thickness(0), Background = Brushes.Transparent, Padding = new Thickness(0, 9, 0, 9), VerticalContentAlignment = VerticalAlignment.Center, FontSize = 13.5, ToolTip = "חיפוש בתוכנה (Ctrl+F)" }; sbox = tb;
    var gray = new SolidColorBrush(Color.FromRgb(156, 163, 175));
    var ph = new TextBlock { Text = "חיפוש הגדרה... (Ctrl+F)", Foreground = gray, FontSize = 13.5, IsHitTestVisible = false, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(5, 0, 5, 0) };
    var clr = Theme.Glyph("\uE711", 11, gray); clr.Cursor = System.Windows.Input.Cursors.Hand; clr.Visibility = Visibility.Collapsed; clr.Margin = new Thickness(6, 0, 0, 0); clr.Background = Brushes.Transparent;
    var ico = Theme.Glyph("\uE721", 14, gray); ico.Margin = new Thickness(0, 0, 8, 0);
    var g = new Grid(); g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto }); g.ColumnDefinitions.Add(new ColumnDefinition()); g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
    Grid.SetColumn(ico, 0); Grid.SetColumn(tb, 1); Grid.SetColumn(ph, 1); Grid.SetColumn(clr, 2);
    g.Children.Add(ico); g.Children.Add(tb); g.Children.Add(ph); g.Children.Add(clr);
    var edge = new SolidColorBrush(Color.FromRgb(229, 231, 235));
    var box = new Border { Background = new SolidColorBrush(Color.FromRgb(249, 250, 251)), BorderBrush = edge, BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(10), Padding = new Thickness(12, 0, 12, 0), Child = g };
    tb.GotKeyboardFocus += (s, e) => { box.BorderBrush = Theme.Accent; box.Background = Brushes.White; };
    tb.LostKeyboardFocus += (s, e) => { box.BorderBrush = edge; box.Background = new SolidColorBrush(Color.FromRgb(249, 250, 251)); };
    clr.MouseLeftButtonUp += (s, e) => { tb.Clear(); tb.Focus(); };
    tb.TextChanged += (s, e) => { var q = tb.Text.Trim(); ph.Visibility = tb.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed; clr.Visibility = tb.Text.Length == 0 ? Visibility.Collapsed : Visibility.Visible; host.Content = q.Length == 0 ? (cur ?? (Func<UIElement>)P1)() : Search(q); };
    return box;
  }
  UIElement Search(string q) {
    bool M(string t) => t.Contains(q, StringComparison.CurrentCultureIgnoreCase);
    var items = new List<UIElement>();
    foreach (var (r, g, f) in new[] { (C.Settings, "\uE713", false), (C.Install, "\uE896", false), (C.Net, "\uE774", false), (C.Usb, "\uE88E", false), (C.Portable, "\uE8A7", false), (C.Movies, "\uE714", true), (C.Songs, "\uE8D6", true), (C.Images, "\uE91B", true) })
      if (M(r.Name)) items.Add(Row(r, null, f, null, g));
    if (M(C.NetApps.Name)) items.Add(NetAppsRow());
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
    var hard = new CheckBox { Content = "חיזוק חסימת קבצים: מונע מבעל הקובץ לשנות הרשאות ולהסיר את החסימה (יחול אחרי 'החל שינויים')", IsChecked = C.Harden, Margin = new Thickness(0, 0, 0, 8) }; hard.Click += (s, e) => { C.Harden = hard.IsChecked == true; C.Save(); };
    var code = Btn("הגדר / שנה קוד ברירת מחדל לחסימות", () => { var k = Ask("קוד ברירת מחדל", true); if (k != null) { C.DefaultCode = Config.Hash(k); C.Save(); MessageBox.Show("הקוד נשמר"); } });
    Func<IEnumerable<(string, string)>> usb = UsbList;
    var exp = Btn("ייצוא הגדרות…", Export); var imp = Btn("ייבוא הגדרות…", Import);
    var un2 = Btn("הסרת שירות ההגנה (בקוד כניסה)", () => {
      if (MessageBox.Show("הפעולה תשבית את כל החסימות ותסיר את שירות ההגנה. להמשיך?", "אישור", MessageBoxButton.YesNo) != MessageBoxResult.Yes) return;
      var k = Ask("קוד כניסה לתוכנה"); if (k == null || !Config.Check(k, C.AppCode)) { MessageBox.Show("קוד שגוי"); return; }
      _ = Uninstall();
    }, "\uE74D");
    var note = new TextBlock { Text = "הערה: רשימה לבנה של הגדרות/רשת/התקנים פועלת בחסימה גמורה.", Foreground = Brushes.Gray, Margin = new Thickness(0, 8, 0, 0), TextWrapping = TextWrapping.Wrap };
    Theme.Tipped(all, "מסומן: החסימות פועלות בכל חשבונות המשתמשים במחשב. לא מסומן: רק בחשבון המשתמש הנוכחי.");
    Theme.Tipped(code, "קוד ברירת המחדל משמש לפתיחת כל חסימה בקוד שלא הוגדר לה קוד נפרד.");
    Theme.Tipped(exp, "שומר את ההגדרות לקובץ, לגיבוי או להעברה למחשב אחר.");
    Theme.Tipped(imp, "טוען הגדרות מקובץ שיוצא קודם. אחרי הטעינה לוחצים 'החל שינויים'.");
    Theme.Tipped(un2, "מכבה את כל החסימות ומסיר את שירות ההגנה מהמחשב, אחרי הקשת קוד הכניסה.");
    return Page("הגדרות כלליות", "\uE713", code, all, hard, SkipAppCheck(), ScanOpts(), PreviewCheck(), Row(C.Settings, () => SettingsPages, false, null, "\uE713"), Row(C.Install, null, false, null, "\uE896"), Row(C.Usb, usb, false, null, "\uE88E"), SchedulePanel(), new StackPanel { Orientation = Orientation.Horizontal, Children = { exp, imp, un2 } }, note);
  }
  // הסרה: ביטול החסימות רץ ברקע (החלון לא נתקע), ותוצאת ההסרה נבדקת לפני שמודיעים שהשירות יוסר
  async Task Uninstall() {
    IsEnabled = false; busy = true; status.Text = "מסיר...";
    try {
      await Task.Factory.StartNew(() => { C.Master = false; C.TempOpenUntil = 0; Enforcer.Apply(C); Enforcer.PurgeAll(); }, CancellationToken.None, TaskCreationOptions.None, Enforcer.Sta);
      var r = await Task.Run(() => {
        var x = Config.Token != null ? Config.Pipe("UNINSTALL|" + Config.Token, 5000) : null;
        if (x != "OK" && Program.Code != null && Config.Auth(Program.Code)) x = Config.Pipe("UNINSTALL|" + Config.Token, 5000);   // הטוקן פג: אימות מחדש וניסיון נוסף
        return x;
      });
      if (r == "OK") { Config.Token = null; status.Text = ""; MessageBox.Show("השירות יוסר בעוד מספר שניות"); }
      else { status.Text = "הסרת השירות נכשלה"; MessageBox.Show("החסימות בוטלו, אך הסרת שירות ההגנה נכשלה. נסה שוב, או הפעל מחדש את המחשב ונסה שוב."); }
    } catch (Exception x) { status.Text = "שגיאה: " + x.Message; MessageBox.Show("שגיאה בהסרה: " + x.Message); }
    busy = false; IsEnabled = true;
  }
  Dictionary<string, object> Sections() => new() { ["1"] = new { C.AllUsers, C.Settings, C.Install, C.Usb }, ["2"] = C.Programs, ["3"] = C.Portable, ["4"] = new { C.Movies, C.Songs, C.Images, C.Exts }, ["5"] = C.Paths, ["6"] = new { C.Net, C.NetApps, C.NetAppsWhite }, ["7"] = new { C.Adv, C.AdvOpts, C.Sched } };
  void Export() {
    var sel = Pick("מה לייצא?", Enumerable.Range(1, 7).Select(i => ($"חלון {i}", i.ToString())), new[] { "1", "2", "3", "4", "5", "6", "7" }); if (sel == null || sel.Count == 0) return;
    var d = new SaveFileDialog { Filter = "DeviceGuard|*.dgcfg", FileName = "settings.dgcfg" }; if (d.ShowDialog() != true) return;
    var node = System.Text.Json.Nodes.JsonNode.Parse(JsonSerializer.Serialize(Sections().Where(k => sel.Contains(k.Key)).ToDictionary(k => k.Key, k => k.Value), Config.O))!; StripOwn(node);   // קודים נפרדים (גם מגובבים) לא מיוצאים
    File.WriteAllText(d.FileName, node.ToJsonString(Config.O));
  }
  void Import() {
    var d = new OpenFileDialog { Filter = "DeviceGuard|*.dgcfg" }; if (d.ShowDialog() != true) return;
    try {
      using var doc = JsonDocument.Parse(File.ReadAllText(d.FileName)); var r = doc.RootElement; T D<T>(JsonElement e, string n) => e.GetProperty(n).Deserialize<T>(Config.O)!;
      if (r.TryGetProperty("1", out var a)) { C.AllUsers = a.GetProperty("AllUsers").GetBoolean(); C.Settings = D<Rule>(a, "Settings"); C.Install = D<Rule>(a, "Install"); if (a.TryGetProperty("Net", out var oldNet)) C.Net = oldNet.Deserialize<Rule>(Config.O)!; C.Usb = D<Rule>(a, "Usb"); }
      if (r.TryGetProperty("2", out var b)) C.Programs = b.Deserialize<List<Rule>>(Config.O)!;
      if (r.TryGetProperty("3", out var c3)) C.Portable = c3.Deserialize<Rule>(Config.O)!;
      if (r.TryGetProperty("4", out var e)) { C.Movies = D<Rule>(e, "Movies"); C.Songs = D<Rule>(e, "Songs"); C.Images = D<Rule>(e, "Images"); C.Exts = D<List<Rule>>(e, "Exts"); }
      if (r.TryGetProperty("5", out var f)) C.Paths = f.Deserialize<List<Rule>>(Config.O)!;
      if (r.TryGetProperty("6", out var g6)) { C.Net = D<Rule>(g6, "Net"); C.NetApps = D<Rule>(g6, "NetApps"); C.NetAppsWhite = D<bool>(g6, "NetAppsWhite"); }
      if (r.TryGetProperty("7", out var g7)) { C.Adv = D<Rule>(g7, "Adv"); C.AdvOpts = D<AdvOpts>(g7, "AdvOpts"); C.Sched = D<Schedule>(g7, "Sched"); }
      C.Save(); host.Content = P1(); status.Text = "יובא (קודים נפרדים לא מיובאים – יש להגדיר מחדש) – לחץ 'החל שינויים'";
    } catch (Exception x) { MessageBox.Show("קובץ לא תקין: " + x.Message); }
  }

  // ---------- חלון 2 ----------
    static string RunCmd(string exe, string args) => Enforcer.RunExe(exe, args);
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
    var list = new StackPanel(); var loading = new TextBlock { Text = "טוען רשימת תוכנות…", Foreground = Brushes.Gray }; list.Children.Add(loading);
    var note = new TextBlock { Text = "התוכנה סורקת תוכנות מותקנות ותפריט התחל. יישום שחסר מהרשימה אפשר לחסום ישירות דרך תיקיית הקבצים שלו בחלון 5.", Foreground = Brushes.Gray, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 10, 0, 0) };
    _ = FillProgs(list, loading);
    return Page("תוכנות מותקנות", "\uE71D", list, note);
  }
  async Task FillProgs(StackPanel list, TextBlock loading) {   // הסריקה רצה ברקע, והשורות נבנות במנות קטנות: החלון לא נתקע
    try {
      var items = await Task.Factory.StartNew(() => Installed(), CancellationToken.None, TaskCreationOptions.None, Enforcer.Sta);
      inst = items; list.Children.Remove(loading); int i = 0;
      foreach (var (n, e) in items) { list.Children.Add(ProgRow(n, e)); if (++i % 15 == 0) await Dispatcher.Yield(DispatcherPriority.Background); }
    } catch { }
  }

  // ---------- חלון 3 ----------
  UIElement P3() {
    Func<IEnumerable<(string, string)>> opts = () => {
      var l = new List<string>(C.Portable.White);
      foreach (var p in Process.GetProcesses()) { try { var f = p.MainModule?.FileName; if (f != null && !f.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase) && !f.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), StringComparison.OrdinalIgnoreCase) && !f.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), StringComparison.OrdinalIgnoreCase) && !l.Contains(f)) l.Add(f); } catch { } finally { p.Dispose(); } }
      return l.Select(f => (System.IO.Path.GetFileName(f) + "  —  " + f, f));
    };
    var drop = new Border { BorderBrush = new SolidColorBrush(Color.FromRgb(203, 213, 225)), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(14), Height = 90, Margin = new Thickness(0, 12, 0, 0), AllowDrop = true, Background = new SolidColorBrush(Color.FromRgb(252, 253, 254)), Child = new TextBlock { Text = "גרור לכאן תוכנה ניידת כדי להוסיפה לרשימה הלבנה", HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center } };
    drop.Drop += (s, e) => { if (e.Data.GetData(DataFormats.FileDrop) is string[] fs) { foreach (var f in fs) if (!C.Portable.White.Contains(f)) C.Portable.White.Add(f); C.Save(); MessageBox.Show($"נוספו {fs.Length} פריטים"); } };
    var warn = new TextBlock { Text = "חסימת ניידות חוסמת הרצה מכל מקום מחוץ ל-Windows ו-Program Files (כולל אפליקציות שמותקנות בתיקיית המשתמש). חסימה זו היא גמורה בלבד.", TextWrapping = TextWrapping.Wrap, Foreground = Brushes.Gray, Margin = new Thickness(0, 8, 0, 0) };
    Theme.Tipped(drop, "גרור לכאן תוכנה ניידת והיא תתווסף לרשימה הלבנה ותורשה לפעול.");
    return Page("תוכנות ניידות", "\uE8A7", Row(C.Portable, opts, false, null, "\uE8A7"), drop, warn);
  }

  // ---------- חלון 4 ----------
  UIElement P4() {
    var ext = new TextBox { Width = 120, Margin = new Thickness(0, 0, 8, 0) }; var list = new StackPanel();
    void Fill() { list.Children.Clear(); foreach (var r in C.Exts.ToList()) { var rr = r; list.Children.Add(Row(rr, null, true, () => { C.Exts.Remove(rr); C.Save(); Fill(); })); } }
    var add = Btn("הוסף סיומת", () => { var x = ext.Text.Trim().TrimStart('.').ToLowerInvariant(); if (x.Length == 0) return; if (Config.Danger.Contains(x)) { MessageBox.Show("סיומת זו חיונית לפעולת המחשב ולא ניתן לחסום אותה"); return; } C.Exts.Add(new Rule { Name = "חסימת ." + x, Path = x }); C.Save(); ext.Clear(); Fill(); });
    Fill(); var tip = new TextBlock { Text = "סרטים: " + string.Join(", ", Config.Vid.Take(12)) + "…  |  שירים: " + string.Join(", ", Config.Aud) + "  |  תמונות: " + string.Join(", ", Config.Img), Foreground = Brushes.Gray, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 8) };
    return Page("סוגי קבצים", "\uE8A5", Row(C.Movies, null, true, null, "\uE714"), Row(C.Songs, null, true, null, "\uE8D6"), Row(C.Images, null, true, null, "\uE91B"), tip, new TextBlock { Text = "סיומות נוספות:" }, new StackPanel { Orientation = Orientation.Horizontal, Children = { ext, add } }, list, Exclusions());
  }

  // ---------- חלון 5 ----------
  UIElement P5() {
    var list = new StackPanel();
    void Fill() { list.Children.Clear(); foreach (var r in C.Paths.ToList()) { var rr = r; list.Children.Add(Row(rr, null, true, () => { C.Paths.Remove(rr); C.Save(); Fill(); }, null, true)); } }
    void AddP(string p) { if (Enforcer.IsDangerous(p)) { MessageBox.Show("זהו נתיב מערכת (או כונן / תיקיית משתמשים), וחסימתו עלולה להקריס את המחשב. בחר תיקייה או קובץ ספציפיים."); return; } if (C.Paths.Any(x => x.Path.Equals(p, StringComparison.OrdinalIgnoreCase))) return; C.Paths.Add(new Rule { Name = p, Path = p }); C.Save(); Fill(); }
    var f = Btn("הוסף קובץ…", () => { var d = new OpenFileDialog { Multiselect = true }; if (d.ShowDialog() == true) foreach (var x in d.FileNames) AddP(x); });
    var g = Btn("הוסף תיקייה…", () => { var d = new OpenFolderDialog(); if (d.ShowDialog() == true) AddP(d.FolderName); });
    Fill(); return Page("קבצים ותיקיות", "\uE8B7", new StackPanel { Orientation = Orientation.Horizontal, Children = { f, g } }, list);
  }

  // ---------- חלון 6 ----------
  UIElement P6() {
    var net = () => {
      var items = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces().Where(n => n.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback).Select(n => (n.Name, n.Name)).ToList();
      items.AddRange(WifiSsids());
      return items.AsEnumerable();
    };
    var note = new TextBlock { Text = "הערה: רשימה לבנה של מתאמי רשת ורשתות Wi-Fi פועלת בחסימה גמורה. חסימה לפי תוכנה פועלת דרך חומת האש של Windows, והתוכנה משחזרת את הכללים אוטומטית אם נמחקו.", Foreground = Brushes.Gray, Margin = new Thickness(0, 8, 0, 0), TextWrapping = TextWrapping.Wrap };
    return Page("רשת", "\uE774", Row(C.Net, net, false, null, "\uE774"), NetAppsRow(), note);
  }
  // חסימת חיבור לרשת לפי תוכנה: רשימה שחורה (התוכנות ברשימה לא יתחברו) או רשימה לבנה (רק התוכנות ברשימה יתחברו)
  UIElement NetAppsRow() {
    var r = C.NetApps; var m12 = new Thickness(0, 4, 12, 4); var red = new SolidColorBrush(Color.FromRgb(185, 28, 28));
    var p = new WrapPanel { VerticalAlignment = VerticalAlignment.Center };
    p.Children.Add(Theme.Badge("\uE71B"));
    var on = new CheckBox { Content = r.Name, IsChecked = r.On, FontWeight = FontWeights.SemiBold, VerticalAlignment = VerticalAlignment.Center }; on.Click += (s, e) => { r.On = on.IsChecked == true; C.Save(); };
    var head = new StackPanel { Orientation = Orientation.Horizontal, MinWidth = 280, Margin = m12, VerticalAlignment = VerticalAlignment.Center }; head.Children.Add(on);
    var inf = Theme.Info("חוסם חיבור לרשת של תוכנות מסוימות, דרך חומת האש של Windows. ברשימה שחורה – התוכנות שבחרת לא יתחברו לרשת. ברשימה לבנה – רק התוכנות שבחרת יתחברו לרשת. יש ללחוץ 'החל שינויים' אחרי כל שינוי."); inf.Margin = new Thickness(8, 0, 0, 0); head.Children.Add(inf);
    var hint = new TextBlock { Foreground = Brushes.Gray, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 0) };
    void H() { hint.Text = C.NetAppsWhite ? "רשימה לבנה: רק התוכנות שברשימה יוכלו להתחבר לרשת, וכל שאר התוכנות ייחסמו. שירותי הרשת הבסיסיים של Windows (DNS ו-DHCP) נשארים פעילים. אם הרשימה ריקה – כל התוכנות ייחסמו." : "רשימה שחורה: התוכנות שברשימה לא יוכלו להתחבר לרשת. כל שאר התוכנות מתחברות כרגיל."; }
    var seg = Segment(new[] { "רשימה שחורה", "רשימה לבנה" }, C.NetAppsWhite ? 1 : 0, i => { C.NetAppsWhite = i == 1; C.Save(); H(); });
    Theme.Tipped((FrameworkElement)seg, "רשימה שחורה – התוכנות שברשימה נחסמות מהרשת.\nרשימה לבנה – רק התוכנות שברשימה מורשות להתחבר לרשת.");
    H();
    var list = new StackPanel { Margin = new Thickness(0, 10, 0, 0) };
    void Fill() {
      list.Children.Clear();
      if (r.White.Count == 0) list.Children.Add(new TextBlock { Text = "לא נוספו תוכנות לרשימה.", Foreground = Brushes.Gray });
      foreach (var path in r.White.ToList()) {
        var pp = path;
        var img = new Image { Source = Icon(pp), Width = 22, Height = 22, Margin = new Thickness(0, 0, 10, 0) }; DockPanel.SetDock(img, Dock.Left);
        var d = new Button { Content = Theme.Glyph("\uE74D", 14, red), Style = Theme.Soft(typeof(Button)), Padding = new Thickness(8, 5, 8, 5), Margin = new Thickness(10, 0, 0, 0) }; Theme.Tint(d, Color.FromRgb(254, 242, 242), Color.FromRgb(185, 28, 28), Color.FromRgb(245, 198, 198));
        d.Click += (s, e) => { r.White.Remove(pp); C.Save(); Fill(); }; DockPanel.SetDock(d, Dock.Right); Theme.Tipped(d, "מסיר את התוכנה מהרשימה.");
        var tx = new TextBlock { Text = pp.StartsWith("pkg:") ? "אפליקציית Store  —  " + pp[4..] : pp.StartsWith("svc:") ? "שירות  —  " + pp[4..] : System.IO.Path.GetFileName(pp) + "  —  " + pp, VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis, ToolTip = pp };
        var dp = new DockPanel { Margin = new Thickness(0, 3, 0, 3) }; dp.Children.Add(img); dp.Children.Add(d); dp.Children.Add(tx); list.Children.Add(dp);
      }
    }
    void AddFiles(IEnumerable<string> fs) {
      foreach (var f in fs) if (f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && !r.White.Any(x => x.Equals(f, StringComparison.OrdinalIgnoreCase))) r.White.Add(f);
      C.Save(); Fill();
    }
    var add = Btn("הוסף תוכנה…", () => { var d = new OpenFileDialog { Multiselect = true, Filter = "תוכנות (*.exe)|*.exe" }; if (d.ShowDialog() == true) AddFiles(d.FileNames); });
    bool Kind(string x) => x.StartsWith("pkg:", StringComparison.Ordinal) || x.StartsWith("svc:", StringComparison.Ordinal);
    void PickKind(string prefix, string title, List<(string, string)> opts) {   // בחירה מתוך סוג אחד של רשומות (אפליקציות Store או שירותים), בלי לגעת בשאר הרשימה
      foreach (var x in r.White.Where(y => y.StartsWith(prefix, StringComparison.Ordinal))) if (!opts.Any(o => o.Item2 == x)) opts.Add((x[prefix.Length..], x));
      var res = Pick(title, opts, r.White); if (res == null) return;
      r.White = r.White.Where(y => !y.StartsWith(prefix, StringComparison.Ordinal)).Concat(res).ToList(); C.Save(); Fill();
    }
    var pick = Btn("בחר מהתוכנות המותקנות…", () => {
      inst ??= Installed();
      var opts = r.White.Where(x => !Kind(x)).Select(x => (System.IO.Path.GetFileName(x) + "  —  " + x, x)).Concat(inst.Where(x => !r.White.Contains(x.E, StringComparer.OrdinalIgnoreCase)).Select(x => (x.N + "  —  " + x.E, x.E))).ToList();
      var res = Pick("תוכנות – " + r.Name, opts, r.White); if (res != null) { r.White = res.Concat(r.White.Where(Kind)).ToList(); C.Save(); Fill(); }
    }, "\uE71D");
    var store = Btn("בחר אפליקציות Store…", () => {
      var opts = new List<(string, string)>();
      var outp = RunCmd("powershell.exe", "-NoLogo -NoProfile -NonInteractive -EncodedCommand " + Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes("Get-AppxPackage | ? { -not $_.IsFramework -and -not $_.IsResourcePackage } | Sort-Object Name | % { $_.Name + '|' + $_.PackageFamilyName }")));
      foreach (var ln in outp.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)) { var z = ln.Split('|'); if (z.Length == 2) opts.Add((z[0], "pkg:" + z[1])); }
      PickKind("pkg:", "אפליקציות Store – " + r.Name, opts);
    }, "\uE719");
    var svc = Btn("בחר שירותים…", () => {
      var opts = new List<(string, string)>();
      try { foreach (var sv in System.ServiceProcess.ServiceController.GetServices().OrderBy(z => z.DisplayName).ToList()) { opts.Add((sv.DisplayName + "  —  " + sv.ServiceName, "svc:" + sv.ServiceName)); sv.Dispose(); } } catch { }
      PickKind("svc:", "שירותים – " + r.Name, opts);
    }, "\uE713");
    Theme.Tipped(add, "מוסיף קובצי הרצה (exe) לרשימה."); Theme.Tipped(pick, "בחירת תוכנות מתוך התוכנות המותקנות במחשב."); Theme.Tipped(store, "בחירת אפליקציות שהותקנו מ-Microsoft Store (הן אינן נשלטות לפי נתיב קובץ)."); Theme.Tipped(svc, "בחירת שירותי Windows (למשל עדכוני Windows), גם אם הם רצים דרך svchost.");
    var drop = new Border { BorderBrush = new SolidColorBrush(Color.FromRgb(203, 213, 225)), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(14), Height = 60, Margin = new Thickness(0, 10, 0, 0), AllowDrop = true, Background = new SolidColorBrush(Color.FromRgb(252, 253, 254)), Child = new TextBlock { Text = "גרור לכאן תוכנות (exe) כדי להוסיף אותן לרשימה", HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center } };
    drop.Drop += (s, e) => { if (e.Data.GetData(DataFormats.FileDrop) is string[] fs) AddFiles(fs); };
    Fill();
    p.Children.Add(head); p.Children.Add(seg); p.Children.Add(add); p.Children.Add(pick); p.Children.Add(store); p.Children.Add(svc);
    var body = new StackPanel(); body.Children.Add(p); body.Children.Add(hint); body.Children.Add(drop); body.Children.Add(list);
    return new Border { Child = body, Background = Brushes.White, CornerRadius = new CornerRadius(14), Padding = new Thickness(16, 12, 16, 12), Margin = new Thickness(0, 0, 0, 12), BorderBrush = new SolidColorBrush(Color.FromRgb(230, 235, 242)), BorderThickness = new Thickness(1), Effect = new System.Windows.Media.Effects.DropShadowEffect { BlurRadius = 16, ShadowDepth = 2, Opacity = 0.05, Color = Color.FromRgb(30, 41, 59) } };
  }

  // ---------- רכיבים חדשים ----------
  static Border Card(UIElement child) => new Border { Child = child, Background = Brushes.White, CornerRadius = new CornerRadius(14), Padding = new Thickness(16, 12, 16, 12), Margin = new Thickness(0, 0, 0, 12), BorderBrush = new SolidColorBrush(Color.FromRgb(230, 235, 242)), BorderThickness = new Thickness(1), Effect = new System.Windows.Media.Effects.DropShadowEffect { BlurRadius = 16, ShadowDepth = 2, Opacity = 0.05, Color = Color.FromRgb(30, 41, 59) } };
  static void StripOwn(System.Text.Json.Nodes.JsonNode? n) {
    if (n is System.Text.Json.Nodes.JsonObject o) { o.Remove("OwnCode"); foreach (var kv in o.ToList()) StripOwn(kv.Value); }
    else if (n is System.Text.Json.Nodes.JsonArray a) foreach (var x in a) StripOwn(x);
  }
  // התקני USB מחוברים: הרשימה הלבנה לפי מזהה מופע (כולל מספר סידורי), כך שכונן אחר מאותו דגם לא יאושר
  IEnumerable<(string, string)> UsbList() {
    var l = new List<(string, string)>();
    try {
      using var s = new System.Management.ManagementObjectSearcher("SELECT Caption, PNPDeviceID FROM Win32_DiskDrive WHERE InterfaceType='USB'");
      foreach (var o in s.Get().Cast<System.Management.ManagementBaseObject>()) { var cap = (string?)o["Caption"] ?? ""; var id = (string?)o["PNPDeviceID"] ?? ""; if (id.Length > 0) l.Add((cap + "  —  " + id, id)); }
    } catch { }
    foreach (var w in C.Usb.White) if (!l.Any(x => x.Item2 == w)) l.Add((w + "  (שמור)", w));
    return l;
  }
  CheckBox SkipAppCheck() {
    var cb = new CheckBox { Content = "אל תחסום קבצים בתיקיית AppData של המשתמשים (מומלץ: מונע שבירת תוכנות)", IsChecked = C.SkipAppData, Margin = new Thickness(0, 0, 0, 8) };
    cb.Click += (s, e) => { C.SkipAppData = cb.IsChecked == true; C.Save(); }; return cb;
  }
  UIElement ScanOpts() {
    var sp = new StackPanel();
    var rem = new CheckBox { Content = "חסום מדיה גם בכוני USB / כוננים נשלפים (ברירת מחדל: לא – כדי לא לפגוע בציוד של אחרים)", IsChecked = C.IncludeRemovable, Margin = new Thickness(0, 0, 0, 8) };
    rem.Click += (s, e) => { C.IncludeRemovable = rem.IsChecked == true; C.Save(); };
    var prog = new CheckBox { Content = "אל תחסום מדיה בתיקיות תוכנות (תיקיות עם קובצי dll, node_modules וכד') – מומלץ, מונע שבירת תוכנות", IsChecked = C.SkipProgramDirs, Margin = new Thickness(0, 0, 0, 8) };
    prog.Click += (s, e) => { C.SkipProgramDirs = prog.IsChecked == true; C.Save(); };
    sp.Children.Add(rem); sp.Children.Add(prog); return sp;
  }
  CheckBox PreviewCheck() {
    var cb = new CheckBox { Content = "הצג סיכום ובקש אישור לפני החלת שינויים", IsChecked = C.PreviewApply, Margin = new Thickness(0, 0, 0, 8) };
    cb.Click += (s, e) => { C.PreviewApply = cb.IsChecked == true; C.Save(); }; return cb;
  }
  // תזמון: החסימות פעילות רק בתוך החלון. השירות מפעיל ומסיר אותן לבד
  UIElement SchedulePanel() {
    var sp = new StackPanel();
    var on = new CheckBox { Content = "תזמון: החסימות פעילות רק בחלון זמן (מחוץ לחלון הכול נפתח אוטומטית, ובתחילתו נסגר שוב)", IsChecked = C.Sched.On, FontWeight = FontWeights.SemiBold };
    on.Click += (s, e) => { C.Sched.On = on.IsChecked == true; if (C.Sched.On && string.IsNullOrEmpty(C.Sched.TzId)) C.Sched.TzId = Schedule.Local(); C.Save(); };
    sp.Children.Add(on);
    var row = new WrapPanel { Margin = new Thickness(0, 10, 0, 0) };
    TextBox Tb(Func<string> get, Action<string> set) {
      var t = new TextBox { Text = get(), Width = 64, Margin = new Thickness(0, 0, 8, 0), TextAlignment = TextAlignment.Center, FlowDirection = FlowDirection.LeftToRight };
      t.LostFocus += (s, e) => { if (TimeSpan.TryParse(t.Text.Trim(), out var ts) && ts >= TimeSpan.Zero && ts < TimeSpan.FromDays(1)) { var v = ts.ToString(@"hh\:mm"); t.Text = v; set(v); if (string.IsNullOrEmpty(C.Sched.TzId)) C.Sched.TzId = Schedule.Local(); C.Save(); } else t.Text = get(); };
      return t;
    }
    row.Children.Add(new TextBlock { Text = "פעיל מהשעה", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) });
    row.Children.Add(Tb(() => C.Sched.From, v => C.Sched.From = v));
    row.Children.Add(new TextBlock { Text = "עד", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) });
    row.Children.Add(Tb(() => C.Sched.To, v => C.Sched.To = v));
    var names = new[] { "א׳", "ב׳", "ג׳", "ד׳", "ה׳", "ו׳", "ש׳" };
    for (int d = 0; d < 7; d++) {
      int bit = 1 << d; var cb = new CheckBox { Content = names[d], IsChecked = (C.Sched.Days & bit) != 0, Margin = new Thickness(8, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center };
      cb.Click += (s, e) => { if (cb.IsChecked == true) C.Sched.Days |= bit; else C.Sched.Days &= ~bit; C.Save(); };
      row.Children.Add(cb);
    }
    sp.Children.Add(row);
    sp.Children.Add(new TextBlock { Text = "אזור הזמן של התזמון: " + (string.IsNullOrEmpty(C.Sched.TzId) ? "של המחשב" : C.Sched.TzId) + " (שינוי שעון במחשב לא יזיז את החלון).", Foreground = Brushes.Gray, Margin = new Thickness(0, 6, 0, 0), TextWrapping = TextWrapping.Wrap });
    sp.Children.Add(new TextBlock { Text = "אם שעת הסיום מוקדמת משעת ההתחלה, החלון עובר את חצות (למשל 20:00–07:00).", Foreground = Brushes.Gray, Margin = new Thickness(0, 6, 0, 0), TextWrapping = TextWrapping.Wrap });
    return Card(sp);
  }
  // החרגות: תיקיות שקבצי המדיה בהן לא ייחסמו (למשל תיקיות של תוכנות)
  UIElement Exclusions() {
    var sp = new StackPanel(); var list = new StackPanel();
    void Fill() {
      list.Children.Clear();
      foreach (var x in C.Exclude.ToList()) {
        var xx = x; var d = new DockPanel { Margin = new Thickness(0, 3, 0, 3) };
        var rm = new Button { Content = Theme.Glyph("\uE74D", 14, new SolidColorBrush(Color.FromRgb(185, 28, 28))), Style = Theme.Soft(typeof(Button)), Padding = new Thickness(8, 4, 8, 4), Margin = new Thickness(0, 0, 8, 0) };
        rm.Click += (s, e) => { C.Exclude.Remove(xx); C.Save(); Fill(); }; DockPanel.SetDock(rm, Dock.Left);
        d.Children.Add(rm); d.Children.Add(new TextBlock { Text = xx, VerticalAlignment = VerticalAlignment.Center, FlowDirection = FlowDirection.LeftToRight, TextAlignment = TextAlignment.Left });
        list.Children.Add(d);
      }
    }
    sp.Children.Add(new TextBlock { Text = "החרגות: קבצי מדיה בתיקיות אלו לא ייחסמו (יחול אחרי 'החל שינויים')", FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 8) });
    var add = Btn("הוסף תיקייה להחרגה…", () => {
      var d = new OpenFolderDialog(); if (d.ShowDialog() == true && !C.Exclude.Contains(d.FolderName, StringComparer.OrdinalIgnoreCase)) { C.Exclude.Add(d.FolderName); C.Save(); Fill(); }
    });
    sp.Children.Add(add); sp.Children.Add(list); Fill();
    return Card(sp);
  }
  // ---------- חלון 7: הגנה מתקדמת ----------
  UIElement P7() {
    var sp = new StackPanel();
    var on = new CheckBox { Content = C.Adv.Name, IsChecked = C.Adv.On, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 6) };
    on.Click += (s, e) => { C.Adv.On = on.IsChecked == true; C.Save(); };
    sp.Children.Add(on);
    void Opt(string text, string tip, Func<bool> get, Action<bool> set) {
      var cb = new CheckBox { Content = text, IsChecked = get(), Margin = new Thickness(18, 4, 0, 4) };
      cb.Click += (s, e) => { set(cb.IsChecked == true); C.Save(); }; Theme.Tipped(cb, tip); sp.Children.Add(cb);
    }
    Opt("חסימת bcdedit / msconfig / reagentc", "מונע שינוי הגדרות אתחול, כניסה למצב בטוח וביטול שחזור – עקיפות נפוצות.", () => C.AdvOpts.BlockBoot, v => C.AdvOpts.BlockBoot = v);
    Opt("חסימת WSL ומכונות וירטואליות (Sandbox)", "מונע הפעלת סביבות שמאפשרות לעקוף את החסימות.", () => C.AdvOpts.NoVirt, v => C.AdvOpts.NoVirt = v);
    Opt("חסימת מנהל המשימות", "מונע סגירת תהליכים ידנית. אפשר לבטל בהסרת הסימון והחלה.", () => C.AdvOpts.NoTaskMgr, v => C.AdvOpts.NoTaskMgr = v);
    Opt("חסימת עורך הרישום (regedit)", "מונע עריכת הרישום דרך regedit.", () => C.AdvOpts.NoRegedit, v => C.AdvOpts.NoRegedit = v);
    Opt("חסימת Microsoft Store", "מונע התקנת אפליקציות מהחנות. פועל ב-Pro/Enterprise/Education.", () => C.AdvOpts.NoStore, v => C.AdvOpts.NoStore = v);
    Opt("חסימת winget (App Installer)", "מונע התקנת תוכנות דרך winget.", () => C.AdvOpts.NoWinget, v => C.AdvOpts.NoWinget = v);
    Opt("דפדפנים: כיבוי DNS מוצפן וגלישה פרטית", "Chrome / Edge / Firefox: מבטל DoH וגלישה בסתר, שעוקפים סינון רשת.", () => C.AdvOpts.Browsers, v => C.AdvOpts.Browsers = v);
    Opt("חסימת הגדרת Proxy / VPN בדפדפנים ובמערכת", "מונע עקיפת סינון דרך שרת Proxy. עלול להפריע אם המחשב משתמש ב-Proxy ארגוני.", () => C.AdvOpts.NoProxy, v => C.AdvOpts.NoProxy = v);
    Opt("חסימת שיתוף אינטרנט (נקודה חמה)", "מסתיר את ממשק השיתוף של חיבור האינטרנט.", () => C.AdvOpts.NoTether, v => C.AdvOpts.NoTether = v);
    Opt("חסימת שינוי הגדרות TCP/IP מתקדמות (DNS)", "מונע שינוי DNS והגדרות רשת מתקדמות בממשק.", () => C.AdvOpts.NoTcpip, v => C.AdvOpts.NoTcpip = v);
    Opt("נעילת קובץ hosts", "מונע עריכת קובץ hosts (עקיפת סינון בדרך זו).", () => C.AdvOpts.LockHosts, v => C.AdvOpts.LockHosts = v);
    var sb = new CheckBox { Content = "השירות פועל גם ב-Safe Mode (מומלץ)", IsChecked = C.AdvOpts.SafeBoot, Margin = new Thickness(0, 12, 0, 4), FontWeight = FontWeights.SemiBold };
    sb.Click += (s, e) => { C.AdvOpts.SafeBoot = sb.IsChecked == true; C.Save(); }; Theme.Tipped(sb, "ללא זה אפשר לעקוף את ההגנה באתחול במצב בטוח."); sp.Children.Add(sb);
    sp.Children.Add(new TextBlock { Text = "הערה: כל ההגדרות כאן חלות אחרי 'החל שינויים'. עקיפה מלאה אפשרית רק למי שיש לו הרשאות מנהל – מומלץ שהמשתמש היומיומי יהיה לא-מנהל.", Foreground = Brushes.Gray, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 0) });
    var alert = new StackPanel(); alert.Children.Add(new TextBlock { Text = "התראה על ניסיונות עקיפה (כתובת Webhook, למשל ntfy.sh/הנושא-שלך):", FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 6) });
    var url = new TextBox { Text = C.AlertUrl ?? "", Width = 420, HorizontalAlignment = HorizontalAlignment.Left, FlowDirection = FlowDirection.LeftToRight };
    url.LostFocus += (s, e) => { var v = url.Text.Trim(); C.AlertUrl = v.Length == 0 ? null : v; C.Save(); };
    alert.Children.Add(url);
    var log = Btn("הצג יומן אירועים", ShowLog); log.Margin = new Thickness(0, 8, 0, 0); log.HorizontalAlignment = HorizontalAlignment.Left; alert.Children.Add(log);
    return Page("הגנה מתקדמת", "\uE72E", Card(sp), Card(alert));
  }
  void ShowLog() {
    string txt;
    try { txt = File.Exists(Alerts.LogPath) ? string.Join("\n", File.ReadLines(Alerts.LogPath).Reverse().Take(300)) : "אין אירועים"; } catch (Exception x) { txt = x.Message; }
    var w = new Window { Title = "יומן אירועים", Width = 680, Height = 460, Owner = this, WindowStartupLocation = WindowStartupLocation.CenterOwner, Content = new TextBox { Text = txt, IsReadOnly = true, TextWrapping = TextWrapping.NoWrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, FlowDirection = FlowDirection.LeftToRight, FontFamily = new FontFamily("Consolas"), Margin = new Thickness(8) } };
    w.ShowDialog();
  }
  // סנכרון עם השירות: הוא יכול לשנות את רשימת ה"הוחל" ואת הפתיחה הזמנית (תזמון / סיום פתיחה זמנית), ולכן טוענים אותם מחדש כדי לא לדרוס אותם בשמירה
  void StartSync() {
    lastStamp = File.GetLastWriteTimeUtc(Config.CfgPath);
    syncTmr = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
    syncTmr.Tick += (s, e) => {
      try {
        var ts = File.GetLastWriteTimeUtc(Config.CfgPath);
        if (ts != lastStamp && !busy) { lastStamp = ts; var f = Config.TryLoad(); if (f != null) { C.Applied = f.Applied; C.TempOpenUntil = f.TempOpenUntil; C.State = f.State; } }
        if (C.TempOpenUntil > DateTime.UtcNow.Ticks) { wasTemp = true; var left = new DateTime(C.TempOpenUntil, DateTimeKind.Utc) - DateTime.UtcNow; status.Text = $"החסימות פתוחות זמנית – נותרו {(int)left.TotalMinutes}:{left.Seconds:00}"; }
        else if (wasTemp) { wasTemp = false; status.Text = "הפתיחה הזמנית הסתיימה – החסימות הוחזרו"; }
      } catch { }
    };
    syncTmr.Start();
  }
}
