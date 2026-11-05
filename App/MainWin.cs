using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Microsoft.Win32;

namespace DG;

public partial class MainWin : Window
{
  Border scanBar = null!,
    scanFill = null!;
  TextBlock scanTxt = null!;
  DispatcherTimer? scanTmr;
  bool scanBusy;
  long scanFrom;
  const double ScanW = 150;
  Config C;
  Func<UIElement>? cur;
  List<(string N, string E)>? inst;
  ContentControl host = new();
  TextBlock status = new();
  DispatcherTimer? tmr,
    syncTmr;
  bool busy,
    wasTemp;
  DateTime lastStamp;

  public MainWin(Config c)
  {
    C = c;
    Title = "DeviceGuard – מנהל חסימות";
    Width = 1050;
    Height = 720;
    FlowDirection = FlowDirection.RightToLeft;
    FontSize = 14;
    Background = new SolidColorBrush(Color.FromRgb(248, 250, 252));
    FontFamily = new FontFamily("Segoe UI");
    Foreground = new SolidColorBrush(Color.FromRgb(30, 41, 59));
    var tg = new ToggleButton
    {
      IsChecked = C.Master,
      Padding = new Thickness(14, 6, 14, 6),
      Margin = new Thickness(0, 0, 8, 0),
      Style = Theme.Soft(typeof(ToggleButton)),
    };
    void Lbl()
    {
      bool on = tg.IsChecked == true;
      var fg = on ? Color.FromRgb(21, 128, 61) : Color.FromRgb(185, 28, 28);
      Theme.Tint(
        tg,
        on ? Color.FromRgb(240, 250, 244) : Color.FromRgb(254, 242, 242),
        fg,
        on ? Color.FromRgb(187, 229, 203) : Color.FromRgb(245, 198, 198)
      );
      tg.Content = on
        ? Theme.IconText("\uE72E", "החסימות פעילות – לחץ להשבתה", new SolidColorBrush(fg))
        : Theme.IconText("\uE785", "החסימות מושבתות – לחץ להפעלה", new SolidColorBrush(fg));
    }
    Lbl();
    tg.Click += async (s, e) =>
    {
      C.Master = tg.IsChecked == true;
      Lbl();
      await Do();
    };
    var ap = Btn("החל שינויים", () => { }, "\uE73E");
    ap.Click += async (s, e) => await Do();
    var un = Btn("פתיחה זמנית (30 דק׳)", () => { }, "\uE785");
    var softFg = Color.FromRgb(52, 90, 158);
    var softBr = new SolidColorBrush(softFg);
    foreach (var (sb, sg, st) in new[] { (ap, "\uE73E", "החל שינויים"), (un, "\uE785", "פתיחה זמנית (30 דק׳)") })
    {
      sb.Style = Theme.Soft(typeof(Button));
      Theme.Tint(sb, Color.FromRgb(238, 243, 252), softFg, Color.FromRgb(206, 220, 242));
      sb.Content = Theme.IconText(sg, st, softBr);
    }
    Theme.Tipped(tg, "המתג הראשי: הפעלה או השבתה של כל החסימות בבת אחת. השינוי מוחל מיד.");
    Theme.Tipped(ap, "מחיל על המחשב את כל החסימות וההגדרות שבחרת. יש ללחוץ עליו אחרי שינוי.");
    Theme.Tipped(un, "פותח את כל החסימות ל-30 דקות אחרי הקשת קוד ברירת המחדל, ואחר כך הן חוזרות אוטומטית.");
    un.Click += async (s, e) =>
    {
      var k = Ask("קוד ברירת מחדל");
      if (k == null)
        return;
      if (!Config.Check(k, C.DefaultCode))
      {
        Say(C.DefaultCode == null ? "לא הוגדר קוד ברירת מחדל (חלון 1)" : "קוד שגוי");
        return;
      }
      IsEnabled = false;
      busy = true;
      try
      {
        await Task.Run(() => Enforcer.TempOpen(C, DateTime.UtcNow.AddMinutes(30).Ticks));
        status.Text = "החסימות פתוחות זמנית (30 דקות)";
      } // השירות מחזיר את החסימות לבד כשהזמן נגמר, גם אם התוכנה נסגרה
      catch (Exception x)
      {
        Say("שגיאה: " + x.Message);
      }
      busy = false;
      IsEnabled = true;
    };
    InitScanBar();
    var top = new StackPanel
    {
      Orientation = Orientation.Horizontal,
      Margin = new Thickness(0),
      Background = Brushes.White,
    };
    top.Children.Add(tg);
    top.Children.Add(ap);
    top.Children.Add(un);
    top.Children.Add(SearchBox());
    top.Children.Add(status);
    top.Children.Add(scanBar);
    status.Foreground = new SolidColorBrush(Color.FromRgb(100, 116, 139));
    status.FontSize = 13;
    foreach (FrameworkElement ch in top.Children)
    {
      ch.Margin = new Thickness(8, 10, 0, 10);
      ch.VerticalAlignment = VerticalAlignment.Center;
    }
    var line = new SolidColorBrush(Color.FromRgb(229, 231, 235));
    var side = new Border
    {
      Width = 92,
      Background = Brushes.White,
      BorderBrush = line,
      BorderThickness = new Thickness(0, 0, 1, 0),
    };
    var sideSp = new StackPanel();
    side.Child = sideSp;
    var pages = new (string, string, Func<UIElement>)[]
    {
      ("הגדרות כלליות", "\uE713", P1),
      ("תוכנות מותקנות", "\uE71D", P2),
      ("תוכנות ניידות", "\uE8A7", P3),
      ("סוגי קבצים", "\uE8A5", P4),
      ("קבצים ותיקיות", "\uE8B7", P5),
      ("רשת", "\uE774", P6),
      ("הגנה מתקדמת", "\uE72E", P7),
    };
    var logoImg = new Image
    {
      Source = Logo.Src,
      Width = 54,
      Height = 54,
      Margin = new Thickness(0, 18, 0, 16),
      HorizontalAlignment = HorizontalAlignment.Center,
    };
    RenderOptions.SetBitmapScalingMode(logoImg, BitmapScalingMode.HighQuality);
    sideSp.Children.Add(logoImg);
    int selIdx = 0;
    var paints = new List<Action>();
    var mute = new SolidColorBrush(Color.FromRgb(107, 114, 128));
    var selBg = new SolidColorBrush(Color.FromRgb(239, 246, 255));
    var hoverBg = new SolidColorBrush(Color.FromRgb(243, 244, 246));
    for (int i = 0; i < pages.Length; i++)
    {
      int k = i;
      var (n, g, f) = pages[i];
      var ic = Theme.Glyph(g, 20, mute);
      var tx = new TextBlock
      {
        Text = n,
        FontSize = 11,
        FontWeight = FontWeights.SemiBold,
        Foreground = mute,
        TextAlignment = TextAlignment.Center,
        TextWrapping = TextWrapping.Wrap,
        Margin = new Thickness(0, 6, 0, 0),
      };
      var col = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
      col.Children.Add(ic);
      col.Children.Add(tx);
      var item = new Border
      {
        CornerRadius = new CornerRadius(12),
        Padding = new Thickness(4, 10, 4, 10),
        Margin = new Thickness(8, 2, 8, 2),
        Background = Brushes.Transparent,
        Child = col,
      };
      var bar = new Border
      {
        Width = 3,
        CornerRadius = new CornerRadius(2),
        Background = Theme.SideAccent,
        HorizontalAlignment = HorizontalAlignment.Left,
        Margin = new Thickness(0, 14, 0, 14),
        Visibility = Visibility.Collapsed,
      };
      var cell = new Grid { Background = Brushes.Transparent, Cursor = System.Windows.Input.Cursors.Hand };
      cell.Children.Add(item);
      cell.Children.Add(bar);
      void Paint()
      {
        bool sel = selIdx == k;
        item.Background = sel ? selBg : Brushes.Transparent;
        ic.Foreground = tx.Foreground = sel ? Theme.SideAccent : mute;
        bar.Visibility = sel ? Visibility.Visible : Visibility.Collapsed;
      }
      paints.Add(Paint);
      cell.MouseEnter += (s, e) =>
      {
        if (selIdx != k)
          item.Background = hoverBg;
      };
      cell.MouseLeave += (s, e) => Paint();
      cell.MouseLeftButtonUp += (s, e) =>
      {
        selIdx = k;
        foreach (var pt in paints)
          pt();
        cur = f;
        host.Content = f();
      };
      sideSp.Children.Add(cell);
    }
    foreach (var pt in paints)
      pt();
    PreviewKeyDown += (s, e) =>
    {
      if (e.Key == System.Windows.Input.Key.F && System.Windows.Input.Keyboard.Modifiers == System.Windows.Input.ModifierKeys.Control)
      {
        sbox?.Focus();
        sbox?.SelectAll();
        e.Handled = true;
      }
    };
    var topBar = new Border
    {
      Child = top,
      Background = Brushes.White,
      BorderBrush = line,
      BorderThickness = new Thickness(0, 0, 0, 1),
    };
    var root = new DockPanel();
    DockPanel.SetDock(topBar, Dock.Top);
    DockPanel.SetDock(side, Dock.Left); // ב-RTL: מופיע מימין
    var foot = new TextBlock
    {
      Text = "האחריות על המשתמש בלבד, בעז\"ה שישמש לדברים חיוביים.",
      FontSize = 12,
      Foreground = new SolidColorBrush(Color.FromRgb(148, 163, 184)),
      HorizontalAlignment = HorizontalAlignment.Center,
      TextAlignment = TextAlignment.Center,
      Margin = new Thickness(0, 7, 0, 9),
    };
    DockPanel.SetDock(foot, Dock.Bottom);
    root.Children.Add(foot);
    root.Children.Add(topBar);
    root.Children.Add(side);
    root.Children.Add(host);
    Content = root;
    host.Content = P1();
    StartSync();
    Closing += (s, e) =>
    {
      syncTmr?.Stop();
    };
  }

  async Task Do()
  {
    if (C.Master && C.DefaultCode == null && C.All().Any(r => r.On && r.Mode == Mode.Code && r.OwnCode == null))
    {
      Say("יש חסימות בקוד שאין להן קוד. הגדר קוד ברירת מחדל (חלון 1) או קוד נפרד לכל חסימה.");
      return;
    }
    C.TempOpenUntil = 0;
    if (C.Master && C.Sched.On && !C.Sched.Active(C.Sched.NowPinned()))
    { // מחוץ לחלון הזמנים: שומרים, והשירות יפעיל לבד בתחילת החלון
      try
      {
        C.Save(true);
      }
      catch (Exception x)
      {
        Say(x.Message);
      }
      status.Text = "מחוץ לחלון הזמנים – החסימות יופעלו אוטומטית בתחילת החלון";
      return;
    }
    if (
      C.PreviewApply
      && !Say(Enforcer.Describe(C) + "\n\nלהחיל?", "סיכום החלה", yesNo: true)
    )
      return;
    status.Text = "מחיל...";
    IsEnabled = false;
    busy = true;
    try
    {
      await Task.Factory.StartNew(() => Enforcer.Apply(C), CancellationToken.None, TaskCreationOptions.None, Enforcer.Sta);
      status.Text =
        "הוחל ✓"
        + (
          Enforcer.Blocked > 0 || Enforcer.Failed > 0
            ? $" (נחסמו {Enforcer.Blocked} קבצים" + (Enforcer.Failed > 0 ? $", נכשלו {Enforcer.Failed}: {Enforcer.LastErr}" : "") + ")"
            : ""
        );
      if (Enforcer.NeedReboot)
        Say("תוקנה הגדרה של Windows 11 שמנעה את חסימת התוכנות הניידות / ההתקנות. החסימה הזו תפעל רק אחרי הפעלה מחדש של המחשב.");
      StartScanWatch();
    }
    catch (Exception x)
    {
      status.Text = "שגיאה: " + x.Message;
      Say("שגיאה בהחלת החסימות: " + x.Message);
    }
    busy = false;
    IsEnabled = true;
  }

  // ---------- התקדמות חסימת הקבצים ברקע (הסריקה רצה בשירות, ולכן אפשר להמשיך להשתמש בתוכנה) ----------
  void InitScanBar()
  {
    scanFill = new Border
    {
      Background = new SolidColorBrush(Color.FromRgb(134, 214, 160)),
      CornerRadius = new CornerRadius(7),
      HorizontalAlignment = HorizontalAlignment.Left,
      Width = 0,
    };
    scanTxt = new TextBlock
    {
      FontSize = 12,
      FontWeight = FontWeights.SemiBold,
      Foreground = new SolidColorBrush(Color.FromRgb(21, 101, 52)),
      HorizontalAlignment = HorizontalAlignment.Center,
      VerticalAlignment = VerticalAlignment.Center,
    };
    var g = new Grid();
    g.Children.Add(scanFill);
    g.Children.Add(scanTxt);
    scanBar = new Border
    {
      Width = ScanW,
      Height = 26,
      CornerRadius = new CornerRadius(8),
      Background = new SolidColorBrush(Color.FromRgb(236, 244, 239)),
      BorderBrush = new SolidColorBrush(Color.FromRgb(206, 228, 214)),
      BorderThickness = new Thickness(1),
      Child = g,
      Visibility = Visibility.Collapsed,
    };
    Theme.Tipped(scanBar, "התקדמות חסימת הקבצים ברקע. אפשר להמשיך להשתמש בתוכנה בזמן הסריקה.");
  }

  void ScanShow(double f, string t)
  {
    scanFill.Width = Math.Max(0, (ScanW - 2) * Math.Min(1, f));
    scanTxt.Text = t;
  }

  void StartScanWatch()
  {
    scanTmr?.Stop();
    if (!(C.Master && Enforcer.ExtMap(C).Count > 0))
    {
      scanBar.Visibility = Visibility.Collapsed;
      return;
    }
    try
    {
      scanFrom = File.GetLastWriteTimeUtc(System.IO.Path.Combine(Config.Dir, "config.json")).Ticks;
    }
    catch
    {
      scanFrom = DateTime.UtcNow.Ticks;
    }
    scanBar.Visibility = Visibility.Visible;
    ScanShow(0, "מתחיל…");
    int miss = 0;
    var t0 = DateTime.UtcNow;
    var tm = scanTmr = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(700) };
    tm.Tick += async (s, e) =>
    {
      if (scanBusy)
        return;
      scanBusy = true;
      try
      {
        var resp = await Task.Run(() => Config.Pipe("SCAN", 1500));
        var q = resp?.Split('|');
        if (q == null || q.Length < 6)
        {
          if (++miss >= 10)
          {
            tm.Stop();
            ScanShow(0, "השירות לא זמין");
          }
          return;
        }
        miss = 0;
        if (q.Length > 6 && q[6].Length > 0)
          status.Text = "אזהרה: אין תמיכה בחסימת קבצים בכוננים " + q[6] + " (FAT/exFAT)";
        long st = long.Parse(q[1]);
        int done = int.Parse(q[2]),
          total = int.Parse(q[3]);
        if (st < scanFrom)
        {
          ScanShow(0, "מתחיל…");
          if ((DateTime.UtcNow - t0).TotalMinutes > 3)
          {
            tm.Stop();
            scanBar.Visibility = Visibility.Collapsed;
          }
          return;
        }
        if (q[5] == "1")
        {
          ScanShow(1, "סיים");
          tm.Stop();
          var cc = C;
          _ = Task.Run(() => Enforcer.ClearViewerCaches(cc));
          return;
        }
        if (total <= 0)
        {
          ScanShow(0, "מכין…");
          return;
        }
        double f = (double)done / total;
        ScanShow(f, (int)(f * 100) + "%");
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
      finally
      {
        scanBusy = false;
      }
    };
    tm.Start();
  }

  void ShowLog()
  {
    string txt;
    try
    {
      txt = File.Exists(Alerts.LogPath) ? string.Join("\n", File.ReadLines(Alerts.LogPath).Reverse().Take(300)) : "אין אירועים";
    }
    catch (Exception x)
    {
      txt = x.Message;
    }
    var w = new Window
    {
      Title = "יומן אירועים",
      Width = 680,
      Height = 460,
      Owner = this,
      WindowStartupLocation = WindowStartupLocation.CenterOwner,
      Content = new TextBox
      {
        Text = txt,
        IsReadOnly = true,
        TextWrapping = TextWrapping.NoWrap,
        VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
        HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
        FlowDirection = FlowDirection.LeftToRight,
        FontFamily = new FontFamily("Consolas"),
        Margin = new Thickness(8),
      },
    };
    w.ShowDialog();
  }

  // סנכרון עם השירות: הוא יכול לשנות את רשימת ה"הוחל" ואת הפתיחה הזמנית (תזמון / סיום פתיחה זמנית), ולכן טוענים אותם מחדש כדי לא לדרוס אותם בשמירה
  void StartSync()
  {
    lastStamp = File.GetLastWriteTimeUtc(Config.CfgPath);
    syncTmr = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
    syncTmr.Tick += (s, e) =>
    {
      try
      {
        var ts = File.GetLastWriteTimeUtc(Config.CfgPath);
        if (ts != lastStamp && !busy)
        {
          lastStamp = ts;
          var f = Config.TryLoad();
          if (f != null)
          {
            C.Applied = f.Applied;
            C.TempOpenUntil = f.TempOpenUntil;
            C.State = f.State;
          }
        }
        if (C.TempOpenUntil > DateTime.UtcNow.Ticks)
        {
          wasTemp = true;
          var left = new DateTime(C.TempOpenUntil, DateTimeKind.Utc) - DateTime.UtcNow;
          status.Text = $"החסימות פתוחות זמנית – נותרו {(int)left.TotalMinutes}:{left.Seconds:00}";
        }
        else if (wasTemp)
        {
          wasTemp = false;
          status.Text = "הפתיחה הזמנית הסתיימה – החסימות הוחזרו";
        }
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    };
    syncTmr.Start();
  }
}
