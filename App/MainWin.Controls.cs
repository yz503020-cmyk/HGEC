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

// חלון ראשי: דיאלוגים ורכיבי ממשק משותפים
public partial class MainWin
{
  // ---------- דיאלוגים ----------
  const int MinCode = 6; // אורך מינימלי לקוד חדש (confirm = הגדרת קוד). קודים קיימים ממשיכים לעבוד

  // הודעה בעיצוב של שאר החלונות (במקום MessageBox הרגיל של Windows). yesNo: מחזיר true רק אם נלחץ "כן"
  public static bool Say(string text, string? title = null, bool yesNo = false, bool warn = false)
  {
    var w = new Window
    {
      Title = title ?? "DeviceGuard",
      SizeToContent = SizeToContent.WidthAndHeight,
      WindowStartupLocation = WindowStartupLocation.CenterScreen,
      FlowDirection = FlowDirection.RightToLeft,
      ResizeMode = ResizeMode.NoResize,
      Topmost = true,
      Background = new SolidColorBrush(Color.FromRgb(248, 250, 252)),
      FontFamily = new FontFamily("Segoe UI"),
      FontSize = 14,
    };
    var owner = Application.Current?.Windows.OfType<Window>().FirstOrDefault(x => x.IsActive && x.IsVisible);
    if (owner != null)
      w.Owner = owner;
    var sp = new StackPanel { Margin = new Thickness(16), MinWidth = 240, MaxWidth = 460 };
    var msg = new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap };
    UIElement body = new ScrollViewer
    {
      Content = msg,
      MaxHeight = 420,
      VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
      HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
    };
    if (warn)
    {
      var row = new DockPanel();
      var g = Theme.Glyph("\uE7BA", 22, new SolidColorBrush(Color.FromRgb(217, 119, 6)));
      g.Margin = new Thickness(0, 0, 10, 0);
      g.VerticalAlignment = VerticalAlignment.Top;
      DockPanel.SetDock(g, Dock.Left);
      row.Children.Add(g);
      row.Children.Add(body);
      body = row;
    }
    sp.Children.Add(body);
    bool res = false;
    var ok = new Button
    {
      Content = yesNo ? "כן" : "אישור",
      IsDefault = true,
      Padding = new Thickness(10, 4, 10, 4),
      Style = Theme.AccentButton(),
    };
    ok.Click += (s, e) =>
    {
      res = true;
      w.Close();
    };
    if (yesNo)
    {
      var no = new Button
      {
        Content = "לא",
        IsCancel = true,
        Padding = new Thickness(10, 4, 10, 4),
        Style = Theme.Soft(typeof(Button)),
      };
      no.Click += (s, e) => w.Close();
      var g2 = new Grid { Margin = new Thickness(0, 12, 0, 0) };
      g2.ColumnDefinitions.Add(new ColumnDefinition());
      g2.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(8) });
      g2.ColumnDefinitions.Add(new ColumnDefinition());
      Grid.SetColumn(no, 2);
      g2.Children.Add(ok);
      g2.Children.Add(no);
      sp.Children.Add(g2);
    }
    else
    {
      ok.IsCancel = true;
      ok.Margin = new Thickness(0, 12, 0, 0);
      sp.Children.Add(ok);
    }
    w.Content = sp;
    w.ShowDialog();
    return res;
  }

  public static string? Ask(string title, bool confirm = false)
  {
    var w = new Window
    {
      Title = title,
      SizeToContent = SizeToContent.WidthAndHeight,
      WindowStartupLocation = WindowStartupLocation.CenterScreen,
      FlowDirection = FlowDirection.RightToLeft,
      ResizeMode = ResizeMode.NoResize,
      Topmost = true,
      Background = new SolidColorBrush(Color.FromRgb(248, 250, 252)),
      FontFamily = new FontFamily("Segoe UI"),
      FontSize = 14,
    };
    var sp = new StackPanel { Margin = new Thickness(16) };
    var a = new PasswordBox { Width = 240, Margin = new Thickness(0, 4, 0, 8) };
    var b = new PasswordBox { Width = 240, Margin = new Thickness(0, 4, 0, 8) };
    sp.Children.Add(new TextBlock { Text = title });
    sp.Children.Add(a);
    if (confirm)
    {
      sp.Children.Add(new TextBlock { Text = "אימות הקוד" });
      sp.Children.Add(b);
    }
    string? res = null;
    var ok = new Button
    {
      Content = "אישור",
      IsDefault = true,
      Padding = new Thickness(10, 4, 10, 4),
    };
    ok.Click += (s, e) =>
    {
      if (a.Password.Length == 0)
        return;
      if (confirm && a.Password.Length < MinCode)
      {
        Say($"הקוד חייב להכיל לפחות {MinCode} תווים");
        return;
      }
      if (confirm && a.Password != b.Password)
      {
        Say("הקודים אינם זהים");
        return;
      }
      res = a.Password;
      w.Close();
    };
    sp.Children.Add(ok);
    w.Content = sp;
    w.ShowDialog();
    return res;
  }

  public static List<string>? Pick(string title, IEnumerable<(string L, string V)> opts, IEnumerable<string> sel)
  {
    var w = new Window
    {
      Title = title,
      Width = 420,
      Height = 520,
      WindowStartupLocation = WindowStartupLocation.CenterScreen,
      FlowDirection = FlowDirection.RightToLeft,
      Background = new SolidColorBrush(Color.FromRgb(248, 250, 252)),
      FontFamily = new FontFamily("Segoe UI"),
      FontSize = 14,
    };
    var lb = new StackPanel();
    var boxes = opts.Select(o => new CheckBox
      {
        Content = o.L,
        Tag = o.V,
        IsChecked = sel.Contains(o.V),
        Margin = new Thickness(6),
      })
      .ToList();
    boxes.ForEach(x => lb.Children.Add(x));
    List<string>? res = null;
    var ok = new Button
    {
      Content = "אישור",
      IsDefault = true,
      Margin = new Thickness(8),
      Padding = new Thickness(10, 4, 10, 4),
    };
    ok.Click += (s, e) =>
    {
      res = boxes.Where(x => x.IsChecked == true).Select(x => (string)x.Tag).ToList();
      w.Close();
    };
    var d = new DockPanel();
    DockPanel.SetDock(ok, Dock.Bottom);
    d.Children.Add(ok);
    d.Children.Add(new ScrollViewer { Content = lb });
    w.Content = d;
    w.ShowDialog();
    return res;
  }

  // ---------- רכיבי UI ----------
  static UIElement Segment(string[] labels, int sel, Action<int> changed)
  {
    var outer = new Border
    {
      Background = new SolidColorBrush(Color.FromRgb(238, 242, 247)),
      CornerRadius = new CornerRadius(10),
      Padding = new Thickness(3),
      Margin = new Thickness(0, 4, 12, 4),
      VerticalAlignment = VerticalAlignment.Center,
    };
    var sp = new StackPanel { Orientation = Orientation.Horizontal };
    var items = new List<Border>();
    void Paint()
    {
      for (int i = 0; i < items.Count; i++)
      {
        items[i].Background = i == sel ? Brushes.White : Brushes.Transparent;
        ((TextBlock)items[i].Child).Foreground = new SolidColorBrush(i == sel ? Color.FromRgb(30, 41, 59) : Color.FromRgb(100, 116, 139));
      }
    }
    for (int i = 0; i < labels.Length; i++)
    {
      int k = i;
      var bd = new Border
      {
        CornerRadius = new CornerRadius(8),
        Padding = new Thickness(12, 5, 12, 5),
        Cursor = System.Windows.Input.Cursors.Hand,
        Background = Brushes.Transparent,
        Child = new TextBlock { Text = labels[i], FontSize = 13 },
      };
      bd.MouseLeftButtonUp += (s, e) =>
      {
        sel = k;
        Paint();
        changed(k);
      };
      items.Add(bd);
      sp.Children.Add(bd);
    }
    Paint();
    outer.Child = sp;
    return outer;
  }

  UIElement Row(
    Rule r,
    Func<IEnumerable<(string, string)>>? wl = null,
    bool file = true,
    Action? remove = null,
    string? glyph = null,
    bool canOpen = false,
    Action? touch = null
  )
  {
    void Sv()
    {
      touch?.Invoke();
      C.Save();
    }
    if (glyph == null && remove != null)
      glyph = Directory.Exists(r.Path) ? "\uE8B7" : "\uE8A5";
    var p = new WrapPanel { VerticalAlignment = VerticalAlignment.Center };
    var m12 = new Thickness(0, 4, 12, 4);
    if (glyph != null)
      p.Children.Add(Theme.Badge(glyph));
    var on = new CheckBox
    {
      Content = r.Name,
      IsChecked = r.On,
      FontWeight = FontWeights.SemiBold,
      VerticalAlignment = VerticalAlignment.Center,
    };
    on.Click += (s, e) =>
    {
      if (ReferenceEquals(r, C.Net) && on.IsChecked == true && !NetWarn())
      {
        on.IsChecked = false;
        return;
      }
      r.On = on.IsChecked == true;
      Sv();
    };
    var sep = new CheckBox
    {
      Content = "קוד נפרד",
      IsChecked = r.OwnCode != null,
      VerticalAlignment = VerticalAlignment.Center,
      Margin = m12,
    };
    var hid = new CheckBox
    {
      Content = "נסתר",
      IsChecked = r.Hidden,
      VerticalAlignment = VerticalAlignment.Center,
      Margin = m12,
    };
    Button? ob = null;
    void V()
    {
      if (ob != null)
        ob.Visibility = r.Mode == Mode.Code ? Visibility.Visible : Visibility.Collapsed;
      sep.Visibility = r.Mode == Mode.Code ? Visibility.Visible : Visibility.Collapsed;
      hid.Visibility = r.Mode == Mode.Full && file ? Visibility.Visible : Visibility.Collapsed;
    }
    var seg = Segment(
      new[] { "חסימה גמורה", "חסימה בקוד" },
      (int)r.Mode,
      i =>
      {
        r.Mode = (Mode)i;
        V();
        Sv();
      }
    );
    sep.Click += (s, e) =>
    {
      if (sep.IsChecked == true)
      {
        var k = Ask("קוד נפרד עבור: " + r.Name, true);
        if (k == null)
        {
          sep.IsChecked = false;
          return;
        }
        r.OwnCode = Config.Hash(k);
      }
      else
        r.OwnCode = null;
      Sv();
    };
    hid.Click += (s, e) =>
    {
      r.Hidden = hid.IsChecked == true;
      Sv();
    };
    var head = new StackPanel
    {
      Orientation = Orientation.Horizontal,
      MinWidth = 280,
      Margin = m12,
      VerticalAlignment = VerticalAlignment.Center,
    };
    head.Children.Add(on);
    var rt = RuleTip(r);
    if (rt != null)
    {
      var inf = Theme.Info(rt);
      inf.Margin = new Thickness(8, 0, 0, 0);
      head.Children.Add(inf);
    }
    Theme.Tipped(
      (FrameworkElement)seg,
      "חסימה גמורה – הפריט חסום לחלוטין ואי אפשר לפתוח אותו.\nחסימה בקוד – מי שמקיש את הקוד הנכון יכול לפתוח אותו."
    );
    Theme.Tipped(sep, "משתמש בקוד מיוחד לפריט הזה, במקום בקוד ברירת המחדל.");
    Theme.Tipped(hid, "מסתיר את הפריט כך שלא יופיע בסייר הקבצים. פועל בחסימה גמורה.");
    p.Children.Add(head);
    p.Children.Add(seg);
    p.Children.Add(sep);
    p.Children.Add(hid);
    if (canOpen)
    {
      ob = Btn("פתח בקוד", () => OpenWithCode(r), "\uE785");
      ob.Margin = m12;
      Theme.Tipped(ob, "פותח את הפריט אחרי הקשת קוד, ונועל אותו שוב אוטומטית כשסוגרים אותו.");
      p.Children.Add(ob);
    }
    V();
    if (wl != null)
    {
      var b = Btn(
        "רשימה לבנה",
        () =>
        {
          var x = Pick("רשימה לבנה – " + r.Name, wl(), r.White);
          if (x != null)
          {
            r.White = x;
            Sv();
          }
        },
        "\uE8FD"
      );
      b.Margin = m12;
      Theme.Tipped(b, WlTip(r));
      p.Children.Add(b);
    }
    if (remove != null)
    {
      var d = new Button
      {
        Content = Theme.Glyph("\uE74D", 15, new SolidColorBrush(Color.FromRgb(185, 28, 28))),
        Style = Theme.Soft(typeof(Button)),
        Padding = new Thickness(10, 7, 10, 7),
        Margin = new Thickness(0, 4, 0, 4),
      };
      Theme.Tint(d, Color.FromRgb(254, 242, 242), Color.FromRgb(185, 28, 28), Color.FromRgb(245, 198, 198));
      d.Click += (s, e) => remove();
      Theme.Tipped(d, "מסיר את הפריט מהרשימה ומבטל את החסימה שלו.");
      p.Children.Add(d);
    }
    return new Border
    {
      Child = p,
      Background = Brushes.White,
      CornerRadius = new CornerRadius(14),
      Padding = new Thickness(16, 12, 16, 12),
      Margin = new Thickness(0, 0, 0, 12),
      BorderBrush = new SolidColorBrush(Color.FromRgb(230, 235, 242)),
      BorderThickness = new Thickness(1),
      Effect = new System.Windows.Media.Effects.DropShadowEffect
      {
        BlurRadius = 16,
        ShadowDepth = 2,
        Opacity = 0.05,
        Color = Color.FromRgb(30, 41, 59),
      },
    };
  }

  // חלון אישור אחריות – מופיע פעם אחת בלבד, בהפעלה הראשונה אחרי הקשת הקוד
  public static bool TermsDialog()
  {
    bool ok = false;
    var w = new Window
    {
      Title = "DeviceGuard",
      Topmost = true,
      WindowStartupLocation = WindowStartupLocation.CenterScreen,
      ResizeMode = ResizeMode.NoResize,
      SizeToContent = SizeToContent.Height,
      Width = 420,
      FlowDirection = FlowDirection.RightToLeft,
      Background = new SolidColorBrush(Color.FromRgb(248, 250, 252)),
      FontFamily = new FontFamily("Segoe UI"),
      Foreground = new SolidColorBrush(Color.FromRgb(30, 41, 59)),
    };
    var sp = new StackPanel { Margin = new Thickness(28, 24, 28, 24) };
    sp.Children.Add(
      new Border
      {
        Width = 52,
        Height = 52,
        CornerRadius = new CornerRadius(16),
        Background = new SolidColorBrush(Color.FromRgb(238, 243, 252)),
        HorizontalAlignment = HorizontalAlignment.Center,
        Child = Theme.Glyph("\uE72E", 26, Theme.Accent),
      }
    );
    sp.Children.Add(
      new TextBlock
      {
        Text = "שים לב",
        FontSize = 20,
        FontWeight = FontWeights.SemiBold,
        HorizontalAlignment = HorizontalAlignment.Center,
        Margin = new Thickness(0, 14, 0, 10),
      }
    );
    sp.Children.Add(
      new TextBlock
      {
        Text = "השימוש בתוכנה על אחריות המשתמש בלבד",
        FontSize = 15,
        LineHeight = 24,
        TextWrapping = TextWrapping.Wrap,
        TextAlignment = TextAlignment.Center,
        Margin = new Thickness(0, 0, 0, 22),
      }
    );
    var b = new Button
    {
      Content = "אני מאשר",
      IsDefault = true,
      FontSize = 15,
      Padding = new Thickness(40, 9, 40, 9),
      HorizontalAlignment = HorizontalAlignment.Center,
    };
    b.Click += (s, e) =>
    {
      ok = true;
      w.Close();
    };
    sp.Children.Add(b);
    w.Content = sp;
    w.ShowDialog();
    return ok;
  }

  // אזהרה שמופיעה בהפעלת חסימת חיבור לרשת; מחזיר true רק אחרי שלוחצים "הבנתי"
  bool NetWarn()
  {
    bool ok = false;
    var w = new Window
    {
      Title = "שים לב",
      Owner = this,
      WindowStartupLocation = WindowStartupLocation.CenterOwner,
      ResizeMode = ResizeMode.NoResize,
      ShowInTaskbar = false,
      SizeToContent = SizeToContent.Height,
      Width = 440,
      FlowDirection = FlowDirection.RightToLeft,
      Background = new SolidColorBrush(Color.FromRgb(248, 250, 252)),
      FontFamily = new FontFamily("Segoe UI"),
      Foreground = new SolidColorBrush(Color.FromRgb(30, 41, 59)),
    };
    var sp = new StackPanel { Margin = new Thickness(28, 24, 28, 24) };
    sp.Children.Add(
      new Border
      {
        Width = 52,
        Height = 52,
        CornerRadius = new CornerRadius(16),
        Background = new SolidColorBrush(Color.FromRgb(254, 243, 199)),
        HorizontalAlignment = HorizontalAlignment.Center,
        Child = Theme.Glyph("\uE7BA", 26, new SolidColorBrush(Color.FromRgb(180, 83, 9))),
      }
    );
    sp.Children.Add(
      new TextBlock
      {
        Text = "שים לב",
        FontSize = 20,
        FontWeight = FontWeights.SemiBold,
        HorizontalAlignment = HorizontalAlignment.Center,
        Margin = new Thickness(0, 14, 0, 10),
      }
    );
    sp.Children.Add(
      new TextBlock
      {
        Text =
          "חוץ מחסימה זו יש להתקין תעודת אבטחה - נטפרי וכדו' (החוסם את חיבור המחשב לאינטרנט ללא סינון) ואין להסתמך רק על חסימה זו, אינטרנט ללא סינון מסוכן מאוד!",
        FontSize = 15,
        LineHeight = 24,
        TextWrapping = TextWrapping.Wrap,
        TextAlignment = TextAlignment.Center,
        Margin = new Thickness(0, 0, 0, 22),
      }
    );
    var b = new Button
    {
      Content = "הבנתי",
      IsDefault = true,
      FontSize = 15,
      Padding = new Thickness(40, 9, 40, 9),
      HorizontalAlignment = HorizontalAlignment.Center,
    };
    b.Click += (s, e) =>
    {
      ok = true;
      w.Close();
    };
    sp.Children.Add(b);
    w.Content = sp;
    w.ShowDialog();
    return ok;
  }

  string? RuleTip(Rule r)
  {
    if (ReferenceEquals(r, C.Settings))
      return "חוסם את הגישה להגדרות המחשב וללוח הבקרה. בחסימה גמורה אפשר להשאיר דפי הגדרות מסוימים פתוחים ברשימה הלבנה. בחסימה בקוד נדרש קוד כדי להיכנס להגדרות.";
    if (ReferenceEquals(r, C.Install))
      return "חוסם התקנה של תוכנות באמצעות מתקין Windows (קובצי MSI). בחסימה בקוד נדרש קוד כדי להתקין.";
    if (ReferenceEquals(r, C.Net))
      return "חוסם חיבור לרשת: מתאמי רשת קוויים מושבתים, ובכרטיס Wi-Fi נחסמות כל הרשתות – גם כאלה שלא היו זמינות בזמן ההחלה. ברשימה הלבנה אפשר להשאיר מתאם או רשת Wi-Fi מסוימת מותרים.";
    if (ReferenceEquals(r, C.Usb))
      return "חוסם את כל ההתקנים החיצוניים (דיסק און קי, דיסק נייד) – גם כאלה שעדיין לא חוברו למחשב. ברשימה הלבנה מופיעים ההתקנים המחוברים כרגע: התקן שתבחר ייזכר ויורשה גם בחיבורים הבאים, ושאר ההתקנים יישארו חסומים.";
    if (ReferenceEquals(r, C.Portable))
      return "חוסם הרצת תוכנות מכל מקום מחוץ ל-Windows ול-Program Files, כולל אפליקציות שמותקנות בתיקיית המשתמש. אפשר להתיר תוכנות מסוימות ברשימה הלבנה. החסימה היא גמורה בלבד.";
    if (ReferenceEquals(r, C.Movies))
      return "חוסם קובצי וידאו (כגון mp4, avi, mkv) בכל הכוננים, וגם קבצים חדשים שיתווספו בהמשך.";
    if (ReferenceEquals(r, C.Songs))
      return "חוסם קובצי שמע ושירים (כגון mp3, wav, flac) בכל הכוננים, וגם קבצים חדשים שיתווספו בהמשך.";
    if (ReferenceEquals(r, C.Images))
      return "חוסם קובצי תמונות (כגון jpg, png, gif) בכל הכוננים, וגם קבצים חדשים שיתווספו בהמשך.";
    if (C.Paths.Contains(r))
      return "חוסם גישה לקובץ או לתיקייה הזו: קריאה, הפעלה ומחיקה. בחסימה בקוד הפריט מוסתר ונפתח רק דרך הכפתור 'פתח בקוד'.";
    if (C.Exts.Contains(r))
      return "חוסם את כל הקבצים בסיומת הזו בכל הכוננים, וגם קבצים חדשים שיתווספו בהמשך.";
    if (!string.IsNullOrEmpty(r.Path))
      return "חוסם את הפעלת התוכנה הזו. בחסימה גמורה היא לא נפתחת, ובחסימה בקוד נדרש קוד כדי להפעיל אותה.";
    return null;
  }

  string WlTip(Rule r) =>
    ReferenceEquals(r, C.Usb)
      ? "ההתקנים המחוברים כרגע מוצגים ברשימה. התקן שתסמן ייזכר ויורשה גם בחיבורים הבאים, ושאר ההתקנים יישארו חסומים."
    : ReferenceEquals(r, C.Net) ? "בחר מתאמי רשת או רשתות Wi-Fi שיישארו מותרים. כל השאר ייחסמו."
    : ReferenceEquals(r, C.Settings) ? "בחר דפי הגדרות שיישארו פתוחים. כל השאר ייחסמו."
    : "פריטים שתסמן ברשימה הלבנה לא ייחסמו.";

  static ScrollViewer Page(string title, string glyph, params UIElement[] items)
  {
    var sp = new StackPanel { Margin = new Thickness(28, 22, 28, 22) };
    var h = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 18) };
    h.Children.Add(Theme.Badge(glyph));
    h.Children.Add(
      new TextBlock
      {
        Text = title,
        FontSize = 22,
        FontWeight = FontWeights.SemiBold,
        Foreground = new SolidColorBrush(Color.FromRgb(30, 41, 59)),
        VerticalAlignment = VerticalAlignment.Center,
      }
    );
    sp.Children.Add(h);
    foreach (var i in items)
      sp.Children.Add(i);
    return new ScrollViewer { Content = sp, VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
  }

  static Button Btn(string t, Action a, string? glyph = null)
  {
    glyph ??=
      t.Contains("הוסף") ? "\uE710"
      : t.Contains("ייצוא") ? "\uE898"
      : t.Contains("ייבוא") ? "\uE896"
      : t.Contains("קוד") ? "\uE72E"
      : null;
    var b = new Button { Content = glyph == null ? t : Theme.IconText(glyph, t), Margin = new Thickness(0, 4, 8, 4) };
    b.Click += (s, e) => a();
    return b;
  }

  static readonly Dictionary<string, ImageSource?> iconCache = new(StringComparer.OrdinalIgnoreCase);

  static new ImageSource? Icon(string exe)
  {
    if (iconCache.TryGetValue(exe, out var c))
      return c;
    ImageSource? r = null;
    try
    {
      using var i = System.Drawing.Icon.ExtractAssociatedIcon(exe);
      if (i != null)
      {
        var b = Imaging.CreateBitmapSourceFromHIcon(i.Handle, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
        b.Freeze();
        r = b;
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    iconCache[exe] = r;
    return r;
  }

  UIElement ProgRow(string n, string e)
  {
    var rule = C.Programs.FirstOrDefault(x => x.Path.Equals(e, StringComparison.OrdinalIgnoreCase)) ?? new Rule { Name = n, Path = e }; // נוסף לרשימה ונשמר רק אחרי שינוי (לא כל תוכנה מותקנת)
    var d = new DockPanel();
    var img = new Image
    {
      Source = Icon(e),
      Width = 32,
      Height = 32,
      Margin = new Thickness(0, 0, 10, 0),
    };
    DockPanel.SetDock(img, Dock.Left);
    d.Children.Add(img);
    d.Children.Add(
      Row(
        rule,
        null,
        true,
        null,
        null,
        false,
        () =>
        {
          if (!C.Programs.Contains(rule))
            C.Programs.Add(rule);
        }
      )
    );
    return d;
  }

  void OpenWithCode(Rule r)
  {
    var g = System.IO.Path.Combine(Config.Dir, "DeviceGuardWatch.exe");
    if (!File.Exists(g))
    {
      Say("יש ללחוץ 'החל שינויים' קודם");
      return;
    }
    Process.Start(new ProcessStartInfo(g, "--open " + r.Id) { UseShellExecute = false });
  }

  TextBox? sbox;

  UIElement SearchBox()
  {
    var tb = new TextBox
    {
      Width = 240,
      BorderThickness = new Thickness(0),
      Background = Brushes.Transparent,
      Padding = new Thickness(0, 9, 0, 9),
      VerticalContentAlignment = VerticalAlignment.Center,
      FontSize = 13.5,
      ToolTip = "חיפוש בתוכנה (Ctrl+F)",
    };
    sbox = tb;
    var gray = new SolidColorBrush(Color.FromRgb(156, 163, 175));
    var ph = new TextBlock
    {
      Text = "חיפוש הגדרה... (Ctrl+F)",
      Foreground = gray,
      FontSize = 13.5,
      IsHitTestVisible = false,
      VerticalAlignment = VerticalAlignment.Center,
      Margin = new Thickness(5, 0, 5, 0),
    };
    var clr = Theme.Glyph("\uE711", 11, gray);
    clr.Cursor = System.Windows.Input.Cursors.Hand;
    clr.Visibility = Visibility.Collapsed;
    clr.Margin = new Thickness(6, 0, 0, 0);
    clr.Background = Brushes.Transparent;
    var ico = Theme.Glyph("\uE721", 14, gray);
    ico.Margin = new Thickness(0, 0, 8, 0);
    var g = new Grid();
    g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
    g.ColumnDefinitions.Add(new ColumnDefinition());
    g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
    Grid.SetColumn(ico, 0);
    Grid.SetColumn(tb, 1);
    Grid.SetColumn(ph, 1);
    Grid.SetColumn(clr, 2);
    g.Children.Add(ico);
    g.Children.Add(tb);
    g.Children.Add(ph);
    g.Children.Add(clr);
    var edge = new SolidColorBrush(Color.FromRgb(229, 231, 235));
    var box = new Border
    {
      Background = new SolidColorBrush(Color.FromRgb(249, 250, 251)),
      BorderBrush = edge,
      BorderThickness = new Thickness(1),
      CornerRadius = new CornerRadius(10),
      Padding = new Thickness(12, 0, 12, 0),
      Child = g,
    };
    tb.GotKeyboardFocus += (s, e) =>
    {
      box.BorderBrush = Theme.Accent;
      box.Background = Brushes.White;
    };
    tb.LostKeyboardFocus += (s, e) =>
    {
      box.BorderBrush = edge;
      box.Background = new SolidColorBrush(Color.FromRgb(249, 250, 251));
    };
    clr.MouseLeftButtonUp += (s, e) =>
    {
      tb.Clear();
      tb.Focus();
    };
    tb.TextChanged += (s, e) =>
    {
      var q = tb.Text.Trim();
      ph.Visibility = tb.Text.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
      clr.Visibility = tb.Text.Length == 0 ? Visibility.Collapsed : Visibility.Visible;
      host.Content = q.Length == 0 ? (cur ?? (Func<UIElement>)P1)() : Search(q);
    };
    return box;
  }

  UIElement Search(string q)
  {
    bool M(string t) => t.Contains(q, StringComparison.CurrentCultureIgnoreCase);
    var items = new List<UIElement>();
    foreach (
      var (r, g, f) in new[]
      {
        (C.Settings, "\uE713", false),
        (C.Install, "\uE896", false),
        (C.Net, "\uE774", false),
        (C.Usb, "\uE88E", false),
        (C.Portable, "\uE8A7", false),
        (C.Movies, "\uE714", true),
        (C.Songs, "\uE8D6", true),
        (C.Images, "\uE91B", true),
      }
    )
      if (M(r.Name))
        items.Add(Row(r, null, f, null, g));
    if (M(C.NetApps.Name))
      items.Add(NetAppsRow());
    inst ??= Installed();
    foreach (var (n, e) in inst.Where(x => M(x.N) || M(System.IO.Path.GetFileName(x.E))))
      items.Add(ProgRow(n, e));
    foreach (var r in C.Exts.Where(x => M(x.Name) || M(x.Path)).ToList())
    {
      var rr = r;
      items.Add(
        Row(
          rr,
          null,
          true,
          () =>
          {
            C.Exts.Remove(rr);
            C.Save();
            host.Content = Search(q);
          }
        )
      );
    }
    foreach (var r in C.Paths.Where(x => M(x.Name) || M(x.Path)).ToList())
    {
      var rr = r;
      items.Add(
        Row(
          rr,
          null,
          true,
          () =>
          {
            C.Paths.Remove(rr);
            C.Save();
            host.Content = Search(q);
          },
          null,
          true
        )
      );
    }
    if (items.Count == 0)
      items.Add(
        new TextBlock
        {
          Text = "לא נמצאו תוצאות",
          Foreground = Brushes.Gray,
          FontSize = 16,
        }
      );
    return Page("תוצאות חיפוש: " + q, "\uE721", items.ToArray());
  }

  // ---------- רכיבים חדשים ----------
  static Border Card(UIElement child) =>
    new Border
    {
      Child = child,
      Background = Brushes.White,
      CornerRadius = new CornerRadius(14),
      Padding = new Thickness(16, 12, 16, 12),
      Margin = new Thickness(0, 0, 0, 12),
      BorderBrush = new SolidColorBrush(Color.FromRgb(230, 235, 242)),
      BorderThickness = new Thickness(1),
      Effect = new System.Windows.Media.Effects.DropShadowEffect
      {
        BlurRadius = 16,
        ShadowDepth = 2,
        Opacity = 0.05,
        Color = Color.FromRgb(30, 41, 59),
      },
    };

  static void StripOwn(System.Text.Json.Nodes.JsonNode? n)
  {
    if (n is System.Text.Json.Nodes.JsonObject o)
    {
      o.Remove("OwnCode");
      foreach (var kv in o.ToList())
        StripOwn(kv.Value);
    }
    else if (n is System.Text.Json.Nodes.JsonArray a)
      foreach (var x in a)
        StripOwn(x);
  }

  // התקני USB מחוברים: הרשימה הלבנה לפי מזהה מופע (כולל מספר סידורי), כך שכונן אחר מאותו דגם לא יאושר
  IEnumerable<(string, string)> UsbList()
  {
    var l = new List<(string, string)>();
    try
    {
      using var s = new System.Management.ManagementObjectSearcher(
        "SELECT Caption, PNPDeviceID FROM Win32_DiskDrive WHERE InterfaceType='USB'"
      );
      foreach (var o in s.Get().Cast<System.Management.ManagementBaseObject>())
      {
        var cap = (string?)o["Caption"] ?? "";
        var id = (string?)o["PNPDeviceID"] ?? "";
        if (id.Length > 0)
          l.Add((cap + "  —  " + id, id));
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    foreach (var w in C.Usb.White)
      if (!l.Any(x => x.Item2 == w))
        l.Add((w + "  (שמור)", w));
    return l;
  }

  CheckBox SkipAppCheck()
  {
    var cb = new CheckBox
    {
      Content = "אל תחסום קבצים בתיקיית AppData של המשתמשים (מומלץ: מונע שבירת תוכנות)",
      IsChecked = C.SkipAppData,
      Margin = new Thickness(0, 0, 0, 8),
    };
    cb.Click += (s, e) =>
    {
      C.SkipAppData = cb.IsChecked == true;
      C.Save();
    };
    return cb;
  }

  UIElement ScanOpts()
  {
    var sp = new StackPanel();
    var rem = new CheckBox
    {
      Content = "חסום מדיה גם בכוני USB / כוננים נשלפים (ברירת מחדל: לא – כדי לא לפגוע בציוד של אחרים)",
      IsChecked = C.IncludeRemovable,
      Margin = new Thickness(0, 0, 0, 8),
    };
    rem.Click += (s, e) =>
    {
      C.IncludeRemovable = rem.IsChecked == true;
      C.Save();
    };
    var prog = new CheckBox
    {
      Content = "אל תחסום מדיה בתיקיות תוכנות (תיקיות עם קובצי dll, node_modules וכד') – מומלץ, מונע שבירת תוכנות",
      IsChecked = C.SkipProgramDirs,
      Margin = new Thickness(0, 0, 0, 8),
    };
    prog.Click += (s, e) =>
    {
      C.SkipProgramDirs = prog.IsChecked == true;
      C.Save();
    };
    sp.Children.Add(rem);
    sp.Children.Add(prog);
    return sp;
  }

  CheckBox PreviewCheck()
  {
    var cb = new CheckBox
    {
      Content = "הצג סיכום ובקש אישור לפני החלת שינויים",
      IsChecked = C.PreviewApply,
      Margin = new Thickness(0, 0, 0, 8),
    };
    cb.Click += (s, e) =>
    {
      C.PreviewApply = cb.IsChecked == true;
      C.Save();
    };
    return cb;
  }

  // תזמון: החסימות פעילות רק בתוך החלון. השירות מפעיל ומסיר אותן לבד
  UIElement SchedulePanel()
  {
    var sp = new StackPanel();
    var on = new CheckBox
    {
      Content = "תזמון: החסימות פעילות רק בחלון זמן (מחוץ לחלון הכול נפתח אוטומטית, ובתחילתו נסגר שוב)",
      IsChecked = C.Sched.On,
      FontWeight = FontWeights.SemiBold,
    };
    on.Click += (s, e) =>
    {
      C.Sched.On = on.IsChecked == true;
      if (C.Sched.On && string.IsNullOrEmpty(C.Sched.TzId))
        C.Sched.TzId = Schedule.Local();
      C.Save();
    };
    sp.Children.Add(on);
    var row = new WrapPanel { Margin = new Thickness(0, 10, 0, 0) };
    TextBox Tb(Func<string> get, Action<string> set)
    {
      var t = new TextBox
      {
        Text = get(),
        Width = 64,
        Margin = new Thickness(0, 0, 8, 0),
        TextAlignment = TextAlignment.Center,
        FlowDirection = FlowDirection.LeftToRight,
      };
      t.LostFocus += (s, e) =>
      {
        if (TimeSpan.TryParse(t.Text.Trim(), out var ts) && ts >= TimeSpan.Zero && ts < TimeSpan.FromDays(1))
        {
          var v = ts.ToString(@"hh\:mm");
          t.Text = v;
          set(v);
          if (string.IsNullOrEmpty(C.Sched.TzId))
            C.Sched.TzId = Schedule.Local();
          C.Save();
        }
        else
          t.Text = get();
      };
      return t;
    }
    row.Children.Add(
      new TextBlock
      {
        Text = "פעיל מהשעה",
        VerticalAlignment = VerticalAlignment.Center,
        Margin = new Thickness(0, 0, 8, 0),
      }
    );
    row.Children.Add(Tb(() => C.Sched.From, v => C.Sched.From = v));
    row.Children.Add(
      new TextBlock
      {
        Text = "עד",
        VerticalAlignment = VerticalAlignment.Center,
        Margin = new Thickness(0, 0, 8, 0),
      }
    );
    row.Children.Add(Tb(() => C.Sched.To, v => C.Sched.To = v));
    var names = new[] { "א׳", "ב׳", "ג׳", "ד׳", "ה׳", "ו׳", "ש׳" };
    for (int d = 0; d < 7; d++)
    {
      int bit = 1 << d;
      var cb = new CheckBox
      {
        Content = names[d],
        IsChecked = (C.Sched.Days & bit) != 0,
        Margin = new Thickness(8, 0, 0, 0),
        VerticalAlignment = VerticalAlignment.Center,
      };
      cb.Click += (s, e) =>
      {
        if (cb.IsChecked == true)
          C.Sched.Days |= bit;
        else
          C.Sched.Days &= ~bit;
        C.Save();
      };
      row.Children.Add(cb);
    }
    sp.Children.Add(row);
    sp.Children.Add(
      new TextBlock
      {
        Text =
          "אזור הזמן של התזמון: "
          + (string.IsNullOrEmpty(C.Sched.TzId) ? "של המחשב" : C.Sched.TzId)
          + " (שינוי שעון במחשב לא יזיז את החלון).",
        Foreground = Brushes.Gray,
        Margin = new Thickness(0, 6, 0, 0),
        TextWrapping = TextWrapping.Wrap,
      }
    );
    sp.Children.Add(
      new TextBlock
      {
        Text = "אם שעת הסיום מוקדמת משעת ההתחלה, החלון עובר את חצות (למשל 20:00–07:00).",
        Foreground = Brushes.Gray,
        Margin = new Thickness(0, 6, 0, 0),
        TextWrapping = TextWrapping.Wrap,
      }
    );
    return Card(sp);
  }

  // החרגות: תיקיות שקבצי המדיה בהן לא ייחסמו (למשל תיקיות של תוכנות)
  UIElement Exclusions()
  {
    var sp = new StackPanel();
    var list = new StackPanel();
    void Fill()
    {
      list.Children.Clear();
      foreach (var x in C.Exclude.ToList())
      {
        var xx = x;
        var d = new DockPanel { Margin = new Thickness(0, 3, 0, 3) };
        var rm = new Button
        {
          Content = Theme.Glyph("\uE74D", 14, new SolidColorBrush(Color.FromRgb(185, 28, 28))),
          Style = Theme.Soft(typeof(Button)),
          Padding = new Thickness(8, 4, 8, 4),
          Margin = new Thickness(0, 0, 8, 0),
        };
        rm.Click += (s, e) =>
        {
          C.Exclude.Remove(xx);
          C.Save();
          Fill();
        };
        DockPanel.SetDock(rm, Dock.Left);
        d.Children.Add(rm);
        d.Children.Add(
          new TextBlock
          {
            Text = xx,
            VerticalAlignment = VerticalAlignment.Center,
            FlowDirection = FlowDirection.LeftToRight,
            TextAlignment = TextAlignment.Left,
          }
        );
        list.Children.Add(d);
      }
    }
    sp.Children.Add(
      new TextBlock
      {
        Text = "החרגות: קבצי מדיה בתיקיות אלו לא ייחסמו (יחול אחרי 'החל שינויים')",
        FontWeight = FontWeights.SemiBold,
        Margin = new Thickness(0, 0, 0, 8),
      }
    );
    var add = Btn(
      "הוסף תיקייה להחרגה…",
      () =>
      {
        var d = new OpenFolderDialog();
        if (d.ShowDialog() == true && !C.Exclude.Contains(d.FolderName, StringComparer.OrdinalIgnoreCase))
        {
          C.Exclude.Add(d.FolderName);
          C.Save();
          Fill();
        }
      }
    );
    sp.Children.Add(add);
    sp.Children.Add(list);
    Fill();
    return Card(sp);
  }
}
