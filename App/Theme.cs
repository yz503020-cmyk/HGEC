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
  public static readonly Brush Accent = new SolidColorBrush(Color.FromRgb(88, 128, 196));
  public static readonly Brush SideAccent = new SolidColorBrush(Color.FromRgb(88, 128, 196));
  static Style Make(Type t, Color bg, Color? offBg = null) {
    var s = new Style(t);
    s.Setters.Add(new Setter(Control.BackgroundProperty, new SolidColorBrush(bg)));
    s.Setters.Add(new Setter(Control.ForegroundProperty, Brushes.White));
    s.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(14, 7, 14, 7)));
    s.Setters.Add(new Setter(Control.BorderThicknessProperty, new Thickness(0)));
    s.Setters.Add(new Setter(FrameworkElement.CursorProperty, System.Windows.Input.Cursors.Hand));
    var b = new FrameworkElementFactory(typeof(Border), "b");
    b.SetValue(Border.CornerRadiusProperty, new CornerRadius(10));
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
  public static UIElement IconText(string g, string text, Brush? fg = null) {
    var sp = new StackPanel { Orientation = Orientation.Horizontal };
    var ic = Glyph(g, 16, fg ?? Brushes.White); ic.Margin = new Thickness(0, 0, 10, 0); sp.Children.Add(ic);
    sp.Children.Add(new TextBlock { Text = text, VerticalAlignment = VerticalAlignment.Center }); return sp;
  }
  public static UIElement Badge(string g) => new Border { Width = 38, Height = 38, CornerRadius = new CornerRadius(12), Background = new SolidColorBrush(Color.FromRgb(238, 243, 252)), Margin = new Thickness(0, 0, 12, 0), VerticalAlignment = VerticalAlignment.Center, Child = Glyph(g, 18, Accent) };
  // בועת הסבר כהה ומעוגלת
  public static ToolTip Tip(string text) => new ToolTip {
    Background = Brushes.Transparent, BorderThickness = new Thickness(0), Padding = new Thickness(0), HasDropShadow = false, Placement = PlacementMode.Bottom, FlowDirection = FlowDirection.RightToLeft,
    Content = new Border { Background = new SolidColorBrush(Color.FromRgb(51, 65, 85)), CornerRadius = new CornerRadius(12), Padding = new Thickness(14, 10, 14, 10), MaxWidth = 320, Margin = new Thickness(0, 4, 0, 0),
      Child = new TextBlock { Text = text, Foreground = Brushes.White, FontSize = 13, LineHeight = 20, TextWrapping = TextWrapping.Wrap } } };
  public static T Tipped<T>(T e, string text) where T : FrameworkElement { e.ToolTip = Tip(text); ToolTipService.SetInitialShowDelay(e, 200); ToolTipService.SetShowDuration(e, 60000); return e; }
  // אייקון ⓘ שמציג בועת הסבר במעבר עכבר
  public static Border Info(string text) => Tipped(new Border { Width = 22, Height = 22, Background = Brushes.Transparent, Cursor = System.Windows.Input.Cursors.Help, VerticalAlignment = VerticalAlignment.Center, Child = Glyph("\uE946", 15, Accent) }, text);
  // סגנון עדין (רקע בהיר, מסגרת דקה) ללחצנים בסרגל העליון
  public static Style Soft(Type t) {
    var s = new Style(t);
    s.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(13, 7, 13, 7)));
    s.Setters.Add(new Setter(Control.BorderThicknessProperty, new Thickness(1)));
    s.Setters.Add(new Setter(FrameworkElement.CursorProperty, System.Windows.Input.Cursors.Hand));
    var b = new FrameworkElementFactory(typeof(Border), "b");
    b.SetValue(Border.CornerRadiusProperty, new CornerRadius(10));
    b.SetValue(Border.BackgroundProperty, new TemplateBindingExtension(Control.BackgroundProperty));
    b.SetValue(Border.BorderBrushProperty, new TemplateBindingExtension(Control.BorderBrushProperty));
    b.SetValue(Border.BorderThicknessProperty, new TemplateBindingExtension(Control.BorderThicknessProperty));
    b.SetValue(Border.PaddingProperty, new TemplateBindingExtension(Control.PaddingProperty));
    var cp = new FrameworkElementFactory(typeof(ContentPresenter));
    cp.SetValue(FrameworkElement.HorizontalAlignmentProperty, HorizontalAlignment.Center);
    cp.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);
    b.AppendChild(cp);
    var tpl = new ControlTemplate(t) { VisualTree = b };
    var hov = new Trigger { Property = UIElement.IsMouseOverProperty, Value = true }; hov.Setters.Add(new Setter(UIElement.OpacityProperty, 0.78, "b"));
    tpl.Triggers.Add(hov);
    s.Setters.Add(new Setter(Control.TemplateProperty, tpl));
    return s;
  }
  public static void Tint(Control c, Color bg, Color fg, Color border) { c.Background = new SolidColorBrush(bg); c.Foreground = new SolidColorBrush(fg); c.BorderBrush = new SolidColorBrush(border); }
  static Style Input(Type t) {
    var s = new Style(t);
    s.Setters.Add(new Setter(Control.BackgroundProperty, Brushes.White));
    s.Setters.Add(new Setter(Control.BorderBrushProperty, new SolidColorBrush(Color.FromRgb(214, 222, 233))));
    s.Setters.Add(new Setter(Control.BorderThicknessProperty, new Thickness(1)));
    s.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(10, 7, 10, 7)));
    var bd = new FrameworkElementFactory(typeof(Border), "bd");
    bd.SetValue(Border.CornerRadiusProperty, new CornerRadius(10));
    bd.SetValue(Border.BackgroundProperty, new TemplateBindingExtension(Control.BackgroundProperty));
    bd.SetValue(Border.BorderBrushProperty, new TemplateBindingExtension(Control.BorderBrushProperty));
    bd.SetValue(Border.BorderThicknessProperty, new TemplateBindingExtension(Control.BorderThicknessProperty));
    bd.SetValue(Border.PaddingProperty, new TemplateBindingExtension(Control.PaddingProperty));
    var sv = new FrameworkElementFactory(typeof(ScrollViewer), "PART_ContentHost");
    sv.SetValue(UIElement.FocusableProperty, false);
    sv.SetValue(ScrollViewer.HorizontalScrollBarVisibilityProperty, ScrollBarVisibility.Hidden);
    sv.SetValue(ScrollViewer.VerticalScrollBarVisibilityProperty, ScrollBarVisibility.Hidden);
    bd.AppendChild(sv);
    var tpl = new ControlTemplate(t) { VisualTree = bd };
    var foc = new Trigger { Property = UIElement.IsKeyboardFocusWithinProperty, Value = true }; foc.Setters.Add(new Setter(Border.BorderBrushProperty, Accent, "bd"));
    tpl.Triggers.Add(foc);
    s.Setters.Add(new Setter(Control.TemplateProperty, tpl)); return s;
  }
  static Style Switch() {
    var s = new Style(typeof(CheckBox));
    s.Setters.Add(new Setter(FrameworkElement.CursorProperty, System.Windows.Input.Cursors.Hand));
    s.Setters.Add(new Setter(Control.ForegroundProperty, new SolidColorBrush(Color.FromRgb(30, 41, 59))));
    var root = new FrameworkElementFactory(typeof(StackPanel)); root.SetValue(StackPanel.OrientationProperty, Orientation.Horizontal); root.SetValue(Panel.BackgroundProperty, Brushes.Transparent);
    var track = new FrameworkElementFactory(typeof(Border), "track");
    track.SetValue(FrameworkElement.WidthProperty, 42.0); track.SetValue(FrameworkElement.HeightProperty, 22.0); track.SetValue(Border.CornerRadiusProperty, new CornerRadius(11));
    track.SetValue(Border.BackgroundProperty, new SolidColorBrush(Color.FromRgb(214, 222, 233))); track.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);
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
    app.Resources[typeof(TextBox)] = Input(typeof(TextBox));
    app.Resources[typeof(PasswordBox)] = Input(typeof(PasswordBox));
    app.Resources[typeof(Button)] = Make(typeof(Button), Color.FromRgb(88, 128, 196));
    app.Resources[typeof(ToggleButton)] = Make(typeof(ToggleButton), Color.FromRgb(22, 163, 74), Color.FromRgb(220, 38, 38));
  }
}
