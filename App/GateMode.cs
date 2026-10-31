using System.Diagnostics; using System.IO; using System.Runtime.InteropServices; using System.Text; using System.Threading; using System.Windows;
using System.Windows.Controls; using System.Windows.Media; using System.Windows.Threading;
namespace DG;
// מצבי "שער": חסימת הפעלת תוכנה וחלון קוד. רצים מתוך אותו קובץ ללא הרשאות מנהל
static class GateMode {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct SI { public int cb; public string? r, d, t; public int x, y, xs, ys, xc, yc, fa, fl; public short sw, cb2; public nint lp, i, o, e; }
  [StructLayout(LayoutKind.Sequential)] struct PI { public nint hp, ht; public uint pid, tid; }
  [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool CreateProcessW(string? app, StringBuilder cmd, nint pa, nint ta, bool inh, uint fl, nint env, string? cwd, ref SI si, out PI pi);
  [DllImport("kernel32")] static extern bool DebugActiveProcessStop(uint pid);
  [DllImport("kernel32")] static extern bool DebugSetProcessKillOnExit(bool k);
  [DllImport("kernel32")] static extern bool CloseHandle(nint h);

  static bool init;
  static void Init() { if (init) return; init = true; var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown }; Theme.Apply(app); }

  // הפעלה עם DEBUG_ONLY_THIS_PROCESS: Windows לא מפעיל שוב את ה-Debugger, ואז מנתקים את הדיבוג והתוכנה רצה כרגיל
  static void Launch(string cmd) {
    var si = new SI { cb = Marshal.SizeOf<SI>() };
    DebugSetProcessKillOnExit(false);
    if (CreateProcessW(null, new StringBuilder(cmd), 0, 0, false, 2, 0, null, ref si, out var pi)) { DebugActiveProcessStop(pi.pid); Config.Pipe("AUTHPID|" + pi.pid, 500); CloseHandle(pi.hp); CloseHandle(pi.ht); }
  }

  // נקרא על ידי Windows כשמנסים להפעיל תוכנה חסומה: DeviceGuard.exe --gate <id> <הפקודה המקורית>
  public static void RunGate(string[] a) {
    var id = a[1]; var cl = Environment.CommandLine; var orig = cl[(cl.IndexOf(id, StringComparison.Ordinal) + id.Length)..].Trim();
    var c = Config.Load(); var r = c.Find(id);
    if (r == null || !c.Master || (!c.AllUsers && Environment.UserName != c.OwnerUser)) { Launch(orig); return; }
    Init();
    if (r.Mode == Mode.Full) { Msg("אנא פנה למנהל המערכת"); return; }
    var need = r.OwnCode != null ? "הקוד הנפרד של התוכנה הזו" : "קוד ברירת המחדל (שהוגדר בחלון 1)";
    while (true) {
      var code = MainWin.Ask("נדרש " + need); if (code == null) return;
      if (c.CodeOk(r, code)) { Launch(orig); return; }
      Msg("קוד שגוי. יש להקיש את " + need + ".");
    }
  }

  // רשת ביטחון לתוכנות שה-IFEO לא תופס לפני ההפעלה (כמו אפליקציות Store): התוכנה כבר רצה, ומבקשים קוד; אם לא מוקש קוד נכון בזמן, התוכנה נסגרת
  public static void PromptKill(string[] a) {
    var id = a[1]; if (!int.TryParse(a[2], out var pid)) return;
    var c = Config.Load(); var r = c.Find(id); if (r == null) return;
    Init();
    var need = r.OwnCode != null ? "הקוד הנפרד של התוכנה הזו" : "קוד ברירת המחדל (שהוגדר בחלון 1)";
    var w = new Window { Title = "DeviceGuard", Topmost = true, ResizeMode = ResizeMode.NoResize, SizeToContent = SizeToContent.WidthAndHeight, WindowStartupLocation = WindowStartupLocation.CenterScreen, FlowDirection = FlowDirection.RightToLeft, FontFamily = new FontFamily("Segoe UI") };
    var sp = new StackPanel { Margin = new Thickness(20) };
    sp.Children.Add(new TextBlock { Text = r.Name + " חסומה. יש להקיש את " + need + " תוך 15 שניות, אחרת היא תיסגר.", TextWrapping = TextWrapping.Wrap, Width = 280, Margin = new Thickness(0, 0, 0, 12) });
    var pb = new PasswordBox { Width = 240 }; sp.Children.Add(pb);
    var lbl = new TextBlock { Margin = new Thickness(0, 8, 0, 0), Foreground = Brushes.Gray }; sp.Children.Add(lbl);
    var ok = new Button { Content = "אישור", IsDefault = true, Margin = new Thickness(0, 12, 0, 0), Padding = new Thickness(12, 5, 12, 5) };
    bool done = false;
    ok.Click += (s, e) => { if (c.CodeOk(r, pb.Password)) { done = true; w.Close(); } else { lbl.Text = "קוד שגוי"; pb.Clear(); } };
    sp.Children.Add(ok); w.Content = sp;
    int left = 15; lbl.Text = $"נותרו {left} שניות";
    var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
    timer.Tick += (s, e) => { left--; lbl.Text = left > 0 ? $"נותרו {left} שניות" : ""; if (left <= 0) { timer.Stop(); w.Close(); } };
    timer.Start();
    w.ShowDialog();
    timer.Stop();
    if (!done) { try { Process.GetProcessById(pid).Kill(); } catch { } }
  }

  static void Msg(string t) {   // הודעה שתמיד מופיעה מעל שאר החלונות
    var o = new Window { Topmost = true, ShowInTaskbar = false, WindowStyle = WindowStyle.None, Width = 0, Height = 0, Opacity = 0, WindowStartupLocation = WindowStartupLocation.CenterScreen };
    o.Show(); MessageBox.Show(o, t, "DeviceGuard", MessageBoxButton.OK, MessageBoxImage.Warning, MessageBoxResult.OK, MessageBoxOptions.RtlReading | MessageBoxOptions.RightAlign); o.Close();
  }
  static void Shell(string path) { try { Process.Start(new ProcessStartInfo(path) { UseShellExecute = true }); } catch { } }
  static bool FolderOpen(string path) {
    try {
      dynamic sh = Activator.CreateInstance(Type.GetTypeFromProgID("Shell.Application")!)!;
      foreach (dynamic w in sh.Windows()) { try { string? u = w.LocationURL; if (string.IsNullOrEmpty(u)) continue; if (new Uri(u).LocalPath.TrimEnd('\\').StartsWith(path.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) return true; } catch { } }
    } catch { }
    return false;
  }
  static bool TitleOpen(string title) {
    foreach (var p in Process.GetProcesses()) { try { if (p.MainWindowTitle.Contains(title, StringComparison.OrdinalIgnoreCase)) return true; } catch { } finally { p.Dispose(); } }
    return false;
  }
  // פתיחה בקוד: הפריט נפתח עד שסוגרים את החלון שלו, ואז ננעל שוב
  public static void OpenFlow(string id) {
    var c = Config.Load(); var r = c.Find(id); if (r == null) return;
    if (!c.Master || !r.On) { Shell(r.Path); return; }
    Init();
    var need = r.OwnCode != null ? "הקוד הנפרד של הפריט הזה" : "קוד ברירת המחדל (שהוגדר בחלון 1)";
    while (true) {
      var code = MainWin.Ask("נדרש " + need); if (code == null) return;
      var resp = Config.Pipe("OPEN|" + id + "|" + code);
      if (resp == "OK") break;
      Msg(resp == null ? "שירות ההגנה אינו פעיל. פתח את התוכנה ולחץ 'החל שינויים'." : resp == "LOCK" ? "יותר מדי ניסיונות. נסה שוב בעוד דקה." : resp == "BAD" ? "קוד שגוי. יש להקיש את " + need + "." : "שגיאה (" + resp + "). ודא שהחסימה פעילה ולחץ 'החל שינויים'.");
      if (resp == null || resp == "LOCK" || resp == "ERR") return;
    }
    Shell(r.Path);
    bool dir = Directory.Exists(r.Path); var title = System.IO.Path.GetFileNameWithoutExtension(r.Path); var t0 = DateTime.UtcNow; bool seen = false; int miss = 0;
    while (true) {
      Thread.Sleep(2000); Config.Pipe("PING|" + id);
      bool open = dir ? FolderOpen(r.Path) : TitleOpen(title);
      if (open) { seen = true; miss = 0; } else if (seen || (DateTime.UtcNow - t0).TotalSeconds > 15) { if (++miss >= 2) break; }
    }
    Config.Pipe("RELOCK|" + id);
  }
}
