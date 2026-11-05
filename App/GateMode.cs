using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

namespace DG;

// מצבי "שער": חסימת הפעלת תוכנה וחלון קוד. רצים מתוך אותו קובץ ללא הרשאות מנהל.
// השער לא קורא את קובץ ההגדרות (הוא נעול למשתמשים רגילים): כל המידע והאימות עוברים דרך שירות ההגנה
static class GateMode
{
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  struct SI
  {
    public int cb;
    public string? r,
      d,
      t;
    public int x,
      y,
      xs,
      ys,
      xc,
      yc,
      fa,
      fl;
    public short sw,
      cb2;
    public nint lp,
      i,
      o,
      e;
  }

  [StructLayout(LayoutKind.Sequential)]
  struct PI
  {
    public nint hp,
      ht;
    public uint pid,
      tid;
  }

  [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern bool CreateProcessW(
    string? app,
    StringBuilder cmd,
    nint pa,
    nint ta,
    bool inh,
    uint fl,
    nint env,
    string? cwd,
    ref SI si,
    out PI pi
  );

  [DllImport("kernel32")]
  static extern bool DebugActiveProcessStop(uint pid);

  [DllImport("kernel32")]
  static extern bool DebugSetProcessKillOnExit(bool k);

  [DllImport("kernel32")]
  static extern bool CloseHandle(nint h);

  [DllImport("kernel32")]
  static extern nint GetStdHandle(int n);

  delegate bool EnumProc(nint h, nint l);

  [DllImport("user32.dll")]
  static extern bool EnumWindows(EnumProc cb, nint l);

  [DllImport("user32.dll", CharSet = CharSet.Unicode)]
  static extern int GetWindowTextW(nint h, StringBuilder s, int n);

  [DllImport("user32.dll")]
  static extern bool IsWindowVisible(nint h);

  sealed class Info
  {
    public bool Exists,
      HasOwn,
      Applies;
    public int Mode;
    public string Name = "",
      Kind = "",
      Path = "";
  }

  static string MySid() => WindowsIdentity.GetCurrent().User?.Value ?? "";

  // null = שירות ההגנה לא זמין; Exists=false = החוק כבר לא קיים
  static Info? GetInfo(string id)
  {
    var r = Config.Pipe("RULE|" + id + "|" + MySid(), 3000);
    if (r == null)
      return null;
    var p = r.Split('|', 7);
    if (p.Length < 7 || p[0] != "OK")
      return new Info();
    return new Info
    {
      Exists = true,
      Name = p[1],
      Mode = int.TryParse(p[2], out var m) ? m : 0,
      HasOwn = p[3] == "1",
      Applies = p[4] == "1",
      Kind = p[5],
      Path = p[6],
    };
  }

  static bool init;

  static void Init()
  {
    if (init)
      return;
    init = true;
    var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
    Theme.Apply(app);
  }

  // הפעלה עם DEBUG_ONLY_THIS_PROCESS: Windows לא מפעיל שוב את ה-Debugger, ואז מנתקים את הדיבוג והתוכנה רצה כרגיל.
  // reg != null: התוכנה אושרה, והשירות מתעד אותה (לפני הניתוק, כדי שלא תהיה מרוץ מול לולאת הניטור). תהליכי בן של תוכנה מאושרת עוברים בלי קוד
  static void Launch(string cmd, string? reg)
  {
    var si = new SI { cb = Marshal.SizeOf<SI>() };
    // מעבירים הלאה את הקלט/פלט הסטנדרטי (חשוב לסקריפטים וכלים שקוראים את הפלט של תוכנה חסומה)
    nint hi = GetStdHandle(-10),
      ho = GetStdHandle(-11),
      he = GetStdHandle(-12);
    bool any = Ok(hi) || Ok(ho) || Ok(he);
    uint fl = 2; // DEBUG_ONLY_THIS_PROCESS
    if (any)
    {
      si.fl |= 0x100;
      si.i = hi;
      si.o = ho;
      si.e = he;
      fl |= 0x08000000;
    } // STARTF_USESTDHANDLES + CREATE_NO_WINDOW
    DebugSetProcessKillOnExit(false);
    if (CreateProcessW(null, new StringBuilder(cmd), 0, 0, any, fl, 0, null, ref si, out var pi))
    {
      if (reg != null)
        Config.Pipe($"AUTHPID|{pi.pid}|{reg}", 1500);
      DebugActiveProcessStop(pi.pid);
      CloseHandle(pi.hp);
      CloseHandle(pi.ht);
    }
  }

  static bool Ok(nint h) => h != 0 && h != -1;

  // נקרא על ידי Windows כשמנסים להפעיל תוכנה חסומה: DeviceGuard.exe --gate <id> <הפקודה המקורית>
  public static void RunGate(string[] a)
  {
    var id = a[1];
    var cl = Environment.CommandLine;
    var marker = "--gate " + id;
    var mi = cl.IndexOf(marker, StringComparison.Ordinal);
    var orig = (mi >= 0 ? cl[(mi + marker.Length)..] : "").Trim();
    if (orig.Length == 0)
      return;
    // Windows עצמו (SYSTEM / שירותים) – למשל שירות Windows Installer (msiexec /V) או עדכון שמריץ reagentc: עובר תמיד.
    // משתמש רגיל לא יכול להריץ דבר בחשבונות האלה, ולכן זה לא פותח עקיפה; בלי זה עדכוני Windows נכשלו בשקט בזמן החסימה
    if (Native.IsServiceAccount())
    {
      Launch(orig, null);
      return;
    }
    bool sys = Native.IsSystemContext();
    var info = GetInfo(id);
    if (info == null)
    {
      if (!sys)
      {
        Init();
        Msg("שירות ההגנה אינו פעיל, ולכן לא ניתן להפעיל תוכנה חסומה. פתח את DeviceGuard ולחץ 'החל שינויים'.");
      }
      return;
    }
    if (!info.Exists || !info.Applies)
    {
      Launch(orig, null);
      return;
    }
    // תוכנה שהופעלה על ידי תוכנה מאושרת (תהליכי בן של דפדפן וכד'), או על ידי DeviceGuard עצמו – עוברת בלי קוד
    var ppid = Native.ParentPid();
    if (Config.Pipe($"ISAUTH|{id}|{ppid}" + (sys ? "|SYS" : ""), 2000) == "OK")
    {
      Launch(orig, id);
      return;
    }
    if (sys)
      return; // שירות/מערכת בלי אישור: נחסם בשקט (אין ממשק להצגת חלון)
    Init();
    if (info.Mode == (int)Mode.Full)
    {
      Msg("אנא פנה למנהל המערכת");
      return;
    }
    var need = info.HasOwn ? "הקוד הנפרד של התוכנה הזו" : "קוד ברירת המחדל (שהוגדר בחלון 1)";
    while (true)
    {
      var code = MainWin.Ask("נדרש " + need);
      if (code == null)
        return;
      var resp = Config.Pipe("VERIFY|" + id + "|" + code, 8000);
      if (resp == "OK")
      {
        Launch(orig, id);
        return;
      }
      Msg(
        resp == null ? "שירות ההגנה אינו פעיל."
        : resp == "LOCK" ? "יותר מדי ניסיונות. נסה שוב בעוד זמן מה."
        : "קוד שגוי. יש להקיש את " + need + "."
      );
      if (resp == null || resp == "LOCK")
        return;
    }
  }

  // רשת ביטחון לתוכנות שה-IFEO לא תופס לפני ההפעלה (כמו אפליקציות Store): התוכנה כבר רצה, ומבקשים קוד; אם לא מוקש קוד נכון בזמן, התוכנה נסגרת
  public static void PromptKill(string[] a)
  {
    var id = a[1];
    if (!int.TryParse(a[2], out var pid))
      return;
    var info = GetInfo(id);
    if (info == null || !info.Exists || !info.Applies)
      return;
    Init();
    var need = info.HasOwn ? "הקוד הנפרד של התוכנה הזו" : "קוד ברירת המחדל (שהוגדר בחלון 1)";
    var w = new Window
    {
      Title = "DeviceGuard",
      Topmost = true,
      ResizeMode = ResizeMode.NoResize,
      SizeToContent = SizeToContent.WidthAndHeight,
      WindowStartupLocation = WindowStartupLocation.CenterScreen,
      FlowDirection = FlowDirection.RightToLeft,
      FontFamily = new FontFamily("Segoe UI"),
      Background = new SolidColorBrush(Color.FromRgb(248, 250, 252)),
    };
    var sp = new StackPanel { Margin = new Thickness(20) };
    sp.Children.Add(
      new TextBlock
      {
        Text = info.Name + " חסומה. יש להקיש את " + need + " תוך 15 שניות, אחרת היא תיסגר.",
        TextWrapping = TextWrapping.Wrap,
        Width = 280,
        Margin = new Thickness(0, 0, 0, 12),
      }
    );
    var pb = new PasswordBox { Width = 240 };
    sp.Children.Add(pb);
    var lbl = new TextBlock { Margin = new Thickness(0, 8, 0, 0), Foreground = Brushes.Gray };
    sp.Children.Add(lbl);
    var ok = new Button
    {
      Content = "אישור",
      IsDefault = true,
      Margin = new Thickness(0, 12, 0, 0),
      Padding = new Thickness(12, 5, 12, 5),
    };
    bool done = false;
    ok.Click += (s, e) =>
    {
      var r = Config.Pipe("VERIFY|" + id + "|" + pb.Password, 8000);
      if (r == "OK")
      {
        done = true;
        w.Close();
      }
      else
      {
        lbl.Text = r == "LOCK" ? "יותר מדי ניסיונות" : "קוד שגוי";
        pb.Clear();
      }
    };
    sp.Children.Add(ok);
    w.Content = sp;
    int left = 15;
    lbl.Text = $"נותרו {left} שניות";
    var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
    timer.Tick += (s, e) =>
    {
      left--;
      lbl.Text = left > 0 ? $"נותרו {left} שניות" : "";
      if (left <= 0)
      {
        timer.Stop();
        w.Close();
      }
    };
    timer.Start();
    w.ShowDialog();
    timer.Stop();
    if (done)
    {
      Config.Pipe($"AUTHPID|{pid}|{id}", 2000);
      return;
    }
    try
    {
      Process.GetProcessById(pid).Kill();
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    Config.Pipe($"KILL|{pid}|{id}", 2000); // אם אין לנו הרשאה לסגור (תוכנה שרצה כמנהל) – השירות סוגר
  }

  static void Msg(string t)
  { // הודעה שתמיד מופיעה מעל שאר החלונות
    MainWin.Say(t, "DeviceGuard", warn: true);
  }

  // תיקייה נפתחת ישירות ב-Explorer (כדי שלא יתפוס במקומה את הקיצור שנוצר לצידה); קובץ נפתח כרגיל
  static void Shell(string path)
  {
    try
    {
      if (Directory.Exists(path))
        Process.Start(
          new ProcessStartInfo("explorer.exe", "\"" + (path.Length > 3 ? path.TrimEnd('\\') : path) + "\"") { UseShellExecute = false }
        );
      else
        Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  static bool FolderOpen(string path)
  {
    try
    {
      dynamic sh = Activator.CreateInstance(Type.GetTypeFromProgID("Shell.Application")!)!;
      foreach (dynamic w in sh.Windows())
      {
        try
        {
          string? u = w.LocationURL;
          if (string.IsNullOrEmpty(u))
            continue;
          var lp = new Uri(u).LocalPath.TrimEnd('\\');
          var pp = path.TrimEnd('\\');
          if (lp.Equals(pp, StringComparison.OrdinalIgnoreCase) || lp.StartsWith(pp + "\\", StringComparison.OrdinalIgnoreCase))
            return true;
        }
        catch (Exception __e)
        {
          Diag.Log(__e);
        }
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    return false;
  }

  // בדיקה זולה: מעבר על חלונות גלויים בלבד (במקום על כל התהליכים)
  static bool TitleOpen(string title)
  {
    bool found = false;
    var sb = new StringBuilder(512);
    EnumWindows(
      (h, l) =>
      {
        if (!IsWindowVisible(h))
          return true;
        sb.Clear();
        if (GetWindowTextW(h, sb, 512) > 0 && sb.ToString().Contains(title, StringComparison.OrdinalIgnoreCase))
        {
          found = true;
          return false;
        }
        return true;
      },
      0
    );
    return found;
  }

  static string Err(string? resp, string need) =>
    resp == null ? "שירות ההגנה אינו פעיל. פתח את התוכנה ולחץ 'החל שינויים'."
    : resp == "LOCK" ? "יותר מדי ניסיונות. נסה שוב בעוד זמן מה."
    : resp == "BAD" ? "קוד שגוי. יש להקיש את " + need + "."
    : "שגיאה (" + resp + "). ודא שהחסימה פעילה ולחץ 'החל שינויים'.";

  // פתיחה בקוד: הפריט נפתח עד שסוגרים את החלון שלו, ואז ננעל שוב. מופע אחד בלבד לכל פריט
  public static void OpenFlow(string id)
  {
    using var mx = new Mutex(false, "Local\\DG.Open." + id);
    bool got = false;
    try
    {
      got = mx.WaitOne(0);
      if (!got)
        return;
      OpenFlowCore(id);
    }
    finally
    {
      if (got)
        mx.ReleaseMutex();
    }
  }

  // פתיחת סיומות (תמונות/שירים/סרטים) בקוד: אחרי קוד נכון הקבצים משוחררים כל זמן שהחלון הזה פתוח, וכשסוגרים אותו הם ננעלים שוב
  public static void OpenExt(string id)
  {
    using var mx = new Mutex(false, "Local\\DG.OpenExt." + id);
    bool got = false;
    try
    {
      got = mx.WaitOne(0);
      if (!got)
        return;
      OpenExtCore(id);
    }
    finally
    {
      if (got)
        mx.ReleaseMutex();
    }
  }

  // מחזיר את אסימון ה-PING של הפתיחה (null = לא נפתח)
  static string? AskOpen(string id, string need)
  {
    while (true)
    {
      var code = MainWin.Ask("נדרש " + need);
      if (code == null)
        return null;
      var resp = Config.Pipe("OPEN|" + id + "|" + code, 15000);
      if (resp != null && resp.StartsWith("OK|"))
        return resp[3..];
      Msg(Err(resp, need));
      if (resp == null || resp == "LOCK" || resp == "ERR")
        return null;
    }
  }

  static void OpenExtCore(string id)
  {
    Init();
    var info = GetInfo(id);
    if (info == null)
    {
      Msg(Err(null, ""));
      return;
    }
    if (!info.Exists)
      return;
    if (!info.Applies || info.Mode != (int)Mode.Code)
    {
      Msg("החסימה הזו אינה פעילה בקוד.");
      return;
    }
    var tok = AskOpen(id, info.HasOwn ? "הקוד הנפרד של הפריט הזה" : "קוד ברירת המחדל (שהוגדר בחלון 1)");
    if (tok == null)
      return;
    var w = new Window
    {
      Title = "DeviceGuard",
      ResizeMode = ResizeMode.CanMinimize,
      SizeToContent = SizeToContent.WidthAndHeight,
      WindowStartupLocation = WindowStartupLocation.CenterScreen,
      FlowDirection = FlowDirection.RightToLeft,
      FontFamily = new FontFamily("Segoe UI"),
      Background = new SolidColorBrush(Color.FromRgb(248, 250, 252)),
    };
    w.Content = new TextBlock
    {
      Text = info.Name + " פתוחה כל זמן שהחלון הזה פתוח. סגור את החלון כדי לנעול שוב.",
      TextWrapping = TextWrapping.Wrap,
      Width = 300,
      Margin = new Thickness(20),
    };
    var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
    timer.Tick += (s, e) => Config.Pipe("PING|" + id + "|" + tok);
    timer.Start();
    w.ShowDialog();
    timer.Stop();
    Config.Pipe("RELOCK|" + id);
  }

  static void OpenFlowCore(string id)
  {
    var info = GetInfo(id);
    if (info == null)
    {
      Init();
      Msg(Err(null, ""));
      return;
    }
    if (!info.Exists)
      return;
    if (!info.Applies)
    {
      Shell(info.Path);
      return;
    }
    Init();
    var tok = AskOpen(id, info.HasOwn ? "הקוד הנפרד של הפריט הזה" : "קוד ברירת המחדל (שהוגדר בחלון 1)");
    if (tok == null)
      return;
    Shell(info.Path);
    bool dir = Directory.Exists(info.Path);
    var title = System.IO.Path.GetFileNameWithoutExtension(info.Path);
    var t0 = DateTime.UtcNow;
    bool seen = false;
    int miss = 0;
    while (true)
    {
      Thread.Sleep(2000);
      Config.Pipe("PING|" + id + "|" + tok);
      bool open = dir ? FolderOpen(info.Path) : TitleOpen(title);
      if (open)
      {
        seen = true;
        miss = 0;
      }
      else if (seen || (DateTime.UtcNow - t0).TotalSeconds > 15)
      {
        if (++miss >= 2)
          break;
      }
    }
    Config.Pipe("RELOCK|" + id);
  }
}
