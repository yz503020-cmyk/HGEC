using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace DGGate;

// שער קל. נקרא על ידי IFEO במקום הפעלת תוכנה חסומה:  DeviceGuardGate.exe --gate <id> <הפקודה המקורית>
// מטפל רק במסלולים שלא דורשים ממשק: החוק לא חל / התוכנה כבר מאושרת (ISAUTH) / שירות מערכת בלי אישור.
// כל מצב שדורש חלון (בקשת קוד, הודעות) מועבר לשער המלא DeviceGuardWatch.exe (אותה פקודה בדיוק)
static unsafe class Program
{
  [StructLayout(LayoutKind.Sequential)]
  struct SI
  {
    public int cb;
    public nint r,
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

  [StructLayout(LayoutKind.Sequential)]
  struct PBI
  {
    public nint Exit,
      Peb,
      Aff,
      Prio,
      Id,
      Parent;
  }

  [DllImport("kernel32", SetLastError = true)]
  static extern bool CreateProcessW(nint app, char* cmd, nint pa, nint ta, bool inh, uint fl, nint env, nint cwd, ref SI si, out PI pi);

  [DllImport("kernel32")]
  static extern bool DebugActiveProcessStop(uint pid);

  [DllImport("kernel32")]
  static extern bool DebugSetProcessKillOnExit(bool k);

  [DllImport("kernel32")]
  static extern bool CloseHandle(nint h);

  [DllImport("kernel32")]
  static extern uint WaitForSingleObject(nint h, uint ms);

  [DllImport("kernel32")]
  static extern bool GetExitCodeProcess(nint h, out uint code);

  [DllImport("kernel32")]
  static extern nint GetStdHandle(int n);

  [DllImport("kernel32")]
  static extern nint GetCurrentProcess();

  [DllImport("kernel32")]
  static extern bool ProcessIdToSessionId(uint pid, out uint sid);

  [DllImport("kernel32")]
  static extern uint GetCurrentProcessId();

  [DllImport("ntdll")]
  static extern int NtQueryInformationProcess(nint h, int cls, ref PBI pbi, int len, out int ret);

  [DllImport("kernel32", SetLastError = true)]
  static extern bool GetNamedPipeServerSessionId(nint pipe, out uint session);

  // שירות ההגנה רץ בסשן 0; Pipe בשם הזה שנפתח בסשן של משתמש אינו השירות
  static bool Trusted(NamedPipeClientStream p)
  {
    try
    {
      return GetNamedPipeServerSessionId(p.SafePipeHandle.DangerousGetHandle(), out var s) && s == 0;
    }
    catch
    {
      return false;
    }
  }

  static string? Pipe(string msg, int ms)
  {
    try
    {
      using var p = new NamedPipeClientStream(".", "DeviceGuard.Unlock", PipeDirection.InOut);
      p.Connect(ms);
      if (!Trusted(p))
        return null;
      var w = new StreamWriter(p) { AutoFlush = true };
      var r = new StreamReader(p);
      w.WriteLine(msg);
      var t = r.ReadLineAsync();
      return t.Wait(Math.Max(ms, 15000)) ? t.Result : null;
    }
    catch
    {
      return null;
    }
  }

  static bool Ok(nint h) => h != 0 && h != -1;

  // קוד יציאה כשהתוכנה נחסמה (ERROR_ACCESS_DISABLED_BY_POLICY), כדי שמי שהפעיל אותה (סקריפט, תוכנת התקנה, Windows) לא יחשוב שהיא הצליחה
  const int Blocked = 1260;

  // מפעיל את התוכנה וממתין לסיומה: השער נשאר "התהליך" שמי שהפעיל אותה מחכה לו, ומחזיר את קוד היציאה שלה.
  // בלי ההמתנה, מי שהפעיל (תוכנת התקנה שמריצה msiexec, Windows שמריץ reagentc, או מנהל השירותים שמפעיל את שירות Windows Installer)
  // קיבל "הצליח" מיד – לפני שהתוכנה בכלל התחילה לעבוד. מחזיר -1 אם ההפעלה נכשלה
  static int Run(string cmd, string? reg, bool debug)
  {
    var si = new SI { cb = sizeof(SI) };
    nint hi = GetStdHandle(-10),
      ho = GetStdHandle(-11),
      he = GetStdHandle(-12);
    bool any = Ok(hi) || Ok(ho) || Ok(he);
    uint fl = debug ? 2u : 0u; // DEBUG_ONLY_THIS_PROCESS
    if (any)
    {
      si.fl |= 0x100;
      si.i = hi;
      si.o = ho;
      si.e = he;
      fl |= 0x08000000;
    }
    if (debug)
      DebugSetProcessKillOnExit(false);
    var buf = new char[cmd.Length + 1];
    cmd.CopyTo(0, buf, 0, cmd.Length);
    fixed (char* pc = buf)
    {
      if (!CreateProcessW(0, pc, 0, 0, any, fl, 0, 0, ref si, out var pi))
        return -1;
      if (debug)
      {
        if (reg != null)
          Pipe($"AUTHPID|{pi.pid}|{reg}", 1500);
        DebugActiveProcessStop(pi.pid);
      }
      CloseHandle(pi.ht);
      WaitForSingleObject(pi.hp, 0xFFFFFFFF);
      int code = GetExitCodeProcess(pi.hp, out var ec) ? unchecked((int)ec) : 0;
      CloseHandle(pi.hp);
      return code;
    }
  }

  static int ParentPid()
  {
    try
    {
      var pbi = new PBI();
      return NtQueryInformationProcess(GetCurrentProcess(), 0, ref pbi, sizeof(PBI), out _) == 0 ? (int)pbi.Parent : 0;
    }
    catch
    {
      return 0;
    }
  }

  static int Main(string[] args)
  {
    if (args.Length < 2 || args[0] != "--gate")
      return 1;
    var id = args[1];
    // מזהה חוק תקין: אותיות, ספרות, מקף וקו תחתון בלבד. מזהה עם "|" (הפעלה ידנית של השער) היה משנה את הפקודה שנשלחת לשירות
    if (id.Length == 0 || id.Length > 64 || !id.All(ch => char.IsAsciiLetterOrDigit(ch) || ch == '-' || ch == '_'))
      return Blocked;
    var cl = Environment.CommandLine;
    var marker = "--gate " + id;
    var mi = cl.IndexOf(marker, StringComparison.Ordinal);
    var orig = (mi >= 0 ? cl[(mi + marker.Length)..] : "").Trim();
    if (orig.Length == 0)
      return 0;
    bool sys = false;
    try
    {
      sys = WindowsIdentity.GetCurrent().IsSystem || (ProcessIdToSessionId(GetCurrentProcessId(), out var sid) && sid == 0);
    }
    catch { }
    string sidStr = "";
    try
    {
      sidStr = WindowsIdentity.GetCurrent().User?.Value ?? "";
    }
    catch { }
    // Windows עצמו (SYSTEM / LocalService / NetworkService) עובר תמיד – משתמש רגיל לא יכול להריץ תוכנה בחשבונות האלה (ראו GateMode.RunGate)
    if (sidStr == "S-1-5-18" || sidStr == "S-1-5-19" || sidStr == "S-1-5-20")
      return Run(orig, null, true);
    // נתיב השער המלא: אותה תיקייה. גם הוא ממתין לתוכנה ומחזיר את קוד היציאה שלה
    var full = Path.Combine(AppContext.BaseDirectory, "DeviceGuardWatch.exe");
    int Delegate()
    {
      if (!File.Exists(full))
        return Blocked;
      var c = Run("\"" + full + "\" --gate " + id + " " + orig, null, false);
      return c == -1 ? Blocked : c;
    }

    var r = Pipe("RULE|" + id + "|" + sidStr, 3000);
    if (r == null)
      return sys ? Blocked : Delegate(); // שירות לא זמין: השער המלא מציג הודעה
    if (r == "NONE")
      return Run(orig, null, true); // החוק כבר לא קיים
    var p = r.Split('|', 7);
    if (p.Length < 7 || p[0] != "OK")
      return sys ? Blocked : Delegate(); // תשובה לא צפויה (שגיאה בשירות): לא פותחים בלי קוד. השער המלא מציג הודעה
    if (p[4] != "1")
      return Run(orig, null, true); // החוק לא חל כרגע
    if (Pipe($"ISAUTH|{id}|{ParentPid()}" + (sys ? "|SYS" : ""), 2000) == "OK")
      return Run(orig, id, true);
    return sys ? Blocked : Delegate();
  }
}
