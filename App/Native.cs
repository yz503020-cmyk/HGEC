using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace DG;

// פונקציות מערכת קטנות: זיהוי תהליכים, משתמשים והורים
static class Native
{
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern nint OpenProcess(uint access, bool inherit, int pid);

  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool QueryFullProcessImageNameW(nint h, uint flags, StringBuilder name, ref uint size);

  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool OpenProcessToken(nint h, uint access, out nint tok);

  [DllImport("kernel32.dll")]
  static extern bool CloseHandle(nint h);

  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool GetNamedPipeClientProcessId(nint pipe, out uint pid);

  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool GetNamedPipeServerSessionId(nint pipe, out uint session);

  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool GetNamedPipeServerProcessId(nint pipe, out uint pid);

  // האם מי שעונה ב-Pipe הוא שירות ההגנה האמיתי: שירותים רצים בסשן 0 (משתמש רגיל לא יכול להריץ שם תהליך), ואם אפשר לבדוק – כ-SYSTEM.
  // מונע ממשתמש לפתוח Pipe באותו שם כשהשירות למטה ולקבל את הקודים שמוקשים אליו
  public static bool TrustedPipeServer(nint pipe)
  {
    try
    {
      if (!GetNamedPipeServerSessionId(pipe, out var ses) || ses != 0)
        return false;
      if (GetNamedPipeServerProcessId(pipe, out var pid))
      {
        var sid = ProcSid((int)pid);
        if (sid != null && sid != "S-1-5-18")
          return false;
      }
      return true;
    }
    catch
    {
      return false;
    }
  }

  [DllImport("ntdll.dll")]
  static extern int NtQueryInformationProcess(nint h, int cls, ref PBI pbi, int len, out int ret);

  [StructLayout(LayoutKind.Sequential)]
  struct PBI
  {
    public nint Exit,
      Peb,
      Aff,
      Prio,
      Pid,
      Parent;
  }

  const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
    TOKEN_QUERY = 0x8;

  public static string? ImagePath(int pid)
  {
    var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
    if (h == 0)
      return null;
    try
    {
      var sb = new StringBuilder(1024);
      uint n = 1024;
      return QueryFullProcessImageNameW(h, 0, sb, ref n) ? sb.ToString(0, (int)n) : null;
    }
    finally
    {
      CloseHandle(h);
    }
  }

  public static string? ProcSid(int pid)
  {
    var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
    if (h == 0)
      return null;
    try
    {
      if (!OpenProcessToken(h, TOKEN_QUERY, out var t))
        return null;
      try
      {
        using var id = new WindowsIdentity(t);
        return id.User?.Value;
      }
      finally
      {
        CloseHandle(t);
      }
    }
    finally
    {
      CloseHandle(h);
    }
  }

  public static int ParentPid()
  {
    try
    {
      var pbi = new PBI();
      using var p = Process.GetCurrentProcess();
      return NtQueryInformationProcess(p.Handle, 0, ref pbi, Marshal.SizeOf<PBI>(), out _) == 0 ? (int)pbi.Parent : 0;
    }
    catch
    {
      return 0;
    }
  }

  // תהליך האב של תהליך כלשהו (0 = לא ידוע)
  public static int ParentOf(int pid)
  {
    var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
    if (h == 0)
      return 0;
    try
    {
      var pbi = new PBI();
      return NtQueryInformationProcess(h, 0, ref pbi, Marshal.SizeOf<PBI>(), out _) == 0 ? (int)pbi.Parent : 0;
    }
    catch
    {
      return 0;
    }
    finally
    {
      CloseHandle(h);
    }
  }

  // שם הקובץ המקורי מתוך משאב הגרסה של קובץ ההפעלה (בלי סיומת). משמש לזיהוי עותקים ששינו להם שם
  public static string? OriginalName(string path)
  {
    try
    {
      var o = FileVersionInfo.GetVersionInfo(path).OriginalFilename;
      return string.IsNullOrWhiteSpace(o) ? null : System.IO.Path.GetFileNameWithoutExtension(o.Trim());
    }
    catch
    {
      return null;
    }
  }

  public static bool Alive(int pid)
  {
    try
    {
      using var p = Process.GetProcessById(pid);
      return !p.HasExited;
    }
    catch
    {
      return false;
    }
  }

  public static bool SameStart(int pid, DateTime start)
  {
    try
    {
      using var p = Process.GetProcessById(pid);
      return p.StartTime == start;
    }
    catch
    {
      return false;
    }
  }

  // המשתמש שיושב מול המחשב (בעל explorer.exe בסשן הנוכחי) – גם כשהתוכנה הורצה כמנהל של חשבון אחר
  public static string? InteractiveUserSid()
  {
    try
    {
      int sess;
      using (var me = Process.GetCurrentProcess())
        sess = me.SessionId;
      foreach (var p in Process.GetProcessesByName("explorer"))
      {
        try
        {
          if (p.SessionId == sess)
          {
            var s = ProcSid(p.Id);
            if (s != null)
              return s;
          }
        }
        finally
        {
          p.Dispose();
        }
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    return WindowsIdentity.GetCurrent().User?.Value;
  }

  public static string? AccountName(string? sid)
  {
    try
    {
      return sid == null ? null : new SecurityIdentifier(sid).Translate(typeof(NTAccount)).Value;
    }
    catch
    {
      return null;
    }
  }

  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern nint CreateFileW(string name, uint access, uint share, nint sec, uint disp, uint flags, nint tmpl);

  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool DeviceIoControl(nint h, uint code, byte[] inb, int inSize, byte[] outb, int outSize, out int ret, nint ov);

  // האם הכונן מחובר דרך USB (או כרטיס SD/MMC). דיסק USB חיצוני מסווג ב-Windows כ"קבוע" (Fixed), ולכן אי אפשר לסמוך על DriveType.
  // root = "E:\". בכל ספק מחזיר false
  public static bool IsUsbBus(string root)
  {
    try
    {
      if (root.Length < 2 || root[1] != ':')
        return false;
      var h = CreateFileW(@"\\.\" + root[..2], 0, 3, 0, 3, 0, 0); // בלי הרשאות קריאה: מספיק לשאילתת מאפיינים
      if (h == 0 || h == -1)
        return false;
      try
      {
        var q = new byte[12]; // STORAGE_PROPERTY_QUERY: StorageDeviceProperty, PropertyStandardQuery
        var o = new byte[1024];
        if (!DeviceIoControl(h, 0x002D1400, q, q.Length, o, o.Length, out var n, 0) || n < 32) // IOCTL_STORAGE_QUERY_PROPERTY
          return false;
        var bus = BitConverter.ToInt32(o, 28); // STORAGE_DEVICE_DESCRIPTOR.BusType
        return bus == 7 || bus == 12 || bus == 13; // Usb, Sd, Mmc
      }
      finally
      {
        CloseHandle(h);
      }
    }
    catch
    {
      return false;
    }
  }

  // חשבונות המערכת (SYSTEM, LocalService, NetworkService). משתמש רגיל לא יכול להריץ תוכנה בחשבונות האלה
  public static bool IsServiceSid(string? sid) => sid == "S-1-5-18" || sid == "S-1-5-19" || sid == "S-1-5-20";

  public static bool IsServiceAccount()
  {
    try
    {
      using var id = WindowsIdentity.GetCurrent();
      return IsServiceSid(id.User?.Value);
    }
    catch
    {
      return false;
    }
  }

  public static bool IsSystemContext()
  {
    try
    {
      using var me = Process.GetCurrentProcess();
      return WindowsIdentity.GetCurrent().IsSystem || me.SessionId == 0;
    }
    catch
    {
      return false;
    }
  }
}
