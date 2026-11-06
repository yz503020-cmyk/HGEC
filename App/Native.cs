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

  // חשבונות משתמש שיש להם פרופיל במחשב (משתמשים אמיתיים בלבד: S-1-5-21-...), לבחירת החשבון שעליו חלות החסימות במצב "רק משתמש אחד"
  public static List<(string Sid, string Name)> LocalProfiles()
  {
    var res = new List<(string, string)>();
    try
    {
      using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList");
      if (k == null)
        return res;
      foreach (var sid in k.GetSubKeyNames())
      {
        if (!sid.StartsWith("S-1-5-21-", StringComparison.Ordinal) || sid.EndsWith(".bak", StringComparison.OrdinalIgnoreCase))
          continue;
        string? name = AccountName(sid);
        if (name == null)
        {
          using var pk = k.OpenSubKey(sid);
          name = pk?.GetValue("ProfileImagePath") is string pp ? System.IO.Path.GetFileName(pp) : sid;
        }
        res.Add((sid, name));
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    return res.OrderBy(x => x.Item2, StringComparer.OrdinalIgnoreCase).ToList();
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

  // ---- זיהוי קובץ/תיקייה לפי מזהה NTFS (נשאר זהה גם אחרי שינוי שם או העברה באותו כונן) ----
  [DllImport("kernel32.dll", SetLastError = true)]
  static extern bool GetFileInformationByHandle(nint h, byte[] info);

  [StructLayout(LayoutKind.Explicit, Size = 24)]
  struct FileIdDesc
  {
    [FieldOffset(0)]
    public int Size;

    [FieldOffset(4)]
    public int Type; // FileIdType

    [FieldOffset(8)]
    public long Id;
  }

  [DllImport("kernel32.dll", SetLastError = true)]
  static extern nint OpenFileById(nint hint, ref FileIdDesc id, uint access, uint share, nint sec, uint flags);

  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern uint GetFinalPathNameByHandleW(nint h, StringBuilder buf, uint len, uint flags);

  const uint ReadAttr = 0x80; // FILE_READ_ATTRIBUTES: לא נחסם על ידי כלל הדחייה שלנו
  const uint IdFlags = 0x02000000 | 0x00200000; // BACKUP_SEMANTICS (תיקיות) + OPEN_REPARSE_POINT

  static (uint Serial, long Index)? Ident(nint h)
  {
    var b = new byte[52]; // BY_HANDLE_FILE_INFORMATION
    if (!GetFileInformationByHandle(h, b))
      return null;
    var serial = BitConverter.ToUInt32(b, 28);
    var idx = ((long)BitConverter.ToUInt32(b, 44) << 32) | BitConverter.ToUInt32(b, 48);
    return (serial, idx);
  }

  // "מספר סידורי של הכונן:מזהה הקובץ" (הקסדצימלי), או null
  public static string? FileId(string path)
  {
    try
    {
      var h = CreateFileW(path, ReadAttr, 7, 0, 3, IdFlags, 0);
      if (h == 0 || h == -1)
        return null;
      try
      {
        return Ident(h) is { } t ? $"{t.Serial:X8}:{t.Index:X16}" : null;
      }
      finally
      {
        CloseHandle(h);
      }
    }
    catch
    {
      return null;
    }
  }

  // הנתיב הנוכחי של קובץ לפי המזהה. Present=false: הכונן לא מחובר עכשיו (אפשר לנסות שוב מאוחר יותר);
  // Present=true ו-Path=null: הכונן מחובר והקובץ לא נמצא (נמחק)
  public static (string? Path, bool Present) PathById(string id)
  {
    try
    {
      var q = id.Split(':');
      if (q.Length != 2)
        return (null, true);
      var serial = Convert.ToUInt32(q[0], 16);
      var idx = Convert.ToInt64(q[1], 16);
      foreach (var d in System.IO.DriveInfo.GetDrives())
      {
        try
        {
          if (!d.IsReady || (d.DriveType != System.IO.DriveType.Fixed && d.DriveType != System.IO.DriveType.Removable))
            continue;
          var root = CreateFileW(d.RootDirectory.FullName, ReadAttr, 7, 0, 3, IdFlags, 0);
          if (root == 0 || root == -1)
            continue;
          try
          {
            if (Ident(root) is not { } rt || rt.Serial != serial)
              continue;
            var desc = new FileIdDesc { Size = 24, Type = 0, Id = idx };
            var h = OpenFileById(root, ref desc, ReadAttr, 7, 0, IdFlags);
            if (h == 0 || h == -1)
              return (null, true);
            try
            {
              var sb = new StringBuilder(1024);
              var n = GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0);
              if (n == 0 || n >= sb.Capacity)
                return (null, false); // לא הצלחנו לקרוא את הנתיב: לא מוותרים
              var p = sb.ToString();
              if (p.StartsWith(@"\\?\UNC\", StringComparison.Ordinal))
                p = @"\\" + p[8..];
              else if (p.StartsWith(@"\\?\", StringComparison.Ordinal))
                p = p[4..];
              return (p, true);
            }
            finally
            {
              CloseHandle(h);
            }
          }
          finally
          {
            CloseHandle(root);
          }
        }
        catch { }
      }
      return (null, false);
    }
    catch
    {
      return (null, false);
    }
  }

  // הנתיב האמיתי של קובץ/תיקייה אחרי מעבר דרך קיצורי תיקייה (junction / symlink), גם באמצע הנתיב. null = לא קיים / לא ניתן לבדוק.
  // משמש לבדיקת "נתיב מסוכן": תיקייה שמפנה ל-C:\Windows או ל-C:\ProgramData נראית כטקסט כמו תיקייה רגילה
  public static string? FinalPath(string path)
  {
    try
    {
      var h = CreateFileW(path, ReadAttr, 7, 0, 3, 0x02000000, 0); // BACKUP_SEMANTICS בלי OPEN_REPARSE_POINT: עוקב אחרי הקישור
      if (h == 0 || h == -1)
        return null;
      try
      {
        var sb = new StringBuilder(1024);
        var n = GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0);
        if (n == 0 || n >= sb.Capacity)
          return null;
        var p = sb.ToString();
        if (p.StartsWith(@"\\?\UNC\", StringComparison.Ordinal))
          p = @"\\" + p[8..];
        else if (p.StartsWith(@"\\?\", StringComparison.Ordinal))
          p = p[4..];
        return p;
      }
      finally
      {
        CloseHandle(h);
      }
    }
    catch
    {
      return null;
    }
  }

  [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
  static extern int CM_Locate_DevNodeW(out uint dev, string id, int flags);

  [DllImport("cfgmgr32.dll")]
  static extern int CM_Get_DevNode_Status(out uint status, out uint problem, uint dev, int flags);

  // מצב התקן לפי מזהה המופע: -1 = לא מחובר כרגע, 1 = מושבת (CM_PROB_DISABLED), 0 = מחובר ולא מושבת. בדיקה זולה (בלי PowerShell)
  public static int DevState(string id)
  {
    try
    {
      if (CM_Locate_DevNodeW(out var d, id, 0) != 0) // CM_LOCATE_DEVNODE_NORMAL: רק התקנים מחוברים
        return -1;
      if (CM_Get_DevNode_Status(out _, out var pr, d, 0) != 0)
        return 0;
      return pr == 22 ? 1 : 0;
    }
    catch
    {
      return 0;
    }
  }

  // מנקה את סימון "מושבת" של התקן שאינו מחובר (CONFIGFLAG_DISABLED ברישום). כשיחובר שוב – יעבוד כרגיל. רק בשירות (SYSTEM)
  public static bool ClearDisabledFlag(string id)
  {
    try
    {
      using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\" + id, true);
      if (k == null)
        return false;
      if (k.GetValue("ConfigFlags") is int f && (f & 1) != 0)
        k.SetValue("ConfigFlags", f & ~1, Microsoft.Win32.RegistryValueKind.DWord);
      return true;
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
