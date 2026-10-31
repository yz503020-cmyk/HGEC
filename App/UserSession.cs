using System.Runtime.InteropServices;
using System.Text;
namespace DG;
// מפעיל תהליך בחוג ההתחברות של המשתמש המחובר, מתוך שירות שרץ כ-SYSTEM (ללא ממשק משלו).
// נדרש כדי שהשירות המוגן יוכל להציג חלון קוד למשתמש, בלי להיות שירות אינטראקטיבי ובלי דרישת הרשאות מנהל מצד המשתמש.
static class UserSession {
  [DllImport("kernel32.dll")] static extern uint WTSGetActiveConsoleSessionId();
  [DllImport("wtsapi32.dll", SetLastError = true)] static extern bool WTSQueryUserToken(uint sessionId, out IntPtr token);
  [DllImport("advapi32.dll", SetLastError = true)] static extern bool DuplicateTokenEx(IntPtr existingToken, uint desiredAccess, IntPtr tokenAttributes, int impersonationLevel, int tokenType, out IntPtr newToken);
  [DllImport("userenv.dll", SetLastError = true)] static extern bool CreateEnvironmentBlock(out IntPtr envBlock, IntPtr token, bool inherit);
  [DllImport("userenv.dll", SetLastError = true)] static extern bool DestroyEnvironmentBlock(IntPtr envBlock);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  [StructLayout(LayoutKind.Sequential)] struct STARTUPINFO { public int cb; public string? lpReserved, lpDesktop, lpTitle; public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags; public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError; }
  [StructLayout(LayoutKind.Sequential)] struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern bool CreateProcessAsUser(IntPtr token, string? appName, StringBuilder cmdLine, IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr env, string? cwd, ref STARTUPINFO si, out PROCESS_INFORMATION pi);

  const uint TOKEN_ALL_ACCESS = 0xF01FF; const int SecurityImpersonation = 2, TokenPrimary = 1;
  const uint CREATE_UNICODE_ENVIRONMENT = 0x400;

  [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr h, uint access, out IntPtr token);
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool LookupPrivilegeValue(string? host, string name, out long luid);
  [StructLayout(LayoutKind.Sequential)] struct LUID_AND_ATTR { public long Luid; public uint Attributes; }
  [StructLayout(LayoutKind.Sequential)] struct TOKEN_PRIVILEGES { public uint Count; public LUID_AND_ATTR Priv; }
  [DllImport("advapi32.dll", SetLastError = true)] static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES newState, uint len, IntPtr prev, IntPtr prevLen);
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  const uint TOKEN_ADJUST_PRIVILEGES = 0x20, TOKEN_QUERY = 0x8, SE_PRIVILEGE_ENABLED = 0x2;
  static bool enabled;
  // מפעיל שירות ה-SYSTEM זקוק להרשאת SE_TCB כדי לשאול את אסימון המשתמש המחובר
  static void EnableTcb() {
    if (enabled) return; enabled = true;
    try {
      if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out var tok)) return;
      try { if (LookupPrivilegeValue(null, "SeTcbPrivilege", out var luid)) { var tp = new TOKEN_PRIVILEGES { Count = 1, Priv = new LUID_AND_ATTR { Luid = luid, Attributes = SE_PRIVILEGE_ENABLED } }; AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero); }
      finally { CloseHandle(tok); }
    } catch { }
  }

  // true אם הופעל בהצלחה בחוג המשתמש המחובר כעת, ללא אישור מנהל
  public static bool Launch(string exe, string args) {
    EnableTcb();
    var session = WTSGetActiveConsoleSessionId();
    if (session == 0xFFFFFFFF) return false;
    if (!WTSQueryUserToken(session, out var userToken)) return false;
    try {
      if (!DuplicateTokenEx(userToken, TOKEN_ALL_ACCESS, IntPtr.Zero, SecurityImpersonation, TokenPrimary, out var dupToken)) return false;
      try {
        var env = IntPtr.Zero; CreateEnvironmentBlock(out env, dupToken, false);
        try {
          var si = new STARTUPINFO { cb = Marshal.SizeOf<STARTUPINFO>(), lpDesktop = "winsta0\\default" };
          var cmd = new StringBuilder($"\"{exe}\" {args}");
          var ok = CreateProcessAsUser(dupToken, null, cmd, IntPtr.Zero, IntPtr.Zero, false, CREATE_UNICODE_ENVIRONMENT, env, null, ref si, out var pi);
          if (ok) { CloseHandle(pi.hThread); CloseHandle(pi.hProcess); }
          return ok;
        } finally { if (env != IntPtr.Zero) DestroyEnvironmentBlock(env); }
      } finally { CloseHandle(dupToken); }
    } finally { CloseHandle(userToken); }
  }
}
