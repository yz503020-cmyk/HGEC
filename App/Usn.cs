using System.IO; using System.Runtime.InteropServices; using System.Text; using System.Threading;
namespace DG;
// מנוע סריקה מהיר: קורא את טבלת הקבצים (MFT) של כונן NTFS דרך FSCTL_ENUM_USN_DATA במקום לעבור על כל תיקייה.
// מחזיר null בכל מקרה של ספק (לא NTFS, אין הרשאה, גרסת רשומה לא צפויה) – ואז הקורא חוזר לסריקה הרגילה
static class UsnScan {
  [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)] static extern nint CreateFileW(string name, uint access, uint share, nint sec, uint disp, uint flags, nint tmpl);
  [DllImport("kernel32", SetLastError = true)] static extern bool DeviceIoControl(nint h, uint code, ref MftEnum inb, int inSize, byte[] outb, int outSize, out int ret, nint ov);
  [DllImport("kernel32")] static extern bool CloseHandle(nint h);
  [StructLayout(LayoutKind.Sequential)] struct MftEnum { public ulong StartFrn; public long LowUsn; public long HighUsn; }
  const uint FSCTL_ENUM_USN_DATA = 0x000900B3;

  public static List<string>? TryList(string root, IEnumerable<string> exts, CancellationToken ct) {
    try {
      if (root.Length < 2 || root[1] != ':') return null;
      var di = new DriveInfo(root.Substring(0, 1)); if (!di.IsReady || !string.Equals(di.DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase)) return null;
      var set = new HashSet<string>(exts.Select(e => "." + e.TrimStart('.')), StringComparer.OrdinalIgnoreCase);
      var h = CreateFileW(@"\\.\" + root.Substring(0, 2), 0x80000000, 3, 0, 3, 0, 0);   // GENERIC_READ, שיתוף קריאה/כתיבה, OPEN_EXISTING
      if (h == 0 || h == -1) return null;
      try {
        var dirs = new Dictionary<ulong, (ulong Parent, string Name)>(1 << 18);
        var files = new List<(ulong Parent, string Name)>();
        var buf = new byte[1 << 16]; var inp = new MftEnum { StartFrn = 0, LowUsn = 0, HighUsn = long.MaxValue };
        while (true) {
          if (ct.IsCancellationRequested) return null;
          if (!DeviceIoControl(h, FSCTL_ENUM_USN_DATA, ref inp, Marshal.SizeOf<MftEnum>(), buf, buf.Length, out int ret, 0)) {
            if (Marshal.GetLastWin32Error() == 38) break;   // ERROR_HANDLE_EOF – סוף הטבלה
            return null;
          }
          if (ret <= 8) break;
          inp.StartFrn = BitConverter.ToUInt64(buf, 0);
          int off = 8;
          while (off + 60 <= ret) {
            int len = BitConverter.ToInt32(buf, off); if (len <= 0 || off + len > ret) break;
            if (BitConverter.ToUInt16(buf, off + 4) != 2) return null;   // רק USN_RECORD_V2
            ulong frn = BitConverter.ToUInt64(buf, off + 8), parent = BitConverter.ToUInt64(buf, off + 16);
            uint attrs = BitConverter.ToUInt32(buf, off + 52); int nl = BitConverter.ToUInt16(buf, off + 56), no = BitConverter.ToUInt16(buf, off + 58);
            if (no + nl <= len) {
              var name = Encoding.Unicode.GetString(buf, off + no, nl);
              if ((attrs & 0x10) != 0) dirs[frn] = (parent, name);
              else if (set.Contains(System.IO.Path.GetExtension(name))) files.Add((parent, name));
            }
            off += len;
          }
        }
        var res = new List<string>(files.Count); var cache = new Dictionary<ulong, string?>();
        string r0 = root.Substring(0, 2);
        foreach (var (parent, name) in files) {
          var dir = DirPath(parent, dirs, cache, r0); if (dir == null) continue;
          res.Add(dir + "\\" + name);
        }
        return res;
      } finally { CloseHandle(h); }
    } catch { return null; }
  }
  // בונה נתיב תיקייה מה-FRN (עם מטמון). null = שרשרת שבורה (תיקייה יתומה) – מדלגים
  static string? DirPath(ulong frn, Dictionary<ulong, (ulong Parent, string Name)> dirs, Dictionary<ulong, string?> cache, string drive) {
    if ((frn & 0xFFFFFFFFFFFF) == 5) return drive;   // תיקיית השורש
    if (cache.TryGetValue(frn, out var c)) return c;
    var stack = new List<ulong>(); var cur = frn; string? basePath = null;
    for (int i = 0; i < 256; i++) {
      if ((cur & 0xFFFFFFFFFFFF) == 5) { basePath = drive; break; }
      if (cache.TryGetValue(cur, out var cp)) { basePath = cp; break; }
      if (!dirs.TryGetValue(cur, out var d)) break;
      stack.Add(cur); cur = d.Parent;
    }
    if (basePath == null) { foreach (var s in stack) cache[s] = null; return null; }
    for (int i = stack.Count - 1; i >= 0; i--) { basePath = basePath + "\\" + dirs[stack[i]].Name; cache[stack[i]] = basePath; }
    return basePath;
  }
}
