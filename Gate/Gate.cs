using System.Diagnostics; using System.Runtime.InteropServices; using System.Text; using System.Windows.Forms; using DG;
static class G {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] struct SI { public int cb; public string? r, d, t; public int x, y, xs, ys, xc, yc, fa, fl; public short sw, cb2; public nint lp, i, o, e; }
  [StructLayout(LayoutKind.Sequential)] struct PI { public nint hp, ht; public uint pid, tid; }
  [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool CreateProcessW(string? app, StringBuilder cmd, nint pa, nint ta, bool inh, uint fl, nint env, string? cwd, ref SI si, out PI pi);
  [DllImport("kernel32")] static extern bool DebugActiveProcessStop(uint pid);
  [DllImport("kernel32")] static extern bool DebugSetProcessKillOnExit(bool k);
  [DllImport("kernel32")] static extern bool CloseHandle(nint h);

  // הפעלה עם DEBUG_ONLY_THIS_PROCESS: Windows לא מפעיל שוב את ה-Debugger, ואז מנתקים את הדיבוג והתוכנה רצה כרגיל
  static void Launch(string cmd) {
    var si = new SI { cb = Marshal.SizeOf<SI>() };
    DebugSetProcessKillOnExit(false);
    if (CreateProcessW(null, new StringBuilder(cmd), 0, 0, false, 2, 0, null, ref si, out var pi)) { DebugActiveProcessStop(pi.pid); CloseHandle(pi.hp); CloseHandle(pi.ht); }
  }
  [STAThread] static void Main(string[] a) {
    Application.EnableVisualStyles();
    if (a.Length == 2 && a[0] == "--open") { OpenFlow(a[1]); return; }
    if (a.Length < 2) return;
    var id = a[0]; var cl = Environment.CommandLine; var orig = cl[(cl.IndexOf(id, StringComparison.Ordinal) + id.Length)..].Trim();
    var c = Config.Load(); var r = c.Find(id);
    if (r == null || !c.Master || (!c.AllUsers && Environment.UserName != c.OwnerUser)) { Launch(orig); return; }
    if (r.Mode == Mode.Full) { MessageBox.Show("אנא פנה למנהל המערכת", "החסימה פעילה", MessageBoxButtons.OK, MessageBoxIcon.Stop, MessageBoxDefaultButton.Button1, MessageBoxOptions.RtlReading | MessageBoxOptions.RightAlign); return; }
    while (true) {
      var code = Ask(); if (code == null) return;
      if (c.CodeOk(r, code)) { Launch(orig); return; }
      MessageBox.Show("קוד שגוי");
    }
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
  static void OpenFlow(string id) {
    var c = Config.Load(); var r = c.Find(id); if (r == null) return;
    if (!c.Master || !r.On) { Shell(r.Path); return; }
    while (true) {
      var code = Ask(); if (code == null) return;
      var resp = Config.Pipe("OPEN|" + id + "|" + code);
      if (resp == "OK") break;
      MessageBox.Show(resp == null ? "שירות ההגנה אינו פעיל. פתח את התוכנה ולחץ 'החל שינויים'." : resp == "LOCK" ? "יותר מדי ניסיונות. נסה שוב בעוד דקה." : resp == "BAD" ? "קוד שגוי" : "שגיאה");
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
  static string? Ask() {
    var f = new Form { Text = "נדרש קוד", RightToLeft = RightToLeft.Yes, RightToLeftLayout = true, Width = 300, Height = 150, StartPosition = FormStartPosition.CenterScreen, TopMost = true, FormBorderStyle = FormBorderStyle.FixedDialog, MaximizeBox = false };
    var t = new TextBox { UseSystemPasswordChar = true, Left = 15, Top = 15, Width = 250 }; var b = new Button { Text = "אישור", Left = 15, Top = 50, DialogResult = DialogResult.OK };
    f.Controls.AddRange(new Control[] { t, b }); f.AcceptButton = b;
    return f.ShowDialog() == DialogResult.OK ? t.Text : null;
  }
}
