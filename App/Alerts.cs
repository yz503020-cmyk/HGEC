using System.IO; using System.Net.Http; using System.Text;
namespace DG;
// יומן אירועים + התראה אופציונלית לכתובת (Webhook, למשל ntfy.sh או בוט) כשמתגלה ניסיון עקיפה
static class Alerts {
  static readonly object L = new(); static DateTime lastPost = DateTime.MinValue; static string? url;
  public static string LogPath => System.IO.Path.Combine(Config.Dir, "var", "events.log");
  public static void SetUrl(string? u) => url = u;
  public static void Log(string msg, bool alert = true) {
    try {
      lock (L) {
        var f = LogPath; Directory.CreateDirectory(System.IO.Path.GetDirectoryName(f)!);
        if (File.Exists(f) && new FileInfo(f).Length > 512 * 1024) { File.Copy(f, f + ".old", true); File.Delete(f); }
        File.AppendAllText(f, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss}  {msg}\n", Encoding.UTF8);
      }
    } catch { }
    if (alert && !string.IsNullOrWhiteSpace(url)) Post(msg);
  }
  static void Post(string msg) {
    var now = DateTime.UtcNow; lock (L) { if ((now - lastPost).TotalSeconds < 30) return; lastPost = now; }
    var u = url!;
    Task.Run(async () => { try { using var h = new HttpClient { Timeout = TimeSpan.FromSeconds(10) }; await h.PostAsync(u, new StringContent("DeviceGuard (" + Environment.MachineName + "): " + msg, Encoding.UTF8)); } catch { } });
  }
}
