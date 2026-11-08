using System.IO;
using System.Net.Http;
using System.Text;

namespace DG;

// יומן אירועים + התראה אופציונלית לכתובת (Webhook, למשל ntfy.sh או בוט) כשמתגלה ניסיון עקיפה
static class Alerts
{
  static readonly object L = new();
  static DateTime lastPost = DateTime.MinValue;
  static string? url;
  public static string LogPath => System.IO.Path.Combine(Config.Dir, "var", "events.log");

  public static void SetUrl(string? u) => url = u;

  // יומן האירועים של Windows: ניסיונות עקיפה נרשמים גם שם, כדי שפעולה של מנהל תתועד גם מחוץ לתוכנה
  static void Evt(string msg, bool warn)
  {
    try
    {
      if (!Config.InService)
        return;
      const string src = "DeviceGuard";
      if (!System.Diagnostics.EventLog.SourceExists(src))
        System.Diagnostics.EventLog.CreateEventSource(src, "Application");
      System.Diagnostics.EventLog.WriteEntry(
        src,
        msg,
        warn ? System.Diagnostics.EventLogEntryType.Warning : System.Diagnostics.EventLogEntryType.Information,
        warn ? 2 : 1
      );
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  public static void Event(string msg) => Evt(msg, false);

  // wait = המתנה קצרה לשליחה (למשל בעצירת שירות, כשהתהליך עומד להיסגר)
  public static void Log(string msg, bool alert = true, bool wait = false)
  {
    try
    {
      lock (L)
      {
        var f = LogPath;
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(f)!);
        if (File.Exists(f) && new FileInfo(f).Length > 512 * 1024)
        {
          File.Copy(f, f + ".old", true);
          File.Delete(f);
        }
        File.AppendAllText(f, $"{DateTime.Now:yyyy-MM-dd HH:mm:ss}  {msg}\n", Encoding.UTF8);
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    if (alert)
      Evt(msg, true);
    if (alert && !string.IsNullOrWhiteSpace(url))
      Post(msg, wait);
  }

  static void Post(string msg, bool wait)
  {
    var now = DateTime.UtcNow;
    lock (L)
    {
      if ((now - lastPost).TotalSeconds < 30)
        return;
      lastPost = now;
    }
    var u = url!;
    var t = Task.Run(async () =>
    {
      try
      {
        using var h = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        await h.PostAsync(u, new StringContent(Config.AppName + " (" + Environment.MachineName + "): " + msg, Encoding.UTF8));
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    });
    if (wait)
    {
      try
      {
        t.Wait(3000);
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
  }
}
