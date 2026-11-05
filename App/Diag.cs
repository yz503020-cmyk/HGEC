using System.Collections.Concurrent;
using System.IO;
using System.Runtime.CompilerServices;

namespace DG;

// יומן אבחון: חריגות שבעבר "נבלעו" בשקט (catch ריק) נרשמות כאן, כדי שאפשר יהיה לאתר תקלות.
// הקובץ: ProgramData\DeviceGuard\var\diag.log (רק השירות והחלון המורם יכולים לכתוב אליו; בשער – הכתיבה פשוט נכשלת בשקט).
// הגבלת קצב: כל מקום בקוד נרשם לכל היותר פעם ב-10 דקות (ההופעות שבינתיים נספרות), והקובץ מוגבל ל-1MB (גרסה קודמת נשמרת ב-diag.log.1).
public static class Diag
{
  static readonly ConcurrentDictionary<string, (DateTime Last, int Skipped)> seen = new();
  static readonly object lk = new();
  const long MaxBytes = 1_000_000;
  public static string LogPath => Path.Combine(Config.Dir, "var", "diag.log");

  public static void Log(
    Exception e,
    [CallerFilePath] string file = "",
    [CallerMemberName] string member = "",
    [CallerLineNumber] int line = 0
  )
  {
    try
    {
      var site = Path.GetFileName(file) + ":" + line;
      var now = DateTime.UtcNow;
      int skipped;
      lock (lk)
      {
        if (seen.TryGetValue(site, out var s))
        {
          if ((now - s.Last).TotalMinutes < 10)
          {
            seen[site] = (s.Last, s.Skipped + 1);
            return;
          }
          skipped = s.Skipped;
        }
        else
          skipped = 0;
        if (seen.Count > 5000)
          seen.Clear();
        seen[site] = (now, 0);
      }
      var msg =
        $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{Environment.ProcessId}] {site} {member}: {e.GetType().Name}: {e.Message}"
        + (skipped > 0 ? $" (+{skipped} נוספות מאותו מקום)" : "");
      lock (lk)
      {
        var p = LogPath;
        if (!Directory.Exists(Path.GetDirectoryName(p)))
          return; // לא יוצרים את התיקייה: ההרשאות שלה נקבעות רק בהתקנה/בשירות
        try
        {
          if (new FileInfo(p).Length > MaxBytes)
            File.Move(p, p + ".1", true);
        }
        catch (FileNotFoundException) { }
        File.AppendAllText(p, msg.Replace('\r', ' ').Replace('\n', ' ') + Environment.NewLine);
      }
    }
    catch { } // היומן עצמו לעולם לא מפיל את התוכנה
  }
}
