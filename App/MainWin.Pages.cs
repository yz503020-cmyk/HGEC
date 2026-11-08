using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Microsoft.Win32;

namespace DG;

// חלון ראשי: העמודים (חלונות 1–7)
public partial class MainWin
{
  // ---------- חלון 1 ----------
  static readonly (string, string)[] SettingsPages =
  {
    ("תצוגה", "display"),
    ("קול", "sound"),
    ("התראות", "notifications"),
    ("אחסון", "storagesense"),
    ("Bluetooth", "bluetooth"),
    ("מדפסות", "printers"),
    ("עכבר", "mousetouchpad"),
    ("Wi-Fi", "network-wifi"),
    ("Ethernet", "network-ethernet"),
    ("פרטיות", "privacy"),
    ("Windows Update", "windowsupdate"),
    ("התאמה אישית", "personalization-background"),
    ("תאריך ושעה", "dateandtime"),
    ("שפה ואזור", "regionlanguage"),
    ("נגישות", "easeofaccess-display"),
    ("אודות", "about"),
    ("אפליקציות ותכונות", "appsfeatures"),
    ("אפליקציות ברירת מחדל", "defaultapps"),
  };

  UIElement P1()
  {
    var all = new CheckBox
    {
      Content = "החסימות יחולו על כל המשתמשים במחשב (אחרת – רק על החשבון שנבחר למטה)",
      IsChecked = C.AllUsers,
      Margin = new Thickness(0, 8, 0, 4),
    };
    // החשבון שעליו חלות החסימות כשהן לא לכל המשתמשים. קודם זה היה תמיד מי שפתח את התוכנה בפעם הראשונה, בלי אפשרות לראות או לשנות –
    // ובמחשב עם כמה חשבונות, פתיחה ראשונה מחשבון המנהל הפעילה את ההגבלות על המנהל במקום על החשבון שרצית
    var ownerTxt = new TextBlock { VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 10, 0) };
    void OwnerShow()
    {
      var n = Native.AccountName(C.OwnerSid) ?? C.OwnerUser ?? "(לא ידוע)";
      ownerTxt.Text = "החשבון שעליו חלות החסימות: " + n;
    }
    OwnerShow();
    var ownerBtn = Btn(
      "בחר חשבון…",
      () =>
      {
        var list = Native.LocalProfiles();
        if (list.Count == 0)
        {
          Say("לא נמצאו חשבונות משתמש במחשב.");
          return;
        }
        var res = Pick("בחר חשבון אחד", list.Select(x => (x.Name, x.Sid)), string.IsNullOrEmpty(C.OwnerSid) ? Array.Empty<string>() : new[] { C.OwnerSid });
        if (res == null)
          return;
        if (res.Count != 1)
        {
          Say("יש לבחור חשבון אחד בלבד.");
          return;
        }
        if (string.Equals(res[0], C.OwnerSid, StringComparison.OrdinalIgnoreCase))
          return;
        C.OwnerSid = res[0];
        C.OwnerUser = Native.AccountName(res[0]) ?? list.First(x => x.Sid == res[0]).Name;
        C.Save();
        OwnerShow();
        Say("החשבון נשמר. לחץ 'החל שינויים' כדי שהחסימות יעברו לחשבון הזה (ההגבלות בחשבון הקודם יבוטלו).");
      }
    );
    var ownerRow = new StackPanel
    {
      Orientation = Orientation.Horizontal,
      Margin = new Thickness(24, 0, 0, 8),
      Children = { ownerTxt, ownerBtn },
      Visibility = C.AllUsers ? Visibility.Collapsed : Visibility.Visible,
    };
    all.Click += (s, e) =>
    {
      C.AllUsers = all.IsChecked == true;
      ownerRow.Visibility = C.AllUsers ? Visibility.Collapsed : Visibility.Visible;
      C.Save();
    };
    var hard = new CheckBox
    {
      Content = "חיזוק חסימת קבצים: מונע מבעל הקובץ לשנות הרשאות ולהסיר את החסימה (יחול אחרי 'החל שינויים')",
      IsChecked = C.Harden,
      Margin = new Thickness(0, 0, 0, 8),
    };
    hard.Click += (s, e) =>
    {
      C.Harden = hard.IsChecked == true;
      C.Save();
    };
    var code = Btn(
      "הגדר / שנה קוד ברירת מחדל לחסימות",
      () =>
      {
        var k = Ask("קוד ברירת מחדל", true);
        if (k != null)
        {
          C.DefaultCode = Config.Hash(k);
          C.Save();
          Say("הקוד נשמר");
        }
      }
    );
    Func<IEnumerable<(string, string)>> usb = UsbList;
    var exp = Btn("ייצוא הגדרות…", Export);
    var imp = Btn("ייבוא הגדרות…", Import);
    var un2 = Btn(
      "הסרת שירות ההגנה (בקוד כניסה)",
      () =>
      {
        if (
          !Say("הפעולה תשבית את כל החסימות ותסיר את שירות ההגנה. להמשיך?", "אישור", yesNo: true)
        )
          return;
        var k = Ask("קוד כניסה לתוכנה");
        if (k == null || !Config.Check(k, C.AppCode))
        {
          Say("קוד שגוי");
          return;
        }
        _ = Uninstall();
      },
      "\uE74D"
    );
    var note = new TextBlock
    {
      Text = "הערה: רשימה לבנה של הגדרות/רשת/התקנים פועלת בחסימה גמורה.",
      Foreground = Brushes.Gray,
      Margin = new Thickness(0, 8, 0, 0),
      TextWrapping = TextWrapping.Wrap,
    };
    Theme.Tipped(
      all,
      "מסומן: החסימות פועלות בכל חשבונות המשתמשים במחשב. לא מסומן: רק בחשבון שנבחר.\n"
        + "חוץ מאלה, שחלות תמיד על כל המחשב (Windows לא מאפשר אותן לחשבון אחד): חסימת רשת ו-Wi-Fi, חסימת רשת לפי תוכנה, "
        + "חסימת USB עם רשימה לבנה של כוננים, וחלק מההגנה המתקדמת (נעילת hosts, הקשחה חזקה, WSL, winget, שיתוף אינטרנט והגדרות TCP/IP).\n"
        + "קבצים שהוגדרו כמוסתרים מוסתרים בכל החשבונות, אבל נחסמים רק בחשבון שנבחר."
    );
    Theme.Tipped(code, "קוד ברירת המחדל משמש לפתיחת כל חסימה בקוד שלא הוגדר לה קוד נפרד.");
    Theme.Tipped(exp, "שומר את ההגדרות לקובץ, לגיבוי או להעברה למחשב אחר.");
    Theme.Tipped(imp, "טוען הגדרות מקובץ שיוצא קודם. אחרי הטעינה לוחצים 'החל שינויים'.");
    Theme.Tipped(un2, "מכבה את כל החסימות ומסיר את שירות ההגנה מהמחשב, אחרי הקשת קוד הכניסה.");
    return Page(
      "הגדרות כלליות",
      "\uE713",
      code,
      all,
      ownerRow,
      hard,
      SkipAppCheck(),
      ScanOpts(),
      PreviewCheck(),
      Row(C.Settings, () => SettingsPages, false, null, "\uE713"),
      Row(C.Install, null, false, null, "\uE896"),
      Row(C.Usb, usb, false, null, "\uE88E"),
      SchedulePanel(),
      new StackPanel { Orientation = Orientation.Horizontal, Children = { exp, imp, un2 } },
      note
    );
  }

  // הסרה: ביטול החסימות רץ ברקע (החלון לא נתקע), ותוצאת ההסרה נבדקת לפני שמודיעים שהשירות יוסר.
  // לפני הסרת השירות נבדק שלא נשאר שום דבר שרק השירות יכול לשחרר אחר כך (משתמש לא מחובר, כונן לא מחובר, Wi-Fi / חומת אש):
  // אם נשאר – מציעים לדחות את ההסרה. החסימות כבר כבויות, והשירות ישחרר את השאר לבד (כשהמשתמש ייכנס / כשהכונן יחובר)
  async Task Uninstall()
  {
    IsEnabled = false;
    busy = true;
    status.Text = "מסיר...";
    string? lsaWarn = null;
    try
    {
      await Task.Factory.StartNew(
        () =>
        {
          C.Master = false;
          C.TempOpenUntil = 0;
          // גם אם השמירה נכשלת (למשל השירות לא עובד), הביטול עצמו כבר בוצע – ממשיכים לנקות, ורק אחר כך מדווחים על השגיאה
          Exception? err = null;
          try
          {
            Enforcer.Apply(C);
          }
          catch (Exception x)
          {
            err = x;
          }
          // שחרורים שהמתינו לכונן שלא היה מחובר: אחרי ההסרה אין מי שינסה שוב
          try
          {
            Enforcer.ProcessPathPending(C);
          }
          catch (Exception __e)
          {
            Diag.Log(__e);
          }
          // הגבלות ברישום של משתמשים שלא מחוברים עכשיו: טעינה זמנית של הרישום שלהם וביטול
          try
          {
            Enforcer.ProcessRegPendingOffline();
          }
          catch (Exception __e)
          {
            Diag.Log(__e);
          }
          // זכויות מנהל שלא הוחזרו בביטול (ההקשחה החזקה): אחרי ההסרה אין שירות שינסה שוב – מנסים עכשיו, ואם לא הצליח – מודיעים
          Enforcer.ProcessLsaPending(C, false);
          if (Enforcer.HasLsaPending())
            lsaWarn = (
              "חלק מזכויות המנהל שהוסרו בהקשחה החזקה לא הוחזרו. אפשר להחזיר אותן ב-secpol.msc (מדיניות מקומית ← הקצאת זכויות משתמש): גיבוי קבצים, שחזור קבצים, לקיחת בעלות, ניפוי באגים – לקבוצת Administrators"
            );
          Enforcer.PurgeAll();
          // אחרי ההסרה אין שירות שישחרר קבצים מאוחר יותר: סורקים את כל הכוננים ומשחררים כל קובץ שעדיין נעול על ידינו
          // (גם קבצים שהועברו ממקומם בזמן החסימה, וגם אם יומן החסימות נפגע)
          Enforcer.SweepAll(C);
          // חומת אש / מסנן Wi-Fi / hosts: וידוא שבאמת שוחררו (בלי המתנה)
          Enforcer.ProcessNetPending(C, false, true);
          if (err != null)
            throw new IOException("החסימות בוטלו, אך " + err.Message, err);
        },
        CancellationToken.None,
        TaskCreationOptions.None,
        Enforcer.Sta
      );
      // מה שעדיין לא שוחרר. "כן" = לנסות שוב (אחרי חיבור הכונן), "לא" = להחליט אם להסיר בכל זאת
      while (true)
      {
        var left = await Task.Run(() => (Users: Enforcer.PendingUsers(), Drives: Enforcer.PendingDrives(), Net: Enforcer.ProcessNetPending(C, false, true)));
        if (left.Users.Count == 0 && left.Drives.Count == 0 && left.Net.Count == 0)
          break;
        var msg = "החסימות בוטלו, אבל לא הכול שוחרר:\n";
        if (left.Users.Count > 0)
          msg += "\n• ההגבלות בחשבון " + string.Join(", ", left.Users.Select(u => Native.AccountName(u) ?? u)) + " (המשתמש לא מחובר, ולא ניתן היה לטעון את הרישום שלו).";
        if (left.Drives.Count > 0)
          msg += "\n• קבצים/תיקיות בכונן " + string.Join(", ", left.Drives) + " (הכונן לא מחובר). אפשר לחבר אותו עכשיו.";
        if (left.Net.Count > 0)
          msg += "\n• חסימת רשת (חומת אש / Wi-Fi) לא הוסרה במלואה.";
        msg += "\n\nלנסות שוב עכשיו? (\"לא\" – לבחור אם להסיר בכל זאת)";
        if (Say(msg, "הסרה", yesNo: true))
        {
          status.Text = "מנסה שוב...";
          await Task.Run(() =>
          {
            Enforcer.RetryReleases(C);
            Enforcer.ProcessRegPendingOffline();
          });
          continue;
        }
        if (
          !Say(
            "מומלץ לא להסיר עכשיו: החסימות כבר כבויות, ושירות ההגנה ישחרר את השאר לבד – כשהמשתמש ייכנס לחשבון שלו / כשהכונן יחובר. אחר כך אפשר להסיר.\n\n"
              + "להסיר בכל זאת? (מה שלא שוחרר יישאר כך)",
            "הסרה",
            yesNo: true
          )
        )
        {
          status.Text = "החסימות בוטלו; הסרת השירות נדחתה";
          busy = false;
          IsEnabled = true;
          return;
        }
        break;
      }
      var r = await Task.Run(() =>
      {
        var x = Config.Token != null ? Config.Pipe("UNINSTALL|" + Config.Token, 5000) : null;
        if (x != "OK" && Program.Code != null && Config.Auth(Program.Code))
          x = Config.Pipe("UNINSTALL|" + Config.Token, 5000); // הטוקן פג: אימות מחדש וניסיון נוסף
        return x;
      });
      if (r == "OK")
      {
        Config.Token = null;
        status.Text = "";
        Say("השירות יוסר בעוד מספר שניות" + (lsaWarn != null ? "\n\nשים לב: " + lsaWarn : ""));
      }
      else
      {
        status.Text = "הסרת השירות נכשלה";
        Say("החסימות בוטלו, אך הסרת שירות ההגנה נכשלה. נסה שוב, או הפעל מחדש את המחשב ונסה שוב.");
      }
    }
    catch (Exception x)
    {
      status.Text = "שגיאה: " + x.Message;
      Say("שגיאה בהסרה: " + x.Message);
    }
    busy = false;
    IsEnabled = true;
  }

  Dictionary<string, object> Sections() =>
    new()
    {
      ["1"] = new
      {
        C.AllUsers,
        C.Settings,
        C.Install,
        C.Usb,
      },
      ["2"] = C.Programs,
      ["3"] = C.Portable,
      ["4"] = new
      {
        C.Movies,
        C.Songs,
        C.Images,
        C.Exts,
      },
      ["5"] = C.Paths,
      ["6"] = new
      {
        C.Net,
        C.NetApps,
        C.NetAppsWhite,
      },
      ["7"] = new
      {
        C.Adv,
        C.AdvOpts,
        C.Sched,
      },
    };

  void Export()
  {
    var sel = Pick(
      "מה לייצא?",
      Enumerable.Range(1, 7).Select(i => ($"חלון {i}", i.ToString())),
      new[] { "1", "2", "3", "4", "5", "6", "7" }
    );
    if (sel == null || sel.Count == 0)
      return;
    var d = new SaveFileDialog { Filter = "DeviceGuard|*.dgcfg", FileName = "settings.dgcfg" };
    if (d.ShowDialog() != true)
      return;
    var node = System.Text.Json.Nodes.JsonNode.Parse(
      JsonSerializer.Serialize(Sections().Where(k => sel.Contains(k.Key)).ToDictionary(k => k.Key, k => k.Value), Config.O)
    )!;
    StripOwn(node); // קודים נפרדים (גם מגובבים) לא מיוצאים
    File.WriteAllText(d.FileName, node.ToJsonString(Config.O));
  }

  void Import()
  {
    var d = new OpenFileDialog { Filter = "DeviceGuard|*.dgcfg" };
    if (d.ShowDialog() != true)
      return;
    try
    {
      using var doc = JsonDocument.Parse(File.ReadAllText(d.FileName));
      var r = doc.RootElement;
      T D<T>(JsonElement e, string n) => e.GetProperty(n).Deserialize<T>(Config.O)!;
      if (r.TryGetProperty("1", out var a))
      {
        C.AllUsers = a.GetProperty("AllUsers").GetBoolean();
        C.Settings = D<Rule>(a, "Settings");
        C.Install = D<Rule>(a, "Install");
        if (a.TryGetProperty("Net", out var oldNet))
          C.Net = oldNet.Deserialize<Rule>(Config.O)!;
        C.Usb = D<Rule>(a, "Usb");
      }
      if (r.TryGetProperty("2", out var b))
        C.Programs = b.Deserialize<List<Rule>>(Config.O)!;
      if (r.TryGetProperty("3", out var c3))
        C.Portable = c3.Deserialize<Rule>(Config.O)!;
      if (r.TryGetProperty("4", out var e))
      {
        C.Movies = D<Rule>(e, "Movies");
        C.Songs = D<Rule>(e, "Songs");
        C.Images = D<Rule>(e, "Images");
        C.Exts = D<List<Rule>>(e, "Exts");
      }
      if (r.TryGetProperty("5", out var f))
        C.Paths = f.Deserialize<List<Rule>>(Config.O)!;
      if (r.TryGetProperty("6", out var g6))
      {
        C.Net = D<Rule>(g6, "Net");
        C.NetApps = D<Rule>(g6, "NetApps");
        C.NetAppsWhite = D<bool>(g6, "NetAppsWhite");
      }
      if (r.TryGetProperty("7", out var g7))
      {
        C.Adv = D<Rule>(g7, "Adv");
        C.AdvOpts = D<AdvOpts>(g7, "AdvOpts");
        C.Sched = D<Schedule>(g7, "Sched");
      }
      C.Save();
      host.Content = P1();
      status.Text = "יובא (קודים נפרדים לא מיובאים – יש להגדיר מחדש) – לחץ 'החל שינויים'";
    }
    catch (Exception x)
    {
      Say("קובץ לא תקין: " + x.Message);
    }
  }

  // ---------- חלון 2 ----------
  static string RunCmd(string exe, string args) => Enforcer.RunExe(exe, args);

  // שמות רשתות Wi-Fi: גם רשתות שבטווח כרגע וגם רשתות ששמורות במחשב (כדי שאפשר יהיה לבחור אותן לרשימה הלבנה גם אם אינן בטווח כרגע)
  static IEnumerable<(string, string)> WifiSsids()
  {
    var names = new HashSet<string>();
    foreach (
      System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(
        RunCmd("netsh", "wlan show networks"),
        @"SSID\s+\d+\s*:\s*(.+)"
      )
    )
    {
      var n = m.Groups[1].Value.Trim();
      if (n.Length > 0)
        names.Add(n);
    }
    foreach (
      System.Text.RegularExpressions.Match m in System.Text.RegularExpressions.Regex.Matches(
        RunCmd("netsh", "wlan show profiles"),
        @"All User Profile\s*:\s*(.+)"
      )
    )
    {
      var n = m.Groups[1].Value.Trim();
      if (n.Length > 0)
        names.Add(n);
    }
    return names.Select(n => ("רשת Wi-Fi: " + n, "ssid:" + n));
  }

  static List<(string N, string E)> Installed()
  {
    var res = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    foreach (
      var (h, v) in new[]
      {
        (RegistryHive.LocalMachine, RegistryView.Registry64),
        (RegistryHive.LocalMachine, RegistryView.Registry32),
        (RegistryHive.CurrentUser, RegistryView.Default),
      }
    )
    {
      try
      {
        using var b = RegistryKey.OpenBaseKey(h, v);
        using var u = b.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
        if (u == null)
          continue;
        foreach (var n in u.GetSubKeyNames())
        {
          using var k = u.OpenSubKey(n);
          var name = k?.GetValue("DisplayName") as string;
          if (string.IsNullOrWhiteSpace(name))
            continue;
          var ic = (k!.GetValue("DisplayIcon") as string)?.Split(',')[0].Trim('"');
          string? exe = null;
          if (ic != null && ic.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && File.Exists(ic))
            exe = ic;
          else
          {
            var loc = (k.GetValue("InstallLocation") as string)?.Trim('"');
            if (loc != null && Directory.Exists(loc))
              exe = Directory
                .EnumerateFiles(loc, "*.exe")
                .Where(f => !System.IO.Path.GetFileName(f).StartsWith("unins", StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(f => new FileInfo(f).Length)
                .FirstOrDefault();
          }
          if (exe != null)
            res.TryAdd(exe, name);
        }
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
    // רשומת התקנה או קיצור שמצביעים על קובץ של Windows (msiexec, rundll32, explorer...) אינם התוכנה עצמה: חסימה שלהם הייתה חוסמת רכיב מערכת.
    // קובצי Windows מוצגים רק מהרשימה המפורשת שלמטה
    var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd('\\') + "\\";
    foreach (var k in res.Keys.Where(x => x.StartsWith(win, StringComparison.OrdinalIgnoreCase)).ToList())
      res.Remove(k);
    var known = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    var sys = Environment.SystemDirectory;
    foreach (
      var (n, f) in new[]
      {
        ("שורת פקודה (cmd)", "cmd.exe"),
        ("PowerShell", @"WindowsPowerShell\v1.0\powershell.exe"),
        ("עורך הרישום (regedit)", @"..\regedit.exe"),
        ("מנהל המשימות", "taskmgr.exe"),
        ("לוח הבקרה", "control.exe"),
        ("פנקס רשימות", @"..\notepad.exe"),
        ("צייר (Paint)", @"..\System32\mspaint.exe"),
        ("מחשבון", "calc.exe"),
        ("Microsoft Management Console", "mmc.exe"),
      }
    )
    {
      var p = System.IO.Path.GetFullPath(System.IO.Path.Combine(sys, f));
      if (File.Exists(p))
      {
        res.TryAdd(p, n);
        known.Add(p);
      }
    }
    var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
    foreach (
      var (n, f) in new[]
      {
        ("Word", "WINWORD.EXE"),
        ("Excel", "EXCEL.EXE"),
        ("PowerPoint", "POWERPNT.EXE"),
        ("Outlook", "OUTLOOK.EXE"),
        ("Access", "MSACCESS.EXE"),
      }
    )
    {
      var p = System.IO.Path.Combine(pf, @"Microsoft Office\root\Office16", f);
      if (File.Exists(p))
        res.TryAdd(p, "Microsoft " + n);
    }
    try
    { // תפריט התחל: תופס גם תוכנות שהזיהוי לפי רשימת ההתקנות מפספס
      dynamic sh = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell")!)!;
      foreach (
        var dir in new[]
        {
          Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu),
          Environment.GetFolderPath(Environment.SpecialFolder.StartMenu),
        }
      )
      {
        if (!Directory.Exists(dir))
          continue;
        foreach (var lnk in Directory.EnumerateFiles(dir, "*.lnk", SearchOption.AllDirectories))
        {
          string? target = null;
          try
          {
            dynamic l = sh.CreateShortcut(lnk);
            target = (string)l.TargetPath;
          }
          catch (Exception __e)
          {
            Diag.Log(__e);
          }
          if (string.IsNullOrEmpty(target) || !target.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || !File.Exists(target))
            continue;
          res.TryAdd(target, System.IO.Path.GetFileNameWithoutExtension(lnk));
        }
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    return res.Where(x =>
        !x.Key.EndsWith("DeviceGuard.exe", StringComparison.OrdinalIgnoreCase)
        && !x.Key.EndsWith("DeviceGuardWatch.exe", StringComparison.OrdinalIgnoreCase)
        && !Enforcer.IsCritical(x.Key)
        && (known.Contains(x.Key) || !x.Key.StartsWith(win, StringComparison.OrdinalIgnoreCase))
      )
      .Select(x => (x.Value, x.Key))
      .OrderBy(x => x.Value)
      .ToList();
  }

  UIElement P2()
  {
    var list = new StackPanel();
    var loading = new TextBlock { Text = "טוען רשימת תוכנות…", Foreground = Brushes.Gray };
    list.Children.Add(loading);
    var note = new TextBlock
    {
      Text = "התוכנה סורקת תוכנות מותקנות ותפריט התחל. יישום שחסר מהרשימה אפשר לחסום ישירות דרך תיקיית הקבצים שלו בחלון 5.",
      Foreground = Brushes.Gray,
      TextWrapping = TextWrapping.Wrap,
      Margin = new Thickness(0, 10, 0, 0),
    };
    _ = FillProgs(list, loading);
    return Page("תוכנות מותקנות", "\uE71D", list, note);
  }

  async Task FillProgs(StackPanel list, TextBlock loading)
  { // הסריקה רצה ברקע, והשורות נבנות במנות קטנות: החלון לא נתקע
    try
    {
      var items = await Task.Factory.StartNew(() => Installed(), CancellationToken.None, TaskCreationOptions.None, Enforcer.Sta);
      inst = items;
      list.Children.Remove(loading);
      int i = 0;
      foreach (var (n, e) in items)
      {
        list.Children.Add(ProgRow(n, e));
        if (++i % 15 == 0)
          await Dispatcher.Yield(DispatcherPriority.Background);
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  // ---------- חלון 3 ----------
  UIElement P3()
  {
    Func<IEnumerable<(string, string)>> opts = () =>
    {
      var l = new List<string>(C.Portable.White);
      foreach (var p in Process.GetProcesses())
      {
        try
        {
          var f = p.MainModule?.FileName;
          if (
            f != null
            && !f.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase)
            && !f.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), StringComparison.OrdinalIgnoreCase)
            && !f.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), StringComparison.OrdinalIgnoreCase)
            && !l.Contains(f)
          )
            l.Add(f);
        }
        catch (Exception __e)
        {
          Diag.Log(__e);
        }
        finally
        {
          p.Dispose();
        }
      }
      return l.Select(f => (System.IO.Path.GetFileName(f) + "  —  " + f, f));
    };
    var drop = new Border
    {
      BorderBrush = new SolidColorBrush(Color.FromRgb(203, 213, 225)),
      BorderThickness = new Thickness(1),
      CornerRadius = new CornerRadius(14),
      Height = 90,
      Margin = new Thickness(0, 12, 0, 0),
      AllowDrop = true,
      Background = new SolidColorBrush(Color.FromRgb(252, 253, 254)),
      Child = new TextBlock
      {
        Text = "גרור לכאן תוכנה ניידת כדי להוסיפה לרשימה הלבנה",
        HorizontalAlignment = HorizontalAlignment.Center,
        VerticalAlignment = VerticalAlignment.Center,
      },
    };
    drop.Drop += (s, e) =>
    {
      if (e.Data.GetData(DataFormats.FileDrop) is string[] fs)
      {
        foreach (var f in fs)
          if (!C.Portable.White.Contains(f))
            C.Portable.White.Add(f);
        C.Save();
        Say($"נוספו {fs.Length} פריטים");
      }
    };
    var warn = new TextBlock
    {
      Text =
        "חסימת ניידות חוסמת הרצה מכל מקום מחוץ ל-Windows ו-Program Files (כולל אפליקציות שמותקנות בתיקיית המשתמש). חסימה זו היא גמורה בלבד.",
      TextWrapping = TextWrapping.Wrap,
      Foreground = Brushes.Gray,
      Margin = new Thickness(0, 8, 0, 0),
    };
    Theme.Tipped(drop, "גרור לכאן תוכנה ניידת והיא תתווסף לרשימה הלבנה ותורשה לפעול.");
    return Page("תוכנות ניידות", "\uE8A7", Row(C.Portable, opts, false, null, "\uE8A7"), drop, warn);
  }

  // ---------- חלון 4 ----------
  UIElement P4()
  {
    var ext = new TextBox { Width = 120, Margin = new Thickness(0, 0, 8, 0) };
    var list = new StackPanel();
    void Fill()
    {
      list.Children.Clear();
      foreach (var r in C.Exts.ToList())
      {
        var rr = r;
        list.Children.Add(
          Row(
            rr,
            null,
            true,
            () =>
            {
              C.Exts.Remove(rr);
              C.Save();
              Fill();
            }
          )
        );
      }
    }
    var add = Btn(
      "הוסף סיומת",
      () =>
      {
        var x = ext.Text.Trim().TrimStart('.').ToLowerInvariant();
        if (x.Length == 0)
          return;
        if (Config.Danger.Contains(x))
        {
          Say("סיומת זו חיונית לפעולת המחשב ולא ניתן לחסום אותה");
          return;
        }
        C.Exts.Add(new Rule { Name = "חסימת ." + x, Path = x });
        C.Save();
        ext.Clear();
        Fill();
      }
    );
    Fill();
    var tip = new TextBlock
    {
      Text =
        "סרטים: "
        + string.Join(", ", Config.Vid.Take(12))
        + "…  |  שירים: "
        + string.Join(", ", Config.Aud)
        + "  |  תמונות: "
        + string.Join(", ", Config.Img),
      Foreground = Brushes.Gray,
      TextWrapping = TextWrapping.Wrap,
      Margin = new Thickness(0, 8, 0, 8),
    };
    return Page(
      "סוגי קבצים",
      "\uE8A5",
      Row(C.Movies, null, true, null, "\uE714"),
      Row(C.Songs, null, true, null, "\uE8D6"),
      Row(C.Images, null, true, null, "\uE91B"),
      tip,
      new TextBlock { Text = "סיומות נוספות:" },
      new StackPanel { Orientation = Orientation.Horizontal, Children = { ext, add } },
      list,
      Exclusions()
    );
  }

  // ---------- חלון 5 ----------
  UIElement P5()
  {
    var list = new StackPanel();
    void Fill()
    {
      list.Children.Clear();
      foreach (var r in C.Paths.ToList())
      {
        var rr = r;
        list.Children.Add(
          Row(
            rr,
            null,
            true,
            () =>
            {
              C.Paths.Remove(rr);
              C.Save();
              Fill();
            },
            null,
            true
          )
        );
      }
    }
    void AddP(string p)
    {
      if (Enforcer.IsDangerous(p))
      {
        Say(
          "זהו נתיב מערכת (כונן, תיקיית משתמשים, קובץ מערכת, או תיקייה שיש בה שירות / מנהל התקן של Windows), וחסימתו עלולה לפגוע במחשב. בחר תיקייה או קובץ ספציפיים.\n\nכדי לחסום תוכנה – השתמש בחלון 'תוכנות מותקנות'."
        );
        return;
      }
      if (C.Paths.Any(x => x.Path.Equals(p, StringComparison.OrdinalIgnoreCase)))
        return;
      C.Paths.Add(new Rule { Name = p, Path = p });
      C.Save();
      Fill();
    }
    var f = Btn(
      "הוסף קובץ…",
      () =>
      {
        var d = new OpenFileDialog { Multiselect = true };
        if (d.ShowDialog() == true)
          foreach (var x in d.FileNames)
            AddP(x);
      }
    );
    var g = Btn(
      "הוסף תיקייה…",
      () =>
      {
        var d = new OpenFolderDialog();
        if (d.ShowDialog() == true)
          AddP(d.FolderName);
      }
    );
    Fill();
    return Page("קבצים ותיקיות", "\uE8B7", new StackPanel { Orientation = Orientation.Horizontal, Children = { f, g } }, list);
  }

  // ---------- חלון 6 ----------
  UIElement P6()
  {
    var net = () =>
    {
      var items = System
        .Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
        .Where(n => n.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
        .Select(n => (n.Name, n.Name))
        .ToList();
      items.AddRange(WifiSsids());
      return items.AsEnumerable();
    };
    var note = new TextBlock
    {
      Text =
        "הערה: רשימה לבנה של מתאמי רשת ורשתות Wi-Fi פועלת בחסימה גמורה. חסימה לפי תוכנה פועלת דרך חומת האש של Windows, והתוכנה משחזרת את הכללים אוטומטית אם נמחקו.",
      Foreground = Brushes.Gray,
      Margin = new Thickness(0, 8, 0, 0),
      TextWrapping = TextWrapping.Wrap,
    };
    return Page("רשת", "\uE774", Row(C.Net, net, false, null, "\uE774"), NetAppsRow(), note);
  }

  // חסימת חיבור לרשת לפי תוכנה: רשימה שחורה (התוכנות ברשימה לא יתחברו) או רשימה לבנה (רק התוכנות ברשימה יתחברו)
  UIElement NetAppsRow()
  {
    var r = C.NetApps;
    var m12 = new Thickness(0, 4, 12, 4);
    var red = new SolidColorBrush(Color.FromRgb(185, 28, 28));
    var p = new WrapPanel { VerticalAlignment = VerticalAlignment.Center };
    p.Children.Add(Theme.Badge("\uE71B"));
    var on = new CheckBox
    {
      Content = r.Name,
      IsChecked = r.On,
      FontWeight = FontWeights.SemiBold,
      VerticalAlignment = VerticalAlignment.Center,
    };
    on.Click += (s, e) =>
    {
      r.On = on.IsChecked == true;
      C.Save();
    };
    var head = new StackPanel
    {
      Orientation = Orientation.Horizontal,
      MinWidth = 280,
      Margin = m12,
      VerticalAlignment = VerticalAlignment.Center,
    };
    head.Children.Add(on);
    var inf = Theme.Info(
      "חוסם חיבור לרשת של תוכנות מסוימות, דרך חומת האש של Windows. ברשימה שחורה – התוכנות שבחרת לא יתחברו לרשת. ברשימה לבנה – רק התוכנות שבחרת יתחברו לרשת. יש ללחוץ 'החל שינויים' אחרי כל שינוי."
    );
    inf.Margin = new Thickness(8, 0, 0, 0);
    head.Children.Add(inf);
    var hint = new TextBlock
    {
      Foreground = Brushes.Gray,
      TextWrapping = TextWrapping.Wrap,
      Margin = new Thickness(0, 8, 0, 0),
    };
    void H()
    {
      hint.Text = C.NetAppsWhite
        ? "רשימה לבנה: רק התוכנות שברשימה יוכלו להתחבר לרשת, וכל שאר התוכנות ייחסמו. שירותי הרשת הבסיסיים של Windows (DNS ו-DHCP) נשארים פעילים. אם הרשימה ריקה – כל התוכנות ייחסמו."
        : "רשימה שחורה: התוכנות שברשימה לא יוכלו להתחבר לרשת. כל שאר התוכנות מתחברות כרגיל.";
    }
    var seg = Segment(
      new[] { "רשימה שחורה", "רשימה לבנה" },
      C.NetAppsWhite ? 1 : 0,
      i =>
      {
        C.NetAppsWhite = i == 1;
        C.Save();
        H();
      }
    );
    Theme.Tipped((FrameworkElement)seg, "רשימה שחורה – התוכנות שברשימה נחסמות מהרשת.\nרשימה לבנה – רק התוכנות שברשימה מורשות להתחבר לרשת.");
    H();
    var list = new StackPanel { Margin = new Thickness(0, 10, 0, 0) };
    void Fill()
    {
      list.Children.Clear();
      if (r.White.Count == 0)
        list.Children.Add(new TextBlock { Text = "לא נוספו תוכנות לרשימה.", Foreground = Brushes.Gray });
      foreach (var path in r.White.ToList())
      {
        var pp = path;
        var img = new Image
        {
          Source = Icon(pp),
          Width = 22,
          Height = 22,
          Margin = new Thickness(0, 0, 10, 0),
        };
        DockPanel.SetDock(img, Dock.Left);
        var d = new Button
        {
          Content = Theme.Glyph("\uE74D", 14, red),
          Style = Theme.Soft(typeof(Button)),
          Padding = new Thickness(8, 5, 8, 5),
          Margin = new Thickness(10, 0, 0, 0),
        };
        Theme.Tint(d, Color.FromRgb(254, 242, 242), Color.FromRgb(185, 28, 28), Color.FromRgb(245, 198, 198));
        d.Click += (s, e) =>
        {
          r.White.Remove(pp);
          C.Save();
          Fill();
        };
        DockPanel.SetDock(d, Dock.Right);
        Theme.Tipped(d, "מסיר את התוכנה מהרשימה.");
        var tx = new TextBlock
        {
          Text =
            pp.StartsWith("pkg:") ? "אפליקציית Store  —  " + pp[4..]
            : pp.StartsWith("svc:") ? "שירות  —  " + pp[4..]
            : System.IO.Path.GetFileName(pp) + "  —  " + pp,
          VerticalAlignment = VerticalAlignment.Center,
          TextTrimming = TextTrimming.CharacterEllipsis,
          ToolTip = pp,
        };
        var dp = new DockPanel { Margin = new Thickness(0, 3, 0, 3) };
        dp.Children.Add(img);
        dp.Children.Add(d);
        dp.Children.Add(tx);
        list.Children.Add(dp);
      }
    }
    void AddFiles(IEnumerable<string> fs)
    {
      foreach (var f in fs)
        if (f.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) && !r.White.Any(x => x.Equals(f, StringComparison.OrdinalIgnoreCase)))
          r.White.Add(f);
      C.Save();
      Fill();
    }
    var add = Btn(
      "הוסף תוכנה…",
      () =>
      {
        var d = new OpenFileDialog { Multiselect = true, Filter = "תוכנות (*.exe)|*.exe" };
        if (d.ShowDialog() == true)
          AddFiles(d.FileNames);
      }
    );
    bool Kind(string x) => x.StartsWith("pkg:", StringComparison.Ordinal) || x.StartsWith("svc:", StringComparison.Ordinal);
    void PickKind(string prefix, string title, List<(string, string)> opts)
    { // בחירה מתוך סוג אחד של רשומות (אפליקציות Store או שירותים), בלי לגעת בשאר הרשימה
      foreach (var x in r.White.Where(y => y.StartsWith(prefix, StringComparison.Ordinal)))
        if (!opts.Any(o => o.Item2 == x))
          opts.Add((x[prefix.Length..], x));
      var res = Pick(title, opts, r.White);
      if (res == null)
        return;
      r.White = r.White.Where(y => !y.StartsWith(prefix, StringComparison.Ordinal)).Concat(res).ToList();
      C.Save();
      Fill();
    }
    var pick = Btn(
      "בחר מהתוכנות המותקנות…",
      () =>
      {
        inst ??= Installed();
        var opts = r
          .White.Where(x => !Kind(x))
          .Select(x => (System.IO.Path.GetFileName(x) + "  —  " + x, x))
          .Concat(inst.Where(x => !r.White.Contains(x.E, StringComparer.OrdinalIgnoreCase)).Select(x => (x.N + "  —  " + x.E, x.E)))
          .ToList();
        var res = Pick("תוכנות – " + r.Name, opts, r.White);
        if (res != null)
        {
          r.White = res.Concat(r.White.Where(Kind)).ToList();
          C.Save();
          Fill();
        }
      },
      "\uE71D"
    );
    var store = Btn(
      "בחר אפליקציות Store…",
      () =>
      {
        var opts = new List<(string, string)>();
        var outp = RunCmd(
          "powershell.exe",
          "-NoLogo -NoProfile -NonInteractive -EncodedCommand "
            + Convert.ToBase64String(
              System.Text.Encoding.Unicode.GetBytes(
                "Get-AppxPackage | ? { -not $_.IsFramework -and -not $_.IsResourcePackage } | Sort-Object Name | % { $_.Name + '|' + $_.PackageFamilyName }"
              )
            )
        );
        foreach (var ln in outp.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
          var z = ln.Split('|');
          if (z.Length == 2)
            opts.Add((z[0], "pkg:" + z[1]));
        }
        PickKind("pkg:", "אפליקציות Store – " + r.Name, opts);
      },
      "\uE719"
    );
    var svc = Btn(
      "בחר שירותים…",
      () =>
      {
        var opts = new List<(string, string)>();
        try
        {
          foreach (var sv in System.ServiceProcess.ServiceController.GetServices().OrderBy(z => z.DisplayName).ToList())
          {
            opts.Add((sv.DisplayName + "  —  " + sv.ServiceName, "svc:" + sv.ServiceName));
            sv.Dispose();
          }
        }
        catch (Exception __e)
        {
          Diag.Log(__e);
        }
        PickKind("svc:", "שירותים – " + r.Name, opts);
      },
      "\uE713"
    );
    Theme.Tipped(add, "מוסיף קובצי הרצה (exe) לרשימה.");
    Theme.Tipped(pick, "בחירת תוכנות מתוך התוכנות המותקנות במחשב.");
    Theme.Tipped(store, "בחירת אפליקציות שהותקנו מ-Microsoft Store (הן אינן נשלטות לפי נתיב קובץ).");
    Theme.Tipped(svc, "בחירת שירותי Windows (למשל עדכוני Windows), גם אם הם רצים דרך svchost.");
    var drop = new Border
    {
      BorderBrush = new SolidColorBrush(Color.FromRgb(203, 213, 225)),
      BorderThickness = new Thickness(1),
      CornerRadius = new CornerRadius(14),
      Height = 60,
      Margin = new Thickness(0, 10, 0, 0),
      AllowDrop = true,
      Background = new SolidColorBrush(Color.FromRgb(252, 253, 254)),
      Child = new TextBlock
      {
        Text = "גרור לכאן תוכנות (exe) כדי להוסיף אותן לרשימה",
        HorizontalAlignment = HorizontalAlignment.Center,
        VerticalAlignment = VerticalAlignment.Center,
      },
    };
    drop.Drop += (s, e) =>
    {
      if (e.Data.GetData(DataFormats.FileDrop) is string[] fs)
        AddFiles(fs);
    };
    Fill();
    p.Children.Add(head);
    p.Children.Add(seg);
    p.Children.Add(add);
    p.Children.Add(pick);
    p.Children.Add(store);
    p.Children.Add(svc);
    var body = new StackPanel();
    body.Children.Add(p);
    body.Children.Add(hint);
    body.Children.Add(drop);
    body.Children.Add(list);
    return new Border
    {
      Child = body,
      Background = Brushes.White,
      CornerRadius = new CornerRadius(14),
      Padding = new Thickness(16, 12, 16, 12),
      Margin = new Thickness(0, 0, 0, 12),
      BorderBrush = new SolidColorBrush(Color.FromRgb(230, 235, 242)),
      BorderThickness = new Thickness(1),
      Effect = new System.Windows.Media.Effects.DropShadowEffect
      {
        BlurRadius = 16,
        ShadowDepth = 2,
        Opacity = 0.05,
        Color = Color.FromRgb(30, 41, 59),
      },
    };
  }

  // ---------- חלון 7: הגנה מתקדמת ----------
  UIElement P7()
  {
    var sp = new StackPanel();
    var on = new CheckBox
    {
      Content = C.Adv.Name,
      IsChecked = C.Adv.On,
      FontWeight = FontWeights.SemiBold,
      Margin = new Thickness(0, 0, 0, 6),
    };
    on.Click += (s, e) =>
    {
      C.Adv.On = on.IsChecked == true;
      C.Save();
    };
    sp.Children.Add(on);
    void Opt(string text, string tip, Func<bool> get, Action<bool> set)
    {
      var cb = new CheckBox
      {
        Content = text,
        IsChecked = get(),
        Margin = new Thickness(18, 4, 0, 4),
      };
      cb.Click += (s, e) =>
      {
        set(cb.IsChecked == true);
        C.Save();
      };
      Theme.Tipped(cb, tip);
      sp.Children.Add(cb);
    }
    Opt(
      "חסימת bcdedit / msconfig / reagentc",
      "מונע שינוי הגדרות אתחול, כניסה למצב בטוח וביטול שחזור – עקיפות נפוצות.",
      () => C.AdvOpts.BlockBoot,
      v => C.AdvOpts.BlockBoot = v
    );
    Opt(
      "חסימת WSL ומכונות וירטואליות (Sandbox)",
      "מונע הפעלת סביבות שמאפשרות לעקוף את החסימות.",
      () => C.AdvOpts.NoVirt,
      v => C.AdvOpts.NoVirt = v
    );
    Opt(
      "חסימת מנהל המשימות",
      "מונע סגירת תהליכים ידנית. אפשר לבטל בהסרת הסימון והחלה.",
      () => C.AdvOpts.NoTaskMgr,
      v => C.AdvOpts.NoTaskMgr = v
    );
    Opt("חסימת עורך הרישום (regedit)", "מונע עריכת הרישום דרך regedit.", () => C.AdvOpts.NoRegedit, v => C.AdvOpts.NoRegedit = v);
    Opt(
      "חסימת Microsoft Store",
      "מונע התקנת אפליקציות מהחנות. פועל ב-Pro/Enterprise/Education.",
      () => C.AdvOpts.NoStore,
      v => C.AdvOpts.NoStore = v
    );
    Opt("חסימת winget (App Installer)", "מונע התקנת תוכנות דרך winget.", () => C.AdvOpts.NoWinget, v => C.AdvOpts.NoWinget = v);
    Opt(
      "דפדפנים: כיבוי DNS מוצפן וגלישה פרטית",
      "Chrome / Edge / Firefox: מבטל DoH וגלישה בסתר, שעוקפים סינון רשת.",
      () => C.AdvOpts.Browsers,
      v => C.AdvOpts.Browsers = v
    );
    Opt(
      "חסימת הגדרת Proxy / VPN בדפדפנים ובמערכת",
      "מונע עקיפת סינון דרך שרת Proxy. עלול להפריע אם המחשב משתמש ב-Proxy ארגוני.",
      () => C.AdvOpts.NoProxy,
      v => C.AdvOpts.NoProxy = v
    );
    Opt(
      "חסימת שיתוף אינטרנט (נקודה חמה)",
      "מסתיר את ממשק השיתוף של חיבור האינטרנט.",
      () => C.AdvOpts.NoTether,
      v => C.AdvOpts.NoTether = v
    );
    Opt(
      "חסימת שינוי הגדרות TCP/IP מתקדמות (DNS)",
      "מונע שינוי DNS והגדרות רשת מתקדמות בממשק.",
      () => C.AdvOpts.NoTcpip,
      v => C.AdvOpts.NoTcpip = v
    );
    Opt("נעילת קובץ hosts", "מונע עריכת קובץ hosts (עקיפת סינון בדרך זו).", () => C.AdvOpts.LockHosts, v => C.AdvOpts.LockHosts = v);
    // הקשחה חזקה: כבויה כברירת מחדל, ומבקשת אישור עם הסבר לפני ההפעלה
    var strong = new CheckBox
    {
      Content = "הקשחה חזקה נגד מנהל (מתקדם)",
      IsChecked = C.AdvOpts.StrongAdmin,
      Margin = new Thickness(18, 4, 0, 4),
    };
    strong.Click += (s, e) =>
    {
      if (
        strong.IsChecked == true
        && !Say(
          "בזמן החסימה, חשבונות מנהל יאבדו את הזכויות: גיבוי ושחזור קבצים, לקיחת בעלות ודיבאג.\n"
            + "כך מנהל לא יוכל להעתיק קבצים חסומים (למשל robocopy /B), לקחת בעלות על הגדרות ההגנה או לסגור את השירות ממנהל המשימות.\n\n"
            + "שימו לב:\n• השינוי נכנס לתוקף רק אחרי יציאה וכניסה מחדש למשתמש.\n"
            + "• בזמן החסימה כלי גיבוי שרצים כמנהל (robocopy /B, wbadmin), דיבאגרים ולקיחת בעלות לא יעבדו.\n"
            + "• אם שירות ההגנה מפסיק לעבוד בזמן החסימה, ייתכן שלא אפשר יהיה לשמור את ביטול החסימות מהחלון עד שהשירות יחזור.\n"
            + "• הזכויות חוזרות אוטומטית בביטול החסימה, בסוף חלון הזמנים ובהסרת התוכנה. אפשר גם להחזיר ידנית ב-secpol.msc (מדיניות מקומית › הקצאת זכויות משתמש).\n\n"
            + "להפעיל?",
          "הקשחה חזקה",
          yesNo: true
        )
      )
      {
        strong.IsChecked = false;
        return;
      }
      C.AdvOpts.StrongAdmin = strong.IsChecked == true;
      C.Save();
    };
    Theme.Tipped(strong, "בזמן החסימה מנהלים מאבדים את זכויות הגיבוי/שחזור, לקיחת בעלות ודיבאג. נכנס לתוקף בכניסה הבאה למשתמש.");
    sp.Children.Add(strong);
    var sb = new CheckBox
    {
      Content = "השירות פועל גם ב-Safe Mode (מומלץ)",
      IsChecked = C.AdvOpts.SafeBoot,
      Margin = new Thickness(0, 12, 0, 4),
      FontWeight = FontWeights.SemiBold,
    };
    sb.Click += (s, e) =>
    {
      C.AdvOpts.SafeBoot = sb.IsChecked == true;
      C.Save();
    };
    Theme.Tipped(sb, "ללא זה אפשר לעקוף את ההגנה באתחול במצב בטוח.");
    sp.Children.Add(sb);
    sp.Children.Add(
      new TextBlock
      {
        Text =
          "הערה: כל ההגדרות כאן חלות אחרי 'החל שינויים'. עקיפה מלאה אפשרית רק למי שיש לו הרשאות מנהל – מומלץ שהמשתמש היומיומי יהיה לא-מנהל.",
        Foreground = Brushes.Gray,
        TextWrapping = TextWrapping.Wrap,
        Margin = new Thickness(0, 8, 0, 0),
      }
    );
    var alert = new StackPanel();
    alert.Children.Add(
      new TextBlock
      {
        Text = "התראה על ניסיונות עקיפה (כתובת Webhook, למשל ntfy.sh/הנושא-שלך):",
        FontWeight = FontWeights.SemiBold,
        Margin = new Thickness(0, 0, 0, 6),
      }
    );
    var url = new TextBox
    {
      Text = C.AlertUrl ?? "",
      Width = 420,
      HorizontalAlignment = HorizontalAlignment.Left,
      FlowDirection = FlowDirection.LeftToRight,
    };
    url.LostFocus += (s, e) =>
    {
      var v = url.Text.Trim();
      C.AlertUrl = v.Length == 0 ? null : v;
      C.Save();
    };
    alert.Children.Add(url);
    var log = Btn("הצג יומן אירועים", ShowLog);
    log.Margin = new Thickness(0, 8, 0, 0);
    log.HorizontalAlignment = HorizontalAlignment.Left;
    alert.Children.Add(log);
    return Page("הגנה מתקדמת", "\uE72E", Card(sp), Card(alert));
  }
}
