using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace DG;

// הקשחה נגד עקיפה בחשבון מנהל (גם בלי סיסמה). אף אחד מהמנגנונים כאן לא חוסם את המחשב: הדרך הרגילה לביטול (קוד הכניסה) תמיד פתוחה,
// ושום דבר לא נוגע בסביבת השחזור של Windows (WinRE) – כך שגם במקרה תקלה יש דרך חזרה.

// ---------- שעה אמינה ----------
// שינוי השעה של המחשב (מותר למנהל) עקף את התזמון ואת הפתיחה הזמנית. השירות מחזיק "שעה אמינה":
// מונה שלא מושפע משינוי שעון (כולל זמן שינה), שמסונכרן לשעה שמגיעה מאתרי אינטרנט כשיש חיבור. שינוי ידני של השעון מזוהה ולא משפיע.
// מחוץ לשירות (החלון, השער) – שעון המערכת הרגיל.
public static class Clock
{
  static Func<DateTime> src = () => DateTime.UtcNow;

  public static DateTime UtcNow() => src();

  static long offset; // שעה אמינה (ticks) = TickNow + offset
  static long lastFollow,
    lastPersist,
    lastNet = long.MinValue / 2,
    lastNetTry = long.MinValue / 2,
    lastJumpAlert = long.MinValue / 2;
  static int netBusy;
  static volatile bool on;

  static long TickNow => Environment.TickCount64 * TimeSpan.TicksPerMillisecond;
  static string StateFile => Path.Combine(Config.Dir, "var", "clock.txt");
  static readonly long Min = TimeSpan.TicksPerMinute;

  static DateTime Trusted() =>
    new(Math.Clamp(TickNow + Interlocked.Read(ref offset), DateTime.MinValue.Ticks, DateTime.MaxValue.Ticks), DateTimeKind.Utc);

  public static void StartTrusted()
  {
    long saved = 0;
    try
    {
      if (File.Exists(StateFile))
        long.TryParse(File.ReadAllText(StateFile).Trim(), out saved);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    var now = DateTime.UtcNow.Ticks;
    // אחרי הפעלה מחדש: השעה לא חוזרת אחורה מעבר למה שנשמר לפני הכיבוי (החזרת השעון אחורה בזמן שהמחשב כבוי)
    Interlocked.Exchange(ref offset, Math.Max(now, saved) - TickNow);
    src = Trusted;
    on = true;
    if (saved > now + 2 * Min)
      Alerts.Log("שעון המחשב קודם לשעה שנשמרה לפני הכיבוי – התזמון ממשיך לפי השעה האמינה", false);
    lastNetTry = TickNow;
    _ = Task.Run(NetSync);
  }

  // נקרא מהלולאה הראשית של השירות (כל שנייה בערך)
  public static void Tick()
  {
    if (!on)
      return;
    var tn = TickNow;
    var diff = DateTime.UtcNow.Ticks - (tn + Interlocked.Read(ref offset));
    if (Math.Abs(diff) <= 2 * Min)
    {
      // תיקונים קטנים (סנכרון השעון של Windows): עוקבים לאט – עד 2 שניות בדקה, כדי שאי אפשר יהיה "לגרור" את השעה בצעדים קטנים
      if (tn - lastFollow >= Min)
      {
        lastFollow = tn;
        Interlocked.Add(ref offset, Math.Clamp(diff, -2 * TimeSpan.TicksPerSecond, 2 * TimeSpan.TicksPerSecond));
      }
    }
    else
    {
      if (tn - lastJumpAlert >= 10 * Min)
      {
        lastJumpAlert = tn;
        Alerts.Log("שעון המחשב שונה – התזמון והפתיחה הזמנית ממשיכים לפי השעה האמינה", false);
      }
      if (tn - lastNetTry >= 5 * Min)
      { // אולי זה תיקון אמיתי (למשל סנכרון אחרי הפעלה): בודקים מול האינטרנט
        lastNetTry = tn;
        _ = Task.Run(NetSync);
      }
    }
    if (tn - lastNet >= 180 * Min && tn - lastNetTry >= 5 * Min)
    {
      lastNetTry = tn;
      _ = Task.Run(NetSync);
    }
    if (tn - lastPersist >= Min)
    {
      lastPersist = tn;
      try
      {
        Directory.CreateDirectory(Path.GetDirectoryName(StateFile)!);
        File.WriteAllText(StateFile, Trusted().Ticks.ToString());
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
      }
    }
  }

  // יציאה ממצב שינה / שינה עמוקה: אם המונה לא כלל את זמן השינה – מסתנכרנים מול האינטרנט, ואם אין חיבור – מקבלים את שעון המערכת
  // (עדיף טעות לטובת השעה האמיתית מאשר תזמון שזז לצמיתות)
  public static void OnResume()
  {
    if (!on)
      return;
    _ = Task.Run(async () =>
    {
      if (!await NetSyncCore())
      {
        var diff = DateTime.UtcNow.Ticks - Trusted().Ticks;
        if (diff > 2 * Min)
          Interlocked.Add(ref offset, diff); // רק קדימה: אחרי שינה הזמן התקדם
      }
    });
  }

  static async Task NetSync() => await NetSyncCore();

  static async Task<bool> NetSyncCore()
  {
    if (Interlocked.Exchange(ref netBusy, 1) == 1)
      return false;
    try
    {
      foreach (var u in new[] { "https://www.google.com/", "https://www.microsoft.com/", "https://www.cloudflare.com/" })
      {
        try
        {
          using var h = new HttpClient { Timeout = TimeSpan.FromSeconds(8) };
          var t0 = TickNow;
          using var r = await h.SendAsync(new HttpRequestMessage(HttpMethod.Head, u));
          var t1 = TickNow;
          if (r.Headers.Date is DateTimeOffset d)
          {
            var real = d.UtcDateTime.Ticks + (t1 - t0) / 2;
            Interlocked.Exchange(ref offset, real - t1);
            lastNet = t1;
            return true;
          }
        }
        catch (Exception __e)
        {
          Diag.Log(__e);
        }
      }
      return false;
    }
    finally
    {
      Interlocked.Exchange(ref netBusy, 0);
    }
  }
}

// ---------- מעקב מיידי אחרי שינויים ברישום ----------
// כשמישהו מוחק חסימה ברישום (IFEO, מדיניות, הגדרות השירות, Safe Mode, חומת האש) – השירות מתעורר מיד ומשחזר,
// במקום לחכות לבדיקה התקופתית (שהשאירה חלון של כמה שניות להפעיל תוכנה חסומה)
static class RegWatch
{
  [DllImport("advapi32.dll")]
  static extern int RegNotifyChangeKeyValue(SafeRegistryHandle key, bool subtree, uint filter, SafeWaitHandle ev, bool async);

  public static volatile bool Dirty;
  public static readonly AutoResetEvent Wake = new(false);

  const string IFEO = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
  static readonly (RegistryView V, string P)[] Keys =
  {
    (RegistryView.Registry64, IFEO),
    (RegistryView.Registry32, IFEO),
    (RegistryView.Registry64, @"SOFTWARE\Policies"),
    (RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies"),
    (RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL"),
    (RegistryView.Registry64, @"SYSTEM\CurrentControlSet\Services\DeviceGuard"),
    (RegistryView.Registry64, @"SYSTEM\CurrentControlSet\Control\SafeBoot"),
    (RegistryView.Registry64, @"SYSTEM\CurrentControlSet\Services\USBSTOR"),
    (RegistryView.Registry64, @"SYSTEM\CurrentControlSet\Services\UASPStor"),
    (RegistryView.Registry64, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"),
  };

  public static void Start() => new Thread(Loop) { IsBackground = true }.Start();

  const uint Filter = 0x1 | 0x2 | 0x4 | 0x8; // שם, מאפיינים, ערך, הרשאות

  static void Loop()
  {
    while (true)
    {
      var keys = new List<RegistryKey>();
      var evs = new List<AutoResetEvent>();
      try
      {
        foreach (var (v, p) in Keys)
        {
          try
          {
            using var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, v);
            var k = b.OpenSubKey(p, false);
            if (k == null)
              continue;
            var e = new AutoResetEvent(false);
            if (RegNotifyChangeKeyValue(k.Handle, true, Filter, e.SafeWaitHandle, true) != 0)
            {
              k.Dispose();
              e.Dispose();
              continue;
            }
            keys.Add(k);
            evs.Add(e);
          }
          catch (Exception __e)
          {
            Diag.Log(__e);
          }
        }
        if (evs.Count == 0)
        {
          Thread.Sleep(30000);
          continue;
        }
        var arr = evs.ToArray();
        // פותחים מחדש כל 10 דקות: מפתח שנוצר בינתיים (או נמחק ונוצר מחדש) נכנס למעקב
        var until = DateTime.UtcNow.AddMinutes(10);
        while (DateTime.UtcNow < until)
        {
          int i = WaitHandle.WaitAny(arr, 30000);
          if (i == WaitHandle.WaitTimeout)
            continue;
          Dirty = true;
          Wake.Set();
          if (RegNotifyChangeKeyValue(keys[i].Handle, true, Filter, evs[i].SafeWaitHandle, true) != 0)
            break; // המפתח נמחק: פותחים הכול מחדש
          Thread.Sleep(50); // רצף שינויים נאסף לסבב אחד
        }
      }
      catch (Exception __e)
      {
        Diag.Log(__e);
        Thread.Sleep(5000);
      }
      finally
      {
        foreach (var k in keys)
          k.Dispose();
        foreach (var e in evs)
          e.Dispose();
      }
    }
  }
}

// ---------- הגנה על הגדרות השירות ברישום ----------
// מנהל יכול היה לשנות ישירות ברישום את סוג ההפעלה של השירות ("מושבת") ולהפעיל מחדש – והשירות לא היה עולה. עכשיו:
// המפתח של השירות נעול (רק SYSTEM כותב, מנהלים קוראים), והשירות משחזר מיד ערכים והרשאות ששונו
static class SvcGuard
{
  const string Key = @"SYSTEM\CurrentControlSet\Services\DeviceGuard";
  static readonly string[] Names =
  {
    "Start",
    "Type",
    "ErrorControl",
    "ImagePath",
    "ObjectName",
    "FailureActions",
    "FailureActionsOnNonCrashFailures",
    "Environment",
  };
  static Dictionary<string, (object V, RegistryValueKind K)>? snap;
  static string? refSddl;
  const AccessControlSections Sec = AccessControlSections.Access | AccessControlSections.Owner;

  static RegistryKey? Open() =>
    Registry.LocalMachine.OpenSubKey(Key, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.FullControl);

  static RegistrySecurity Wanted()
  {
    var s = new RegistrySecurity();
    s.SetAccessRuleProtection(true, false);
    var sys = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
    s.AddAccessRule(
      new RegistryAccessRule(sys, RegistryRights.FullControl, InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow)
    );
    foreach (var r in new[] { WellKnownSidType.BuiltinAdministratorsSid, WellKnownSidType.BuiltinUsersSid })
      s.AddAccessRule(
        new RegistryAccessRule(
          new SecurityIdentifier(r, null),
          RegistryRights.ReadKey,
          InheritanceFlags.ContainerInherit,
          PropagationFlags.None,
          AccessControlType.Allow
        )
      );
    s.SetOwner(sys);
    return s;
  }

  public static void Init()
  {
    try
    {
      using var k = Open();
      if (k == null)
        return;
      var d = new Dictionary<string, (object, RegistryValueKind)>();
      foreach (var n in Names)
      {
        var v = k.GetValue(n, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        if (v != null)
          d[n] = (v, k.GetValueKind(n));
      }
      d["Start"] = (2, RegistryValueKind.DWord); // השירות רץ עכשיו, ולכן הוא אמור להיות "אוטומטי" (גם אם מישהו שינה לפני ההפעלה)
      snap = d;
      k.SetAccessControl(Wanted());
      refSddl = k.GetAccessControl(Sec).GetSecurityDescriptorSddlForm(Sec);
      if (k.GetValue("DeleteFlag") != null)
        k.DeleteValue("DeleteFlag", false);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  static bool Same(object? have, object want) =>
    have switch
    {
      null => false,
      byte[] hb => want is byte[] wb && hb.AsSpan().SequenceEqual(wb),
      string[] hs => want is string[] ws && hs.SequenceEqual(ws),
      _ => Equals(have, want),
    };

  // removing = השירות מוסר/מתעדכן מבקשת התוכנה עצמה: לא משחזרים
  public static bool Heal(bool removing)
  {
    if (removing || snap == null)
      return false;
    try
    {
      using var k = Open();
      if (k == null)
        return false;
      bool changed = false;
      if (refSddl != null && k.GetAccessControl(Sec).GetSecurityDescriptorSddlForm(Sec) != refSddl)
      {
        k.SetAccessControl(Wanted());
        changed = true;
      }
      foreach (var (n, (v, kind)) in snap)
        if (!Same(k.GetValue(n, null, RegistryValueOptions.DoNotExpandEnvironmentNames), v))
        {
          k.SetValue(n, v, kind);
          changed = true;
        }
      if (k.GetValue("DeleteFlag") != null)
      {
        k.DeleteValue("DeleteFlag", false);
        changed = true;
      }
      if (changed)
        Alerts.Log("זוהה שינוי בהגדרות שירות ההגנה ברישום – שוחזר");
      return changed;
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
      return false;
    }
  }
}

// ---------- הגנה על תהליך השירות ----------
// מונע מ-taskkill / Stop-Process / תוכנות אחרות של מנהל לסגור או להשהות את השירות (מנהל שמפעיל הרשאת דיבאג – למשל מנהל המשימות – עדיין יכול;
// במקרה כזה השירות עולה מחדש אוטומטית תוך שנייה). קריאת מידע על התהליך נשארת מותרת לכולם
static class ProcGuard
{
  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint rev, out IntPtr sd, IntPtr size);

  [DllImport("advapi32.dll", SetLastError = true)]
  static extern bool SetKernelObjectSecurity(IntPtr h, uint info, IntPtr sd);

  [DllImport("kernel32.dll")]
  static extern IntPtr GetCurrentProcess();

  [DllImport("kernel32.dll")]
  static extern IntPtr LocalFree(IntPtr h);

  public static void Protect()
  {
    // דחייה למי שמחובר למחשב (INTERACTIVE, כולל מנהל מורם) ולמשימות מתוזמנות (BATCH): סגירה (0x1), יצירת תהליכון (0x2), שינוי זיכרון (0x8, 0x20),
    // השהיה (0x800), שינוי הרשאות/בעלות (0x40000, 0x80000). לא דוחים את קבוצת המנהלים עצמה – גם SYSTEM חבר בה, ומערכת ההפעלה צריכה גישה.
    // SYSTEM: הכול. כולם: SYNCHRONIZE + קריאת מידע מוגבלת (זיהוי התהליך שעונה ב-Pipe)
    const string sddl = "D:P(D;;0xC082B;;;IU)(D;;0xC082B;;;S-1-5-3)(A;;0x1FFFFF;;;SY)(A;;0x101000;;;WD)";
    try
    {
      if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out var sd, IntPtr.Zero))
        return;
      try
      {
        SetKernelObjectSecurity(GetCurrentProcess(), 4, sd); // DACL_SECURITY_INFORMATION
      }
      finally
      {
        LocalFree(sd);
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }
}
