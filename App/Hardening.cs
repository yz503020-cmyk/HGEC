using System.Security.Cryptography;
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
  static readonly long Min = TimeSpan.TicksPerMinute;

  static DateTime Trusted() =>
    new(Math.Clamp(TickNow + Interlocked.Read(ref offset), DateTime.MinValue.Ticks, DateTime.MaxValue.Ticks), DateTimeKind.Utc);

  public static void StartTrusted()
  {
    // נשמר במפתח הרישום המוגן (Trust) – לא בתיקייה שמנהלים יכולים לכתוב אליה
    long saved = Trust.ClockGet();
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
      Trust.ClockSet(Trusted().Ticks);
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
    (RegistryView.Registry64, @"SOFTWARE\DeviceGuard"),
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

// ---------- הגדרות מהימנות ----------
// מנהל יכול לכתוב כל קובץ בעזרת הרשאת הגיבוי/שחזור (למשל robocopy /B), גם את קובץ ההגדרות – ואז לסגור את השירות, שבעלייה היה מקבל אותו.
// עכשיו: עותק של ההגדרות האחרונות שהשירות כתב נשמר במפתח רישום שרק המערכת כותבת אליו, יחד עם מפתח חתימה שנגזר מקוד הכניסה
// (מוצפן כך שרק המערכת יכולה לפענח). קובץ הגדרות שונה מקבל רק אם הוא חתום בקוד הכניסה (החלון חותם כשהשירות לא עובד); אחרת משוחזר העותק.
// גם השעה האמינה נשמרת כאן (ולא בתיקייה שמנהלים יכולים לכתוב אליה)
static class Trust
{
  const string Key = @"SOFTWARE\DeviceGuard\Trust";
  public static string SigPath => Path.Combine(Config.Dir, "config.sig");

  static string? good; // ההגדרות המהימנות האחרונות (בזיכרון)
  static byte[]? kc; // מפתח החתימה (בזיכרון)

  public static string? Good => good;

  [StructLayout(LayoutKind.Sequential)]
  struct Blob
  {
    public int cb;
    public IntPtr pb;
  }

  [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern bool CryptProtectData(ref Blob d, string? desc, IntPtr ent, IntPtr res, IntPtr prompt, int flags, out Blob o);

  [DllImport("crypt32.dll", SetLastError = true)]
  static extern bool CryptUnprotectData(ref Blob d, IntPtr desc, IntPtr ent, IntPtr res, IntPtr prompt, int flags, out Blob o);

  [DllImport("kernel32.dll")]
  static extern IntPtr LocalFree(IntPtr h);

  // DPAPI בחשבון SYSTEM: רק תהליך שרץ כ-SYSTEM יכול לפענח (מנהל רגיל – גם עם הרשאת גיבוי – לא)
  static byte[]? Dp(byte[] data, bool protect)
  {
    var h = GCHandle.Alloc(data, GCHandleType.Pinned);
    try
    {
      var i = new Blob { cb = data.Length, pb = h.AddrOfPinnedObject() };
      Blob o;
      bool ok = protect
        ? CryptProtectData(ref i, "DeviceGuard", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out o)
        : CryptUnprotectData(ref i, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out o);
      if (!ok)
        return null;
      try
      {
        var r = new byte[o.cb];
        Marshal.Copy(o.pb, r, 0, o.cb);
        return r;
      }
      finally
      {
        LocalFree(o.pb);
      }
    }
    catch
    {
      return null;
    }
    finally
    {
      h.Free();
    }
  }

  static RegistrySecurity Wanted()
  {
    var s = new RegistrySecurity();
    s.SetAccessRuleProtection(true, false);
    var sys = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
    s.AddAccessRule(
      new RegistryAccessRule(sys, RegistryRights.FullControl, InheritanceFlags.ContainerInherit, PropagationFlags.None, AccessControlType.Allow)
    );
    s.AddAccessRule(
      new RegistryAccessRule(
        new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
        RegistryRights.ReadKey,
        InheritanceFlags.ContainerInherit,
        PropagationFlags.None,
        AccessControlType.Allow
      )
    );
    s.SetOwner(sys);
    return s;
  }

  static RegistryKey? Open(bool create)
  {
    try
    {
      var k = Registry.LocalMachine.OpenSubKey(Key, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.FullControl);
      if (k == null && create)
        k = Registry.LocalMachine.CreateSubKey(Key, RegistryKeyPermissionCheck.ReadWriteSubTree);
      return k;
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
      return null;
    }
  }

  static string? refSddl;
  const AccessControlSections Sec = AccessControlSections.Access | AccessControlSections.Owner;

  // בהפעלת השירות: טעינה לזיכרון ונעילת המפתח
  public static void Init()
  {
    try
    {
      using var k = Open(true);
      if (k == null)
        return;
      k.SetAccessControl(Wanted());
      refSddl = k.GetAccessControl(Sec).GetSecurityDescriptorSddlForm(Sec);
      if (k.GetValue("Cfg") is byte[] z)
        good = Unzip(z);
      if (k.GetValue("K") is byte[] e)
        kc = Dp(e, false);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  static byte[] Zip(string s)
  {
    using var ms = new MemoryStream();
    using (var g = new System.IO.Compression.GZipStream(ms, System.IO.Compression.CompressionLevel.Optimal))
    {
      var b = System.Text.Encoding.UTF8.GetBytes(s);
      g.Write(b, 0, b.Length);
    }
    return ms.ToArray();
  }

  static string? Unzip(byte[] z)
  {
    try
    {
      using var g = new System.IO.Compression.GZipStream(new MemoryStream(z), System.IO.Compression.CompressionMode.Decompress);
      using var r = new StreamReader(g, System.Text.Encoding.UTF8);
      return r.ReadToEnd();
    }
    catch
    {
      return null;
    }
  }

  // נקרא מהשירות אחרי כל כתיבה של קובץ ההגדרות
  public static void SaveGood(string json)
  {
    good = json;
    try
    {
      var z = Zip(json);
      if (z.Length > 4_000_000)
        return; // גדול מדי לרישום (לא צפוי): מסתפקים בעותק שבזיכרון
      using var k = Open(true);
      k?.SetValue("Cfg", z, RegistryValueKind.Binary);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  // מפתח החתימה נגזר מקוד הכניסה: מי שיודע את הקוד (החלון) יכול לחתום; מי שלא יודע – לא, גם אם הוא מנהל
  public static byte[] Derive(string code, string? appCode) =>
    Rfc2898DeriveBytes.Pbkdf2(
      code,
      SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("DG-cfgsig|" + (appCode ?? ""))),
      100_000,
      HashAlgorithmName.SHA256,
      32
    );

  public static string Sign(byte[] key, string json) => Convert.ToBase64String(HMACSHA256.HashData(key, System.Text.Encoding.UTF8.GetBytes(json)));

  // נקרא מהשירות אחרי אימות קוד כניסה מוצלח (הקוד נבדק מול ההגדרות המהימנות)
  public static void SetCode(string code, string? appCode)
  {
    try
    {
      var k2 = Derive(code, appCode);
      if (kc != null && CryptographicOperations.FixedTimeEquals(kc, k2))
        return;
      var e = Dp(k2, true);
      if (e == null)
        return;
      kc = k2;
      using var k = Open(true);
      k?.SetValue("K", e, RegistryValueKind.Binary);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  // קובץ הגדרות שנכתב על ידי החלון כשהשירות לא עבד, וחתום בקוד הכניסה
  public static bool SigOk(string json)
  {
    try
    {
      if (kc == null || !File.Exists(SigPath))
        return false;
      var have = Convert.FromBase64String(File.ReadAllText(SigPath).Trim());
      return CryptographicOperations.FixedTimeEquals(have, HMACSHA256.HashData(kc, System.Text.Encoding.UTF8.GetBytes(json)));
    }
    catch
    {
      return false;
    }
  }

  // השעה האמינה האחרונה (Clock)
  public static long ClockGet()
  {
    try
    {
      using var k = Open(false);
      return k?.GetValue("Clock") is long v ? v : 0;
    }
    catch
    {
      return 0;
    }
  }

  public static void ClockSet(long ticks)
  {
    try
    {
      using var k = Open(true);
      k?.SetValue("Clock", ticks, RegistryValueKind.QWord);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  // שינוי מבחוץ במפתח (אחרי לקיחת בעלות): הרשאות וערכים חוזרים מהזיכרון
  public static void Heal(bool removing)
  {
    if (removing || refSddl == null)
      return;
    try
    {
      using var k = Open(true);
      if (k == null)
        return;
      bool changed = false;
      if (k.GetAccessControl(Sec).GetSecurityDescriptorSddlForm(Sec) != refSddl)
      {
        k.SetAccessControl(Wanted());
        changed = true;
      }
      if (good != null && !(k.GetValue("Cfg") is byte[] z && Unzip(z) == good))
      {
        var nz = Zip(good);
        if (nz.Length <= 4_000_000)
        {
          k.SetValue("Cfg", nz, RegistryValueKind.Binary);
          changed = true;
        }
      }
      if (kc != null && !(k.GetValue("K") is byte[] e && Dp(e, false) is byte[] d && CryptographicOperations.FixedTimeEquals(d, kc)))
      {
        if (Dp(kc, true) is byte[] ne)
        {
          k.SetValue("K", ne, RegistryValueKind.Binary);
          changed = true;
        }
      }
      if (changed)
        Alerts.Log("זוהה שינוי במפתח ההגדרות המהימנות – שוחזר");
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  // הסרה מלאה של התוכנה
  public static void Remove()
  {
    try
    {
      Registry.LocalMachine.DeleteSubKeyTree(@"SOFTWARE\DeviceGuard", false);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    try
    {
      if (File.Exists(SigPath))
        File.Delete(SigPath);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }
}

// ---------- זכויות משתמש (הקשחה חזקה – אופציונלית) ----------
// גישה ל-LSA: מי מחזיק בזכות (למשל SeBackupPrivilege), הסרה והחזרה. משמש את "הקשחה חזקה" בחלון "הגנה מתקדמת"
static class Lsa
{
  [StructLayout(LayoutKind.Sequential)]
  struct US
  {
    public ushort Length;
    public ushort MaximumLength;
    public IntPtr Buffer;
  }

  [StructLayout(LayoutKind.Sequential)]
  struct OA
  {
    public int Length;
    public IntPtr RootDirectory;
    public IntPtr ObjectName;
    public uint Attributes;
    public IntPtr SecurityDescriptor;
    public IntPtr SecurityQualityOfService;
  }

  [DllImport("advapi32.dll")]
  static extern uint LsaOpenPolicy(IntPtr sys, ref OA oa, uint access, out IntPtr h);

  [DllImport("advapi32.dll")]
  static extern uint LsaClose(IntPtr h);

  [DllImport("advapi32.dll")]
  static extern uint LsaFreeMemory(IntPtr p);

  [DllImport("advapi32.dll")]
  static extern uint LsaEnumerateAccountsWithUserRight(IntPtr h, ref US right, out IntPtr buf, out uint count);

  [DllImport("advapi32.dll")]
  static extern uint LsaAddAccountRights(IntPtr h, byte[] sid, US[] rights, uint count);

  [DllImport("advapi32.dll")]
  static extern uint LsaRemoveAccountRights(IntPtr h, byte[] sid, bool all, US[] rights, uint count);

  static IntPtr Open()
  {
    var oa = new OA { Length = Marshal.SizeOf<OA>() };
    return LsaOpenPolicy(IntPtr.Zero, ref oa, 0x000F0FFF, out var h) == 0 ? h : IntPtr.Zero; // POLICY_ALL_ACCESS (מנהל / SYSTEM)
  }

  static US Str(string s, IntPtr mem) => new() { Length = (ushort)(s.Length * 2), MaximumLength = (ushort)(s.Length * 2 + 2), Buffer = mem };

  static byte[] Sid(string sid)
  {
    var s = new SecurityIdentifier(sid);
    var b = new byte[s.BinaryLength];
    s.GetBinaryForm(b, 0);
    return b;
  }

  // מי מחזיק בזכות (רשימת SID). null = לא ניתן לקרוא
  public static List<string>? Holders(string right)
  {
    var h = Open();
    if (h == IntPtr.Zero)
      return null;
    var mem = Marshal.StringToHGlobalUni(right);
    try
    {
      var us = Str(right, mem);
      var st = LsaEnumerateAccountsWithUserRight(h, ref us, out var buf, out var n);
      if (st == 0x8000001A) // STATUS_NO_MORE_ENTRIES: אף אחד
        return new List<string>();
      if (st != 0)
        return null;
      try
      {
        var res = new List<string>();
        for (int i = 0; i < n; i++)
        {
          var p = Marshal.ReadIntPtr(buf, i * IntPtr.Size);
          res.Add(new SecurityIdentifier(p).Value);
        }
        return res;
      }
      finally
      {
        LsaFreeMemory(buf);
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
      return null;
    }
    finally
    {
      Marshal.FreeHGlobal(mem);
      LsaClose(h);
    }
  }

  public static bool Change(string sid, string right, bool add)
  {
    var h = Open();
    if (h == IntPtr.Zero)
      return false;
    var mem = Marshal.StringToHGlobalUni(right);
    try
    {
      var arr = new[] { Str(right, mem) };
      return (add ? LsaAddAccountRights(h, Sid(sid), arr, 1) : LsaRemoveAccountRights(h, Sid(sid), false, arr, 1)) == 0;
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
      return false;
    }
    finally
    {
      Marshal.FreeHGlobal(mem);
      LsaClose(h);
    }
  }
}
