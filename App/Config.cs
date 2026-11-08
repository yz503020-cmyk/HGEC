using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace DG;

public enum Mode
{
  Full,
  Code,
}

public class Rule
{
  public string Id = Guid.NewGuid().ToString("N");
  public string Name = "",
    Path = "";
  public bool On,
    Hidden;
  public Mode Mode;
  public string? OwnCode;
  public List<string> White = new();
}

// אפשרויות "הגנה מתקדמת" (חלון 7)
public class AdvOpts
{
  public bool BlockBoot = true,
    NoVirt,
    NoTaskMgr,
    NoRegedit,
    NoStore,
    NoWinget,
    NoTether,
    NoTcpip,
    LockHosts,
    NoProxy;
  public bool Browsers = true; // כיבוי DoH וגלישה פרטית בדפדפנים
  public bool SafeBoot = true; // השירות רץ גם ב-Safe Mode
  public bool StrongAdmin; // הקשחה חזקה (כבוי כברירת מחדל): בזמן החסימה מנהלים מאבדים את זכויות הגיבוי/שחזור, לקיחת בעלות ודיבאג
}

// תזמון: החסימות פעילות רק בתוך החלון (מחוץ לו הכול נפתח אוטומטית)
public class Schedule
{
  public bool On;
  public string From = "20:00",
    To = "07:00";
  public int Days = 127; // ביט 0 = יום ראשון
  public string? TzId; // אזור הזמן שבו מוגדר התזמון. נקבע בהגדרה, כדי ששינוי אזור הזמן במחשב (מותר למשתמש רגיל) לא יזיז את החלון

  public static string? Local()
  {
    try
    {
      return TimeZoneInfo.Local.Id;
    }
    catch
    {
      return null;
    }
  }

  public DateTime NowPinned()
  {
    try
    {
      var tz = string.IsNullOrEmpty(TzId) ? TimeZoneInfo.Local : TimeZoneInfo.FindSystemTimeZoneById(TzId);
      return TimeZoneInfo.ConvertTime(Clock.UtcNow(), tz); // בשירות: שעה אמינה (שינוי שעון המחשב לא מזיז את החלון)
    }
    catch
    {
      return Clock.UtcNow().ToLocalTime();
    }
  }

  static TimeSpan P(string s) => TimeSpan.TryParse(s, out var t) ? t : TimeSpan.Zero;

  bool DayOn(DayOfWeek d) => (Days & (1 << (int)d)) != 0;

  public bool Active(DateTime now)
  {
    var t = now.TimeOfDay;
    var f = P(From);
    var to = P(To);
    if (f == to)
      return DayOn(now.DayOfWeek);
    if (f < to)
      return DayOn(now.DayOfWeek) && t >= f && t < to;
    if (t >= f)
      return DayOn(now.DayOfWeek);
    if (t < to)
      return DayOn(now.AddDays(-1).DayOfWeek);
    return false;
  }
}

public class Config
{
  public string? AppCode,
    DefaultCode,
    OwnerUser,
    OwnerSid,
    UiExe,
    AlertUrl;
  public bool IncludeRemovable; // false (ברירת מחדל): לא חוסמים קבצים בכוננים נשלפים, כדי שלא יישארו נעולים גם במחשבים אחרים
  public bool SkipProgramDirs = true; // לא חוסמים קבצי מדיה בתיקיות תוכנה (תיקייה שיש בה קובצי dll), תיקיות נקודה ו-node_modules – מונע שבירת תוכנות
  public bool Master = true,
    AllUsers = true,
    Terms,
    Harden = true,
    SkipAppData = true,
    PreviewApply; // Harden: חיזוק חסימת קבצים – מונע מבעל הקובץ לשנות את ההרשאות
  public long TempOpenUntil; // פתיחה זמנית: זמן סיום (UTC ticks). השירות מחזיר את החסימות לבד כשהזמן עובר
  public int State; // 1 = החסימות הוחלו כרגע (בשימוש התזמון והפתיחה הזמנית)
  public Rule Settings = new() { Name = "חסימת הגדרות המחשב" },
    Install = new() { Name = "חסימת התקנת תוכנות" },
    Net = new() { Name = "חסימת חיבור לרשת" },
    Usb = new() { Name = "חסימת התקנים חיצוניים" },
    Portable = new() { Name = "חסימת תוכנות ניידות" },
    Movies = new() { Name = "חסימת סרטים" },
    Songs = new() { Name = "חסימת שירים" },
    Images = new() { Name = "חסימת תמונות" };
  public Rule NetApps = new() { Name = "חסימת חיבור לרשת לפי תוכנה" }; // חלון "רשת": רשימת התוכנות נשמרת ב-NetApps.White
  public bool NetAppsWhite; // false = רשימה שחורה, true = רשימה לבנה
  public Rule Adv = new() { Id = "adv", Name = "הגנה מתקדמת" };
  public AdvOpts AdvOpts = new();
  public Schedule Sched = new();
  public List<Rule> Programs = new(),
    Exts = new(),
    Paths = new();
  public List<string> Applied = new(),
    Exclude = new();

  public IEnumerable<Rule> All() =>
    new[] { Settings, Install, Net, Usb, Portable, Movies, Songs, Images, Adv }.Concat(Programs).Concat(Exts).Concat(Paths);

  public Rule? Find(string id) => All().FirstOrDefault(r => r.Id == id);

  public bool AnyOn() => All().Any(r => r.On) || NetApps.On;

  // רשימות סיומות ברירת מחדל. הוסרו סיומות שנשברות בקלות (ts = TypeScript, mod, ps, ico, svg ...) – אפשר להוסיף ידנית בחלון 4
  public static readonly string[] Vid =
    "3g2 3gp amv asf avi avs cpk divx dv dvr-ms f4v fli flv gxv h264 m1v m2p m2t m2ts m2v m4v mkv mov mp4 mpe mpeg mpeg1 mpeg2 mpeg4 mpg mts mxf nvavi ogm qt rmvb trp vfw vob wmv yuv".Split(
      ' '
    );
  public static readonly string[] Aud = "aac ac3 amr ape flac m4r mmf mp2 mp3 ogg wav wma wv m4a".Split(' ');
  public static readonly string[] Img = "bmp gif jpg jpeg jpe jfif png tga tif tiff webp wmf heic heif avif".Split(' ');

  // סיומות שאסור לחסום (חוסמות את המחשב עצמו)
  public static readonly HashSet<string> Danger = new(StringComparer.OrdinalIgnoreCase)
  {
    "exe",
    "dll",
    "sys",
    "lnk",
    "ini",
    "json",
    "xml",
    "config",
    "bat",
    "cmd",
    "ps1",
    "vbs",
    "js",
    "msi",
    "com",
    "scr",
    "cpl",
    "drv",
    "ocx",
    "dat",
    "db",
    "bin",
    "inf",
    "reg",
    "mui",
    "cat",
    "manifest",
    "jar",
    "py",
    "tmp",
    "log",
    "txt",
  };

  public static readonly JsonSerializerOptions O = new() { IncludeFields = true, WriteIndented = true };

  // השם שמוצג למשתמש (חלונות, הודעות, קיצורי דרך). השמות הפנימיים – השירות, תיקיית ההגדרות, מפתחות הרישום, קובצי ההפעלה – נשארים DeviceGuard,
  // כדי שהתקנות קיימות ימשיכו לעבוד ויתעדכנו כרגיל
  public const string AppName = "אלף המגן";
  public static string Dir = System.IO.Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
    "DeviceGuard"
  );
  public static string CfgPath => System.IO.Path.Combine(Dir, "config.json");
  public static string BakPath => CfgPath + ".bak";
  public static bool InService; // true כשהקוד רץ בתוך שירות ההגנה
  static Config? lastGood;

  static Config? Read(string p)
  {
    try
    {
      return JsonSerializer.Deserialize<Config>(File.ReadAllText(p), O);
    }
    catch
    {
      return null;
    }
  }

  // טעינה עמידה: ניסיונות חוזרים, גיבוי .bak, והגדרות אחרונות תקינות. null = לא ניתן לקרוא (לא מחזירים הגדרות ריקות בטעות)
  public static Config? TryLoad()
  {
    for (int i = 0; i < 6; i++)
    {
      if (File.Exists(CfgPath))
      {
        var c = Read(CfgPath);
        if (c != null)
        {
          lastGood = c;
          return c;
        }
      }
      else if (!File.Exists(BakPath))
        return lastGood ?? new Config(); // הפעלה ראשונה
      else
        break;
      Thread.Sleep(100 * (i + 1));
    }
    var b = File.Exists(BakPath) ? Read(BakPath) : null;
    if (b != null)
    {
      lastGood = b;
      return b;
    }
    return lastGood;
  }

  public static Config Load() =>
    TryLoad() ?? throw new IOException("קובץ ההגדרות אינו קריא. אם יש גיבוי (config.json.bak) אפשר לשחזר ממנו.");

  public static string? Token;

  public static string? Pipe(string msg, int ms = 3000)
  {
    try
    {
      using var p = new NamedPipeClientStream(".", "DeviceGuard.Unlock", PipeDirection.InOut);
      p.Connect(ms);
      if (!Native.TrustedPipeServer(p.SafePipeHandle.DangerousGetHandle()))
        return null; // לא שולחים קודים לשרת שאינו שירות ההגנה
      var w = new StreamWriter(p) { AutoFlush = true };
      var r = new StreamReader(p);
      w.WriteLine(msg);
      var t = r.ReadLineAsync();
      return t.Wait(Math.Max(ms, 15000)) ? t.Result : null;
    }
    catch
    {
      return null;
    }
  }

  public static bool Up(int ms = 1500) => Pipe("HELLO", ms) == "OK";

  // ביטול פתיחה זמנית ("החל שינויים" מחוץ לחלון הזמנים): השירות מאפס רק את זמן הפתיחה, בלי לגעת ברשימת "מה הוחל"
  public static void CancelTemp()
  {
    for (int i = 0; i < 2; i++)
    {
      if (Token == null && !(Program.Code != null && Auth(Program.Code)))
        return;
      var r = Pipe("CANCELTEMP|" + Token, 5000);
      if (r != "DENY")
        return;
      Token = null; // הטוקן פג: אימות מחדש
    }
  }

  // פקודה מאומתת בטוקן: אם השירות דוחה את הטוקן (פג אחרי 8 שעות, או שהשירות הופעל מחדש) – אימות מחדש בקוד הכניסה וניסיון נוסף.
  // build מקבל את הטוקן ומחזיר את הפקודה. null = השירות לא זמין; "DENY" = לא ניתן היה לאמת
  public static string? PipeAuth(Func<string, string> build, int ms = 3000)
  {
    for (int i = 0; i < 2; i++)
    {
      if (Token == null)
      {
        if (Program.Code == null)
          return Up(300) ? "DENY" : null;
        if (!Auth(Program.Code))
          return Up(300) ? "DENY" : null;
      }
      var r = Pipe(build(Token!), ms);
      if (r != "DENY")
        return r;
      Token = null;
    }
    return "DENY";
  }

  public static bool Auth(string code)
  {
    var t = Pipe("AUTH|" + code);
    if (t != null && t.StartsWith("TOKEN|"))
    {
      Token = t[6..];
      return true;
    }
    return false;
  }

  // runtime = true: השמירה כוללת גם את מצב ההחלה (Applied / State / TempOpenUntil). שמירה רגילה לא דורסת אותו, כדי שה-UI לא ידרוס מצב שהשירות עדכן בינתיים
  public void Save(bool runtime = false)
  {
    Programs.RemoveAll(r => !r.On && r.OwnCode == null && !r.Hidden && r.Mode == Mode.Full && r.White.Count == 0); // לא שומרים תוכנות כבויות (מקטין את הקובץ)
    var json = JsonSerializer.Serialize(this, O);
    if (InService)
    {
      if (runtime)
        SaveRuntimeMerged(json);
      else
        WriteSecure(json);
      return;
    }
    if (Token != null || Pipe("HELLO", 300) == "OK" || Enforcer.TryStartService())
    { // כשהשירות המוגן פעיל – השמירה עוברת דרכו בלבד
      var b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(json));
      var cmd = runtime ? "SAVERT|" : "SAVE|";
      for (int i = 0; i < 2; i++)
      {
        if (Token == null && !(Program.Code != null && Auth(Program.Code)))
          break;
        var r = Pipe(cmd + Token + "|" + b64, 10000);
        if (r == "OK")
          return;
        if (r == "DENY")
        {
          Token = null;
          continue;
        } // הטוקן פג (השירות הופעל מחדש): מאמתים שוב ומנסים שוב
        break;
      }
      throw new IOException("שמירת ההגדרות דרך שירות ההגנה נכשלה");
    }
    try
    {
      if (!Directory.Exists(Dir))
      {
        Directory.CreateDirectory(Dir);
        Enforcer.RunExe(
          "icacls",
          $"\"{Dir}\" /inheritance:r /grant *S-1-5-32-544:(OI)(CI)F /grant *S-1-5-18:(OI)(CI)F /grant *S-1-5-32-545:(OI)(CI)RX"
        );
      }
      var tmp = CfgPath + ".tmp";
      File.WriteAllText(tmp, json);
      if (File.Exists(CfgPath))
        File.Copy(CfgPath, BakPath, true);
      File.Move(tmp, CfgPath, true);
    }
    catch (UnauthorizedAccessException)
    {
      // התיקייה נעולה (רק השירות כותב אליה) והשירות לא עונה: כתיבה בעזרת הרשאת השחזור של מנהל מורם
      // חתימה בקוד הכניסה: כשהשירות יחזור לעבוד הוא יקבל את הקובץ (קובץ לא חתום שנכתב מבחוץ – משוחזר)
      if (
        File.Exists(CfgPath)
        && Program.Code != null
        && Enforcer.WriteFileBackup(CfgPath, json)
        && Enforcer.WriteFileBackup(Trust.SigPath, Trust.Sign(Trust.Derive(Program.Code, AppCode), json))
      )
        return;
      // ההקשחה החזקה הסירה ממנהלים את הרשאת השחזור, ולכן גם הדרך החלופית נכשלה: מחזירים את הזכויות עכשיו (אחרי קוד כניסה בלבד),
      // והן ייכנסו לתוקף אחרי יציאה וכניסה מחדש למשתמש. בלי זה לא הייתה דרך לבטל חסימות כשהשירות לא עובד
      if (Program.Code != null && !Enforcer.HasRestorePriv())
      {
        Enforcer.RestoreStrongRights(this);
        throw new IOException(
          "שירות ההגנה אינו פעיל, וההקשחה החזקה מונעת שמירה בלעדיו. זכויות המנהל הוחזרו: צא מהמשתמש (Sign out), היכנס שוב ונסה שוב"
        );
      }
      throw new IOException("שירות ההגנה אינו פעיל, ולכן לא ניתן לשמור. המתן רגע ונסה שוב, או הפעל מחדש את המחשב");
    }
  }

  // שמירה מתוך השירות: משנה רק את מצב ההחלה בקובץ העדכני, ולא דורסת הגדרות שהמשתמש שמר בינתיים
  void SaveRuntimeMerged(string fallbackJson)
  {
    lock (WriteLock) // קריאה-שינוי-כתיבה אטומיים מול שמירות אחרות בשירות (Pipe, ביטול פתיחה זמנית)
      SaveRuntimeMergedCore(fallbackJson);
  }

  // קריאת הקובץ העדכני, שינוי וכתיבה – בלי ששמירה אחרת בשירות תיכנס באמצע (אחרת אחת מהן הייתה דורסת את רשימת "מה הוחל" של השנייה)
  public static void Locked(Action a)
  {
    lock (WriteLock)
      a();
  }

  void SaveRuntimeMergedCore(string fallbackJson)
  {
    var latest = TryLoad();
    if (latest == null || ReferenceEquals(latest, this))
    {
      WriteSecure(fallbackJson);
      return;
    }
    List<string> ap;
    lock (Applied)
      ap = Applied.ToList();
    latest.Applied = ap;
    latest.State = State;
    latest.TempOpenUntil = TempOpenUntil;
    WriteSecure(JsonSerializer.Serialize(latest, O));
  }

  // כתיבה אטומית + הרשאות מוגבלות (SYSTEM ומנהלים בלבד). משמש את השירות
  // התוכן האחרון שהשירות כתב (או טען בהפעלה). שינוי של הקובץ שלא דרך השירות (מנהל שלקח בעלות על הקובץ) מזוהה ומשוחזר
  public static volatile string? LastWritten;

  static readonly object WriteLock = new();

  public static void WriteSecure(string json)
  {
    lock (WriteLock) // הכתיבה ו-LastWritten יחד: שתי כתיבות במקביל לא ייראו כ"שינוי מבחוץ"
      WriteSecureCore(json);
  }

  static void WriteSecureCore(string json)
  {
    LastWritten = json;
    if (InService)
      Trust.SaveGood(json); // קודם העותק המהימן (במפתח רישום מוגן), ואז הקובץ – ראו Trust.SaveGood
    Directory.CreateDirectory(Dir);
    var tmp = CfgPath + ".tmp";
    File.WriteAllText(tmp, json);
    SecureFile(tmp);
    try
    {
      if (File.Exists(CfgPath))
      {
        File.Copy(CfgPath, BakPath, true);
        SecureFile(BakPath);
      }
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
    File.Move(tmp, CfgPath, true);
  }

  public static void SecureFile(string p)
  {
    try
    {
      var fi = new FileInfo(p);
      if (!fi.Exists)
        return;
      var s = new FileSecurity();
      s.SetAccessRuleProtection(true, false);
      s.AddAccessRule(
        new FileSystemAccessRule(
          new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
          FileSystemRights.FullControl,
          AccessControlType.Allow
        )
      );
      s.AddAccessRule(
        new FileSystemAccessRule(
          new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
          FileSystemRights.Read,
          AccessControlType.Allow
        )
      );
      fi.SetAccessControl(s);
    }
    catch (Exception __e)
    {
      Diag.Log(__e);
    }
  }

  // גיבוב קודים: PBKDF2-SHA256, 600,000 איטרציות. קודים ישנים (100,000, בלי קידומת) עדיין נבדקים
  const int Iter = 600000;

  public static string Hash(string s)
  {
    var salt = RandomNumberGenerator.GetBytes(16);
    return "v2$"
      + Iter
      + "$"
      + Convert.ToBase64String(salt)
      + "$"
      + Convert.ToBase64String(Rfc2898DeriveBytes.Pbkdf2(s, salt, Iter, HashAlgorithmName.SHA256, 32));
  }

  public static bool Check(string s, string? st)
  {
    if (st == null)
      return false;
    try
    {
      var p = st.Split('$');
      string salt,
        hash;
      int it;
      if (p.Length == 4 && p[0] == "v2")
      {
        it = int.Parse(p[1]);
        salt = p[2];
        hash = p[3];
      }
      else if (p.Length == 2)
      {
        it = 100000;
        salt = p[0];
        hash = p[1];
      }
      else
        return false;
      var h = Rfc2898DeriveBytes.Pbkdf2(s, Convert.FromBase64String(salt), it, HashAlgorithmName.SHA256, 32);
      return CryptographicOperations.FixedTimeEquals(h, Convert.FromBase64String(hash));
    }
    catch
    {
      return false;
    }
  }

  public bool CodeOk(Rule r, string s) => Check(s, r.OwnCode ?? DefaultCode);
}
