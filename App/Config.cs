using System.Diagnostics; using System.IO; using System.IO.Pipes; using System.Security.AccessControl; using System.Security.Cryptography; using System.Security.Principal; using System.Text; using System.Text.Json;
namespace DG;
public enum Mode { Full, Code }
public class Rule {
  public string Id = Guid.NewGuid().ToString("N");
  public string Name = "", Path = "";
  public bool On, Hidden; public Mode Mode; public string? OwnCode;
  public List<string> White = new();
}
// אפשרויות "הגנה מתקדמת" (חלון 7)
public class AdvOpts {
  public bool BlockBoot = true, NoVirt, NoTaskMgr, NoRegedit, NoStore, NoWinget, NoTether, NoTcpip, LockHosts, NoProxy;
  public bool Browsers = true;   // כיבוי DoH וגלישה פרטית בדפדפנים
  public bool SafeBoot = true;   // השירות רץ גם ב-Safe Mode
}
// תזמון: החסימות פעילות רק בתוך החלון (מחוץ לו הכול נפתח אוטומטית)
public class Schedule {
  public bool On; public string From = "20:00", To = "07:00"; public int Days = 127;   // ביט 0 = יום ראשון
  public string? TzId;   // אזור הזמן שבו מוגדר התזמון. נקבע בהגדרה, כדי ששינוי אזור הזמן במחשב (מותר למשתמש רגיל) לא יזיז את החלון
  public static string? Local() { try { return TimeZoneInfo.Local.Id; } catch { return null; } }
  public DateTime NowPinned() {
    try { var tz = string.IsNullOrEmpty(TzId) ? TimeZoneInfo.Local : TimeZoneInfo.FindSystemTimeZoneById(TzId); return TimeZoneInfo.ConvertTime(DateTime.UtcNow, tz); } catch { return DateTime.Now; }
  }
  static TimeSpan P(string s) => TimeSpan.TryParse(s, out var t) ? t : TimeSpan.Zero;
  bool DayOn(DayOfWeek d) => (Days & (1 << (int)d)) != 0;
  public bool Active(DateTime now) {
    var t = now.TimeOfDay; var f = P(From); var to = P(To);
    if (f == to) return DayOn(now.DayOfWeek);
    if (f < to) return DayOn(now.DayOfWeek) && t >= f && t < to;
    if (t >= f) return DayOn(now.DayOfWeek);
    if (t < to) return DayOn(now.AddDays(-1).DayOfWeek);
    return false;
  }
}
public class Config {
  public string? AppCode, DefaultCode, OwnerUser, OwnerSid, UiExe, AlertUrl;
  public bool IncludeRemovable;   // false (ברירת מחדל): לא חוסמים קבצים בכוננים נשלפים, כדי שלא יישארו נעולים גם במחשבים אחרים
  public bool SkipProgramDirs = true;   // לא חוסמים קבצי מדיה בתיקיות תוכנה (תיקייה שיש בה קובצי dll), תיקיות נקודה ו-node_modules – מונע שבירת תוכנות
  public bool Master = true, AllUsers = true, Terms, Harden = true, SkipAppData = true, PreviewApply;   // Harden: חיזוק חסימת קבצים – מונע מבעל הקובץ לשנות את ההרשאות
  public long TempOpenUntil;   // פתיחה זמנית: זמן סיום (UTC ticks). השירות מחזיר את החסימות לבד כשהזמן עובר
  public int State;            // 1 = החסימות הוחלו כרגע (בשימוש התזמון והפתיחה הזמנית)
  public Rule Settings = new() { Name = "חסימת הגדרות המחשב" }, Install = new() { Name = "חסימת התקנת תוכנות" },
    Net = new() { Name = "חסימת חיבור לרשת" }, Usb = new() { Name = "חסימת התקנים חיצוניים" },
    Portable = new() { Name = "חסימת תוכנות ניידות" }, Movies = new() { Name = "חסימת סרטים" },
    Songs = new() { Name = "חסימת שירים" }, Images = new() { Name = "חסימת תמונות" };
  public Rule NetApps = new() { Name = "חסימת חיבור לרשת לפי תוכנה" };   // חלון "רשת": רשימת התוכנות נשמרת ב-NetApps.White
  public bool NetAppsWhite;   // false = רשימה שחורה, true = רשימה לבנה
  public Rule Adv = new() { Id = "adv", Name = "הגנה מתקדמת" };
  public AdvOpts AdvOpts = new(); public Schedule Sched = new();
  public List<Rule> Programs = new(), Exts = new(), Paths = new();
  public List<string> Applied = new(), Exclude = new();
  public IEnumerable<Rule> All() => new[] { Settings, Install, Net, Usb, Portable, Movies, Songs, Images, Adv }.Concat(Programs).Concat(Exts).Concat(Paths);
  public Rule? Find(string id) => All().FirstOrDefault(r => r.Id == id);
  public bool AnyOn() => All().Any(r => r.On) || NetApps.On;

  // רשימות סיומות ברירת מחדל. הוסרו סיומות שנשברות בקלות (ts = TypeScript, mod, ps, ico, svg ...) – אפשר להוסיף ידנית בחלון 4
  public static readonly string[] Vid = "3g2 3gp amv asf avi avs cpk divx dv dvr-ms f4v fli flv gxv h264 m1v m2p m2t m2ts m2v m4v mkv mov mp4 mpe mpeg mpeg1 mpeg2 mpeg4 mpg mts mxf nvavi ogm qt rmvb trp vfw vob wmv yuv".Split(' ');
  public static readonly string[] Aud = "aac ac3 amr ape flac m4r mmf mp2 mp3 ogg wav wma wv m4a".Split(' ');
  public static readonly string[] Img = "bmp gif jpg jpeg jpe jfif png tga tif tiff webp wmf heic heif avif".Split(' ');
  // סיומות שאסור לחסום (חוסמות את המחשב עצמו)
  public static readonly HashSet<string> Danger = new(StringComparer.OrdinalIgnoreCase) { "exe", "dll", "sys", "lnk", "ini", "json", "xml", "config", "bat", "cmd", "ps1", "vbs", "js", "msi", "com", "scr", "cpl", "drv", "ocx", "dat", "db", "bin", "inf", "reg", "mui", "cat", "manifest", "jar", "py", "tmp", "log", "txt" };

  public static readonly JsonSerializerOptions O = new() { IncludeFields = true, WriteIndented = true };
  public static string Dir = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DeviceGuard");
  public static string CfgPath => System.IO.Path.Combine(Dir, "config.json");
  public static string BakPath => CfgPath + ".bak";
  public static bool InService;   // true כשהקוד רץ בתוך שירות ההגנה
  static Config? lastGood;
  static Config? Read(string p) { try { return JsonSerializer.Deserialize<Config>(File.ReadAllText(p), O); } catch { return null; } }
  // טעינה עמידה: ניסיונות חוזרים, גיבוי .bak, והגדרות אחרונות תקינות. null = לא ניתן לקרוא (לא מחזירים הגדרות ריקות בטעות)
  public static Config? TryLoad() {
    for (int i = 0; i < 6; i++) {
      if (File.Exists(CfgPath)) { var c = Read(CfgPath); if (c != null) { lastGood = c; return c; } }
      else if (!File.Exists(BakPath)) return lastGood ?? new Config();   // הפעלה ראשונה
      else break;
      Thread.Sleep(100 * (i + 1));
    }
    var b = File.Exists(BakPath) ? Read(BakPath) : null;
    if (b != null) { lastGood = b; return b; }
    return lastGood;
  }
  public static Config Load() => TryLoad() ?? throw new IOException("קובץ ההגדרות אינו קריא. אם יש גיבוי (config.json.bak) אפשר לשחזר ממנו.");

  public static string? Token;
  public static string? Pipe(string msg, int ms = 3000) {
    try {
      using var p = new NamedPipeClientStream(".", "DeviceGuard.Unlock", PipeDirection.InOut); p.Connect(ms);
      var w = new StreamWriter(p) { AutoFlush = true }; var r = new StreamReader(p); w.WriteLine(msg);
      var t = r.ReadLineAsync(); return t.Wait(Math.Max(ms, 15000)) ? t.Result : null;
    } catch { return null; }
  }
  public static bool Up(int ms = 1500) => Pipe("HELLO", ms) == "OK";
  public static bool Auth(string code) { var t = Pipe("AUTH|" + code); if (t != null && t.StartsWith("TOKEN|")) { Token = t[6..]; return true; } return false; }

  // runtime = true: השמירה כוללת גם את מצב ההחלה (Applied / State / TempOpenUntil). שמירה רגילה לא דורסת אותו, כדי שה-UI לא ידרוס מצב שהשירות עדכן בינתיים
  public void Save(bool runtime = false) {
    Programs.RemoveAll(r => !r.On && r.OwnCode == null && !r.Hidden && r.Mode == Mode.Full && r.White.Count == 0);   // לא שומרים תוכנות כבויות (מקטין את הקובץ)
    var json = JsonSerializer.Serialize(this, O);
    if (InService) { if (runtime) SaveRuntimeMerged(json); else WriteSecure(json); return; }
    if (Token != null || Pipe("HELLO", 300) == "OK" || Enforcer.TryStartService()) {   // כשהשירות המוגן פעיל – השמירה עוברת דרכו בלבד
      var b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(json));
      var cmd = runtime ? "SAVERT|" : "SAVE|";
      for (int i = 0; i < 2; i++) {
        if (Token == null && !(Program.Code != null && Auth(Program.Code))) break;
        var r = Pipe(cmd + Token + "|" + b64, 10000);
        if (r == "OK") return;
        if (r == "DENY") { Token = null; continue; }   // הטוקן פג (השירות הופעל מחדש): מאמתים שוב ומנסים שוב
        break;
      }
      throw new IOException("שמירת ההגדרות דרך שירות ההגנה נכשלה");
    }
    try {
      if (!Directory.Exists(Dir)) {
        Directory.CreateDirectory(Dir);
        Enforcer.RunExe("icacls", $"\"{Dir}\" /inheritance:r /grant *S-1-5-32-544:(OI)(CI)F /grant *S-1-5-18:(OI)(CI)F /grant *S-1-5-32-545:(OI)(CI)RX");
      }
      var tmp = CfgPath + ".tmp"; File.WriteAllText(tmp, json);
      if (File.Exists(CfgPath)) File.Copy(CfgPath, BakPath, true);
      File.Move(tmp, CfgPath, true);
    } catch (UnauthorizedAccessException) { throw new IOException("שירות ההגנה אינו פעיל, ולכן לא ניתן לשמור. המתן רגע ונסה שוב, או הפעל מחדש את המחשב"); }
  }
  // שמירה מתוך השירות: משנה רק את מצב ההחלה בקובץ העדכני, ולא דורסת הגדרות שהמשתמש שמר בינתיים
  void SaveRuntimeMerged(string fallbackJson) {
    var latest = TryLoad();
    if (latest == null || ReferenceEquals(latest, this)) { WriteSecure(fallbackJson); return; }
    List<string> ap; lock (Applied) ap = Applied.ToList();
    latest.Applied = ap; latest.State = State; latest.TempOpenUntil = TempOpenUntil;
    WriteSecure(JsonSerializer.Serialize(latest, O));
  }
  // כתיבה אטומית + הרשאות מוגבלות (SYSTEM ומנהלים בלבד). משמש את השירות
  public static void WriteSecure(string json) {
    Directory.CreateDirectory(Dir);
    var tmp = CfgPath + ".tmp"; File.WriteAllText(tmp, json); SecureFile(tmp);
    try { if (File.Exists(CfgPath)) { File.Copy(CfgPath, BakPath, true); SecureFile(BakPath); } } catch { }
    File.Move(tmp, CfgPath, true);
  }
  public static void SecureFile(string p) {
    try {
      var fi = new FileInfo(p); if (!fi.Exists) return;
      var s = new FileSecurity(); s.SetAccessRuleProtection(true, false);
      s.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl, AccessControlType.Allow));
      s.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.Read, AccessControlType.Allow));
      fi.SetAccessControl(s);
    } catch { }
  }

  // גיבוב קודים: PBKDF2-SHA256, 600,000 איטרציות. קודים ישנים (100,000, בלי קידומת) עדיין נבדקים
  const int Iter = 600000;
  public static string Hash(string s) {
    var salt = RandomNumberGenerator.GetBytes(16);
    return "v2$" + Iter + "$" + Convert.ToBase64String(salt) + "$" + Convert.ToBase64String(Rfc2898DeriveBytes.Pbkdf2(s, salt, Iter, HashAlgorithmName.SHA256, 32));
  }
  public static bool Check(string s, string? st) {
    if (st == null) return false;
    try {
      var p = st.Split('$'); string salt, hash; int it;
      if (p.Length == 4 && p[0] == "v2") { it = int.Parse(p[1]); salt = p[2]; hash = p[3]; }
      else if (p.Length == 2) { it = 100000; salt = p[0]; hash = p[1]; }
      else return false;
      var h = Rfc2898DeriveBytes.Pbkdf2(s, Convert.FromBase64String(salt), it, HashAlgorithmName.SHA256, 32);
      return CryptographicOperations.FixedTimeEquals(h, Convert.FromBase64String(hash));
    } catch { return false; }
  }
  public bool CodeOk(Rule r, string s) => Check(s, r.OwnCode ?? DefaultCode);
}
