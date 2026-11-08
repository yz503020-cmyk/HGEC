using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using DG;
using Xunit;

// הבדיקות של Enforcer משנות שדות סטטיים (SkipAppData וכו'), ולכן לא מריצים בדיקות במקביל
[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace DG.Tests;

// ---------- תזמון: מתי החסימות פעילות ----------
public class ScheduleTests
{
  // נובמבר 2026: ה-1 הוא יום ראשון, ה-3 יום שלישי, ה-4 יום רביעי
  static DateTime At(int day, int h, int m = 0) => new(2026, 11, day, h, m, 0);

  static Schedule S(string from, string to, int days = 127) =>
    new()
    {
      From = from,
      To = to,
      Days = days,
    };

  const int Tue = 1 << (int)DayOfWeek.Tuesday;

  [Fact]
  public void SameDayWindow()
  {
    var s = S("08:00", "12:00");
    Assert.False(s.Active(At(3, 7, 59)));
    Assert.True(s.Active(At(3, 8)));
    Assert.True(s.Active(At(3, 11, 59)));
    Assert.False(s.Active(At(3, 12))); // שעת הסיום אינה כלולה
  }

  [Fact]
  public void OvernightWindow()
  {
    var s = S("20:00", "07:00");
    Assert.True(s.Active(At(3, 22)));
    Assert.True(s.Active(At(4, 3)));
    Assert.False(s.Active(At(3, 12)));
    Assert.False(s.Active(At(4, 7)));
  }

  [Fact]
  public void OvernightAfterMidnightBelongsToPreviousDay()
  {
    var s = S("20:00", "07:00", Tue); // רק ליל שלישי מסומן
    Assert.True(s.Active(At(3, 22))); // שלישי בערב
    Assert.True(s.Active(At(4, 3))); // רביעי לפנות בוקר = המשך ליל שלישי
    Assert.False(s.Active(At(3, 3))); // שלישי לפנות בוקר = המשך ליל שני (לא מסומן)
    Assert.False(s.Active(At(4, 22))); // רביעי בערב (לא מסומן)
  }

  [Fact]
  public void EqualFromToMeansWholeDay()
  {
    var s = S("00:00", "00:00", Tue);
    Assert.True(s.Active(At(3, 0)));
    Assert.True(s.Active(At(3, 23, 59)));
    Assert.False(s.Active(At(4, 12)));
  }

  [Fact]
  public void NoDaysMeansNeverActive() => Assert.False(S("08:00", "12:00", 0).Active(At(3, 10)));

  [Fact]
  public void InvalidTimesAreTreatedAsMidnight() => Assert.True(S("abc", "xyz").Active(At(3, 10)));
}

// ---------- בדיקת קודים ----------
public class CodeCheckTests
{
  [Fact]
  public void HashRoundTrip()
  {
    var h = Config.Hash("123456");
    Assert.StartsWith("v2$", h);
    Assert.True(Config.Check("123456", h));
    Assert.False(Config.Check("123457", h));
    Assert.False(Config.Check("", h));
  }

  [Fact]
  public void HashIsSalted()
  {
    var a = Config.Hash("secret1");
    var b = Config.Hash("secret1");
    Assert.NotEqual(a, b);
    Assert.True(Config.Check("secret1", a) && Config.Check("secret1", b));
  }

  [Fact]
  public void LegacyFormatStillAccepted()
  { // פורמט ישן: salt$hash עם 100,000 איטרציות
    var salt = RandomNumberGenerator.GetBytes(16);
    var hash = Rfc2898DeriveBytes.Pbkdf2("4321", salt, 100000, HashAlgorithmName.SHA256, 32);
    var st = Convert.ToBase64String(salt) + "$" + Convert.ToBase64String(hash);
    Assert.True(Config.Check("4321", st));
    Assert.False(Config.Check("4322", st));
  }

  [Theory]
  [InlineData(null)]
  [InlineData("")]
  [InlineData("garbage")]
  [InlineData("v2$notanumber$AAAA$AAAA")]
  [InlineData("v2$1000$***$***")]
  public void InvalidStoredValuesNeverMatch(string? stored) => Assert.False(Config.Check("123456", stored));

  [Fact]
  public void OwnCodeOverridesDefault()
  {
    var c = new Config { DefaultCode = Config.Hash("default1") };
    var plain = new Rule();
    var own = new Rule { OwnCode = Config.Hash("own123") };
    Assert.True(c.CodeOk(plain, "default1"));
    Assert.False(c.CodeOk(plain, "own123"));
    Assert.True(c.CodeOk(own, "own123"));
    Assert.False(c.CodeOk(own, "default1"));
  }
}

// ---------- נתיבים שאסור לחסום ----------
public class DangerousPathTests
{
  static readonly string Sys = Environment.GetEnvironmentVariable("SystemDrive") ?? "C:";

  static string F(Environment.SpecialFolder f) => Environment.GetFolderPath(f);

  [Fact]
  public void DriveRootIsDangerous()
  {
    Assert.True(Enforcer.IsDangerous(Sys));
    Assert.True(Enforcer.IsDangerous(Sys + "\\"));
  }

  [Fact]
  public void SystemFoldersAreDangerous()
  {
    Assert.True(Enforcer.IsDangerous(F(Environment.SpecialFolder.Windows)));
    Assert.True(Enforcer.IsDangerous(F(Environment.SpecialFolder.Windows) + "\\"));
    Assert.True(Enforcer.IsDangerous(Path.Combine(F(Environment.SpecialFolder.Windows), "System32")));
    Assert.True(Enforcer.IsDangerous(F(Environment.SpecialFolder.ProgramFiles)));
    Assert.True(Enforcer.IsDangerous(F(Environment.SpecialFolder.ProgramFilesX86)));
    Assert.True(Enforcer.IsDangerous(F(Environment.SpecialFolder.CommonApplicationData)));
    Assert.True(Enforcer.IsDangerous(Path.Combine(Sys + "\\", "Users")));
  }

  [Fact]
  public void UserProfileRootIsDangerous() => Assert.True(Enforcer.IsDangerous(F(Environment.SpecialFolder.UserProfile)));

  [Fact]
  public void SharedSystemFoldersAreDangerous()
  {
    Assert.True(Enforcer.IsDangerous(Path.Combine(F(Environment.SpecialFolder.UserProfile), "AppData")));
    Assert.True(Enforcer.IsDangerous(Path.Combine(F(Environment.SpecialFolder.UserProfile), "AppData", "Local")));
    Assert.True(Enforcer.IsDangerous(Path.Combine(F(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows Defender")));
    Assert.True(Enforcer.IsDangerous(Path.Combine(F(Environment.SpecialFolder.ProgramFiles), "Common Files")));
    Assert.True(Enforcer.IsDangerous(Path.Combine(F(Environment.SpecialFolder.ProgramFiles), "WindowsApps")));
    Assert.True(Enforcer.IsDangerous(Path.Combine(Sys + "\\", "Recovery")));
  }

  [Fact]
  public void SystemProcessesAreCritical()
  {
    Assert.True(Enforcer.IsCritical("consent.exe"));
    Assert.True(Enforcer.IsCritical(@"C:\ProgramData\DeviceGuard\DeviceGuardGate.exe"));
    Assert.False(Enforcer.IsCritical("notepad.exe"));
    Assert.True(Enforcer.IsGenericName(@"C:\x\Update.exe"));
    Assert.False(Enforcer.IsGenericName(@"C:\x\Discord.exe"));
  }

  // תיקייה שהיא קישור (junction) לתיקיית מערכת: הנתיב נראה רגיל, אבל חסימה דרכו נועלת את תיקיית המערכת האמיתית
  [Fact]
  public void JunctionToSystemFolderIsDangerous()
  {
    var root = Path.Combine(Sys + "\\", "dg-junction-" + Guid.NewGuid().ToString("N")); // לא בתיקייה הזמנית: היא בתוך AppData (שאסור לחסום ממילא)
    Directory.CreateDirectory(root);
    try
    {
      var toWin = Path.Combine(root, "win");
      var toData = Path.Combine(root, "data");
      var ok = Path.Combine(root, "ok");
      Directory.CreateDirectory(Path.Combine(root, "target"));
      foreach (var (link, target) in new[] { (toWin, F(Environment.SpecialFolder.Windows)), (toData, F(Environment.SpecialFolder.CommonApplicationData)), (ok, Path.Combine(root, "target")) })
      {
        using var p = System.Diagnostics.Process.Start(
          new System.Diagnostics.ProcessStartInfo("cmd.exe", $"/c mklink /J \"{link}\" \"{target}\"") { CreateNoWindow = true, UseShellExecute = false }
        )!;
        p.WaitForExit();
      }
      Assert.True(Directory.Exists(toWin));
      Assert.True(Enforcer.IsDangerous(toWin));
      Assert.True(Enforcer.IsDangerous(Path.Combine(toWin, "System32"))); // גם כשהקישור באמצע הנתיב
      Assert.True(Enforcer.IsDangerous(toData));
      Assert.False(Enforcer.IsDangerous(ok)); // קישור לתיקייה רגילה – מותר
    }
    finally
    {
      // מחיקת הקישורים עצמם בלבד (Directory.Delete על junction לא נכנס לתיקיית היעד)
      foreach (var d in Directory.GetDirectories(root))
        try
        {
          Directory.Delete(d, false);
        }
        catch { }
      try
      {
        Directory.Delete(root, false);
      }
      catch { }
    }
  }

  // קישור מובנה של Windows: C:\ProgramData\Application Data מפנה ל-C:\ProgramData עצמה
  [Fact]
  public void BuiltInProgramDataJunctionIsDangerous()
  {
    var j = Path.Combine(F(Environment.SpecialFolder.CommonApplicationData), "Application Data");
    if (Directory.Exists(j))
      Assert.True(Enforcer.IsDangerous(j));
  }

  // קובצי זיכרון/שינה/אתחול בשורש הכונן, והרישום הפרטי של המשתמש (NTUSER.DAT) בשורש הפרופיל
  [Fact]
  public void SystemFilesAreDangerous()
  {
    Assert.True(Enforcer.IsDangerous(Path.Combine(Sys + "\\", "pagefile.sys")));
    Assert.True(Enforcer.IsDangerous(Path.Combine(Sys + "\\", "hiberfil.sys")));
    Assert.True(Enforcer.IsDangerous(Path.Combine(Sys + "\\", "$WINDOWS.~BT")));
    Assert.True(Enforcer.IsDangerous(Path.Combine(F(Environment.SpecialFolder.UserProfile), "NTUSER.DAT")));
    Assert.True(Enforcer.IsDangerous(Path.Combine(F(Environment.SpecialFolder.UserProfile), "ntuser.dat.LOG1")));
    Assert.False(Enforcer.IsDangerous(Path.Combine(F(Environment.SpecialFolder.UserProfile), "Desktop")));
  }

  // פענוח נתיב קובץ ההפעלה מתוך ImagePath של שירות
  [Fact]
  public void ServiceImagePathIsParsed()
  {
    var win = F(Environment.SpecialFolder.Windows);
    Assert.Equal(@"C:\Program Files\Av\svc.exe", Enforcer.ServicePath("\"C:\\Program Files\\Av\\svc.exe\" -k run"));
    Assert.Equal(@"C:\Program Files\Av\svc.exe", Enforcer.ServicePath(@"C:\Program Files\Av\svc.exe -k run"));
    Assert.Equal(Path.Combine(win, @"System32\drivers\x.sys"), Enforcer.ServicePath(@"\SystemRoot\System32\drivers\x.sys"));
    Assert.Equal(Path.Combine(win, @"system32\drivers\y.sys"), Enforcer.ServicePath(@"system32\drivers\y.sys"));
    Assert.Equal(@"D:\Drv\z.sys", Enforcer.ServicePath(@"\??\D:\Drv\z.sys"));
  }

  // תיקייה שיש בה שירות רשום (מחוץ ל-Windows) – אסור לחסום
  [Fact]
  public void FolderWithServiceIsDangerous()
  {
    using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
    var win = F(Environment.SpecialFolder.Windows);
    foreach (var n in k!.GetSubKeyNames())
    {
      using var sk = k.OpenSubKey(n);
      if (sk?.GetValue("ImagePath") is not string ip || Enforcer.ServicePath(ip) is not { } bin)
        continue;
      if (bin.StartsWith(win + "\\", StringComparison.OrdinalIgnoreCase) || !File.Exists(bin))
        continue;
      Assert.True(Enforcer.IsDangerous(Path.GetDirectoryName(bin)!), bin);
      Assert.True(Enforcer.IsDangerous(bin), bin);
      return;
    }
  }

  [Fact]
  public void OrdinaryFoldersAreNotDangerous()
  {
    Assert.False(Enforcer.IsDangerous(Path.Combine(F(Environment.SpecialFolder.UserProfile), "Pictures")));
    Assert.False(Enforcer.IsDangerous(Path.Combine(Sys + "\\", "Data", "Photos")));
    Assert.False(Enforcer.IsDangerous(Path.Combine(F(Environment.SpecialFolder.ProgramFiles), "SomeApp")));
  }
}

// ---------- תיקיות שהסריקה מדלגת עליהן ----------
public class SkippedPathTests : IDisposable
{
  static readonly string Sys = (Environment.GetEnvironmentVariable("SystemDrive") ?? "C:") + "\\";
  static readonly string Win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
  readonly bool skipAppData = Enforcer.SkipAppData,
    skipProg = Enforcer.SkipProgramDirs;
  readonly string[] exclude = Enforcer.Exclude;
  readonly List<string> temp = new();

  public SkippedPathTests()
  {
    Enforcer.SkipAppData = true;
    Enforcer.SkipProgramDirs = false;
    Enforcer.Exclude = Array.Empty<string>();
  }

  public void Dispose()
  {
    Enforcer.SkipAppData = skipAppData;
    Enforcer.SkipProgramDirs = skipProg;
    Enforcer.Exclude = exclude;
    foreach (var d in temp)
      try
      {
        Directory.Delete(d, true);
      }
      catch { }
  }

  [Fact]
  public void WindowsIsSkippedExceptTemp()
  {
    Assert.True(Enforcer.InSkipped(Path.Combine(Win, "System32", "a.jpg")));
    Assert.False(Enforcer.InSkipped(Path.Combine(Win, "Temp", "a.jpg")));
  }

  [Fact]
  public void ProgramFilesAndSystemFoldersAreSkipped()
  {
    Assert.True(Enforcer.InSkipped(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "App", "a.jpg")));
    Assert.True(
      Enforcer.InSkipped(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "a.jpg"))
    );
    Assert.True(Enforcer.InSkipped(Path.Combine(Sys, "$Recycle.Bin", "S-1-5-21", "a.jpg")));
    Assert.True(Enforcer.InSkipped(Path.Combine(Sys, "System Volume Information", "a.jpg")));
  }

  [Fact]
  public void OrdinaryPathIsNotSkipped() => Assert.False(Enforcer.InSkipped(Path.Combine(Sys, "Data", "Photos", "a.jpg")));

  [Fact]
  public void AppDataFollowsSetting()
  {
    var p = Path.Combine(Sys, "Users", "someone", "AppData", "Local", "a.jpg");
    Assert.True(Enforcer.InSkipped(p));
    Enforcer.SkipAppData = false;
    Assert.False(Enforcer.InSkipped(p));
  }

  [Fact]
  public void ExclusionsAreSkipped()
  {
    Enforcer.Exclude = new[] { Path.Combine(Sys, "Data", "Keep") + "\\" };
    Assert.True(Enforcer.InSkipped(Path.Combine(Sys, "Data", "Keep", "a.jpg")));
    Assert.True(Enforcer.InSkipped(Path.Combine(Sys, "Data", "Keep", "Sub", "a.jpg")));
    Assert.False(Enforcer.InSkipped(Path.Combine(Sys, "Data", "Keeper", "a.jpg"))); // לא תיקייה אחרת שמתחילה באותו שם
  }

  [Fact]
  public void ProgramLikeFolderNamesAloneDoNotSkip()
  {
    // תיקייה שהמשתמש יצר ונתן לה שם כזה (כאן: לא קיימת, ולכן לא בבעלות מערכת) אינה עוקפת את החסימה
    Enforcer.SkipProgramDirs = true;
    Assert.False(Enforcer.InSkipped(Path.Combine(Sys, "Proj_" + Guid.NewGuid().ToString("N"), "node_modules", "pkg", "a.png")));
    Assert.False(Enforcer.InSkipped(Path.Combine(Sys, "Proj_" + Guid.NewGuid().ToString("N"), ".git", "a.png")));
  }

  [Fact]
  public void ArchiveTempFoldersAreNotSkipped()
  {
    var baseP = Path.Combine(Sys, "Users", "someone", "AppData", "Local", "Temp");
    Assert.False(Enforcer.InSkipped(Path.Combine(baseP, "Temp1_photos.zip", "a.jpg")));
    Assert.False(Enforcer.InSkipped(Path.Combine(baseP, "7zO1234", "a.jpg")));
    Assert.False(Enforcer.InSkipped(Path.Combine(baseP, "Rar$EXa1.234", "a.jpg")));
    Assert.True(Enforcer.InSkipped(Path.Combine(baseP, "SomeApp", "a.jpg")));
    Assert.True(Enforcer.InSkipped(Path.Combine(baseP, "TempState", "a.jpg")));
  }

  [Fact]
  public void FolderWithDllIsSkippedWhenEnabled()
  {
    var d = Path.Combine(Path.GetTempPath(), "dgtest_" + Guid.NewGuid().ToString("N"));
    temp.Add(d);
    Directory.CreateDirectory(d);
    File.WriteAllBytes(Path.Combine(d, "x.dll"), new byte[] { 0 });
    Enforcer.SkipAppData = false; // התיקייה הזמנית נמצאת בתוך AppData
    Enforcer.SkipProgramDirs = false;
    Assert.False(Enforcer.InSkipped(Path.Combine(d, "a.jpg")));
    Enforcer.SkipProgramDirs = true;
    // מדלגים רק כשה-dll הותקן על ידי המערכת/מנהל, ולא כשמשתמש רגיל שם אותו בעצמו
    Assert.Equal(Enforcer.PrivOwned(Path.Combine(d, "x.dll")), Enforcer.InSkipped(Path.Combine(d, "a.jpg")));
  }
}

// ---------- רשימה לבנה בחומת האש: אילו כללי היתר קיימים מושבתים ----------
public class FirewallLeakTests
{
  static readonly string[] SysPkg = { "S-1-15-2-1" };

  static bool Leak(string v) => Enforcer.FwLeakRule(v, SysPkg, @"C:\Windows");

  [Fact]
  public void StoreAppsAndProgramsAreDisabled()
  {
    Assert.True(Leak("v2.31|Action=Allow|Active=TRUE|Dir=Out|AppPkgId=S-1-15-2-99|Name=Mail|EmbedCtxt=@{microsoft.windowscommunicationsapps}|"));
    Assert.True(Leak(@"v2.31|Action=Allow|Active=TRUE|Dir=Out|App=C:\Program Files\X\x.exe|Name=x|"));
    Assert.True(Leak("v2.31|Action=Allow|Active=TRUE|Dir=Out|Protocol=6|RPort=443|Name=Any443|")); // כלל לכל התוכנות שאינו של Windows
  }

  [Fact]
  public void WindowsItselfIsKept()
  {
    Assert.False(Leak("v2.31|Action=Allow|Active=TRUE|Dir=Out|AppPkgId=S-1-15-2-1|Name=x|")); // אפליקציית מערכת
    Assert.False(Leak(@"v2.31|Action=Allow|Active=TRUE|Dir=Out|App=%SystemRoot%\system32\svchost.exe|Svc=dnscache|Name=CoreNet-DNS|EmbedCtxt=@FirewallAPI.dll,-25000|"));
    Assert.False(Leak(@"v2.31|Action=Allow|Active=TRUE|Dir=Out|App=C:\Windows\System32\x.exe|Name=x|"));
    Assert.False(Leak("v2.31|Action=Allow|Active=TRUE|Dir=Out|App=System|Name=x|"));
    Assert.False(Leak("v2.31|Action=Allow|Active=TRUE|Dir=Out|Protocol=6|Name=x|EmbedCtxt=@FirewallAPI.dll,-28502|"));
  }

  [Fact]
  public void OursInactiveInboundAndBlockAreKept()
  {
    Assert.False(Leak(@"v2.31|Action=Allow|Active=TRUE|Dir=Out|App=C:\Program Files\X\x.exe|Name=DeviceGuard Allow|EmbedCtxt=DeviceGuardNet|"));
    Assert.False(Leak(@"v2.31|Action=Allow|Active=FALSE|Dir=Out|App=C:\Program Files\X\x.exe|Name=x|"));
    Assert.False(Leak(@"v2.31|Action=Allow|Active=TRUE|Dir=In|App=C:\Program Files\X\x.exe|Name=x|"));
    Assert.False(Leak(@"v2.31|Action=Block|Active=TRUE|Dir=Out|App=C:\Program Files\X\x.exe|Name=x|"));
  }
}

// ---------- כלל הדחייה של נעילת קבצים: לכל המשתמשים או לחשבון אחד ----------
public class DenyRuleTests
{
  const FileSystemRights M = FileSystemRights.ReadData | FileSystemRights.ExecuteFile | FileSystemRights.Delete;

  static FileSystemAccessRule R(string sid, FileSystemRights r, AccessControlType t = AccessControlType.Deny) => new(new SecurityIdentifier(sid), r, t);

  [Fact]
  public void OursForEveryoneOrOneAccount()
  {
    Assert.True(Enforcer.IsOurDeny(R("S-1-1-0", M)));
    Assert.True(Enforcer.IsOurDeny(R("S-1-5-21-1-2-3-1001", M)));
  }

  [Fact]
  public void OtherRulesAreNotOurs()
  {
    Assert.False(Enforcer.IsOurDeny(R("S-1-5-21-1-2-3-1001", FileSystemRights.Write)));
    Assert.False(Enforcer.IsOurDeny(R("S-1-5-21-1-2-3-1001", M | FileSystemRights.Write)));
    Assert.False(Enforcer.IsOurDeny(R("S-1-5-21-1-2-3-1001", M, AccessControlType.Allow)));
    Assert.False(Enforcer.IsOurDeny(R("S-1-5-32-544", M)));
  }
}
