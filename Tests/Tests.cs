using System.IO;
using System.Security.Cryptography;
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
  public void ProgramLikeFoldersAreSkippedWhenEnabled()
  {
    Enforcer.SkipProgramDirs = true;
    Assert.True(Enforcer.InSkipped(Path.Combine(Sys, "Proj", "node_modules", "pkg", "a.png")));
    Assert.True(Enforcer.InSkipped(Path.Combine(Sys, "Proj", ".git", "a.png")));
    Assert.True(Enforcer.InSkipped(Path.Combine(Sys, "Py", "Lib", "site-packages", "a.png")));
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
    Assert.True(Enforcer.InSkipped(Path.Combine(d, "a.jpg")));
  }
}
