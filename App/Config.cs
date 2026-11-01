using System.Diagnostics; using System.IO; using System.IO.Pipes; using System.Security.Cryptography; using System.Text; using System.Text.Json;
namespace DG;
public enum Mode { Full, Code }
public class Rule {
  public string Id = Guid.NewGuid().ToString("N");
  public string Name = "", Path = "";
  public bool On, Hidden; public Mode Mode; public string? OwnCode;
  public List<string> White = new();
}
public class Config {
  public string? AppCode, DefaultCode, OwnerUser;
  public bool Master = true, AllUsers = true, Terms, Harden = true;   // Harden: חיזוק חסימת קבצים – מונע מבעל הקובץ לשנות את ההרשאות
  public Rule Settings = new() { Name = "חסימת הגדרות המחשב" }, Install = new() { Name = "חסימת התקנת תוכנות" },
    Net = new() { Name = "חסימת חיבור לרשת" }, Usb = new() { Name = "חסימת התקנים חיצוניים" },
    Portable = new() { Name = "חסימת תוכנות ניידות" }, Movies = new() { Name = "חסימת סרטים" },
    Songs = new() { Name = "חסימת שירים" }, Images = new() { Name = "חסימת תמונות" };
  public List<Rule> Programs = new(), Exts = new(), Paths = new();
  public List<string> Applied = new();
  public IEnumerable<Rule> All() => new[] { Settings, Install, Net, Usb, Portable, Movies, Songs, Images }.Concat(Programs).Concat(Exts).Concat(Paths);
  public Rule? Find(string id) => All().FirstOrDefault(r => r.Id == id);

  public static readonly string[] Vid = "3g2 3gp amv asf avi avs cpk dif divx dv dvr-ms f4v fli flv gxv h264 m1v m2p m2t m2ts m2v m4v mkv mod mov mp2 mp4 mpe mpeg mpeg1 mpeg2 mpeg4 mpg mts mxf nd nvavi ogg ogm ps qt rm rmvb trp ts vfw vob wmv yuv".Split(' ');
  public static readonly string[] Aud = "aac ac3 amr ape flac m4r mmf mp2 mp3 ogg wav wma wv m4a".Split(' ');
  public static readonly string[] Img = "bmp gif ico jpg jpeg jpe jfif png tga tif tiff webp wmf nth heic heif avif svg".Split(' ');

  public static readonly JsonSerializerOptions O = new() { IncludeFields = true, WriteIndented = true };
  public static string Dir = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DeviceGuard");
  public static Config Load() { try { return JsonSerializer.Deserialize<Config>(File.ReadAllText(System.IO.Path.Combine(Dir, "config.json")), O)!; } catch { return new Config(); } }
  public static string? Token;
  public static string? Pipe(string msg, int ms = 3000) {
    try { using var p = new NamedPipeClientStream(".", "DeviceGuard.Unlock", PipeDirection.InOut); p.Connect(ms); var w = new StreamWriter(p) { AutoFlush = true }; var r = new StreamReader(p); w.WriteLine(msg); return r.ReadLine(); } catch { return null; }
  }
  public static bool Up() => Pipe("HELLO", 3000) == "OK";
  public static bool Auth(string code) { var t = Pipe("AUTH|" + code); if (t != null && t.StartsWith("TOKEN|")) { Token = t[6..]; return true; } return false; }
  public void Save() {
    var json = JsonSerializer.Serialize(this, O);
    if (Token != null) {   // כשהשירות המוגן פעיל – השמירה עוברת דרכו בלבד
      if (Pipe("SAVE|" + Token + "|" + Convert.ToBase64String(Encoding.UTF8.GetBytes(json))) == "OK") return;
      throw new IOException("שמירת ההגדרות דרך שירות ההגנה נכשלה");
    }
    if (!Directory.Exists(Dir)) {
      Directory.CreateDirectory(Dir);
      Process.Start(new ProcessStartInfo("icacls", $"\"{Dir}\" /inheritance:r /grant *S-1-5-32-544:(OI)(CI)F /grant *S-1-5-18:(OI)(CI)F /grant *S-1-5-32-545:(OI)(CI)RX") { CreateNoWindow = true, UseShellExecute = false })!.WaitForExit();
    }
    File.WriteAllText(System.IO.Path.Combine(Dir, "config.json"), json);
  }
  public static string Hash(string s) {
    var salt = RandomNumberGenerator.GetBytes(16);
    return Convert.ToBase64String(salt) + "$" + Convert.ToBase64String(Rfc2898DeriveBytes.Pbkdf2(s, salt, 100000, HashAlgorithmName.SHA256, 32));
  }
  public static bool Check(string s, string? st) {
    if (st == null) return false; var p = st.Split('$');
    var h = Rfc2898DeriveBytes.Pbkdf2(s, Convert.FromBase64String(p[0]), 100000, HashAlgorithmName.SHA256, 32);
    return CryptographicOperations.FixedTimeEquals(h, Convert.FromBase64String(p[1]));
  }
  public bool CodeOk(Rule r, string s) => Check(s, r.OwnCode ?? DefaultCode);
}
