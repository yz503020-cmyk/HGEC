using System.IO;
using Microsoft.Win32;

namespace DG;

// האם השער הופעל באמת על ידי IFEO (ולא ידנית, עם מזהה חוק שהומצא או של חוק אחר).
// השער מפעיל את התוכנה עם דגל דיבאג, ו-Windows לא מחיל IFEO על הפעלה כזו. לכן ההפעלה הזו מותרת רק כשב-IFEO של התוכנה
// שמופעלת רשום השער עם אותו מזהה בדיוק – אחרת מי שמפעיל את השער בעצמו ("--gate x notepad.exe") היה מריץ כל תוכנה חסומה בלי החסימה.
// הקובץ משותף לשער המלא ולשער הקל (מקושר לפרויקט Gate), כך שהבדיקה זהה בשניהם
public static class GateCheck
{
  const string IfeoKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

  // ה-Debugger מפנה לשער עם המזהה הזה בדיוק (ולא למזהה שמתחיל באותן אותיות)
  public static bool DebuggerIs(string debugger, string id)
  {
    var mark = "--gate " + id;
    var i = debugger.IndexOf(mark, StringComparison.Ordinal);
    return i >= 0 && (i + mark.Length == debugger.Length || char.IsWhiteSpace(debugger[i + mark.Length]));
  }

  // שמות הקבצים (מפתחות IFEO, בשתי תצוגות הרישום) שה-Debugger שלהם הוא השער עם המזהה הזה
  public static HashSet<string> IfeoNames(string id)
  {
    var res = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    foreach (var v in new[] { RegistryView.Registry64, RegistryView.Registry32 })
    {
      try
      {
        using var b = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, v);
        using var k = b.OpenSubKey(IfeoKey);
        if (k == null)
          continue;
        foreach (var n in k.GetSubKeyNames())
        {
          try
          {
            using var s = k.OpenSubKey(n);
            if (s?.GetValue("Debugger") is string d && DebuggerIs(d, id))
              res.Add(n);
          }
          catch { }
        }
      }
      catch { }
    }
    return res;
  }

  // לפני הפעלה רגילה (בלי דגל דיבאג) כשאין IFEO עם המזהה: מסמנים בסביבה של התהליך (התוכנה שמופעלת יורשת אותה, וגם שער ש-IFEO מפעיל עבורה).
  // אם השער מגיע לכאן שוב עם אותו מזהה וכבר מסומן – קריאת הרישום כנראה נכשלה ו-IFEO החזיר את ההפעלה אליו: לא מפעילים שוב (אחרת לולאה אינסופית).
  // סימון מזויף מבחוץ רק גורם לחסימה, לא לעקיפה
  const string PlainVar = "DG_GATE_PLAIN";

  public static bool PlainStart(string id)
  {
    try
    {
      if (string.Equals(Environment.GetEnvironmentVariable(PlainVar), id, StringComparison.Ordinal))
        return false;
      Environment.SetEnvironmentVariable(PlainVar, id);
    }
    catch { }
    return true;
  }

  [System.Runtime.InteropServices.DllImport("kernel32", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
  static extern uint GetLongPathNameW(string shortPath, [System.Runtime.InteropServices.Out] char[] buf, uint len);

  // שם הקובץ הארוך של נתיב קצר (8.3). null = לא ניתן
  static string? LongName(string path)
  {
    try
    {
      var buf = new char[1024];
      var r = GetLongPathNameW(path, buf, (uint)buf.Length);
      if (r == 0 || r >= buf.Length)
        return null;
      var f = Path.GetFileName(new string(buf, 0, (int)r));
      return f.Length > 0 ? f : null;
    }
    catch
    {
      return null;
    }
  }

  // שם הקובץ שהפקודה מפעילה, כמו ש-Windows קובע אותו: בין מרכאות; אחרת – הקידומת הקצרה ביותר (עד רווח) שהיא קובץ קיים,
  // ושם בלי תיקייה – המילה הראשונה. בלי סיומת – ".exe" (כמו ב-Windows). exists = בדיקת קיום קובץ (ניתן להחלפה בבדיקות). null = לא ניתן לקבוע
  public static string? ImageName(string cmd, Func<string, bool>? exists = null)
  {
    bool disk = exists == null; // בדיקה מול הדיסק האמיתי (לא בבדיקות האוטומטיות)
    exists ??= File.Exists;
    try
    {
      var s = cmd.TrimStart();
      if (s.Length == 0)
        return null;
      string? tok = null;
      if (s[0] == '"')
      {
        var e = s.IndexOf('"', 1);
        tok = e < 0 ? s[1..] : s[1..e];
      }
      else
      {
        int i = 0;
        while (true)
        {
          var sp = s.IndexOfAny(new[] { ' ', '\t' }, i);
          var pre = sp < 0 ? s : s[..sp];
          if (pre.IndexOfAny(new[] { '\\', '/' }) < 0)
          {
            tok = pre; // שם בלי תיקייה: Windows מחפש אותו בנתיבי החיפוש
            break;
          }
          if (exists(Path.HasExtension(pre) ? pre : pre + ".exe"))
          {
            tok = pre;
            break;
          }
          if (sp < 0)
            break;
          i = sp + 1;
        }
        if (tok == null)
        {
          var sp = s.IndexOfAny(new[] { ' ', '\t' });
          tok = sp < 0 ? s : s[..sp];
        }
      }
      tok = tok.Trim();
      var n = Path.GetFileName(tok);
      if (n.Length == 0)
        return null;
      n = Path.HasExtension(n) ? n : n + ".exe";
      // שם קצר בסגנון 8.3 (MYLONG~1.EXE) – IFEO רשום לפי השם הארוך
      if (n.Contains('~') && disk && LongName(Path.HasExtension(tok) ? tok : tok + ".exe") is string ln)
        n = ln;
      return n;
    }
    catch
    {
      return null;
    }
  }
}
