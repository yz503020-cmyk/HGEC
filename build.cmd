@echo off
rem בנייה מקומית: Windows + .NET 10 SDK (השער הקל דורש גם רכיב "Desktop development with C++" של Visual Studio Build Tools בשביל NativeAOT)
rem התוצר: out\DeviceGuard.exe (קובץ יחיד; השער והשירות נוצרים ממנו אוטומטית)
setlocal
echo [1/2] Building light gate (NativeAOT, optional)...
dotnet publish Gate\DeviceGuardGate.csproj -c Release -r win-x64 -o Gate\out
if errorlevel 1 (
  echo Light gate build failed - continuing without it. The full gate will be used.
  if exist Gate\out\DeviceGuardGate.exe del Gate\out\DeviceGuardGate.exe
)
echo [2/2] Building DeviceGuard...
dotnet publish App\DeviceGuard.csproj -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -o out || exit /b 1
echo.
echo Output: out\DeviceGuard.exe
