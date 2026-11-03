@echo off
rem בנייה מקומית: Windows + .NET 8 SDK. התוצר: out\DeviceGuard.exe (קובץ יחיד; השער והשירות נוצרים ממנו אוטומטית)
dotnet publish App\DeviceGuard.csproj -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -o out
echo.
echo Output: out\DeviceGuard.exe
