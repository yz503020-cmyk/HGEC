@echo off
dotnet publish App\DeviceGuard.csproj -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -o out
dotnet publish Gate\Gate.csproj -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -o out
echo Portable folder: out\ (DeviceGuard.exe + Gate.exe)
