# Final Fantasy XIII-2 X360 Save Editor

Windows save editor for **Final Fantasy XIII-2 on Xbox360**.

Extract the Windows ZIP and run `FFXIII2SaveEditor.exe` or `RUN_EDITOR.bat`.

## Build from source

Requirements:

- Windows 10/11 x64
- .NET 8 SDK

Build the editor with:

```powershell
dotnet restore FFXIII2SaveEditor\FFXIII2SaveEditor.csproj
dotnet build FFXIII2SaveEditor\FFXIII2SaveEditor.csproj -c Release
```

Create a self-contained Windows x64 folder build with:

```powershell
dotnet publish FFXIII2SaveEditor\FFXIII2SaveEditor.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -p:PublishReadyToRun=false
```
