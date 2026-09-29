; Milky VPN — per-user installer (no admin rights needed).
; Build: flutter build windows --release, then ISCC.exe installer\windows.iss
#define MyAppName "Milky VPN"
#define MyAppVersion "1.0.0"
#define MyAppExe "milkyvpn.exe"

[Setup]
AppId={{9F2C1A3E-7B1D-4E5F-9A0B-M1LKYVPN0001}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=Milky
PrivilegesRequired=lowest
DefaultDirName={localappdata}\MilkyVPN
DefaultGroupName={#MyAppName}
OutputDir=..\build\installer
OutputBaseFilename=MilkyVPN-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "..\build\windows\x64\runner\Release\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Run]
Filename: "{app}\{#MyAppExe}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: postinstall nowait skipifsilent

[Code]
// Drain before replace: kal2-client gets 'stop' on its ctl socket (it closes
// sessions, restores routes, unloads the wintun adapter and exits), then we
// WAIT for it — force-kill is only a fallback for a wedged process, otherwise
// an abrupt kill mid-restore leaves orphaned /1 routes and a stale adapter.
// milkyvpn.exe gets a graceful WM_CLOSE first (taskkill without /F) for the
// same reason: let the app tear down its child and the system proxy cleanly.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Exec('powershell.exe', '-NoProfile -WindowStyle Hidden -Command "try { $c = New-Object System.Net.Sockets.TcpClient(''127.0.0.1'',11909); $w = New-Object System.IO.StreamWriter($c.GetStream()); $w.WriteLine(''stop''); $w.Flush(); $c.Close() } catch {}; try { Wait-Process -Name kal2-client -Timeout 20 } catch {}"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('taskkill.exe', '/F /IM kal2-client.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('taskkill.exe', '/IM milkyvpn.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('powershell.exe', '-NoProfile -WindowStyle Hidden -Command "try { Wait-Process -Name milkyvpn -Timeout 15 } catch {}"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('taskkill.exe', '/F /IM milkyvpn.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(500);
  Result := '';
end;
