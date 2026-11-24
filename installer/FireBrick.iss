; FireBrick — Windows Firewall Control
; Inno Setup 6 Installer Script

#define MyAppName "FireBrick"
#define MyAppFullName "FireBrick — Windows Firewall Control"
#define MyAppPublisher "FireBrick"
#define MyAppURL "https://github.com/piyushagade/FireBrick"
#define MyAppExeName "FireBrick.App.exe"
#define MyServiceName "FireBrickService"

#ifndef MyAppVersion
  #define MyAppVersion "1.2.0"
#endif

#ifndef MyAppNumericVersion
  #define MyAppNumericVersion "1.2.0.0"
#endif

#ifndef SourceDir
  #define SourceDir "..\publish\app"
#endif

#ifndef OutputDir
  #define OutputDir "..\release"
#endif

[Setup]
AppId={{A7F4C2D8-9E3B-4B15-8D6E-2F1C3A4E5B6D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
VersionInfoVersion={#MyAppNumericVersion}
VersionInfoProductName={#MyAppFullName}
VersionInfoProductVersion={#MyAppNumericVersion}
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppFullName} Setup
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
OutputDir={#OutputDir}
OutputBaseFilename=FireBrick-Setup-{#MyAppVersion}-win-x64
SetupIconFile=..\src\FireBrick.App\Assets\FireBrick.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppFullName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
MinVersion=10.0.17763

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "installservice"; Description: "Install and start the FireBrick background firewall service (Recommended)"; GroupDescription: "System Integration:"
Name: "autostart"; Description: "Start FireBrick automatically when Windows starts"; GroupDescription: "System Integration:"
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "{#MyAppName}"; ValueData: """{app}\{#MyAppExeName}"""; Flags: uninsdeletevalue; Tasks: autostart

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[Code]
procedure StopFireBrickProcesses();
var
  ResultCode: Integer;
begin
  Exec('sc.exe', 'stop {#MyServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec('taskkill.exe', '/F /IM {#MyAppExeName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Sleep(1500);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  StopFireBrickProcesses();
  Result := '';
end;

procedure InstallOrUpdateService();
var
  ServiceExe: String;
  PsCommand: String;
  ResultCode: Integer;
begin
  ServiceExe := ExpandConstant('{app}\service\FireBrick.Service.exe');
  if not FileExists(ServiceExe) then
    Exit;

  PsCommand :=
    '-NoProfile -ExecutionPolicy Bypass -Command "' +
    '$svc = Get-Service -Name ''{#MyServiceName}'' -ErrorAction SilentlyContinue; ' +
    'if ($svc) { ' +
    '  if ($svc.Status -ne ''Stopped'') { sc.exe stop {#MyServiceName} | Out-Null; Start-Sleep -Seconds 2 }; ' +
    '  sc.exe config {#MyServiceName} binPath= ''\"' + ServiceExe + '\"'' start= auto DisplayName= ''FireBrick Firewall Service'' | Out-Null; ' +
    '} else { ' +
    '  sc.exe create {#MyServiceName} binPath= ''\"' + ServiceExe + '\"'' start= auto DisplayName= ''FireBrick Firewall Service'' | Out-Null; ' +
    '}; ' +
    'sc.exe description {#MyServiceName} ''Privileged background firewall monitoring and rule enforcement service for FireBrick.'' | Out-Null; ' +
    'sc.exe failure {#MyServiceName} reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null; ' +
    'sc.exe start {#MyServiceName} | Out-Null"';

  Exec('powershell.exe', PsCommand, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and WizardIsTaskSelected('installservice') then
  begin
    InstallOrUpdateService();
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    StopFireBrickProcesses();
    Exec('sc.exe', 'delete {#MyServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(1000);
  end;
end;
