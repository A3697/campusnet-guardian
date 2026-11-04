#define AppName "校园网连接守护"
#define AppVersion "0.1.2+desktop.20261104.3"
#define AppExe "校园网连接守护.exe"

[Setup]
AppId=CampusNetGuardian.Desktop
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=demo133 / campusnet contributors
AppPublisherURL=https://github.com/demo133/campusnet
AppSupportURL=https://github.com/A3697/campusnet-guardian
VersionInfoVersion=0.1.2.3
VersionInfoProductVersion=0.1.2.3
VersionInfoProductTextVersion={#AppVersion}
VersionInfoDescription={#AppName} 安装程序
VersionInfoCopyright=Copyright (c) 2026 campusnet contributors
DefaultDirName={code:DefaultInstallDir}
DisableDirPage=no
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
SetupArchitecture=x64
WizardStyle=modern
WizardSizePercent=110
DisableWelcomePage=no
DisableReadyPage=no
SetupIconFile=app_icon.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
UninstallFilesDir={app}
OutputDir=output
OutputBaseFilename=校园网连接守护-20261104.3-安装包
Compression=lzma2
SolidCompression=yes
CloseApplications=no
RestartApplications=no
SetupMutex=CampusNetGuardian.Installer
LicenseFile=payload\LICENSE
InfoBeforeFile=payload\使用说明.txt

[Languages]
Name: "zhcn"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"

[Tasks]
Name: "desktopicon"; Description: "在桌面“工具”文件夹创建快捷方式"; GroupDescription: "快捷方式："
Name: "startmenuicon"; Description: "创建开始菜单快捷方式"; GroupDescription: "快捷方式："
Name: "startup"; Description: "登录 Windows 后在托盘运行并自动连接（首次使用需填写账号）"; GroupDescription: "自动运行："

[Dirs]
Name: "{app}\profile"; Flags: uninsneveruninstall

[Files]
Source: "payload\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "payload\使用说明.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "payload\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "payload\AUTHORS.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "payload\源码与构建.zip"; DestDir: "{app}"; Flags: ignoreversion
Source: "payload\licenses\*"; DestDir: "{app}\licenses"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "payload\default-config.json"; DestDir: "{app}\profile"; DestName: "config.json"; Flags: onlyifdoesntexist uninsneveruninstall

[Icons]
Name: "{userdesktop}\工具\{#AppName}"; Filename: "{app}\{#AppExe}"; WorkingDir: "{app}"; Tasks: desktopicon
Name: "{userprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"; WorkingDir: "{app}"; Tasks: startmenuicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "campusnet"; ValueData: """{app}\{#AppExe}"" watch --config ""{app}\profile\config.json"" --desktop-startup"; Tasks: startup

[Run]
Filename: "{app}\{#AppExe}"; WorkingDir: "{app}"; Description: "打开{#AppName}"; Flags: nowait postinstall skipifsilent

[Code]
const
  RunKey = 'Software\Microsoft\Windows\CurrentVersion\Run';
  ApprovedKey = 'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run';

function DefaultInstallDir(Param: String): String;
begin
  if DirExists('D:\') then
    Result := 'D:\campusnet'
  else
    Result := ExpandConstant('{localappdata}\Programs\CampusNetGuardian');
end;

function IsOurExecutable(Path: String): Boolean;
begin
  Result := (CompareText(Path, ExpandConstant('{app}\{#AppExe}')) = 0) or
    (CompareText(Path, ExpandConstant('{app}\校园网助手.exe')) = 0);
end;

function CommandUsesExecutable(Command, Executable: String): Boolean;
var
  QuotedPrefix, PlainPrefix: String;
begin
  QuotedPrefix := '"' + Executable + '" ';
  PlainPrefix := Executable + ' ';
  Result := (CompareText(Copy(Command, 1, Length(QuotedPrefix)), QuotedPrefix) = 0) or
    (CompareText(Copy(Command, 1, Length(PlainPrefix)), PlainPrefix) = 0) or
    (CompareText(Command, '"' + Executable + '"') = 0) or
    (CompareText(Command, Executable) = 0);
end;

function OwnsStartupEntry: Boolean;
var
  Value: String;
begin
  Result := False;
  if not RegQueryStringValue(HKCU, RunKey, 'campusnet', Value) then begin
    Log('Startup entry is absent or unreadable.');
    Exit;
  end;
  Value := Trim(Value);
  Result := CommandUsesExecutable(Value, ExpandConstant('{app}\{#AppExe}')) or
    CommandUsesExecutable(Value, ExpandConstant('{app}\校园网助手.exe'));
  if Result then Log('Startup entry belongs to this install directory.')
    else Log('Startup entry belongs to a different install directory; kept.');
end;

procedure RemoveOwnedStartup;
begin
  if OwnsStartupEntry then begin
    if not RegDeleteValue(HKCU, RunKey, 'campusnet') then
      RaiseException('无法删除此程序的登录自启项，请重试卸载。');
    RegDeleteValue(HKCU, ApprovedKey, 'campusnet');
  end;
end;

function StopInstalledApp: String;
var
  Locator, Service, Processes, Process: Variant;
  I, Attempt, Remaining: Integer;
  ImagePath: String;
begin
  Result := '';
  try
    Locator := CreateOleObject('WbemScripting.SWbemLocator');
    Service := Locator.ConnectServer('', 'root\CIMV2');
    for Attempt := 1 to 12 do begin
      Remaining := 0;
      Processes := Service.ExecQuery('SELECT * FROM Win32_Process WHERE Name="{#AppExe}" OR Name="校园网助手.exe"');
      for I := 0 to Processes.Count - 1 do begin
        Process := Processes.ItemIndex(I);
        if not VarIsNull(Process.ExecutablePath) then begin
          ImagePath := Process.ExecutablePath;
          if IsOurExecutable(ImagePath) then begin
            Remaining := Remaining + 1;
            Log('Closing application in selected install directory: ' + ImagePath);
            Process.Terminate(0);
          end;
        end;
      end;
      if Remaining = 0 then Exit;
      Sleep(250);
    end;
    Result := '无法关闭安装目录中的程序。请先保存设置并退出此程序的主窗口和后台，然后重试。';
  except
    Result := '无法检查正在运行的程序：' + GetExceptionMessage;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := StopInstalledApp;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then begin
    if not WizardIsTaskSelected('startup') then
      RemoveOwnedStartup
    else if OwnsStartupEntry then
      RegDeleteValue(HKCU, ApprovedKey, 'campusnet');
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Error: String;
begin
  if CurUninstallStep = usUninstall then begin
    Error := StopInstalledApp;
    if Error <> '' then RaiseException(Error);
    RemoveOwnedStartup;
  end;
end;

function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo,
  MemoTypeInfo, MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
begin
  Result := MemoDirInfo + NewLine + NewLine + MemoTasksInfo + NewLine + NewLine +
    '安装会关闭此目录正在运行的主窗口和后台，请先保存设置。' + NewLine +
    '原有账号和重连配置会保留。首次安装后请填写自己的账号和密码。';
end;
