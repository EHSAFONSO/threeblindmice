; Instalador do Windows (Inno Setup 6). Gerado por packaging/windows/build.py, que passa:
;   /DAppVersion=0.7.0 /DSourceDir=<pasta do PyInstaller> /DOutputDir=<dist> /DIconFile=<.ico>
;
; Instala por usuário, sem pedir administrador (%LOCALAPPDATA%\Programs\threeblindmice).
; O AppUserModelID dos atalhos é o mesmo que o app define ao abrir: assim a janela
; fica agrupada sob o ícone fixado na barra de tarefas.

#ifndef AppVersion
  #error Rode via build.py (falta /DAppVersion)
#endif

[Setup]
AppId={{7F3E569F-EDB9-4D65-A8E2-370A7907512E}
AppName=threeblindmice
AppVersion={#AppVersion}
AppVerName=threeblindmice {#AppVersion}
AppPublisher=threeblindmice
AppPublisherURL=https://github.com/EHSAFONSO/threeblindmice
AppSupportURL=https://github.com/EHSAFONSO/threeblindmice/issues
AppUpdatesURL=https://github.com/EHSAFONSO/threeblindmice/releases
VersionInfoVersion={#AppVersion}
VersionInfoDescription=Instalador do threeblindmice
DefaultDirName={autopf}\threeblindmice
DefaultGroupName=threeblindmice
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#OutputDir}
OutputBaseFilename=threeblindmice_{#AppVersion}_x64-setup
SetupIconFile={#IconFile}
UninstallDisplayIcon={app}\threeblindmice.exe
UninstallDisplayName=threeblindmice
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ChangesEnvironment=yes
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
brazilianportuguese.AddToPath=Permitir usar o comando "tbm" no terminal (adiciona ao PATH)
english.AddToPath=Allow using the "tbm" command in a terminal (adds to PATH)
brazilianportuguese.Cmdline=Linha de comando:
english.Cmdline=Command line:

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "addtopath"; Description: "{cm:AddToPath}"; GroupDescription: "{cm:Cmdline}"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[InstallDelete]
; versões novas trocam bibliotecas: não deixar sobras da anterior misturadas
Type: filesandordirs; Name: "{app}\_internal"

[Icons]
Name: "{autoprograms}\threeblindmice"; Filename: "{app}\threeblindmice.exe"; AppUserModelID: "threeblindmice.desktop"; Comment: "Segurança da sua rede"
Name: "{autodesktop}\threeblindmice"; Filename: "{app}\threeblindmice.exe"; AppUserModelID: "threeblindmice.desktop"; Comment: "Segurança da sua rede"; Tasks: desktopicon

[Run]
Filename: "{app}\threeblindmice.exe"; Description: "{cm:LaunchProgram,threeblindmice}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; remove só os vigias (Agendador de Tarefas) criados por esta cópia instalada
Filename: "{app}\tbm.exe"; Parameters: "uninstall-cleanup"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveWatchTasks"

[Code]
const
  EnvKey = 'Environment';

function PathRoot: Integer;
begin
  if IsAdminInstallMode then Result := HKEY_LOCAL_MACHINE else Result := HKEY_CURRENT_USER;
end;

function PathKey: String;
begin
  if IsAdminInstallMode then
    Result := 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
  else
    Result := EnvKey;
end;

function PathHas(const Paths, Dir: String): Boolean;
begin
  Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Paths) + ';') > 0;
end;

procedure AddToPath(const Dir: String);
var
  Paths: String;
begin
  if not RegQueryStringValue(PathRoot, PathKey, 'Path', Paths) then Paths := '';
  if PathHas(Paths, Dir) then exit;
  // Preserva o estilo do PATH existente (com ou sem ';' no fim), para a
  // desinstalação devolver exatamente o valor original.
  if Paths = '' then
    Paths := Dir
  else if Copy(Paths, Length(Paths), 1) = ';' then
    Paths := Paths + Dir + ';'
  else
    Paths := Paths + ';' + Dir;
  RegWriteExpandStringValue(PathRoot, PathKey, 'Path', Paths);
end;

procedure RemoveFromPath(const Dir: String);
var
  Paths: String;
  P: Integer;
begin
  if not RegQueryStringValue(PathRoot, PathKey, 'Path', Paths) then exit;
  Paths := ';' + Paths + ';';
  P := Pos(';' + Uppercase(Dir) + ';', Uppercase(Paths));
  if P = 0 then exit;
  // apaga "<Dir>;" e mantém o ';' anterior; depois tira os dois ';' de embrulho
  Delete(Paths, P + 1, Length(Dir) + 1);
  Paths := Copy(Paths, 2, Length(Paths) - 2);
  RegWriteExpandStringValue(PathRoot, PathKey, 'Path', Paths);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and WizardIsTaskSelected('addtopath') then
    AddToPath(ExpandConstant('{app}'));
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveFromPath(ExpandConstant('{app}'));
end;
