# Собирает MilkyVPN-Setup.exe через встроенный iexpress.
#   -PayloadDir : папка с файлами приложения (milkyvpn.exe, data\, kal2\kal2-client.exe)
#   -OutDir     : куда положить MilkyVPN-Setup.exe
param(
    [Parameter(Mandatory=$true)][string]$PayloadDir,
    [Parameter(Mandatory=$true)][string]$OutDir
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

$stage = Join-Path $env:TEMP ('milkyvpn-setup-' + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Force $stage | Out-Null

# Приложение → один zip (iexpress плющит деревья; zip сохраняет структуру)
Compress-Archive -Path (Join-Path $PayloadDir '*') -DestinationPath (Join-Path $stage 'payload.zip') -Force
Copy-Item -Force (Join-Path $here 'install.ps1') (Join-Path $stage 'install.ps1')

$target = Join-Path $OutDir 'MilkyVPN-Setup.exe'

$sed = @"
[Version]
Class=IEXPRESS
SEDVersion=3
[Options]
PackagePurpose=InstallApp
ShowInstallProgramWindow=0
HideExtractAnimation=0
UseLongFileName=1
InsideCompressed=0
CAB_FixedSize=0
CAB_ResvCodeSigning=0
RebootMode=N
InstallPrompt=%InstallPrompt%
DisplayLicense=%DisplayLicense%
FinishMessage=%FinishMessage%
TargetName=%TargetName%
FriendlyName=%FriendlyName%
AppLaunched=%AppLaunched%
PostInstallCmd=%PostInstallCmd%
AdminQuietInstCmd=%AdminQuietInstCmd%
UserQuietInstCmd=%UserQuietInstCmd%
SourceFiles=SourceFiles
[Strings]
InstallPrompt=Установить Milky VPN на этот компьютер?
DisplayLicense=
FinishMessage=Milky VPN установлен. Ярлык на рабочем столе: Milky_VPN.
TargetName=$target
FriendlyName=Milky VPN Setup
AppLaunched=powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1
PostInstallCmd=<None>
AdminQuietInstCmd=
UserQuietInstCmd=
FILE0="payload.zip"
FILE1="install.ps1"
[SourceFiles]
SourceFiles0=$stage\
[SourceFiles0]
%FILE0%
%FILE1%
"@

$sedPath = Join-Path $stage 'milkyvpn.sed'
Set-Content $sedPath $sed -Encoding ASCII
& "$env:WINDIR\System32\iexpress.exe" /N /Q $sedPath
if ($LASTEXITCODE -ne 0) { throw "iexpress exited $LASTEXITCODE" }
if (-not (Test-Path $target)) { throw 'setup exe not produced' }
$mb = [math]::Round((Get-Item $target).Length / 1MB, 1)
Write-Host "Built: $target  $mb MB"
