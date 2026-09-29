# Milky VPN — установщик. Рядом с этим файлом лежит payload.zip
# (самораспаковывающийся MilkyVPN-Setup.exe кладёт их во временную папку).
$ErrorActionPreference = 'Stop'
$src  = Split-Path -Parent $MyInvocation.MyCommand.Path
$zip  = Join-Path $src 'payload.zip'
$dest = Join-Path $env:LOCALAPPDATA 'MilkyVPN'

Write-Host '=== Milky VPN: установка ===' -ForegroundColor Cyan
Write-Host "Папка: $dest"

Get-Process milkyvpn -ErrorAction SilentlyContinue | Stop-Process -Force

New-Item -ItemType Directory -Force -Path $dest | Out-Null
Expand-Archive -Force -Path $zip -DestinationPath $dest
if (-not (Test-Path (Join-Path $dest 'milkyvpn.exe'))) {
    throw 'milkyvpn.exe не найден в payload.zip'
}

$wsh = New-Object -ComObject WScript.Shell
foreach ($lnkPath in @(
    (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Milky_VPN.lnk'),
    (Join-Path ([Environment]::GetFolderPath('StartMenu')) 'Programs\Milky_VPN.lnk')
)) {
    $lnk = $wsh.CreateShortcut($lnkPath)
    $lnk.TargetPath = Join-Path $dest 'milkyvpn.exe'
    $lnk.WorkingDirectory = $dest
    $lnk.Description = 'Milky VPN — KAL/2'
    $lnk.Save()
}

$un = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\MilkyVPN'
New-Item -Force -Path $un | Out-Null
Set-ItemProperty $un DisplayName 'Milky VPN'
Set-ItemProperty $un DisplayIcon (Join-Path $dest 'milkyvpn.exe')
Set-ItemProperty $un InstallLocation $dest
Set-ItemProperty $un UninstallString "powershell -NoProfile -ExecutionPolicy Bypass -File `"$dest\uninstall.ps1`""
Set-ItemProperty $un Publisher 'MilkyVPN'

@'
$d = $PSScriptRoot
Get-Process milkyvpn -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-Item -Recurse -Force $d -ErrorAction SilentlyContinue
Remove-Item -Force "$([Environment]::GetFolderPath('Desktop'))\Milky_VPN.lnk" -ErrorAction SilentlyContinue
Remove-Item -Force "$([Environment]::GetFolderPath('StartMenu'))\Programs\Milky_VPN.lnk" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\MilkyVPN' -ErrorAction SilentlyContinue
Write-Host 'Milky VPN удалён.'
'@ | Set-Content (Join-Path $dest 'uninstall.ps1') -Encoding UTF8

Write-Host ''
Write-Host 'Готово! Ярлык Milky_VPN на рабочем столе.' -ForegroundColor Green
$ans = Read-Host 'Запустить Milky VPN сейчас? [Y/n]'
if ($ans -notmatch '^[nN]') { Start-Process (Join-Path $dest 'milkyvpn.exe') }
