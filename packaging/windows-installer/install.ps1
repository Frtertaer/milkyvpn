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
Get-Process milkyvpn,kal2-client -ErrorAction SilentlyContinue | Stop-Process -Force
# Restore the system proxy if it still points at our dead SOCKS listener —
# otherwise every browser stays broken after uninstall.
$is = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$cur = (Get-ItemProperty -Path $is -Name ProxyServer -ErrorAction SilentlyContinue).ProxyServer
if ($cur -eq 'socks=127.0.0.1:11808') {
  Remove-ItemProperty -Path $is -Name ProxyServer -ErrorAction SilentlyContinue
  Set-ItemProperty -Path $is -Name ProxyEnable -Value 0
  $sig = '[DllImport("wininet.dll")] public static extern bool InternetSetOption(System.IntPtr h,int o,System.IntPtr b,int l);'
  $t = Add-Type -MemberDefinition $sig -Name W -Namespace I -PassThru
  [void]$t::InternetSetOption([System.IntPtr]::Zero,39,[System.IntPtr]::Zero,0)
  [void]$t::InternetSetOption([System.IntPtr]::Zero,37,[System.IntPtr]::Zero,0)
}
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
