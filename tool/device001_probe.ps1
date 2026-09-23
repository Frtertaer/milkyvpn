param(
    [Parameter(Mandatory=$true)][string]$Serial,
    [Parameter(Mandatory=$true)][ValidateSet('Auto','Finland','USA')][string]$Mode,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-z0-9_-]+$')][string]$Run
)
$ErrorActionPreference = 'Stop'
$adb = 'D:\vpnapp\.toolchains\android-sdk\platform-tools\adb.exe'
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root 'build\device001'
function Read-MilkyTree {
    & $adb -s $Serial shell uiautomator dump /sdcard/milky-device001.xml | Out-Null
    & $adb -s $Serial pull /sdcard/milky-device001.xml (Join-Path $out 'runner.local.xml') 2>$null | Out-Null
    [xml]$tree = Get-Content (Join-Path $out 'runner.local.xml')
    return $tree
}
function Tap-Node($node) {
    if($null -eq $node) { throw 'Expected MilkyVPN control absent; no tap performed.' }
    $m = [regex]::Match($node.bounds, '^\[(\d+),(\d+)\]\[(\d+),(\d+)\]$')
    if(-not $m.Success) { throw 'No valid control bounds' }
    $x = [int]( ([int]$m.Groups[1].Value + [int]$m.Groups[3].Value) / 2 )
    $y = [int]( ([int]$m.Groups[2].Value + [int]$m.Groups[4].Value) / 2 )
    & $adb -s $Serial shell input tap $x $y
}
$tree = Read-MilkyTree
if($tree.SelectNodes('//node') | Where-Object { $_.'content-desc' -eq 'Не удалось подключиться' }) {
    & $adb -s $Serial shell input keyevent 4
    $tree = Read-MilkyTree
}
$nodes = $tree.SelectNodes('//node[@package="homes.milky.vpn"]')
$disconnect = $nodes | Where-Object { $_.'content-desc' -like 'VPN подключён,*' } | Select-Object -First 1
if($disconnect) {
    Tap-Node $disconnect
    Start-Sleep -Seconds 2
    $tree = Read-MilkyTree
    $nodes = $tree.SelectNodes('//node[@package="homes.milky.vpn"]')
}
$label = @{Auto='Авто'; Finland='Финляндия'; USA='США'}[$Mode]
$location = $nodes | Where-Object { ($_.'content-desc' -split '\r?\n')[0] -eq $label -and $_.bounds -ne '[0,0][0,0]' } | Select-Object -First 1
Tap-Node $location
$orb = $nodes | Where-Object { $_.'content-desc' -like 'Не подключено,*' } | Select-Object -First 1
& $adb -s $Serial logcat -c
Tap-Node $orb
$clock = [Diagnostics.Stopwatch]::StartNew()
$file = Join-Path $out ($Run + '.local.log')
$connected = $false
$failures = 0
do {
    Start-Sleep -Seconds 2
    & $adb -s $Serial logcat -d -v threadtime MilkyVPN:I '*:S' > $file
    $log = Get-Content $file -Raw
    $connected = $log.Contains('stage=CONNECTED result=OK')
    $failures = [regex]::Matches($log, 'result=FAILED').Count
} while(-not $connected -and $failures -lt 4 -and $clock.Elapsed.TotalSeconds -lt 70)
$lastFailure = [regex]::Matches($log, 'stage=([A-Z_]+) result=FAILED lastSuccessfulStage=([A-Z_]+) code=([a-z_]+)') | Select-Object -Last 1
$result = [ordered]@{run=$Run; mode=$Mode; connected=$connected; postConnectProbe=$connected; failures=$failures; elapsedSeconds=[int]$clock.Elapsed.TotalSeconds}
if($lastFailure) { $result.firstFailedStage=$lastFailure.Groups[1].Value; $result.lastSuccessfulStage=$lastFailure.Groups[2].Value; $result.nativeCode=$lastFailure.Groups[3].Value }
$result | ConvertTo-Json | Set-Content (Join-Path $out ($Run + '.result.json'))
$result | ConvertTo-Json -Compress
