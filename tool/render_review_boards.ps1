Add-Type -AssemblyName System.Drawing
$project = Split-Path -Parent $PSScriptRoot
$source = Join-Path $project 'test\features\goldens'
$target = Join-Path $project 'design\flutter-v2'
New-Item -ItemType Directory -Path $target -Force | Out-Null
Get-ChildItem -LiteralPath $source -Filter *.png | Copy-Item -Destination $target
$groups = @(
  @('home_disconnected_dark','home_connecting','home_connected_finland','home_connected_usa','home_disconnected_light','home_connecting_finland'),
  @('onboarding_1','onboarding_2','onboarding_3','subscription','settings','diagnostics'),
  @('failure_sheet','import_success','remove_subscription','diagnostics_details','home_small','home_large'),
  @('home_tablet','tablet_landscape')
)
$index = 0
foreach ($group in $groups) {
  $index++
  $cellW = 340; $cellH = 760; $cols = 3
  if ($index -eq 4) { $cellW = 540; $cols = 2 }
  $rows = [int][Math]::Ceiling($group.Count / $cols)
  $board = [Drawing.Bitmap]::new($cols * $cellW, $rows * $cellH)
  $g = [Drawing.Graphics]::FromImage($board)
  $g.Clear([Drawing.Color]::FromArgb(238,237,242))
  $g.InterpolationMode = [Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
  $font = [Drawing.Font]::new('Segoe UI',11)
  for ($i = 0; $i -lt $group.Count; $i++) {
    $im = [Drawing.Image]::FromFile((Join-Path $source ($group[$i]+'.png')))
    $scale = [Math]::Min(($cellW-20)/$im.Width, ($cellH-42)/$im.Height)
    $w = [int]($im.Width*$scale); $h = [int]($im.Height*$scale)
    $x = ($i%$cols)*$cellW+[int](($cellW-$w)/2)
    $y = [int][Math]::Floor($i/$cols)*$cellH+32
    $g.DrawString($group[$i],$font,[Drawing.Brushes]::Black,[single]$x,[single]($y-26))
    $g.DrawImage($im,$x,$y,$w,$h)
    $im.Dispose()
  }
  $board.Save((Join-Path $target ("review-board-$index.png")),[Drawing.Imaging.ImageFormat]::Png)
  $font.Dispose(); $g.Dispose(); $board.Dispose()
}
