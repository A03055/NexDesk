# Generates build/icon.png (512x512) and src/renderer/assets/icon.png for NexDesk.
param([string]$Root = (Split-Path -Parent $PSScriptRoot))
Add-Type -AssemblyName System.Drawing

function New-RoundRect([float]$x, [float]$y, [float]$w, [float]$h, [float]$r) {
  $p = New-Object System.Drawing.Drawing2D.GraphicsPath
  $d = $r * 2
  $p.AddArc($x, $y, $d, $d, 180, 90)
  $p.AddArc($x + $w - $d, $y, $d, $d, 270, 90)
  $p.AddArc($x + $w - $d, $y + $h - $d, $d, $d, 0, 90)
  $p.AddArc($x, $y + $h - $d, $d, $d, 90, 90)
  $p.CloseFigure()
  return $p
}

$S = 512
$bmp = New-Object System.Drawing.Bitmap $S, $S
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = 'AntiAlias'
$g.Clear([System.Drawing.Color]::Transparent)

$bg = New-RoundRect 16 16 480 480 140
$brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush (New-Object System.Drawing.Point 0, 0), (New-Object System.Drawing.Point $S, $S), ([System.Drawing.Color]::FromArgb(255, 124, 92, 255)), ([System.Drawing.Color]::FromArgb(255, 34, 211, 238))
$blend = New-Object System.Drawing.Drawing2D.ColorBlend 3
$blend.Colors = @([System.Drawing.Color]::FromArgb(255, 124, 92, 255), [System.Drawing.Color]::FromArgb(255, 79, 124, 255), [System.Drawing.Color]::FromArgb(255, 34, 211, 238))
$blend.Positions = @(0.0, 0.5, 1.0)
$brush.InterpolationColors = $blend
$g.FillPath($brush, $bg)


$pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::White), 32
$pen.StartCap = 'Round'; $pen.EndCap = 'Round'; $pen.LineJoin = 'Round'

# monitor
$mon = New-RoundRect 117 138 278 182 38
$g.DrawPath($pen, $mon)
# stand
$g.DrawLine($pen, 256, 320, 256, 384)
$g.DrawLine($pen, 202, 384, 310, 384)
# check mark
$g.DrawLines($pen, @((New-Object System.Drawing.Point 213, 230), (New-Object System.Drawing.Point 245, 262), (New-Object System.Drawing.Point 302, 200)))

$g.Dispose()
New-Item -ItemType Directory -Force (Join-Path $Root 'build') | Out-Null
New-Item -ItemType Directory -Force (Join-Path $Root 'src\renderer\assets') | Out-Null
$bmp.Save((Join-Path $Root 'build\icon.png'), [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Save((Join-Path $Root 'src\renderer\assets\icon.png'), [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Output 'icon ok'
