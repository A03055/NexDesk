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

# ---- Splash shown by the portable launcher while it unpacks (24-bit BMP) ----
$W = 480; $H = 280
$sp = New-Object System.Drawing.Bitmap $W, $H, ([System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
$sg = [System.Drawing.Graphics]::FromImage($sp)
$sg.SmoothingMode = 'AntiAlias'; $sg.TextRenderingHint = 'AntiAliasGridFit'
$sg.Clear([System.Drawing.Color]::FromArgb(255, 11, 13, 23))
$glow = New-Object System.Drawing.Drawing2D.GraphicsPath
$glow.AddEllipse(-60, -140, 600, 360)
$pgb = New-Object System.Drawing.Drawing2D.PathGradientBrush $glow
$pgb.CenterColor = [System.Drawing.Color]::FromArgb(255, 40, 30, 90)
$pgb.SurroundColors = @([System.Drawing.Color]::FromArgb(255, 11, 13, 23))
$sg.FillPath($pgb, $glow)
$logo = [System.Drawing.Image]::FromFile((Join-Path $Root 'build\icon.png'))
$sg.DrawImage($logo, [int](($W - 96) / 2), 46, 96, 96)
$logo.Dispose()
$fmt = New-Object System.Drawing.StringFormat; $fmt.Alignment = 'Center'
$f1 = New-Object System.Drawing.Font('Segoe UI Semibold', 22)
$f2 = New-Object System.Drawing.Font('Segoe UI', 10)
$sg.DrawString('NexDesk', $f1, [System.Drawing.Brushes]::White, (New-Object System.Drawing.RectangleF 0, 156, $W, 40), $fmt)
$sub = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 141, 147, 173))
$trText = 'Starting... / Ba' + [char]0x015F + 'lat' + [char]0x0131 + 'l' + [char]0x0131 + 'yor...'
$sg.DrawString($trText, $f2, $sub, (New-Object System.Drawing.RectangleF 0, 204, $W, 24), $fmt)
$bar = New-Object System.Drawing.Drawing2D.LinearGradientBrush (New-Object System.Drawing.Point 140, 0), (New-Object System.Drawing.Point 340, 0), ([System.Drawing.Color]::FromArgb(255, 124, 92, 255)), ([System.Drawing.Color]::FromArgb(255, 34, 211, 238))
$sg.FillRectangle($bar, 190, 240, 100, 3)
$sg.Dispose()
$sp.Save((Join-Path $Root 'build\splash.bmp'), [System.Drawing.Imaging.ImageFormat]::Bmp)
$sp.Dispose()
Write-Output 'splash ok'
