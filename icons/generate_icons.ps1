Add-Type -AssemblyName System.Drawing

$basePath = $PSScriptRoot + "\"
$sizes = @(16, 48, 128)

foreach ($s in $sizes) {
    $bmp = New-Object System.Drawing.Bitmap $s, $s
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'

    # Dark background
    $bgColor = [System.Drawing.Color]::FromArgb(10, 14, 23)
    $g.Clear($bgColor)

    # Shield outline (teal)
    $teal = [System.Drawing.Color]::FromArgb(34, 211, 238)
    $penWidth = [Math]::Max(1, $s * 0.04)
    $pen = New-Object System.Drawing.Pen($teal, $penWidth)

    $cx = $s / 2.0
    $points = @(
        (New-Object System.Drawing.PointF(($cx), ($s * 0.12))),
        (New-Object System.Drawing.PointF(($s * 0.82), ($s * 0.28))),
        (New-Object System.Drawing.PointF(($s * 0.82), ($s * 0.58))),
        (New-Object System.Drawing.PointF(($cx), ($s * 0.9))),
        (New-Object System.Drawing.PointF(($s * 0.18), ($s * 0.58))),
        (New-Object System.Drawing.PointF(($s * 0.18), ($s * 0.28)))
    )
    $g.DrawPolygon($pen, $points)

    # Center dot (eye)
    $brush = New-Object System.Drawing.SolidBrush($teal)
    $r = [Math]::Max(2, $s * 0.12)
    $eyeY = $cx * 1.05
    $g.FillEllipse($brush, [float]($cx - $r), [float]($eyeY - $r), [float]($r * 2), [float]($r * 2))

    # Pupil
    $brushDark = New-Object System.Drawing.SolidBrush($bgColor)
    $r2 = [Math]::Max(1, $s * 0.05)
    $g.FillEllipse($brushDark, [float]($cx - $r2), [float]($eyeY - $r2), [float]($r2 * 2), [float]($r2 * 2))

    $g.Dispose()
    $outPath = $basePath + "icon" + $s + ".png"
    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    Write-Host "Created icon${s}.png at $outPath"
}
