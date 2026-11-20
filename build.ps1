# Builds Feverfew.exe, signs it, packages it as dist\setup.exe and signs that.
# Needs the .NET SDK (8 or later), Inno Setup 6 and Hawthorn (`hawthorn sign`, with a
# registered YubiKey plugged in): the PIN is asked once per batch and one touch covers each.
# -Unsigned: a local build without the key. Never release one (`hawthorn release` refuses it).
param([switch]$Unsigned)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

function Find-Hawthorn {
    $cmd = Get-Command hawthorn -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    # The shim lives in ~\bin, which only Git Bash has on PATH, and `hawthorn setup`'s PATH fix
    # reaches only programs started afterwards.
    $shim = Join-Path $HOME 'bin\hawthorn.cmd'
    if (Test-Path $shim) { return $shim }
    return $null
}

function Invoke-Sign([string[]]$Files) {
    if ($Unsigned) { Write-Host "not signed (-Unsigned): $($Files -join ', ')"; return }
    $hawthorn = Find-Hawthorn
    if (-not $hawthorn) {
        throw 'hawthorn not on PATH: run `python <Hawthorn>\hawthorn.py setup`, or build with -Unsigned'
    }
    & $hawthorn sign @Files
    if ($LASTEXITCODE -ne 0) { throw "hawthorn sign failed: $($Files -join ', ') not signed" }
}

[xml]$project = Get-Content 'src\Feverfew\Feverfew.csproj'
$version = ($project.Project.PropertyGroup | ForEach-Object { $_.Version } | Where-Object { $_ }) | Select-Object -First 1

dotnet build 'src\Feverfew\Feverfew.csproj' -c Release --nologo
if ($LASTEXITCODE -ne 0) { throw 'dotnet build failed' }

# Batch 1: the programs the installer packs (setup.iss [Files]), signed before they're packed.
Invoke-Sign @('src\Feverfew\bin\Release\net48\Feverfew.exe')

$iscc = @(
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw 'Inno Setup 6 not found. Install it with: winget install JRSoftware.InnoSetup' }

& $iscc /Qp "/DAppVersion=$version" 'installer\setup.iss'
if ($LASTEXITCODE -ne 0) { throw 'Inno Setup failed' }

# Batch 2: the installer.
Invoke-Sign @('dist\setup.exe')

$hash = (Get-FileHash 'dist\setup.exe' -Algorithm SHA256).Hash
Write-Host "dist\setup.exe  version $version  SHA256 $hash$(if ($Unsigned) { '  (UNSIGNED)' })"
