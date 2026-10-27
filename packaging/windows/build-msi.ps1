# Build the pingrail installer on Windows: dist\pingrail-<version>-x64.msi.
#
# Needs MSYS2 (https://www.msys2.org), which provides the compiler, Rust and
# wixl. Install it once with:
#   winget install --id MSYS2.MSYS2
#
# Then, from the unpacked source folder, in PowerShell:
#   powershell -ExecutionPolicy Bypass -File packaging\windows\build-msi.ps1
#
# The first run installs MSYS2's build tools (a few hundred MB) and compiles
# everything, OpenSSL included, which takes several minutes.

param(
    # Where MSYS2 is installed.
    [string]$Msys2 = "C:\msys64"
)

$ErrorActionPreference = "Stop"
$bash = Join-Path $Msys2 "usr\bin\bash.exe"
if (-not (Test-Path $bash)) {
    Write-Error "MSYS2 isn't installed at $Msys2. Install it with: winget install --id MSYS2.MSYS2 (or pass -Msys2 <folder>)."
}

$src = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Set-Location $src
[Environment]::CurrentDirectory = $src

# Run bash commands in MSYS2's UCRT64 environment, in the source folder.
$env:MSYSTEM = "UCRT64"
$env:CHERE_INVOKING = "1"
function Invoke-Msys([string]$command) {
    # Show the output; return only the exit code.
    & $bash -lc $command | Out-Host
    return $LASTEXITCODE
}

Write-Host "==> Updating MSYS2 and installing build tools"
# A core update can end the first pass early; the second finishes it.
$null = Invoke-Msys "pacman -Syu --noconfirm"
$null = Invoke-Msys "pacman -Syu --noconfirm"
# perl and make build the OpenSSL that passkeys use, which is compiled into
# pingrail.exe (nothing extra to install on the machines that run it).
$packages = "mingw-w64-ucrt-x86_64-rust mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-msitools perl make"
if ((Invoke-Msys "pacman -S --needed --noconfirm $packages") -ne 0) {
    Write-Error "Installing the build tools failed. Open 'MSYS2 UCRT64' and run: pacman -S --needed $packages"
}

Write-Host "==> Building"
if ((Invoke-Msys "bash packaging/build-msi.sh") -ne 0) {
    Write-Error "The build failed (see the messages above)."
}

$msi = Get-ChildItem (Join-Path $src "dist") -Filter "pingrail-*-x64.msi" | Sort-Object LastWriteTime | Select-Object -Last 1
Write-Host ""
Write-Host "Installer: $($msi.FullName)"
