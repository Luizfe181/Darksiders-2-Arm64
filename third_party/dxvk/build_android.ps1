# build_android.ps1 -- fetches, patches and cross-builds DXVK 1.10.3 for
# aarch64-linux-android26, copying libdxvk_d3d11.so next to this script.
#
# It stops with a clear message on the prerequisites DXVK 1.10.3 needs and the
# Android build does not have yet; see README.md in this directory for the state.
param(
    [string]$Ndk        = 'C:\android-ndk-r27c',
    [string]$Work       = (Join-Path $PSScriptRoot '.build'),
    [string]$Version    = '1.10.3',
    [string]$Api        = '26',
    [string]$Meson      = ''
)

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$src  = Join-Path $Work "dxvk-$Version"

function Require-Tool([string]$name) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if (-not $cmd) {
        Write-Host "[!] '$name' nao encontrado no PATH." -ForegroundColor Red
        Write-Host "    DXVK 1.10.3 exige-o no build (ver README.md, Bloqueios)." -ForegroundColor Yellow
        return $false
    }
    Write-Host "[+] $name -> $($cmd.Source)"
    return $true
}

Write-Host "[*] DXVK $Version -> aarch64-linux-android$Api"

$ok = $true
# glslangValidator compila os shaders do DXVK no build.
$ok = (Require-Tool 'glslangValidator') -and $ok
# windres produz os recursos .rc das DLLs Windows.
$ok = (Require-Tool 'windres') -and $ok
if (-not (Test-Path (Join-Path $Ndk 'build\cmake\android.toolchain.cmake'))) {
    Write-Host "[!] NDK nao encontrado em $Ndk" -ForegroundColor Red
    $ok = $false
}
if (-not $ok) {
    Write-Host ""
    Write-Host "Parado antes de configurar: faltam pre-requisitos." -ForegroundColor Yellow
    Write-Host "O patch de WSI (patches/) aplica-se na mesma e esta verificado:" -ForegroundColor Yellow
    Write-Host "  git apply --check patches/0001-android-external-surface.patch" -ForegroundColor Gray
    exit 2
}

if (-not (Test-Path $Meson)) {
    $Meson = (Get-Command meson -ErrorAction SilentlyContinue).Source
    if (-not $Meson) { throw "meson nao encontrado; 'pip install meson'" }
}

New-Item -ItemType Directory -Force -Path $Work | Out-Null

if (-not (Test-Path $src)) {
    Write-Host "[*] a descarregar DXVK $Version"
    $tar = Join-Path $Work "dxvk-$Version.tar.gz"
    & curl.exe -L --fail --silent --show-error -o $tar `
        "https://github.com/doitsujin/dxvk/archive/refs/tags/v$Version.tar.gz"
    if ($LASTEXITCODE -ne 0) { throw "download falhou" }
    & tar.exe -xzf $tar -C $Work
}

Push-Location $src
try {
    Write-Host "[*] a aplicar patches"
    & git apply --check (Join-Path $here 'patches\0001-android-external-surface.patch')
    if ($LASTEXITCODE -ne 0) { throw "o patch nao aplica (arvore ja modificada?)" }
    & git apply (Join-Path $here 'patches\0001-android-external-surface.patch')
    if ($LASTEXITCODE -ne 0) { throw "git apply falhou" }
} finally {
    Pop-Location
}

$build = Join-Path $Work "build-android$Api"
Write-Host "[*] meson setup -> $build"
& $Meson setup $build $src --cross-file (Join-Path $here 'cross-android-arm64.ini') --buildtype release
if ($LASTEXITCODE -ne 0) { throw "meson setup falhou (ver Bloqueios no README)" }

& $Meson compile -C $build
if ($LASTEXITCODE -ne 0) { throw "meson compile falhou" }

$so = Get-ChildItem $build -Recurse -Filter 'libdxvk_d3d11.so' | Select-Object -First 1
if (-not $so) { throw "libdxvk_d3d11.so nao foi produzida" }
Copy-Item $so.FullName (Join-Path $here 'libdxvk_d3d11.so') -Force
Write-Host "[+] $(Join-Path $here 'libdxvk_d3d11.so')" -ForegroundColor Green
