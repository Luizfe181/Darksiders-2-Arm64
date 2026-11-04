# build_apk.ps1 -- builds the native library and packages the boot-test APK.
#
#   1. CMake + NDK r27c, stand-alone: proves the native side builds with the
#      same toolchain Gradle will use (and fails loudly instead of inside AGP).
#   2. Gradle assembleDebug, which re-runs CMake through externalNativeBuild and
#      produces the APK.
#
# Output: dist\darksiders2-boot-test.apk
param(
    [string]$Ndk    = 'C:\android-ndk-r27c',
    [string]$Sdk    = "$env:LOCALAPPDATA\Android\Sdk",
    [string]$Api    = '26',
    [string]$Abi    = 'arm64-v8a',
    [string]$Sdl2Dir = '',
    [switch]$SkipNative,
    [switch]$SkipGradle
)

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot                          # ...\source\android
$project = $here                               # o modulo Gradle + CMakeLists
$root = Split-Path (Split-Path $here -Parent) -Parent   # repo root
$dist = Join-Path $root 'dist'
$cmake = 'C:\Program Files\CMake\bin\cmake.exe'
if (-not (Test-Path $cmake)) { $cmake = (Get-Command cmake -ErrorAction SilentlyContinue).Source }

function Fail($message) {
    Write-Host "[!] $message" -ForegroundColor Red
    exit 1
}

Write-Host "[*] Darksiders II - APK de boot test ($Abi, API $Api)"

if (-not (Test-Path "$Ndk\build\cmake\android.toolchain.cmake")) { Fail "NDK nao encontrado em $Ndk" }
if (-not (Test-Path "$Sdk\platforms")) { Fail "Android SDK nao encontrado em $Sdk" }
if (-not $cmake) { Fail "cmake nao encontrado" }

# local.properties: AGP le sdk.dir e ndk.dir daqui.
$lp = Join-Path $project 'local.properties'
$escapedSdk = $Sdk -replace '\\', '\\' -replace ':', '\:'
$escapedNdk = $Ndk -replace '\\', '\\' -replace ':', '\:'
@"
# Gerado por build_apk.ps1 -- caminhos desta maquina, nao versionar.
sdk.dir=$escapedSdk
ndk.dir=$escapedNdk
"@ | Set-Content -Path $lp -Encoding ascii
Write-Host "[+] local.properties -> sdk.dir / ndk.dir"

# --- 1. Nativo, fora do Gradle -------------------------------------------
if (-not $SkipNative) {
    $build = Join-Path $root 'out\cmake_ndk_sdl'
    Write-Host "[*] CMake configure -> $build"
    $cmakeArgs = @(
        '-S', $project, '-B', $build, '-G', 'Ninja',
        "-DCMAKE_TOOLCHAIN_FILE=$Ndk\build\cmake\android.toolchain.cmake",
        "-DANDROID_ABI=$Abi",
        "-DANDROID_PLATFORM=android-$Api",
        '-DANDROID_STL=c++_shared'
    )
    if ($Sdl2Dir) { $cmakeArgs += "-DSDL2_DIR=$Sdl2Dir" }
    & $cmake @cmakeArgs 2>&1 | Select-Object -Last 3
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[i] Configure falhou: SDL2 tem de estar instalado ou vendorizado." -ForegroundColor Yellow
        Write-Host "    Passe -Sdl2Dir <dir com SDL2Config.cmake> ou coloque o SDL2 em" -ForegroundColor Yellow
        Write-Host "    source/android/third_party/SDL2 (o CMake prefere essa via)." -ForegroundColor Yellow
        Fail "CMake configure falhou"
    }
    & $cmake --build $build 2>&1 | Select-Object -Last 4
    if ($LASTEXITCODE -ne 0) { Fail "CMake build falhou" }
    Write-Host "[+] libdarksiders2_runtime.so construida"
}

# --- 2. APK ---------------------------------------------------------------
if ($SkipGradle) {
    Write-Host "[i] -SkipGradle: a parar depois do nativo."
    exit 0
}

Write-Host "[*] Gradle assembleDebug"
Push-Location $project
try {
    if (Test-Path (Join-Path $project 'gradlew.bat')) {
        & (Join-Path $project 'gradlew.bat') assembleDebug
    } elseif (Get-Command gradle -ErrorAction SilentlyContinue) {
        & gradle assembleDebug
    } else {
        Write-Host "[!] Sem gradlew.bat nem 'gradle' no PATH." -ForegroundColor Red
        Write-Host "    Gere o wrapper uma vez com um Gradle instalado:" -ForegroundColor Yellow
        Write-Host "      gradle wrapper --gradle-version 8.1.2" -ForegroundColor Gray
        Write-Host "    (ou instale o Gradle 8.1.x e volte a correr este script)" -ForegroundColor Yellow
        exit 2
    }
    if ($LASTEXITCODE -ne 0) { Fail "Gradle assembleDebug falhou" }
} finally {
    Pop-Location
}

# --- 3. Recolher o APK ----------------------------------------------------
$apk = Get-ChildItem (Join-Path $project 'app\build\outputs\apk\debug') -Filter '*.apk' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $apk) { Fail "APK nao encontrado em app\build\outputs\apk\debug" }

New-Item -ItemType Directory -Force -Path $dist | Out-Null
$target = Join-Path $dist 'darksiders2-boot-test.apk'
Copy-Item $apk.FullName $target -Force
Write-Host "[+] $target ($([math]::Round($apk.Length/1MB,1)) MB)" -ForegroundColor Green
