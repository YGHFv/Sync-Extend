param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('windows', 'ksu')][string]$Platform,
    [string]$AndroidNdk,
    [switch]$SkipBuild
)
$ErrorActionPreference = 'Stop'
$workspace = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
Set-Location -LiteralPath $workspace
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
$target = if ($Platform -eq 'windows') { 'x86_64-pc-windows-msvc' } else { 'aarch64-linux-android' }
$binaryName = if ($Platform -eq 'windows') { 'syncd.exe' } else { 'syncd' }
if ($Platform -eq 'ksu') {
    if (!$AndroidNdk) { throw '-AndroidNdk is required; no SDK download is performed' }
    $ndk = (Resolve-Path -LiteralPath $AndroidNdk).Path
    $tools = Join-Path $ndk 'toolchains/llvm/prebuilt/windows-x86_64/bin'
    $compiler = Join-Path $tools 'aarch64-linux-android26-clang.cmd'
    if (!(Test-Path -LiteralPath $compiler -PathType Leaf)) { throw 'Android API 26 clang missing' }
    $env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = $compiler
    $env:CC_aarch64_linux_android = $compiler
    $env:AR_aarch64_linux_android = Join-Path $tools 'llvm-ar.exe'
}
if (!$SkipBuild) {
    & cargo build -p sync-extend-daemon --release --locked --target $target
    if ($LASTEXITCODE -ne 0) { throw 'Release cross-build failed' }
}
$binary = Join-Path $workspace "target/$target/release/$binaryName"
if (!(Test-Path -LiteralPath $binary -PathType Leaf)) { throw 'Local release binary missing' }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$output = Join-Path $workspace ".local/packages/$Platform-$stamp-$([Guid]::NewGuid().ToString('N').Substring(0,8))"
# Fresh destinations only; no recursive deletion, reused package directory or overwrite.
if (Test-Path -LiteralPath $output) { throw 'Package destination already exists' }
New-Item -ItemType Directory -Path $output | Out-Null
$source = Join-Path $PSScriptRoot $Platform
if ($Platform -eq 'windows') {
    Copy-Item -LiteralPath (Join-Path $source 'run.ps1') -Destination $output
    Copy-Item -LiteralPath $binary -Destination (Join-Path $output $binaryName)
} else {
    foreach ($name in @('module.prop', 'config.example', 'common.sh', 'customize.sh', 'service.sh', 'action.sh', 'uninstall.sh')) {
        $text = [IO.File]::ReadAllText((Join-Path $source $name)).Replace("`r`n", "`n")
        [IO.File]::WriteAllText((Join-Path $output $name), $text, [Text.UTF8Encoding]::new($false))
    }
    New-Item -ItemType Directory -Path (Join-Path $output 'bin') | Out-Null
    Copy-Item -LiteralPath $binary -Destination (Join-Path $output 'bin/syncd')
}
$inputs = Get-ChildItem -LiteralPath $output -File -Recurse | ForEach-Object {
    "$((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash) $([IO.Path]::GetRelativePath($output, $_.FullName))"
}
$inputs | Set-Content -LiteralPath "$output.sha256" -Encoding ascii
Compress-Archive -Path (Join-Path $output '*') -DestinationPath "$output.zip"
Write-Output "Local package: $output.zip"
Write-Output 'Build/package evidence only. Device runtime certification remains separate.'
