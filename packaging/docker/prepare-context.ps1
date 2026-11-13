param(
    [Parameter(Mandatory=$true)][string]$Binary,
    [Parameter(Mandatory=$true)][string]$RuntimeImage,
    [Parameter(Mandatory=$true)][ValidateSet('amd64','arm64')][string]$Architecture,
    [Parameter(Mandatory=$true)][string]$Output
)
$ErrorActionPreference='Stop'
if ($RuntimeImage -notmatch '^[a-zA-Z0-9][a-zA-Z0-9./:_-]*@sha256:[0-9a-f]{64}$') {
    throw 'Supply an explicitly selected runtime image pinned by full sha256 digest'
}
$taskBinary=(Resolve-Path -LiteralPath $Binary).Path
$taskItem=Get-Item -LiteralPath $taskBinary
if ($taskItem.PSIsContainer -or ($taskItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Linux binary must be an exact regular file'
}
$taskStream=[IO.File]::OpenRead($taskBinary)
try {
    $taskHeader=New-Object byte[] 20
    if ($taskStream.Read($taskHeader,0,20) -ne 20 -or
        $taskHeader[0] -ne 0x7f -or $taskHeader[1] -ne 0x45 -or
        $taskHeader[2] -ne 0x4c -or $taskHeader[3] -ne 0x46 -or
        $taskHeader[4] -ne 2 -or $taskHeader[5] -ne 1) {
        throw '64-bit little-endian Linux ELF binary required'
    }
    $taskMachine=[BitConverter]::ToUInt16($taskHeader,18)
    if (($Architecture -eq 'amd64' -and $taskMachine -ne 62) -or
        ($Architecture -eq 'arm64' -and $taskMachine -ne 183)) {
        throw 'ELF machine differs from explicit architecture'
    }
} finally {$taskStream.Dispose()}
$taskOutput=[IO.Path]::GetFullPath($Output)
if (Test-Path -LiteralPath $taskOutput) {throw 'New bounded build-context directory required'}
New-Item -ItemType Directory -Path $taskOutput|Out-Null
Copy-Item -LiteralPath $taskBinary -Destination (Join-Path $taskOutput 'syncd')
foreach ($taskName in @('Dockerfile','entrypoint.sh')) {
    $taskText=[IO.File]::ReadAllText((Join-Path $PSScriptRoot $taskName)).Replace("`r`n","`n")
    [IO.File]::WriteAllText((Join-Path $taskOutput $taskName),$taskText,[Text.UTF8Encoding]::new($false))
}
@{runtime_image=$RuntimeImage;architecture=$Architecture;
    binary_sha256=(Get-FileHash -LiteralPath $taskBinary -Algorithm SHA256).Hash.ToLowerInvariant();
    context=$taskOutput;image_built=$false;runtime_tested=$false} |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $taskOutput 'build-inputs.json') -Encoding utf8
Write-Output 'Prepared local context only. Build with the explicit digest; remove context after verification.'
