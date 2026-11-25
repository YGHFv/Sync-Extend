param(
    [Parameter(Mandatory = $true)][string]$DataDir,
    [string]$Root,
    [ValidateRange(1, 86400)][int]$ScanIntervalSecs = 30,
    [ValidateSet('local','files','metadata-client','metadata-server')][string]$Mode = 'local',
    [string]$PeerDevice,
    [string]$Listen,
    [string]$Address,
    [ValidateRange(1, 64)][int]$MetadataRounds = 16
)
$ErrorActionPreference = 'Stop'
$binary = Join-Path $PSScriptRoot 'syncd.exe'
if (!(Test-Path -LiteralPath $binary -PathType Leaf)) {
    throw 'Locally built syncd.exe must be next to this launcher'
}
$data = [IO.Path]::GetFullPath($DataDir)
if (!(Test-Path -LiteralPath (Join-Path $data 'journal.sqlite'))) {
    if (!$Root) { throw 'First run requires an existing -Root directory' }
    $worktree = (Resolve-Path -LiteralPath $Root).Path
    & $binary init --data-dir $data --root $worktree
    if ($LASTEXITCODE -ne 0) { throw 'Initialization failed; existing data is preserved' }
}
& $binary status --data-dir $data
if ($LASTEXITCODE -ne 0) { throw 'Existing identity/worktree validation failed' }
Write-Host 'Foreground alpha; Ctrl+C stops. This is not an SCM service or automatic file sync.'
if ($Mode -eq 'files') {
    if ($PeerDevice -notmatch '\A[0-9a-f]{64}\z' -or !$Listen) {
        throw 'File-server mode requires -PeerDevice and explicit -Listen address'
    }
    & $binary serve-files --data-dir $data --peer-device $PeerDevice --listen $Listen
} elseif ($Mode -eq 'metadata-client') {
    if ($PeerDevice -notmatch '\A[0-9a-f]{64}\z' -or !$Address) {
        throw 'Metadata-client mode requires -PeerDevice and explicit -Address'
    }
    & $binary run-metadata --data-dir $data --peer-device $PeerDevice --address $Address `
        --rounds $MetadataRounds --interval-secs $ScanIntervalSecs
} elseif ($Mode -eq 'metadata-server') {
    if ($PeerDevice -notmatch '\A[0-9a-f]{64}\z' -or !$Listen) {
        throw 'Metadata-server mode requires -PeerDevice and explicit -Listen'
    }
    & $binary serve-metadata --data-dir $data --peer-device $PeerDevice --listen $Listen `
        --max-rounds $MetadataRounds
} else {
    & $binary run --data-dir $data --scan-interval-secs $ScanIntervalSecs
}
if ($LASTEXITCODE -ne 0) { throw "syncd exited with code $LASTEXITCODE" }
