#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Worktree,
    [string]$ProfileDirectory = (Join-Path $env:LOCALAPPDATA 'SyncExtend\client'),
    [string]$Binary = (Join-Path $PSScriptRoot 'syncd.exe'),
    [ValidateRange(1024, 65535)][int]$ManagementPort = 17423,
    [ValidateRange(1, 86400)][int]$ScanIntervalSeconds = 30,
    [switch]$EnableReadOnlyWebdav,
    [ValidateRange(1024, 65535)][int]$WebdavPort = 17842
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-common.ps1')

$root = Resolve-SyncExtendPath $Worktree -Directory
$profilePath = Resolve-SyncExtendPath $ProfileDirectory
$binaryPath = Resolve-SyncExtendPath $Binary -File
if (Test-Path -LiteralPath $profilePath) { throw 'Choose a new client profile directory.' }
$rootPrefix = $root.TrimEnd('\') + '\'
if ($profilePath.Equals($root, [StringComparison]::OrdinalIgnoreCase) -or
    $profilePath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Choose a profile outside the worktree so private state cannot enter sync.'
}
if ($EnableReadOnlyWebdav -and $WebdavPort -eq $ManagementPort) {
    throw 'Use different management and WebDAV ports.'
}
[void][IO.Directory]::CreateDirectory($profilePath)
$statePath = Join-Path $profilePath 'data'
$managementPath = Join-Path $profilePath 'management.json'
$deploymentPath = Join-Path $profilePath 'deployment.json'
Write-SyncExtendJson $managementPath @{
    format_version = 1
    address = "127.0.0.1:$ManagementPort"
    token_file = (Join-Path $profilePath 'management.token')
    token_protection = 'windows_user'
    request_timeout_secs = 3
    max_connections = 1000000
    control = @{ status = $true; stop = $true; dashboard = $true; max_control_requests = 32 }
}
$null = Invoke-SyncExtendJson $binaryPath @('management-credentials-generate', '--config', $managementPath)
$initialized = Invoke-SyncExtendJson $binaryPath @('init', '--data-dir', $statePath, '--root', $root) -TimeoutMs 60000
$role = @{ kind = 'local_polling'; data_dir = $statePath; scan_interval_secs = $ScanIntervalSeconds }
$gatewayPath = $null
if ($EnableReadOnlyWebdav) {
    $gatewayPath = New-SyncExtendReadOnlyGateway $profilePath $statePath $initialized.space_id $WebdavPort $binaryPath
    $role = @{ kind = 'webdav_client'; gateway_config = $gatewayPath; scan_interval_secs = $ScanIntervalSeconds }
}
Write-SyncExtendJson $deploymentPath @{
    format_version = 1
    management = $managementPath
    role = $role
}
$null = Invoke-SyncExtendJson $binaryPath @('deployment-check', '--config', $deploymentPath)
[pscustomobject]@{ Deployment = $deploymentPath; Management = $managementPath; Data = $statePath; Worktree = $root; Webdav = $gatewayPath }
