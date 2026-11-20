#Requires -Version 7.0
[CmdletBinding()]
param(
    [string]$ProfileDirectory = (Join-Path $env:LOCALAPPDATA 'SyncExtend\client'),
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'SyncExtend\install'),
    [string]$Worktree,
    [ValidateRange(1024, 65535)][int]$ManagementPort = 17423,
    [switch]$Snapshot
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-common.ps1')
$profilePath = Resolve-SyncExtendPath $ProfileDirectory
$deploymentPath = Join-Path $profilePath 'deployment.json'
$binaryPath = Join-Path $PSScriptRoot 'syncd.exe'
$manage = Join-Path $PSScriptRoot 'manage-user.ps1'
if (!(Test-Path -LiteralPath $deploymentPath -PathType Leaf)) {
    if (!$Worktree) {
        if ($Snapshot) { throw 'Specify -Worktree when creating a client without the folder picker.' }
        Add-Type -AssemblyName System.Windows.Forms
        $picker = [Windows.Forms.FolderBrowserDialog]::new()
        try {
            $picker.Description = 'Choose the folder SyncExtend will watch.'
            if ($picker.ShowDialog() -ne 'OK') { return }
            $Worktree = $picker.SelectedPath
        } finally { $picker.Dispose() }
    }
    $null = & (Join-Path $PSScriptRoot 'configure-client.ps1') -Worktree $Worktree `
        -ProfileDirectory $profilePath -Binary $binaryPath -ManagementPort $ManagementPort
}
$profile = Read-SyncExtendJson $deploymentPath
if (!(Test-Path -LiteralPath (Join-Path $InstallRoot 'state.json') -PathType Leaf)) {
    $null = & $manage start -InstallRoot $InstallRoot -Deployment $deploymentPath
} else {
    $current = & $manage status -InstallRoot $InstallRoot
    if (!$current.process_active) {
        $null = & $manage start -InstallRoot $InstallRoot -Deployment $deploymentPath
    }
}
& (Join-Path $PSScriptRoot 'client.ps1') -Deployment $deploymentPath -Binary $binaryPath -Snapshot:$Snapshot
