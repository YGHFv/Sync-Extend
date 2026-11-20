#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateSet('install', 'start', 'status', 'stop', 'upgrade', 'rollback', 'uninstall', 'webdav-enable', 'webdav-disable')][string]$Action,
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'SyncExtend\install'),
    [string]$Package = (Join-Path $PSScriptRoot 'package.json'),
    [string]$Deployment = (Join-Path $env:LOCALAPPDATA 'SyncExtend\client\deployment.json'),
    [ValidateRange(1024, 65535)][int]$WebdavPort = 17842,
    [ValidatePattern('\A[0-9a-f]{32}\z')][string]$OwnerGeneration
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-common.ps1')

$root = Resolve-SyncExtendPath $InstallRoot
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$markerPath = Join-Path $root 'owner.json'
$statePath = Join-Path $root 'state.json'
$versions = Join-Path $root 'versions'

if (!(Test-Path -LiteralPath $root)) {
    if ($Action -notin @('install', 'start')) { throw 'Install this client package first.' }
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetOwner($sid)
    $security.SetAccessRuleProtection($true, $false)
    $security.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($root))
    [IO.FileSystemAclExtensions]::Create([IO.DirectoryInfo]::new($root), $security)
    Write-SyncExtendJson $markerPath @{ format_version = 1; application = 'SyncExtend'; owner_sid = $sid.Value }
}
$marker = Read-SyncExtendJson $markerPath 4096
$security = Get-Acl -LiteralPath $root
$identity = $security.GetOwner([Security.Principal.SecurityIdentifier])
$rules = @($security.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
if ($marker.format_version -ne 1 -or $marker.application -cne 'SyncExtend' -or $marker.owner_sid -cne $sid.Value -or
    $identity -ne $sid -or !$security.AreAccessRulesProtected -or $rules.Count -ne 1 -or
    $rules[0].IdentityReference -ne $sid -or $rules[0].AccessControlType -ne 'Allow') {
    throw 'The install directory must be owned and accessible only by the current user.'
}

function Get-PackageImage {
    param($Manifest)
    if ($Manifest.Count -ne 7 -or $Manifest.format_version -ne 1 -or $Manifest.application -cne 'SyncExtend' -or
        $Manifest.target -cne 'x86_64-pc-windows-msvc' -or $Manifest.binary -cne 'syncd.exe' -or
        $Manifest.version_id -cnotmatch '\A[a-z0-9][a-z0-9._-]{0,63}\z' -or $Manifest.version_id.EndsWith('.') -or
        $Manifest.version_id -match '\A(?:con|aux|nul|prn|com[0-9]|lpt[0-9])(?:\.|$)' -or
        $Manifest.sha256 -cnotmatch '\A[0-9a-f]{64}\z' -or
        $Manifest.bytes -isnot [long] -or $Manifest.bytes -lt 1 -or $Manifest.bytes -gt 536870912) {
        throw 'Use a valid locally built SyncExtend Windows package.'
    }
    return (Join-Path (Join-Path $versions $Manifest.version_id) 'syncd.exe')
}

function Confirm-PackageImage {
    param([string]$Path, $Manifest)
    $imagePath = Resolve-SyncExtendPath $Path -File
    if ((Get-Item -LiteralPath $imagePath).Length -ne $Manifest.bytes -or
        (Get-FileHash -LiteralPath $imagePath -Algorithm SHA256).Hash -ne $Manifest.sha256) {
        throw 'The package executable differs from its declared size or hash.'
    }
    return $imagePath
}

function Install-Package {
    param([string]$ManifestPath)
    $manifestPath = Resolve-SyncExtendPath $ManifestPath -File
    $manifest = Read-SyncExtendJson $manifestPath 4096
    $imagePath = Get-PackageImage $manifest
    $source = Confirm-PackageImage (Join-Path ([IO.Path]::GetDirectoryName($manifestPath)) 'syncd.exe') $manifest
    $directory = [IO.Path]::GetDirectoryName($imagePath)
    if (Test-Path -LiteralPath $directory) {
        $stored = Read-SyncExtendJson (Join-Path $directory 'package.json') 4096
        $null = Get-PackageImage $stored
        if ($stored.sha256 -cne $manifest.sha256 -or $stored.version_id -cne $manifest.version_id -or
            $stored.bytes -ne $manifest.bytes) { throw 'This version is already installed with different content.' }
    } else {
        $staging = Resolve-SyncExtendPath (Join-Path $versions ('.new-' + [Guid]::NewGuid().ToString('N')))
        [void][IO.Directory]::CreateDirectory($staging)
        $stageImage = Join-Path $staging 'syncd.exe'
        [IO.File]::Copy($source, $stageImage, $false)
        $null = Confirm-PackageImage $stageImage $manifest
        Write-SyncExtendJson (Join-Path $staging 'package.json') $manifest
        [IO.Directory]::Move($staging, $directory)
    }
    $null = Confirm-PackageImage $imagePath $manifest
    return $manifest
}

function Get-OwnedProcess {
    param($Record)
    try { $process = [Diagnostics.Process]::GetProcessById([int]$Record.pid) }
    catch [ArgumentException] { return }
    $keep = $false
    try {
        if ($process.HasExited -or $process.StartTime.ToFileTimeUtc().ToString() -cne $Record.birth -or
            ![string]::Equals($process.MainModule.FileName, $Record.image, [StringComparison]::OrdinalIgnoreCase)) { return }
        $null = $process.Handle
        $keep = $true
        return $process
    } finally { if (!$keep) { $process.Dispose() } }
}

function Save-State($Record) {
    Write-SyncExtendJson $statePath $Record -Replace
}

function Get-GatewayBinding([string]$Image, [string]$Config, $Profile) {
    if ($Profile.role.kind -cne 'webdav_client') { return }
    # The CLI checks that the gateway config remains inside this deployment's
    # private directory. Remember its exact content alongside the deployment.
    $summary = Invoke-SyncExtendJson $Image @('deployment-check', '--config', $Config, '--describe-webdav')
    $path = Resolve-SyncExtendPath $Profile.role.gateway_config -File
    return [pscustomobject]@{ path = $path; sha256 = (Get-FileHash -LiteralPath $path).Hash;
        enabled = $summary.webdav.enabled }
}

function Start-Installed {
    param($Selected, [string]$Config, $Previous)
    $image = Confirm-PackageImage (Get-PackageImage $Selected) $Selected
    $deploymentPath = Resolve-SyncExtendPath $Config -File
    $profile = Read-SyncExtendJson $deploymentPath
    $managementPath = Resolve-SyncExtendPath $profile.management -File
    $null = Invoke-SyncExtendJson $image @('deployment-check', '--config', $deploymentPath)
    $gateway = Get-GatewayBinding $image $deploymentPath $profile
    $check = Invoke-SyncExtendJson $image @('management-check', '--config', $managementPath)
    if (!$check.status_allowed -or !$check.stop_allowed -or $check.token_protection -ne 'windows_user') {
        throw 'Enable status and stop with a current-user protected management credential in the profile.'
    }
    $authority = [Net.IPEndPoint]::Parse((Read-SyncExtendJson $managementPath).address)
    $probe = [Net.Sockets.TcpListener]::new($authority)
    try { $probe.ExclusiveAddressUse = $true; $probe.Start() }
    finally { $probe.Stop() }
    $logName = [Guid]::NewGuid().ToString('N')
    $logRoot = Resolve-SyncExtendPath (Join-Path $root 'logs')
    [void][IO.Directory]::CreateDirectory($logRoot)
    $record = @{
        format_version = 1; state = 'starting'; owner_sid = $sid.Value; selected = $Selected; previous = $Previous
        deployment = $deploymentPath; management = $managementPath
        deployment_sha256 = (Get-FileHash -LiteralPath $deploymentPath -Algorithm SHA256).Hash
        management_sha256 = (Get-FileHash -LiteralPath $managementPath -Algorithm SHA256).Hash
    }
    if ($gateway) {
        $record.gateway = $gateway.path
        $record.gateway_sha256 = $gateway.sha256
    }
    $child = Start-Process -FilePath $image -ArgumentList @('deployment-run', '--config', ('"' + $deploymentPath + '"')) `
        -WorkingDirectory ([IO.Path]::GetDirectoryName($image)) -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $logRoot "$logName.out") -RedirectStandardError (Join-Path $logRoot "$logName.err")
    try {
        $record.process = @{ pid = $child.Id; birth = $child.StartTime.ToFileTimeUtc().ToString(); image = $image }
        Save-State $record
        $deadline = [Diagnostics.Stopwatch]::StartNew()
        while (!$child.HasExited -and $deadline.Elapsed.TotalSeconds -lt 25) {
            $status = $null
            try { $status = Invoke-SyncExtendJson $image @('management-status', '--config', $managementPath) -TimeoutMs 6000 }
            catch { }
            if (!$child.HasExited -and $status.resources_ready) {
                $record.state = 'running'
                $record.owner_generation = $status.owner_generation
                Save-State $record
                return $record
            }
            Start-Sleep -Milliseconds 150
        }
        throw 'The deployment did not reach authenticated readiness.'
    } catch {
        if (!$child.HasExited) { $child.Kill(); [void]$child.WaitForExit(5000) }
        $record.state = 'startup_failed'
        if ($child.HasExited) { $record.exit_code = $child.ExitCode }
        Save-State $record
        throw
    } finally { $child.Dispose() }
}

function Confirm-Configuration($Record) {
    if ((Get-FileHash -LiteralPath $Record.deployment -Algorithm SHA256).Hash -cne $Record.deployment_sha256 -or
        (Get-FileHash -LiteralPath $Record.management -Algorithm SHA256).Hash -cne $Record.management_sha256 -or
        ($Record.gateway -and ((Get-FileHash -LiteralPath (Resolve-SyncExtendPath $Record.gateway -File)).Hash -cne $Record.gateway_sha256))) {
        throw 'The active configuration changed. Restore its file contents before stopping or switching versions.'
    }
}

function Stop-Installed($Record) {
    if ($Record.state -cne 'running') { throw 'No healthy current-user deployment is recorded.' }
    if ($OwnerGeneration -and $OwnerGeneration -cne $Record.owner_generation) {
        throw 'The running client no longer matches this session. Refresh and retry.'
    }
    Confirm-Configuration $Record
    $process = Get-OwnedProcess $Record.process
    if (!$process) { throw 'The recorded deployment process is unavailable.' }
    try {
        $image = Confirm-PackageImage (Get-PackageImage $Record.selected) $Record.selected
        $status = Invoke-SyncExtendJson $image @('management-status', '--config', $Record.management)
        if ($status.owner_generation -cne $Record.owner_generation) { throw 'The authenticated deployment owner changed.' }
        $null = Invoke-SyncExtendJson $image @('management-stop', '--config', $Record.management, '--owner-generation',
            $Record.owner_generation, '--request-id', [Guid]::NewGuid().ToString('N'))
        if (!$process.WaitForExit(30000)) { throw 'The deployment did not exit within 30 seconds.' }
        $Record.exit_code = $process.ExitCode
        $Record.state = if ($process.ExitCode -eq 0) { 'stopped' } else { 'failed' }
        Save-State $Record
        if ($process.ExitCode -ne 0) { throw 'The recorded deployment exited with an error.' }
        return $Record
    } finally { $process.Dispose() }
}

function Set-InstalledGateway($Record, [bool]$Enable, [int]$Port) {
    if (!$Record -or $Record.state -cne 'running') { throw 'Start the installed local client before changing WebDAV.' }
    if (![string]::Equals((Resolve-SyncExtendPath $Deployment -File), $Record.deployment, [StringComparison]::OrdinalIgnoreCase) -or
        ($OwnerGeneration -and $OwnerGeneration -cne $Record.owner_generation)) {
        throw 'The running client no longer matches this profile. Refresh and retry.'
    }
    Confirm-Configuration $Record
    $image = Confirm-PackageImage (Get-PackageImage $Record.selected) $Record.selected
    $deploymentPath = Resolve-SyncExtendPath $Record.deployment -File
    $profile = Read-SyncExtendJson $deploymentPath
    $role = $profile.role
    if ($role.kind -cnotin @('local_polling', 'webdav_client')) {
        throw 'WebDAV can be changed here only for a local client profile.'
    }
    $gateway = Get-GatewayBinding $image $deploymentPath $profile
    if ($Enable -and $gateway -and $gateway.enabled) { throw 'WebDAV is already enabled in this profile.' }
    if (!$Enable -and (!$gateway -or !$gateway.enabled)) { throw 'WebDAV is already disabled in this profile.' }
    if ($Enable -and !$gateway -and $Port -eq [Net.IPEndPoint]::Parse((Read-SyncExtendJson $Record.management).address).Port) {
        throw 'Use a different WebDAV port from local management.'
    }
    if ($gateway -and !$role.scan_interval_secs) {
        throw 'Set a polling interval in the stopped gateway-only deployment before using this switch.'
    }
    # Verify the live process through its authenticated generation and wait
    # for it to release the worktree before editing the existing deployment.
    $null = Stop-Installed $Record
    $restorePath = $null
    $original = $null
    try {
        if ($gateway) {
            $config = Read-SyncExtendJson $gateway.path
            $config.listener.enabled = $Enable
            $restorePath = $gateway.path
            $original = [IO.File]::ReadAllBytes($restorePath)
            Write-SyncExtendJson $restorePath $config -Replace
            $null = Invoke-SyncExtendJson $image @('webdav-check', '--config', $restorePath)
        } else {
            $directory = [IO.Path]::GetDirectoryName($deploymentPath)
            $data = Resolve-SyncExtendPath $role.data_dir -Directory
            $space = Invoke-SyncExtendJson $image @('status', '--data-dir', $data)
            $gatewayPath = New-SyncExtendReadOnlyGateway $directory $data $space.space_id $Port $image
            $restorePath = $deploymentPath
            $original = [IO.File]::ReadAllBytes($restorePath)
            $profile.role = @{ kind = 'webdav_client'; gateway_config = $gatewayPath;
                scan_interval_secs = $role.scan_interval_secs }
            Write-SyncExtendJson $restorePath $profile -Replace
        }
        $running = Start-Installed $Record.selected $deploymentPath $Record.previous
        return [pscustomobject]@{ enabled = $Enable; deployment = $deploymentPath; gateway = $running.gateway;
            owner_generation = $running.owner_generation }
    } catch {
        $failure = $_.Exception.Message
        try {
            if ($original) { Write-SyncExtendBytes $restorePath $original -Replace }
            $null = Start-Installed $Record.selected $deploymentPath $Record.previous
        } catch {
            throw "The WebDAV change failed and the previous deployment could not restart. Check this profile and its logs. $failure"
        }
        throw "The WebDAV setting was not applied. The previous local deployment was restarted. $failure"
    }
}

$lockPath = Resolve-SyncExtendPath (Join-Path $root 'operation.lock')
$lock = [IO.File]::Open($lockPath, 'OpenOrCreate', 'ReadWrite', 'None')
try {
    $record = if (Test-Path -LiteralPath $statePath) { Read-SyncExtendJson $statePath }
    if ($record -and ($record.format_version -ne 1 -or $record.owner_sid -cne $sid.Value)) { throw 'Install state ownership differs.' }
    switch ($Action) {
        'install' { Install-Package $Package }
        'start' {
            if ($record.process -and $record.state -in @('running', 'starting')) {
                $process = Get-OwnedProcess $record.process
                if ($process) { $process.Dispose(); throw 'The current-user deployment is still running.' }
            }
            $selected = Install-Package $Package
            $previous = if ($record.selected.version_id -ceq $selected.version_id) { $record.previous } else { $record.selected }
            Start-Installed $selected $Deployment $previous
        }
        'status' {
            if (!$record) { throw 'Start an installed version first.' }
            $process = if ($record.process) { Get-OwnedProcess $record.process }
            try {
                $health = if ($record.state -eq 'running' -and $process) {
                    $image = Confirm-PackageImage (Get-PackageImage $record.selected) $record.selected
                    $status = Invoke-SyncExtendJson $image @('management-status', '--config', $record.management)
                    if ($status.owner_generation -ceq $record.owner_generation) { $status }
                }
                [pscustomobject]@{ state = $record.state; version = $record.selected.version_id;
                    process_active = [bool]$process; management = $health }
            } finally { if ($process) { $process.Dispose() } }
        }
        'stop' {
            if ($OwnerGeneration -and ![string]::Equals((Resolve-SyncExtendPath $Deployment -File),
                    $record.deployment, [StringComparison]::OrdinalIgnoreCase)) {
                throw 'The running client no longer matches this profile. Refresh and retry.'
            }
            Stop-Installed $record
        }
        'webdav-enable' { Set-InstalledGateway $record $true $WebdavPort }
        'webdav-disable' { Set-InstalledGateway $record $false $WebdavPort }
        { $_ -in @('upgrade', 'rollback') } {
            if ($record.state -cne 'running') { throw 'Start the installed version before switching versions.' }
            $selected = if ($Action -eq 'upgrade') { Install-Package $Package } else { $record.previous }
            if (!$selected -or $selected.version_id -ceq $record.selected.version_id) { throw 'Choose a different installed version.' }
            $null = Confirm-PackageImage (Get-PackageImage $selected) $selected
            $null = Stop-Installed $record
            try { Start-Installed $selected $record.deployment $record.selected }
            catch {
                $null = Start-Installed $record.selected $record.deployment $record.previous
                throw 'The version switch failed. The last running version was restored.'
            }
        }
        'uninstall' {
            if (!$record) { throw 'There is no managed deployment to retire.' }
            if ($record.state -eq 'running') {
                $process = Get-OwnedProcess $record.process
                if ($process) { $process.Dispose(); $record = Stop-Installed $record }
            }
            if ($record.state -eq 'starting') { throw 'Resolve the pending deployment start first.' }
            $record.state = 'uninstalled'
            Save-State $record
            [pscustomobject]@{ uninstalled = $true; profile = $record.deployment; retained_versions = $versions }
        }
    }
} finally { $lock.Dispose() }
