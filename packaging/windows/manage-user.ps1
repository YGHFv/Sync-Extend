#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [ValidateSet('install', 'start', 'resume', 'status', 'stop', 'upgrade', 'rollback', 'uninstall', 'webdav-enable', 'webdav-disable',
        'restore', 'restore-resume')][string]$Action,
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'SyncExtend\install'),
    [string]$Package = (Join-Path $PSScriptRoot 'package.json'),
    [string]$Deployment = (Join-Path $env:LOCALAPPDATA 'SyncExtend\client\deployment.json'),
    [ValidateRange(1024, 65535)][int]$WebdavPort = 17842,
    [ValidatePattern('\A[0-9a-f]{32}\z')][string]$OwnerGeneration,
    [string]$RestoreRequestHex,
    [ValidatePattern('\A[0-9a-f]{64}\z')][string]$RestorePreviewDigest,
    [long]$RestorePreviewAtMs,
    [string]$RestoreBudgets,
    [ValidatePattern('\A[0-9a-f]{32}\z')][string]$RestoreTransaction,
    [switch]$AllowIrreversibleAdmission,
    [switch]$AllowNonAtomicTree
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-common.ps1')
. (Join-Path $PSScriptRoot 'client-view.ps1')

$root = Resolve-SyncExtendPath $InstallRoot
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
$markerPath = Join-Path $root 'owner.json'
$statePath = Join-Path $root 'state.json'
$versions = Join-Path $root 'versions'
$pendingRestorePath = Join-Path $root 'pending-restore.json'
$script:restoreLaunchPending = $null

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
        if ($script:restoreLaunchPending) {
            $script:restoreLaunchPending.restart_process = $record.process
            Save-PendingRestore $script:restoreLaunchPending
        }
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
        if (!$child.HasExited) { $child.Kill() }
        $child.WaitForExit()
        $record.state = 'startup_failed'
        $record.exit_code = $child.ExitCode
        $record.process_exit_verified = $true
        if ($record.process) {
            $record.exit_receipt = @{
                pid = $child.Id; birth = $record.process.birth; image = $record.process.image
                actual_wait = $true; exit_code = $child.ExitCode
                failed_restore_restart = [bool]$script:restoreLaunchPending
            }
        }
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

function Stop-Installed($Record, [string]$RequestId = [Guid]::NewGuid().ToString('N')) {
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
            $Record.owner_generation, '--request-id', $RequestId)
        if (!$process.WaitForExit(30000)) { throw 'The deployment did not exit within 30 seconds.' }
        $Record.exit_code = $process.ExitCode
        $Record.process_exit_verified = $true
        $Record.exit_receipt = @{
            pid = $process.Id; birth = $Record.process.birth; image = $Record.process.image
            actual_wait = $true; exit_code = $process.ExitCode
        }
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

function Save-PendingRestore($Pending) {
    if ($Pending.format_version -ne 1 -or $Pending.owner_sid -cne $sid.Value) {
        throw 'Pending restoration ownership differs.'
    }
    $Pending.updated_at_ms = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    Write-SyncExtendJson $pendingRestorePath $Pending -Replace
}

function Get-PendingRestore {
    if (!(Test-Path -LiteralPath $pendingRestorePath)) { return }
    $pending = Read-SyncExtendJson $pendingRestorePath 262144
    if ($pending.format_version -ne 1 -or $pending.owner_sid -cne $sid.Value) {
        throw 'Pending restoration ownership or version differs.'
    }
    Assert-SyncExtendViewId $pending.transaction_id 32
    $request = ConvertFrom-SyncExtendRestoreRequestHex $pending.request_hex
    foreach ($flag in @('stop_requested', 'original_process_exit_verified', 'owner_creation_requested',
            'owner_ready_verified', 'execution_requested', 'native_final_verified', 'restart_requested')) {
        Assert-SyncExtendViewFlag $pending[$flag]
    }
    if ($pending.space_id -cne $request.request.space_id -or $pending.baseline_snapshot -cne $request.request.expected_baseline -or
        $pending.target_snapshot -cne $request.request.snapshot -or $pending.original_owner_generation -cne $request.owner_generation) {
        throw 'Pending restoration fields differ from its exact original request.'
    }
    if ((Get-SyncExtendRestoreByteDigest ([Convert]::FromHexString($pending.request_hex))) -cne $pending.request_sha256 -or
        (Get-SyncExtendRestoreObjectDigest (Get-SyncExtendRestoreTreeScope $request)) -cne $pending.scope_sha256) {
        throw 'Pending restoration exact request or native scope changed.'
    }
    if ($pending.budget_hex.Length -gt 131072 -or $pending.budget_hex.Length % 2 -ne 0 -or
        $pending.budget_hex -cnotmatch '\A[0-9a-f]+\z') { throw 'Pending budget bytes are invalid.' }
    $budgetBytes = [Convert]::FromHexString($pending.budget_hex)
    if ($budgetBytes.Length -ne $pending.budget_bytes -or
        (Get-SyncExtendRestoreByteDigest $budgetBytes) -cne $pending.budget_sha256) {
        throw 'Pending restoration raw budget digest changed.'
    }
    return $pending
}

function Confirm-RestoreBinding($Pending, $Record) {
    if (!$Record -or $Record.owner_sid -cne $sid.Value -or
        ![string]::Equals((Resolve-SyncExtendPath $Deployment -File), $Pending.deployment, [StringComparison]::OrdinalIgnoreCase) -or
        ![string]::Equals($Record.deployment, $Pending.deployment, [StringComparison]::OrdinalIgnoreCase) -or
        ![string]::Equals($Record.management, $Pending.management, [StringComparison]::OrdinalIgnoreCase) -or
        ![string]::Equals($Record.gateway, $Pending.gateway, [StringComparison]::OrdinalIgnoreCase) -or
        $Record.selected.version_id -cne $Pending.selected.version_id -or
        $Record.selected.sha256 -cne $Pending.selected.sha256 -or $Record.selected.bytes -ne $Pending.selected.bytes -or
        $Record.deployment_sha256 -cne $Pending.deployment_sha256 -or
        $Record.management_sha256 -cne $Pending.management_sha256 -or
        $Record.gateway_sha256 -cne $Pending.gateway_sha256) {
        throw 'The pending restoration requires its exact original installed version and configuration.'
    }
    Confirm-Configuration $Record
    $image = Confirm-PackageImage (Get-PackageImage $Pending.selected) $Pending.selected
    if (![string]::Equals($image, $Pending.image, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The pending restoration executable path changed.'
    }
    $inputs = Resolve-SyncExtendPath (Join-Path (Join-Path $root 'restore') $Pending.transaction_id) -Directory
    $budgetPath = Resolve-SyncExtendPath $Pending.budget_path -File
    if (![string]::Equals($budgetPath, (Join-Path $inputs 'budgets.json'), [StringComparison]::OrdinalIgnoreCase) -or
        (Get-Item -LiteralPath $budgetPath).Length -ne $Pending.budget_bytes -or
        (Get-FileHash -LiteralPath $budgetPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Pending.budget_sha256) {
        throw 'The pending restoration private budget input changed.'
    }
    $dataDirectory = Resolve-SyncExtendPath $Pending.data_dir -Directory
    $profileDirectory = Get-RestoreDataDirectory (Read-SyncExtendJson $Pending.deployment) $Pending.space_id
    if (![string]::Equals($dataDirectory, $profileDirectory, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The original deployment-to-workspace mapping changed.'
    }
}

function Get-RestoreDataDirectory($Profile, [string]$Space) {
    if ($Profile.role.kind -cin @('local_polling', 'metadata_client', 'metadata_server')) {
        return Resolve-SyncExtendPath $Profile.role.data_dir -Directory
    }
    if ($Profile.role.kind -ceq 'webdav_client') {
        $gateway = Read-SyncExtendJson (Resolve-SyncExtendPath $Profile.role.gateway_config -File)
        if (!(@($gateway.spaces.Keys) -ccontains $Space)) { throw 'This WebDAV profile does not own the selected space.' }
        return Resolve-SyncExtendPath $gateway.spaces[$Space] -Directory
    }
    throw 'Native history restoration requires a managed local workspace role.'
}

function Test-OwnedProcessActive($ProcessRecord) {
    if (!$ProcessRecord) { return $false }
    $process = Get-OwnedProcess $ProcessRecord
    try { return [bool]$process }
    finally { if ($process) { $process.Dispose() } }
}

function Invoke-InstalledRestoreJson($Pending, [string[]]$Arguments) {
    # Native effects are never cancelled by a UI timer. Retain and wait the
    # actual original process, then consume both original stream tasks.
    $child = New-SyncExtendProcess $Pending.image $Arguments -Capture
    $stdout = $null
    $stderr = $null
    $birth = $null
    $receiptSaved = $false
    try {
        $null = $child.Handle
        $birth = $child.StartTime.ToFileTimeUtc().ToString()
        $stdout = $child.StandardOutput.ReadToEndAsync()
        $stderr = $child.StandardError.ReadToEndAsync()
        $Pending.active_command = @{
            name = $Arguments[0]; pid = $child.Id
            birth = $birth; image = $Pending.image
        }
        Save-PendingRestore $Pending
        $child.WaitForExit()
        $Pending.last_command = @{
            name = $Arguments[0]; pid = $child.Id; birth = $birth
            actual_wait = $true; exit_code = $child.ExitCode; image = $Pending.image
        }
        $Pending.command_count = [long]$Pending.command_count + 1
        $Pending.active_command = $null
        Save-PendingRestore $Pending
        $receiptSaved = $true
        $result = $stdout.GetAwaiter().GetResult()
        $null = $stderr.GetAwaiter().GetResult()
        if ($child.ExitCode -ne 0) { throw "The $($Arguments[0]) command was refused (exit $($child.ExitCode))." }
        if ([Text.Encoding]::UTF8.GetByteCount($result) -gt 1100000) { throw 'The native restoration response exceeds its bound.' }
        return ConvertFrom-Json -InputObject $result -AsHashtable -ErrorAction Stop
    } finally {
        try {
            $child.WaitForExit()
            if (!$receiptSaved -and $birth) {
                $Pending.last_command = @{
                    name = $Arguments[0]; pid = $child.Id; birth = $birth
                    actual_wait = $true; exit_code = $child.ExitCode; image = $Pending.image
                }
                $Pending.active_command = $null
                Save-PendingRestore $Pending
            }
            if ($stdout) { $null = $stdout.GetAwaiter().GetResult() }
            if ($stderr) { $null = $stderr.GetAwaiter().GetResult() }
        } finally { $child.Dispose() }
    }
}

function Confirm-PreviousRestoreCommandClosed($Pending) {
    if (!$Pending.active_command) { return }
    $process = Get-OwnedProcess $Pending.active_command
    if (!$process) {
        # This is an explicit continuation. Native reopen audits the durable
        # lineage; missing process alone never supplies an exit-code receipt.
        $Pending.interrupted_command = $Pending.active_command.name
        $Pending.active_command = $null
        Save-PendingRestore $Pending
        return
    }
    try {
        if (!$process.WaitForExit(30000)) { throw 'The original native restoration helper is still active.' }
        $Pending.last_command = @{
            name = $Pending.active_command.name; pid = $process.Id; birth = $Pending.active_command.birth
            image = $Pending.active_command.image; actual_wait = $true; exit_code = $process.ExitCode
        }
        $Pending.active_command = $null
        Save-PendingRestore $Pending
    } finally { $process.Dispose() }
}

function Stop-RestoreOriginal($Pending, $Record) {
    $original = $Pending.original_process
    if ($Record.process.pid -ne $original.pid -or $Record.process.birth -cne $original.birth -or
        ![string]::Equals($Record.process.image, $original.image, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The original deployment process identity changed before restoration.'
    }
    $process = Get-OwnedProcess $original
    try {
        if ($Record.state -ceq 'stopped' -and $Record.owner_generation -ceq $Pending.original_owner_generation -and
            $Record.exit_code -eq 0 -and $Record.process_exit_verified -ceq $true -and
            $Record.exit_receipt.actual_wait -ceq $true -and $Record.exit_receipt.exit_code -eq 0 -and
            $Record.exit_receipt.pid -eq $original.pid -and $Record.exit_receipt.birth -ceq $original.birth -and
            [string]::Equals($Record.exit_receipt.image, $original.image, [StringComparison]::OrdinalIgnoreCase) -and !$process) {
            $Pending.original_process_exit_verified = $true
            $Pending.phase = 'stopped'
            Save-PendingRestore $Pending
            return $Record
        }
        if (!$process -or $Record.state -cne 'running' -or $Record.owner_generation -cne $Pending.original_owner_generation) {
            throw 'The original process exit was not verified; native restoration remains refused.'
        }
        $status = $null
        try { $status = Invoke-SyncExtendJson $Pending.image @('management-status', '--config', $Pending.management) }
        catch { if (!$Pending.stop_requested) { throw } }
        if ($status) {
            if ($status.owner_generation -cne $Pending.original_owner_generation) { throw 'The authenticated original owner changed.' }
            $Pending.stop_requested = $true
            $Pending.phase = 'stop_requested'
            Save-PendingRestore $Pending
            $Record = Stop-Installed $Record $Pending.stop_request_id
        } else {
            if (!$process.WaitForExit(30000)) { throw 'The previously stopped original owner has not exited.' }
            $Record.exit_code = $process.ExitCode
            $Record.process_exit_verified = $true
            $Record.exit_receipt = @{
                pid = $process.Id; birth = $original.birth; image = $original.image
                actual_wait = $true; exit_code = $process.ExitCode
            }
            $Record.state = if ($process.ExitCode -eq 0) { 'stopped' } else { 'failed' }
            Save-State $Record
            if ($process.ExitCode -ne 0) { throw 'The original owner exited with an error; restoration remains stopped.' }
        }
        $Pending.original_process_exit_verified = $true
        $Pending.phase = 'stopped'
        Save-PendingRestore $Pending
        return $Record
    } finally { if ($process) { $process.Dispose() } }
}

function Confirm-RestorePreparation($Pending, $Preparation) {
    if ($Preparation.intent.transaction_id -cne $Pending.transaction_id -or
        (Get-SyncExtendRestoreObjectDigest $Preparation.intent.scope) -cne $Pending.scope_sha256) {
        throw 'Native preparation transaction or exact selection scope changed.'
    }
    $budgets = ConvertFrom-Json -InputObject ([Text.UTF8Encoding]::new($false, $true).GetString(
        [Convert]::FromHexString($Pending.budget_hex))) -AsHashtable
    if ((Get-SyncExtendRestoreObjectDigest $Preparation.intent.limits) -cne
            (Get-SyncExtendRestoreObjectDigest $budgets.plan)) { throw 'Native plan budgets changed.' }
    $checks = @(
        @{ value = $Preparation.history_reservation.intent.history.limits; budget = 'history' }
        @{ value = $Preparation.native_reservation.intent.request.limits; budget = 'identity' }
        @{ value = $Preparation.execution_description.intent.input.limits; budget = 'execution' }
        @{ value = $Preparation.original_pins.request.limits; budget = 'originals' }
        @{ value = $Preparation.coordinator_admission.request.limits; budget = 'coordinator' }
        @{ value = $Preparation.native_storage.request.layout_limits; budget = 'actions' }
        @{ value = $Preparation.native_storage.request.inventory_limits; budget = 'inventory' }
        @{ value = $Preparation.native_future_admission.request.layout_limits; budget = 'future' }
        @{ value = $Preparation.native_future_admission.request.inventory_limits; budget = 'inventory' }
    )
    foreach ($check in $checks) {
        if ($null -ne $check.value -and (Get-SyncExtendRestoreObjectDigest $check.value) -cne
            (Get-SyncExtendRestoreObjectDigest $budgets[$check.budget])) {
            throw "Native persisted $($check.budget) budgets changed."
        }
    }
}

function Get-RestoreLineageDigest($Preparation) {
    return Get-SyncExtendRestoreObjectDigest ([ordered]@{
        intent = $Preparation.intent
        history_intent = $Preparation.history_reservation.intent
        history_projection_hash = $Preparation.history_reservation.projection_hash
        final_snapshot_id = $Preparation.history_reservation.final_snapshot_id
        native_intent = $Preparation.native_reservation.intent
        execution_intent = $Preparation.execution_description.intent
        original_request = $Preparation.original_pins.request
        owner_intent = $Preparation.owner_description.intent
        native_storage_capacity_hash = $Preparation.native_storage.capacity_hash
        native_future_capacity_hash = $Preparation.native_future_admission.capacity_hash
    })
}

function Get-ExactRestorePreparation($Pending) {
    $all = @(Invoke-InstalledRestoreJson $Pending @('tree-transactions', '--data-dir', $Pending.data_dir))
    $exact = @($all | Where-Object { $_.intent.transaction_id -ceq $Pending.transaction_id })
    if ($exact.Count -ne 1) { throw 'The exact original TREE transaction cannot be reopened.' }
    Confirm-RestorePreparation $Pending $exact[0]
    return $exact[0]
}

function Confirm-RestoreFinal($Pending, $Result) {
    if ($Result.transaction_id -cne $Pending.transaction_id -or $Result.owner_cleanup_complete -cne $true -or
        $Result.tree_atomic -cne $false -or $Result.snapshot_id -cne $Pending.final_snapshot_id -or
        $Result.snapshot_id -ceq $Pending.baseline_snapshot -or $Result.snapshot_id -ceq $Pending.target_snapshot) {
        throw 'Native restoration requires a new Final and complete exact original owner cleanup.'
    }
    Assert-SyncExtendViewId $Result.snapshot_id
}

function Invoke-RestoreNative($Pending) {
    if ($Pending.original_process_exit_verified -cne $true) { throw 'Verify the original stopped owner first.' }
    Confirm-PreviousRestoreCommandClosed $Pending
    $request = ConvertFrom-SyncExtendRestoreRequestHex $Pending.request_hex
    if (!$Pending.owner_creation_requested) {
        $status = Invoke-InstalledRestoreJson $Pending @('status', '--data-dir', $Pending.data_dir)
        if ($status.space_id -cne $Pending.space_id -or $status.snapshot_id -cne $Pending.baseline_snapshot) {
            throw 'The stopped workspace space or baseline changed before fresh native admission.'
        }
        $arguments = @('tree-prepare', '--data-dir', $Pending.data_dir, '--baseline', $Pending.baseline_snapshot,
            '--target', $Pending.target_snapshot, '--transaction', $Pending.transaction_id, '--budgets', $Pending.budget_path)
        $arguments += Get-SyncExtendRestoreTreeArguments $request
        $Pending.phase = 'preparation_requested'
        Save-PendingRestore $Pending
        $prepared = Invoke-InstalledRestoreJson $Pending $arguments
        Confirm-RestorePreparation $Pending $prepared
        $Pending.phase = 'admission_requested'
        Save-PendingRestore $Pending
        $admitted = Invoke-InstalledRestoreJson $Pending @('tree-admit', '--data-dir', $Pending.data_dir,
            '--transaction', $Pending.transaction_id, '--budgets', $Pending.budget_path, '--allow-irreversible-admission')
        Confirm-RestorePreparation $Pending $admitted
        if (!$admitted.native_future_admission -or !$admitted.native_reservation -or !$admitted.original_pins -or
            !$admitted.owner_description -or $admitted.executor_available -cne $true) {
            throw 'The original native TREE admission is incomplete.'
        }
        $Pending.lineage_sha256 = Get-RestoreLineageDigest $admitted
        $Pending.final_snapshot_id = $admitted.history_reservation.final_snapshot_id
        Assert-SyncExtendViewId $Pending.final_snapshot_id
        $Pending.owner_creation_requested = $true
        $Pending.phase = 'owner_creation_requested'
        Save-PendingRestore $Pending
        # Persist first. An interrupted original CREATE is never issued again.
        $owner = Invoke-InstalledRestoreJson $Pending @('tree-create-owner', '--data-dir', $Pending.data_dir,
            '--transaction', $Pending.transaction_id)
        if ($owner.transaction_id -cne $Pending.transaction_id -or $owner.owner_ready -cne $true -or
            $owner.whole_tree_completed -cne $false -or $owner.tree_atomic -cne $false) {
            throw 'The original admitted native owner was not sealed.'
        }
        $Pending.owner_ready_verified = $true
        $Pending.phase = 'owner_ready'
        Save-PendingRestore $Pending
    }
    $reopened = Get-ExactRestorePreparation $Pending
    if ((Get-RestoreLineageDigest $reopened) -cne $Pending.lineage_sha256) {
        throw 'The exact admitted native lineage changed.'
    }
    $command = if ($Pending.execution_requested) { 'tree-resume' } else { 'tree-execute' }
    $Pending.execution_requested = $true
    $Pending.phase = if ($command -ceq 'tree-resume') { 'execution_resume_requested' } else { 'execution_requested' }
    Save-PendingRestore $Pending
    $result = Invoke-InstalledRestoreJson $Pending @($command, '--data-dir', $Pending.data_dir,
        '--transaction', $Pending.transaction_id, '--allow-non-atomic-tree')
    Confirm-RestoreFinal $Pending $result
    $Pending.phase = 'final_reopen_requested'
    Save-PendingRestore $Pending
    # A separate original process reopens this same Journal and checks the
    # immutable Final plus exact physical cleanup, rather than trusting stdout.
    $reopenResult = Invoke-InstalledRestoreJson $Pending @('tree-resume', '--data-dir', $Pending.data_dir,
        '--transaction', $Pending.transaction_id, '--allow-non-atomic-tree')
    Confirm-RestoreFinal $Pending $reopenResult
    $final = Get-ExactRestorePreparation $Pending
    $status = Invoke-InstalledRestoreJson $Pending @('status', '--data-dir', $Pending.data_dir)
    if ($final.state -cne 'native_cleaned' -or (Get-RestoreLineageDigest $final) -cne $Pending.lineage_sha256 -or
        $status.space_id -cne $Pending.space_id -or $status.snapshot_id -cne $Pending.final_snapshot_id -or
        $status.tree_restore_writer_gate_held -cne $false) {
        throw 'The fresh same-Journal Final and released native owner cannot be verified.'
    }
    $Pending.native_final_verified = $true
    $Pending.phase = 'final_verified'
    Save-PendingRestore $Pending
}

function Complete-RestoreRestart($Pending, $Record) {
    Confirm-RestoreBinding $Pending $Record
    $process = if ($Record.process) { Get-OwnedProcess $Record.process }
    try {
        if ($process) {
            if (!$Pending.restart_requested -or !$Pending.restart_process -or
                $Record.process.pid -ne $Pending.restart_process.pid -or $Record.process.birth -cne $Pending.restart_process.birth -or
                $Record.process.birth -ceq $Pending.original_process.birth) {
                throw 'A process outside the recorded restore restart is still active.'
            }
            $status = Invoke-SyncExtendJson $Pending.image @('management-status', '--config', $Pending.management)
            if ($status.resources_ready -cne $true -or $status.owner_generation -ceq $Pending.original_owner_generation) {
                throw 'The restored deployment has not reached a new authenticated owner.'
            }
            $Record.state = 'running'
            $Record.owner_generation = $status.owner_generation
            Save-State $Record
        } else {
            if ($Record.state -cnotin @('stopped', 'startup_failed') -or $Pending.native_final_verified -cne $true) {
                throw 'Restoration restart requires verified Final/cleanup/reopen and no active recorded process.'
            }
            $Pending.restart_requested = $true
            $Pending.phase = 'restart_requested'
            Save-PendingRestore $Pending
            $script:restoreLaunchPending = $Pending
            try { $Record = Start-Installed $Pending.selected $Pending.deployment $Pending.previous }
            finally { $script:restoreLaunchPending = $null }
        }
    } finally { if ($process) { $process.Dispose() } }
    $status = Invoke-SyncExtendJson $Pending.image @('management-status', '--config', $Pending.management)
    $owner = Get-OwnedProcess $Record.process
    try {
        if (!$owner -or $Record.state -cne 'running' -or $status.resources_ready -cne $true -or
            $status.owner_generation -cne $Record.owner_generation -or
            $status.owner_generation -ceq $Pending.original_owner_generation) {
            throw 'The original configuration restart has no verified new authenticated owner.'
        }
    } finally { if ($owner) { $owner.Dispose() } }
    $Pending.new_owner_generation = $status.owner_generation
    $Pending.phase = 'completed'
    $Pending.completed_at_ms = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    Save-PendingRestore $Pending
    $receipt = Resolve-SyncExtendPath (Join-Path ([IO.Path]::GetDirectoryName($Pending.budget_path)) 'completed.json')
    [IO.File]::Move((Resolve-SyncExtendPath $pendingRestorePath -File), $receipt, $false)
    return [pscustomobject]@{
        restored = $true; transaction_id = $Pending.transaction_id; snapshot_id = $Pending.final_snapshot_id
        owner_cleanup_complete = $true; same_journal_reopened = $true; new_owner_generation = $Pending.new_owner_generation
        tree_atomic = $false; remote_backup_complete = $false
    }
}

function Close-FailedRestoreRestart($Pending) {
    if (!$Pending.restart_requested) { return }
    $record = Read-SyncExtendJson $statePath
    if (!$record.process -or !$Pending.restart_process -or $record.process.pid -ne $Pending.restart_process.pid -or
        $record.process.birth -cne $Pending.restart_process.birth -or $record.process.birth -ceq $Pending.original_process.birth -or
        ![string]::Equals($record.process.image, $Pending.image, [StringComparison]::OrdinalIgnoreCase)) { return }
    $process = Get-OwnedProcess $record.process
    try {
        if ($process) {
            # This exact process was created for the recorded restart. No
            # unrelated PID or substituted image can be stopped here.
            if (!$process.HasExited) { $process.Kill() }
            $process.WaitForExit()
            $record.exit_code = $process.ExitCode
            $record.process_exit_verified = $true
            $record.exit_receipt = @{
                pid = $process.Id; birth = $record.process.birth; image = $record.process.image
                actual_wait = $true; exit_code = $process.ExitCode; failed_restore_restart = $true
            }
            $record.state = 'startup_failed'
            Save-State $record
        }
    } finally { if ($process) { $process.Dispose() } }
}

function Invoke-ManagedRestore($Record, $Pending, [bool]$Resume) {
    if (!$AllowIrreversibleAdmission -or !$AllowNonAtomicTree) {
        throw 'Explicit irreversible admission and non-atomic TREE execution are required.'
    }
    if ($Resume) {
        if (!$Pending -or !$RestoreTransaction -or $Pending.transaction_id -cne $RestoreTransaction) {
            throw 'Continue only the exact recorded pending restoration transaction.'
        }
        Confirm-RestoreBinding $Pending $Record
    } else {
        if ($Pending -or !$Record -or $Record.state -cne 'running' -or !$OwnerGeneration -or
            $Record.owner_generation -cne $OwnerGeneration) { throw 'Use a current authenticated managed owner and fresh preview.' }
        Confirm-Configuration $Record
        $request = ConvertFrom-SyncExtendRestoreRequestHex $RestoreRequestHex
        if ($request.owner_generation -cne $OwnerGeneration) { throw 'The selected preview owner changed.' }
        $age = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() - $RestorePreviewAtMs
        if ($age -lt 0 -or $age -gt 10000 -or !$RestorePreviewDigest) { throw 'The preview expired; generate a fresh preview.' }
        $image = Confirm-PackageImage (Get-PackageImage $Record.selected) $Record.selected
        if (![string]::Equals((Resolve-SyncExtendPath $Deployment -File), $Record.deployment, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'The current managed deployment differs from the selected profile.'
        }
        $context = Invoke-SyncExtendJson $image @('management-restore-preview', '--config', $Record.management,
            '--context', '--space-id', $request.request.space_id)
        Assert-SyncExtendRestoreContext $context
        if ($context.owner_generation -cne $OwnerGeneration -or $context.space_id -cne $request.request.space_id -or
            $context.current_snapshot_id -cne $request.request.expected_baseline -or !$context.available) {
            throw 'The current owner, selected space or baseline changed.'
        }
        $fresh = Invoke-SyncExtendJson $image @('management-restore-preview', '--config', $Record.management,
            '--request-hex', $RestoreRequestHex)
        if ((Get-SyncExtendRestorePreviewBinding $fresh $request) -cne $RestorePreviewDigest) {
            throw 'The fresh historical source, baseline, selection or preview changed.'
        }
        $freshAt = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        $budgetSource = Resolve-SyncExtendPath $RestoreBudgets -File
        $budgetStream = [IO.File]::Open($budgetSource, 'Open', 'Read', 'Read')
        try {
            if ($budgetStream.Length -lt 1 -or $budgetStream.Length -gt 65536) { throw 'Choose an explicit TREE budget JSON within 64 KiB.' }
            $budgetBytes = [byte[]]::new([int]$budgetStream.Length)
            $read = 0
            while ($read -lt $budgetBytes.Length) {
                $received = $budgetStream.Read($budgetBytes, $read, $budgetBytes.Length - $read)
                if ($received -eq 0) { throw 'The explicit budget file was truncated while reading.' }
                $read += $received
            }
        } finally { $budgetStream.Dispose() }
        $budgets = ConvertFrom-Json -InputObject ([Text.UTF8Encoding]::new($false, $true).GetString($budgetBytes)) -AsHashtable
        Assert-SyncExtendRestoreBudgets $budgets
        $profile = Read-SyncExtendJson $Record.deployment
        $dataDir = Get-RestoreDataDirectory $profile $request.request.space_id
        $transaction = [Guid]::NewGuid().ToString('N')
        $inputs = Resolve-SyncExtendPath (Join-Path (Join-Path $root 'restore') $transaction)
        [void][IO.Directory]::CreateDirectory($inputs)
        $budgetPath = Join-Path $inputs 'budgets.json'
        Write-SyncExtendBytes $budgetPath $budgetBytes
        $Pending = @{
            format_version = 1; owner_sid = $sid.Value; transaction_id = $transaction; phase = 'requested'
            request_hex = $RestoreRequestHex; request_sha256 = Get-SyncExtendRestoreByteDigest ([Convert]::FromHexString($RestoreRequestHex))
            scope_sha256 = Get-SyncExtendRestoreObjectDigest (Get-SyncExtendRestoreTreeScope $request)
            preview_sha256 = $RestorePreviewDigest; preview_at_ms = $RestorePreviewAtMs; fresh_preview_at_ms = $freshAt
            budget_hex = [Convert]::ToHexString($budgetBytes).ToLowerInvariant(); budget_sha256 = Get-SyncExtendRestoreByteDigest $budgetBytes
            budget_bytes = $budgetBytes.Length; budget_path = $budgetPath; image = $image
            selected = $Record.selected; previous = $Record.previous
            deployment = $Record.deployment; deployment_sha256 = $Record.deployment_sha256
            management = $Record.management; management_sha256 = $Record.management_sha256
            gateway = $Record.gateway; gateway_sha256 = $Record.gateway_sha256
            space_id = $request.request.space_id; data_dir = $dataDir
            baseline_snapshot = $request.request.expected_baseline; target_snapshot = $request.request.snapshot
            original_owner_generation = $OwnerGeneration; original_process = $Record.process
            stop_request_id = [Guid]::NewGuid().ToString('N'); stop_requested = $false
            original_process_exit_verified = $false; owner_creation_requested = $false; owner_ready_verified = $false
            execution_requested = $false; native_final_verified = $false; restart_requested = $false
            active_command = $null; command_count = 0; created_at_ms = $freshAt
        }
        Save-PendingRestore $Pending
        if ([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() - $freshAt -gt 10000) {
            throw 'The authenticated preview expired before the stopped restore workflow.'
        }
    }
    try {
        Confirm-RestoreBinding $Pending $Record
        if (!$Pending.native_final_verified) {
            $Record = Stop-RestoreOriginal $Pending $Record
            Invoke-RestoreNative $Pending
        } elseif (!$Pending.restart_requested -or !(Test-OwnedProcessActive $Record.process)) {
            # A retry after a failed restart obtains new native cleanup and
            # same-Journal receipts before any new service start.
            Invoke-RestoreNative $Pending
        }
        Complete-RestoreRestart $Pending $Record
    } catch {
        $failureReason = [string]$_.Exception.Message
        Close-FailedRestoreRestart $Pending
        $Pending.last_failure_phase = $Pending.phase
        $Pending.last_failure_at_ms = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        $Pending.last_failure_reason = $failureReason.Substring(0, [Math]::Min(512, $failureReason.Length))
        Save-PendingRestore $Pending
        throw "Restoration transaction $($Pending.transaction_id) remains pending at $($Pending.phase). Keep the service stopped and explicitly continue this transaction after resolving the refusal."
    }
}

$lockPath = Resolve-SyncExtendPath (Join-Path $root 'operation.lock')
$lock = [IO.File]::Open($lockPath, 'OpenOrCreate', 'ReadWrite', 'None')
try {
    $record = if (Test-Path -LiteralPath $statePath) { Read-SyncExtendJson $statePath }
    if ($record -and ($record.format_version -ne 1 -or $record.owner_sid -cne $sid.Value)) { throw 'Install state ownership differs.' }
    $pending = Get-PendingRestore
    if ($pending -and $Action -cnotin @('status', 'restore-resume')) {
        throw "Restoration transaction $($pending.transaction_id) is pending. Continue it before starting, switching, uninstalling or changing the gateway."
    }
    switch ($Action) {
        'restore' { Invoke-ManagedRestore $record $pending $false }
        'restore-resume' { Invoke-ManagedRestore $record $pending $true }
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
        'resume' {
            if (!$record -or $record.state -cne 'stopped' -or
                ![string]::Equals((Resolve-SyncExtendPath $Deployment -File), $record.deployment,
                    [StringComparison]::OrdinalIgnoreCase)) {
                throw 'Resume requires this profile and its successfully stopped installed version.'
            }
            $process = if ($record.process) { Get-OwnedProcess $record.process }
            if ($process) { $process.Dispose(); throw 'The recorded deployment process is still active.' }
            $null = Resolve-SyncExtendPath $record.management -File
            Confirm-Configuration $record
            # Retain the selected installed image and previous version. Resuming
            # from an older launcher must not silently install or roll back it.
            Start-Installed $record.selected $record.deployment $record.previous
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
                $pendingView = if ($pending) {
                    $helper = if ($pending.active_command) { Get-OwnedProcess $pending.active_command }
                    try {
                        @{
                            transaction_id = $pending.transaction_id; phase = $pending.phase
                            request_sha256 = $pending.request_sha256; scope_sha256 = $pending.scope_sha256
                            original_process_exit_verified = [bool]$pending.original_process_exit_verified
                            native_final_verified = [bool]$pending.native_final_verified; helper_active = [bool]$helper
                            refusal_reason = $pending.last_failure_reason
                        }
                    } finally { if ($helper) { $helper.Dispose() } }
                }
                [pscustomobject]@{ state = $record.state; version = $record.selected.version_id;
                    process_active = [bool]$process
                    process_exit_verified = $(if ($record.Contains('process_exit_verified')) { [bool]$record.process_exit_verified } else {
                        $record.state -ceq 'stopped' -and $record.exit_code -eq 0
                    })
                    management = $health; pending_restore = $pendingView }
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
