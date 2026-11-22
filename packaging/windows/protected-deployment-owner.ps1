#Requires -Version 7.0

function Initialize-SyncExtendProtectedOwner {
    if (!('SyncExtend.Windows.OwnerProcess' -as [type])) {
        Add-Type -Path (Resolve-SyncExtendPath (Join-Path $PSScriptRoot 'windows-owner-channel.cs') -File) `
            -ErrorAction Stop
    }
}

function Assert-SyncExtendProtectedFields($Value, [string[]]$Required, [string[]]$Optional = @()) {
    if ($Value -isnot [Collections.IDictionary]) { throw 'The deployment response must be a JSON object.' }
    $fields = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in @($Required) + @($Optional)) { [void]$fields.Add($name) }
    foreach ($name in $Value.Keys) {
        if (!$fields.Contains([string]$name)) { throw 'The deployment response has an unsupported field.' }
    }
    foreach ($name in $Required) {
        if (!(@($Value.Keys) -ccontains $name)) { throw 'The deployment response is missing a required field.' }
    }
}

function Assert-SyncExtendProtectedDigest($Value) {
    if ($Value -isnot [string] -or $Value -cnotmatch '\A[0-9a-f]{64}\z') {
        throw 'The deployment response has an invalid content binding.'
    }
}

function Assert-SyncExtendProtectedOwnerObject($Owner) {
    if ($Owner -isnot [Collections.IDictionary] -or
        $Owner.Native -isnot [SyncExtend.Windows.OwnerProcess]) {
        throw 'Use the original deployment control process from this window.'
    }
}

function New-SyncExtendProtectedOwner {
    param(
        [Parameter(Mandatory)][string]$Image,
        [Parameter(Mandatory)][string]$Descriptor,
        [Parameter(Mandatory)][string]$Mapping
    )

    Initialize-SyncExtendProtectedOwner
    $imagePath = Resolve-SyncExtendPath $Image -File
    $descriptorPath = Resolve-SyncExtendPath $Descriptor -File
    $mappingPath = Resolve-SyncExtendPath $Mapping -File
    $null = Read-SyncExtendJson $descriptorPath 1048576
    $null = Read-SyncExtendJson $mappingPath 1048576
    $owner = @{
        Native = $null; Identity = $null; FrameTask = $null; DrainTask = $null; WriteTask = $null
        Pending = $null; Startup = $null; LastState = $null; EndOfStream = $false
        ProtocolFailure = $false; Terminal = $false; ExitReceipt = $null; FrameCount = 0
        Input = @{
            Image = $imagePath
            ImageSha256 = (Get-FileHash -LiteralPath $imagePath -Algorithm SHA256).Hash
            Descriptor = $descriptorPath
            DescriptorSha256 = (Get-FileHash -LiteralPath $descriptorPath -Algorithm SHA256).Hash
            Mapping = $mappingPath
            MappingSha256 = (Get-FileHash -LiteralPath $mappingPath -Algorithm SHA256).Hash
        }
    }
    try {
        $owner.Native = [SyncExtend.Windows.OwnerProcess]::Start($imagePath, [string[]]@(
            'protected-deployment', '--descriptor', $descriptorPath,
            'install', '--mapping', $mappingPath, '--wait-for-run'))
        $owner.FrameTask = $owner.Native.Stdout.ReadNextAsync()
        $original = $owner.Native.Original
        $null = $original.Handle
        $observedImage = $original.MainModule.FileName
        $owner.Identity = @{
            pid = $original.Id; birth = $original.StartTime.ToFileTimeUtc().ToString()
            image = $observedImage; original_handle_retained = $true
        }
        if (![string]::Equals($observedImage, $imagePath, [StringComparison]::OrdinalIgnoreCase) -or
            (Get-FileHash -LiteralPath $imagePath -Algorithm SHA256).Hash -cne $owner.Input.ImageSha256) {
            throw 'The original deployment control process image changed.'
        }
        return $owner
    } catch {
        if (!$owner.Native) {
            $failure = $_.Exception
            while ($failure -and !$owner.Native) {
                $owner.Native = $failure.Data['SyncExtendOriginalProtectedProcess']
                $failure = $failure.InnerException
            }
        }
        if (!$owner.Native) { throw }
        # EOF asks this original owner to finish and close its own resources.
        # A failed observation never authorizes a replacement owner or path
        # cleanup, and an unfinished original remains reachable.
        try { $owner.Native.CloseInput() } catch { }
        $owner.ProtocolFailure = $true
        if ($owner.Native.FailedStartStdout) { $owner.DrainTask = $owner.Native.FailedStartStdout }
        elseif ($owner.Native.Stdout) { $owner.DrainTask = $owner.Native.Stdout.DrainAsync() }
        if (!$script:syncExtendUnclosedProtectedOwners) {
            $script:syncExtendUnclosedProtectedOwners = [Collections.Generic.List[object]]::new()
        }
        $script:syncExtendUnclosedProtectedOwners.Add($owner)
        $_.Exception.Data['SyncExtendOriginalProtectedOwner'] = $owner
        throw
    }
}

function Read-SyncExtendProtectedOwnerEvent($Owner) {
    Assert-SyncExtendProtectedOwnerObject $Owner
    if ($Owner.Terminal -or $Owner.ProtocolFailure) { return }
    try {
        if ($Owner.WriteTask -and $Owner.WriteTask.IsCompleted) {
            $null = $Owner.WriteTask.GetAwaiter().GetResult()
            $Owner.WriteTask = $null
        }
        if (!$Owner.FrameTask.IsCompleted) { return }
        $frame = $Owner.FrameTask.GetAwaiter().GetResult()
        if ($null -eq $frame) {
            $Owner.EndOfStream = $true
            return
        }
        $Owner.FrameCount++
        if ($Owner.FrameCount -gt 4096) { throw 'The deployment control response count exceeds its limit.' }
        $value = ConvertFrom-SyncExtendJson $frame.Json
        if ($value.format_version -isnot [long] -or $value.format_version -ne 2) {
            throw 'The deployment control response version is unsupported.'
        }
        Assert-SyncExtendProtectedDigest $value.bundle_sha256
        Assert-SyncExtendProtectedDigest $value.mapping_sha256
        if ($null -eq $Owner.Startup) {
            Assert-SyncExtendProtectedFields $value @(
                'event', 'format_version', 'state', 'bundle_sha256', 'mapping_sha256',
                'root_deployment', 'native_files_verified', 'native_node_restores_closed',
                'services_started', 'receipt')
            if ($value.event -cne 'installed' -or $value.state -cne 'installed' -or
                $value.native_files_verified -isnot [bool] -or !$value.native_files_verified -or
                $value.native_node_restores_closed -isnot [bool] -or !$value.native_node_restores_closed -or
                $value.services_started -isnot [bool] -or $value.services_started -or
                $value.receipt -isnot [Collections.IDictionary]) {
                throw 'The original deployment owner did not verify a closed native installation.'
            }
            $null = Resolve-SyncExtendPath $value.root_deployment -File
            $Owner.Startup = $value
        } else {
            if ($value.bundle_sha256 -cne $Owner.Startup.bundle_sha256 -or
                $value.mapping_sha256 -cne $Owner.Startup.mapping_sha256) {
                throw 'The original deployment owner response changed its installed binding.'
            }
            if ($value.event -ceq 'response') {
                Assert-SyncExtendProtectedFields $value @(
                    'event', 'format_version', 'request_id', 'command', 'bundle_sha256',
                    'mapping_sha256', 'state', 'accepted', 'resources_ready',
                    'services_started', 'generation', 'status', 'error')
                if (!$Owner.Pending -or $value.request_id -cne $Owner.Pending.request_id -or
                    $value.command -cne $Owner.Pending.command -or
                    $value.request_id -isnot [string] -or $value.request_id -cnotmatch '\A[0-9a-f]{32}\z' -or
                    $value.accepted -isnot [bool] -or
                    $value.accepted -and $null -ne $value.error -or
                    !$value.accepted -and ($value.error -isnot [string] -or
                        $value.error.Length -gt 128 -or $value.error -cnotmatch '\A[a-z][a-z0-9_]*\z')) {
                    throw 'The original deployment owner response does not match its pending request.'
                }
                $Owner.Pending = $null
            } elseif ($value.event -ceq 'state') {
                Assert-SyncExtendProtectedFields $value @(
                    'event', 'format_version', 'bundle_sha256', 'mapping_sha256',
                    'state', 'resources_ready', 'services_started', 'generation', 'status', 'reason')
                if ($value.reason -cne 'authenticated_management_stop') {
                    throw 'The original deployment owner emitted an unsupported state event.'
                }
            } else { throw 'The original deployment owner emitted an unsupported event.' }
            if ($value.state -isnot [string] -or $value.state -cnotin @('running', 'installed', 'closed', 'uncertain') -or
                $value.resources_ready -isnot [bool] -or $value.services_started -isnot [bool] -or
                $null -ne $value.status -and $value.status -isnot [Collections.IDictionary] -or
                ($value.generation -isnot [long] -and $value.generation -isnot [bigint]) -or
                $value.generation -lt 0 -or $value.generation -gt [bigint]::Parse('18446744073709551615') -or
                $value.resources_ready -and (!$value.services_started -or $value.state -cne 'running')) {
                throw 'The original deployment owner emitted an invalid runtime state.'
            }
        }
        if ($Owner.Native.Original.HasExited -and $value.state -cne 'closed') {
            throw 'The original deployment control process exited before its state was verified.'
        }
        $Owner.LastState = $value
        $Owner.FrameTask = $Owner.Native.Stdout.ReadNextAsync()
        return [pscustomobject]@{
            Value = $value
            actual_original_stdout_frame_bytes = $frame.WireBytes
            actual_original_stdout_frame_sha256 = $frame.WireSha256
        }
    } catch {
        $Owner.ProtocolFailure = $true
        try { $Owner.Native.CloseInput() } catch { }
        $Owner.DrainTask = $Owner.Native.Stdout.DrainAsync()
        throw 'The original deployment control response could not be verified.'
    }
}

function Send-SyncExtendProtectedOwnerCommand {
    param(
        [Parameter(Mandatory)]$Owner,
        [Parameter(Mandatory)][ValidateSet('run', 'status', 'stop', 'close')][string]$Command
    )
    Assert-SyncExtendProtectedOwnerObject $Owner
    if ($Owner.Terminal -or $Owner.ProtocolFailure -or !$Owner.Startup -or $Owner.Pending -or
        $Owner.EndOfStream -or $Owner.Native.Original.HasExited) {
        throw 'The original deployment control process is not ready for a new request.'
    }
    if ($Command -ceq 'run') {
        foreach ($binding in @(
            @{path=$Owner.Input.Image;digest=$Owner.Input.ImageSha256}
            @{path=$Owner.Input.Descriptor;digest=$Owner.Input.DescriptorSha256}
            @{path=$Owner.Input.Mapping;digest=$Owner.Input.MappingSha256})) {
            if ((Get-FileHash -LiteralPath (Resolve-SyncExtendPath $binding.path -File) -Algorithm SHA256).Hash -cne
                $binding.digest) { throw 'A selected deployment input changed; keep this original control process.' }
        }
    }
    $request = [ordered]@{
        format_version = 2; command = $Command; request_id = [Guid]::NewGuid().ToString('N')
        bundle_sha256 = $Owner.Startup.bundle_sha256; mapping_sha256 = $Owner.Startup.mapping_sha256
    }
    $json = $request | ConvertTo-Json -Depth 6 -Compress
    if ([Text.Encoding]::UTF8.GetByteCount($json) + 1 -gt 4096) {
        throw 'The deployment control request exceeds its byte limit.'
    }
    $Owner.Pending = $request
    try { $Owner.WriteTask = $Owner.Native.WriteJsonLineAsync($json) }
    catch {
        $Owner.ProtocolFailure = $true
        try { $Owner.Native.CloseInput() } catch { }
        $Owner.DrainTask = $Owner.Native.Stdout.DrainAsync()
        throw 'The original deployment control request could not be delivered.'
    }
}

function Close-SyncExtendProtectedOwnerInput($Owner) {
    Assert-SyncExtendProtectedOwnerObject $Owner
    if (!$Owner.Terminal) { $Owner.Native.CloseInput() }
}

function Complete-SyncExtendProtectedOwner($Owner) {
    Assert-SyncExtendProtectedOwnerObject $Owner
    if ($Owner.Terminal) { return $Owner.ExitReceipt }
    $original = $Owner.Native.Original
    if (!$original.WaitForExit(0)) { return }
    if (!$Owner.Native.Stdout -or !$Owner.Native.Stderr) { return }
    if ($Owner.DrainTask) {
        if (!$Owner.DrainTask.IsCompleted) { return }
        $null = $Owner.DrainTask.GetAwaiter().GetResult()
    } else {
        if (!$Owner.EndOfStream -or !$Owner.FrameTask.IsCompleted) { return }
        if ($null -ne $Owner.FrameTask.GetAwaiter().GetResult()) {
            throw 'The original deployment stdout EOF was not consumed.'
        }
    }
    if ($Owner.WriteTask) {
        if (!$Owner.WriteTask.IsCompleted) { return }
        try { $null = $Owner.WriteTask.GetAwaiter().GetResult() } catch { $Owner.ProtocolFailure = $true }
        $Owner.WriteTask = $null
    }
    if (!$Owner.Native.Stdout.Capture -or !$Owner.Native.Stderr.IsCompleted) { return }
    $stdout = $Owner.Native.Stdout.Capture
    $stderr = $Owner.Native.Stderr.GetAwaiter().GetResult()
    $Owner.ExitReceipt = @{
        original_identity = $Owner.Identity; actual_original_process_wait = $true
        actual_original_exit_code = $original.ExitCode
        original_stdout_EOF_consumed = $true; original_stderr_task_consumed = $true
        stdout_bytes = $stdout.Bytes; stdout_sha256 = $stdout.Sha256
        stderr_bytes = $stderr.Bytes; stderr_sha256 = $stderr.Sha256
        installed_binding = $(if ($Owner.Startup) {
            @{bundle_sha256=$Owner.Startup.bundle_sha256;mapping_sha256=$Owner.Startup.mapping_sha256}
        } else { $null })
    }
    $Owner.Native.Stdout.Dispose()
    $original.Dispose()
    $Owner.Terminal = $true
    return $Owner.ExitReceipt
}
