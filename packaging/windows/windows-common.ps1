#Requires -Version 7.0

function Resolve-SyncExtendPath {
    param([string]$Path, [switch]$File, [switch]$Directory)

    if ($Path -notmatch '^[A-Za-z]:[\\/]') { throw 'Use an absolute local drive path.' }
    $absolute = [IO.Path]::GetFullPath($Path)
    $cursor = $absolute
    while ($cursor) {
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction SilentlyContinue
        if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Choose a path without directories or files redirected by a reparse point.'
        }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
    if ($File -and !(Test-Path -LiteralPath $absolute -PathType Leaf)) { throw 'The selected file is missing.' }
    if ($Directory -and !(Test-Path -LiteralPath $absolute -PathType Container)) { throw 'The selected directory is missing.' }
    return $absolute
}

function Read-SyncExtendJson {
    param([string]$Path, [int]$MaxBytes = 65536)

    $file = Resolve-SyncExtendPath $Path -File
    $stream = [IO.File]::Open($file, 'Open', 'Read', 'Read')
    try {
        if ($stream.Length -gt $MaxBytes) { throw 'The selected JSON file exceeds its size limit.' }
        $reader = [IO.StreamReader]::new($stream, [Text.UTF8Encoding]::new($false, $true), $false)
        try { return ConvertFrom-SyncExtendJson ($reader.ReadToEnd()) }
        finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
}

function ConvertFrom-SyncExtendJson {
    param([Parameter(Mandatory)][string]$Text)

    # Validate the original text before PowerShell can collapse duplicate keys.
    # JsonProperty.Name is decoded, so "plan" and "\u0070lan" are the same key.
    $document = $null
    try {
        $options = [Text.Json.JsonDocumentOptions]::new()
        $options.MaxDepth = 128
        $document = [Text.Json.JsonDocument]::Parse($Text, $options)
        $pending = [Collections.Generic.Stack[Text.Json.JsonElement]]::new()
        $pending.Push($document.RootElement)
        while ($pending.Count) {
            $element = $pending.Pop()
            if ($element.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
                $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                foreach ($property in $element.EnumerateObject()) {
                    if (!$names.Add($property.Name)) { throw 'Duplicate decoded JSON object key.' }
                    $pending.Push($property.Value)
                }
            } elseif ($element.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
                foreach ($item in $element.EnumerateArray()) { $pending.Push($item) }
            }
        }
    } catch {
        throw 'The JSON contains invalid syntax or duplicate object fields.'
    } finally {
        if ($document) { $document.Dispose() }
    }
    try { return ConvertFrom-Json -InputObject $Text -AsHashtable -ErrorAction Stop }
    catch { throw 'The JSON cannot be represented by the supported client format.' }
}

function New-SyncExtendProcess {
    param([string]$Image, [string[]]$Arguments, [switch]$Capture)

    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = Resolve-SyncExtendPath $Image -File
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.WorkingDirectory = [IO.Path]::GetDirectoryName($info.FileName)
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    if ($Capture) {
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $info.StandardOutputEncoding = [Text.Encoding]::UTF8
        $info.StandardErrorEncoding = [Text.Encoding]::UTF8
    }
    return [Diagnostics.Process]::Start($info)
}

function New-SyncExtendLoggedProcess {
    param(
        [Parameter(Mandatory)][string]$Image,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$StandardOutputPath,
        [Parameter(Mandatory)][string]$StandardErrorPath
    )

    $imagePath = Resolve-SyncExtendPath $Image -File
    $outputPath = Resolve-SyncExtendPath $StandardOutputPath
    $errorPath = Resolve-SyncExtendPath $StandardErrorPath
    if (!('SyncExtend.Windows.LoggedProcess' -as [type])) {
        Add-Type -Path (Resolve-SyncExtendPath (Join-Path $PSScriptRoot 'windows-native-launch.cs') -File) `
            -ErrorAction Stop
    }
    $child = [SyncExtend.Windows.LoggedProcess]::Start(
        $imagePath, $Arguments, [IO.Path]::GetDirectoryName($imagePath), $outputPath, $errorPath)
    try {
        $null = $child.Handle
        $null = $child.StartTime
        $observedImage = $child.MainModule.FileName
        if (!$child.OriginalHandleReturnedByCreateProcess -or !$child.ImageObservedFromOriginalHandle -or
                !$observedImage) {
            throw 'The original logged process handle or image could not be observed.'
        }
        if (![string]::Equals($observedImage, $imagePath, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'The original logged process image differs from the selected executable.'
        }
        return $child
    } catch {
        $exited = $false
        try {
            try { if (!$child.HasExited) { $child.Kill() } }
            finally { $exited = $child.WaitForExit(5000) }
        } finally {
            if ($exited) { $child.Dispose() }
            else {
                if (!$script:syncExtendUnclosedHelpers) {
                    $script:syncExtendUnclosedHelpers = [Collections.Generic.List[object]]::new()
                }
                $script:syncExtendUnclosedHelpers.Add(@{
                    process = $child; process_exit_verified = $false
                    command = $Arguments[0]; original_create_process_handle = $true
                })
            }
        }
        throw
    }
}

function Invoke-SyncExtendJson {
    param([string]$Image, [string[]]$Arguments, [int]$TimeoutMs = 12000)

    $child = New-SyncExtendProcess $Image $Arguments -Capture
    $stdout = $null
    $stderr = $null
    $exited = $false
    $capturesClosed = $false
    $captureDeadline = $null
    try {
        $null = $child.Handle
        $stdout = $child.StandardOutput.ReadToEndAsync()
        $stderr = $child.StandardError.ReadToEndAsync()
        $exited = $child.WaitForExit($TimeoutMs)
        if (!$exited) {
            throw "The $($Arguments[0]) command timed out."
        }
        if ($child.ExitCode -ne 0) { throw "The $($Arguments[0]) command was refused (exit $($child.ExitCode))." }
        $captureDeadline = [Diagnostics.Stopwatch]::StartNew()
        if (![Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($stdout, $stderr), 5000)) {
            throw 'The original client helper capture tasks did not close within the cleanup deadline.'
        }
        $result = $stdout.GetAwaiter().GetResult()
        $null = $stderr.GetAwaiter().GetResult()
        $capturesClosed = $true
        if ([Text.Encoding]::UTF8.GetByteCount($result) -gt 1100000) { throw 'The local response exceeds its size limit.' }
        return ConvertFrom-SyncExtendJson $result
    } finally {
        try {
            if (!$exited) {
                # Kill can race the original process's natural exit. This
                # exact Process is still waited before any exit is reported.
                try { if (!$child.HasExited) { $child.Kill() } }
                catch { if (!$child.HasExited) { $exited = $false } }
                $exited = $child.WaitForExit(5000)
            }
            if (!$exited) { throw 'The original client helper exit remains unverified after the cleanup deadline.' }
            if (!$capturesClosed) {
                if (!$captureDeadline) { $captureDeadline = [Diagnostics.Stopwatch]::StartNew() }
                $remaining = [int][Math]::Max(0, 5000 - $captureDeadline.ElapsedMilliseconds)
                $captures = [Threading.Tasks.Task[]]@(@($stdout, $stderr) | Where-Object { $null -ne $_ })
                if ($captures.Count -and ![Threading.Tasks.Task]::WaitAll($captures, $remaining)) {
                    throw 'The original client helper capture tasks did not close within the cleanup deadline.'
                }
                if ($stdout) { $null = $stdout.GetAwaiter().GetResult() }
                if ($stderr) { $null = $stderr.GetAwaiter().GetResult() }
                $capturesClosed = $true
            }
        } finally {
            if ($exited -and $capturesClosed) {
                $child.Dispose()
            } else {
                # Keep the exact original handles reachable in this invocation;
                # an unresolved cleanup is an error, never an exit receipt.
                if (!$script:syncExtendUnclosedHelpers) {
                    $script:syncExtendUnclosedHelpers = [Collections.Generic.List[object]]::new()
                }
                $script:syncExtendUnclosedHelpers.Add(@{
                    process = $child; stdout = $stdout; stderr = $stderr
                    process_exit_verified = $exited; capture_tasks_closed = $capturesClosed
                    command = $Arguments[0]
                })
            }
        }
    }
}

function Write-SyncExtendJson {
    param([string]$Path, $Value, [switch]$Replace)

    $text = ($Value | ConvertTo-Json -Depth 12) + "`n"
    Write-SyncExtendBytes $Path ([Text.Encoding]::UTF8.GetBytes($text)) -Replace:$Replace
}

function Write-SyncExtendBytes {
    param([string]$Path, [byte[]]$Bytes, [switch]$Replace)

    $absolute = Resolve-SyncExtendPath $Path
    $temporary = Join-Path ([IO.Path]::GetDirectoryName($absolute)) ('.sync-extend-' + [Guid]::NewGuid().ToString('N'))
    $stream = [IO.File]::Open($temporary, 'CreateNew', 'Write', 'None')
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
    try {
        [IO.File]::Move($temporary, $absolute, $Replace.IsPresent)
    } finally {
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}

function New-SyncExtendReadOnlyGateway {
    param([string]$Profile, [string]$DataDirectory, [string]$SpaceId, [int]$Port, [string]$Image)

    if ($SpaceId -cnotmatch '\A[0-9a-f]{32}\z' -or $Port -lt 1024 -or $Port -gt 65535) {
        throw 'A valid local space and WebDAV port are required.'
    }
    # Unique credentials and working files avoid adopting, overwriting, or
    # rotating any previous profile's credential after an interrupted switch.
    $id = [Guid]::NewGuid().ToString('N')
    $gateway = Join-Path $Profile "webdav-$id.json"
    $spaces = @{}
    $spaces[$SpaceId] = $DataDirectory
    Write-SyncExtendJson $gateway @{
        listener = @{
            format_version = 1; enabled = $true; listener_id = $id
            address = "127.0.0.1:$Port"; request_timeout_secs = 20
            max_header_bytes = 8192; max_requests = 1000000
            exports = @(@{
                name = 'files'; space_id = $SpaceId; subtree = $null
                writable = $false; max_upload_bytes = 1; allow_native_windows_writes = $false
            })
            accounts = @(@{ username = 'local'; exports = @('files'); writable_exports = @() })
        }
        credentials = (Join-Path $Profile "webdav-$id.credentials")
        uploads = (Join-Path $Profile "webdav-$id-uploads")
        spaces = $spaces
    }
    $null = Invoke-SyncExtendJson $Image @('webdav-credentials-generate', '--config', $gateway)
    $null = Invoke-SyncExtendJson $Image @('webdav-check', '--config', $gateway)
    return $gateway
}
