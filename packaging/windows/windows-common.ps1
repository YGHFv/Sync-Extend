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
        try { return ($reader.ReadToEnd() | ConvertFrom-Json -AsHashtable -ErrorAction Stop) }
        finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
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

function Invoke-SyncExtendJson {
    param([string]$Image, [string[]]$Arguments, [int]$TimeoutMs = 12000)

    $child = New-SyncExtendProcess $Image $Arguments -Capture
    try {
        $stdout = $child.StandardOutput.ReadToEndAsync()
        $stderr = $child.StandardError.ReadToEndAsync()
        if (!$child.WaitForExit($TimeoutMs)) {
            $child.Kill()
            [void]$child.WaitForExit(5000)
            throw "The $($Arguments[0]) command timed out."
        }
        if ($child.ExitCode -ne 0) { throw "The $($Arguments[0]) command was refused (exit $($child.ExitCode))." }
        $result = $stdout.GetAwaiter().GetResult()
        if ($result.Length -gt 1100000) { throw 'The local response exceeds its size limit.' }
        return ($result | ConvertFrom-Json -AsHashtable -ErrorAction Stop)
    } finally { $child.Dispose() }
}

function Write-SyncExtendJson {
    param([string]$Path, $Value, [switch]$Replace)

    $absolute = Resolve-SyncExtendPath $Path
    $temporary = Join-Path ([IO.Path]::GetDirectoryName($absolute)) ('.sync-extend-' + [Guid]::NewGuid().ToString('N'))
    $stream = [IO.File]::Open($temporary, 'CreateNew', 'Write', 'None')
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes(($Value | ConvertTo-Json -Depth 12) + "`n")
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
    try {
        [IO.File]::Move($temporary, $absolute, $Replace.IsPresent)
    } finally {
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}
