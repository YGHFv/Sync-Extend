#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$GatewayConfig,
    [Parameter(Mandatory)][string]$Username,
    [Parameter(Mandatory)][string]$Export,
    [Parameter(Mandatory)][ValidatePattern('\A[a-zA-Z]\z')][string]$DriveLetter,
    [string]$Binary = (Join-Path $PSScriptRoot 'syncd.exe')
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-common.ps1')
$config = Resolve-SyncExtendPath $GatewayConfig -File
$test = Invoke-SyncExtendJson $Binary @('webdav-connection-test', '--config', $config, '--username', $Username, '--export', $Export)
$uri = [uri]$test.url
if ($uri.Host -ne '127.0.0.1') { throw 'This mapping wizard needs a gateway configured on 127.0.0.1.' }
$drive = $DriveLetter.ToUpperInvariant() + ':'
if (Get-PSDrive -Name $DriveLetter -ErrorAction SilentlyContinue) { throw 'Choose an unused drive letter.' }
if ((Get-Service -Name WebClient -ErrorAction Stop).Status -ne 'Running') {
    throw 'Start the Windows WebClient service before mapping a drive.'
}
$remote = '\\127.0.0.1@' + $uri.Port + '\DavWWWRoot\' + $test.export
Write-Host "Enter the WebDAV password for $Username at the prompt. This mapping is limited to the current Windows session."
& (Join-Path $env:SystemRoot 'System32\net.exe') use $drive $remote '*' "/user:$Username" '/persistent:no'
if ($LASTEXITCODE) { throw 'Windows rejected the mapping. Use the connection URL in your WebDAV application.' }
