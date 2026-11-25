param(
    [Parameter(Mandatory=$true)][string]$Name,
    [Parameter(Mandatory=$true)][string]$Binary,
    [Parameter(Mandatory=$true)][string]$DeploymentConfig,
    [Parameter(Mandatory=$true)][string]$ServiceAccount,
    [System.Management.Automation.PSCredential]$Credential
)
$ErrorActionPreference='Stop'
if ($Name -notmatch '^[a-zA-Z0-9_-]{1,80}$') {throw 'Bounded ASCII service name required'}
$taskBinary=(Resolve-Path -LiteralPath $Binary).Path
$taskConfig=(Resolve-Path -LiteralPath $DeploymentConfig).Path
foreach ($taskPath in @($taskBinary,$taskConfig)) {
    $taskItem=Get-Item -LiteralPath $taskPath
    if ($taskItem.PSIsContainer -or ($taskItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $taskPath.Contains('"')) {throw 'Regular absolute service binary/config paths required'}
}
if (Get-Service -Name $Name -ErrorAction SilentlyContinue) {throw 'Service already exists; no replacement or identity migration'}
$taskForbidden=@('LocalSystem','NT AUTHORITY\SYSTEM','NT AUTHORITY\LocalService','NT AUTHORITY\NetworkService')
if ($ServiceAccount -in $taskForbidden -or !$ServiceAccount) {
    throw 'Choose an explicit dedicated unprivileged account with access to its private state'
}
if (!$Credential -or $Credential.UserName -ne $ServiceAccount) {
    throw 'Matching dedicated-account credential required'
}
& $taskBinary deployment-check --config $taskConfig | Out-Null
if ($LASTEXITCODE) {throw 'Deployment configuration failed before service registration'}
$taskCommand='"'+$taskBinary+'" windows-service --name '+$Name+' --config "'+$taskConfig+'"'
New-Service -Name $Name -BinaryPathName $taskCommand -DisplayName $Name `
    -StartupType Manual -Credential $Credential |
    Select-Object Name,Status
Write-Output 'Native SCM registration complete. Service remains stopped until explicitly started.'
