#Requires -Version 7.0
[CmdletBinding()]
param(
    [string]$Deployment = (Join-Path $env:LOCALAPPDATA 'SyncExtend\client\deployment.json'),
    [string]$Binary = (Join-Path $PSScriptRoot 'syncd.exe'),
    [switch]$Snapshot
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-common.ps1')
$binaryPath = Resolve-SyncExtendPath $Binary -File
$deploymentFile = Read-SyncExtendJson $Deployment
$managementPath = Resolve-SyncExtendPath $deploymentFile.management -File
$gatewayPath = if ($deploymentFile.role.kind -eq 'webdav_client') {
    Resolve-SyncExtendPath $deploymentFile.role.gateway_config -File
}

function Get-ClientSnapshot {
    Invoke-SyncExtendJson $binaryPath @('management-dashboard', '--config', $managementPath)
}

if ($Snapshot) {
    Get-ClientSnapshot | ConvertTo-Json -Depth 12 -Compress
    return
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
$form = [Windows.Forms.Form]::new()
$form.Text = 'SyncExtend'
$form.StartPosition = 'CenterScreen'
$form.MinimumSize = [Drawing.Size]::new(760, 490)
$form.Size = [Drawing.Size]::new(980, 650)
$form.Font = [Drawing.Font]::new('Segoe UI', 10)
$form.BackColor = [Drawing.Color]::White

$layout = [Windows.Forms.TableLayoutPanel]::new()
$layout.ColumnCount = 1
$layout.RowCount = 4
$layout.Dock = 'Fill'
$layout.Padding = [Windows.Forms.Padding]::new(18, 14, 18, 14)
foreach ($height in @(46, 66, 45)) {
    [void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new('Absolute', $height))
}
[void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new('Percent', 100))
$form.Controls.Add($layout)

$heading = [Windows.Forms.Label]::new()
$heading.Text = 'SyncExtend  /  Local client'
$heading.Font = [Drawing.Font]::new('Segoe UI', 20, 'Bold')
$heading.ForeColor = [Drawing.Color]::FromArgb(22, 63, 57)
$heading.Dock = 'Fill'
$layout.Controls.Add($heading, 0, 0)

$summary = [Windows.Forms.Label]::new()
$summary.Dock = 'Fill'
$summary.Text = 'Waiting for the local deployment.'
$layout.Controls.Add($summary, 0, 1)

$actions = [Windows.Forms.FlowLayoutPanel]::new()
$actions.Dock = 'Fill'
$layout.Controls.Add($actions, 0, 2)
function Add-ClientButton {
    param([string]$Text, [scriptblock]$OnClick)
    $button = [Windows.Forms.Button]::new()
    $button.Text = $Text
    $button.AutoSize = $true
    $button.Height = 31
    $button.Add_Click($OnClick)
    $actions.Controls.Add($button)
    return $button
}

$tabs = [Windows.Forms.TabControl]::new()
$tabs.Dock = 'Fill'
$layout.Controls.Add($tabs, 0, 3)
$lists = @{}
function Add-ColumnsTab {
    param([string]$Name, [string[]]$Names, [int[]]$Widths)
    $page = [Windows.Forms.TabPage]::new($Name)
    $list = [Windows.Forms.ListView]::new()
    $list.Dock = 'Fill'
    $list.View = 'Details'
    $list.GridLines = $true
    $list.FullRowSelect = $true
    for ($index = 0; $index -lt $Names.Length; $index++) {
        [void]$list.Columns.Add($Names[$index], $Widths[$index])
    }
    $page.Controls.Add($list)
    $tabs.TabPages.Add($page)
    $lists[$Name] = $list
}

Add-ColumnsTab 'Status' @('Property', 'Value') @(225, 590)
Add-ColumnsTab 'Files' @('Path', 'Type', 'Bytes') @(515, 135, 150)
Add-ColumnsTab 'History' @('Snapshot', 'State', 'Current') @(530, 145, 125)
Add-ColumnsTab 'Conflicts' @('Transaction', 'Resolution', 'On disk') @(510, 150, 150)
Add-ColumnsTab 'Unavailable chunks' @('Observed chunk') @(790)
Add-ColumnsTab 'WebDAV' @('Export URL', 'Access', 'Upload limit (bytes)') @(470, 140, 190)
$lists['WebDAV'].MultiSelect = $false

function Add-ClientRow {
    param([string]$Tab, [object[]]$Values)
    $item = [Windows.Forms.ListViewItem]::new([string]$Values[0])
    for ($index = 1; $index -lt $Values.Count; $index++) {
        [void]$item.SubItems.Add([string]$Values[$index])
    }
    [void]$lists[$Tab].Items.Add($item)
}

function Update-Client {
    $form.UseWaitCursor = $true
    $stopButton.Enabled = $false
    $testButton.Enabled = $false
    $form.Refresh()
    try {
        $script:current = Get-ClientSnapshot
        $local = $current.observation.local
        foreach ($list in $lists.Values) { $list.Items.Clear() }
        $ready = if ($current.resources_ready) { 'Local resources ready' } else { 'Local resources unavailable' }
        $age = if ($local) { "   |   Sample age: $($current.observation.age_ms) ms" } else { '' }
        $summary.Text = "$ready$age`r`nRemote backup: unverified"
        if ($local) {
            Add-ClientRow 'Status' @('Space', $local.space_id)
            Add-ClientRow 'Status' @('Device', $local.device_id)
            Add-ClientRow 'Status' @('Pending files / publications', "$($local.outstanding_mutations) / $($local.outstanding_publications)")
            Add-ClientRow 'Status' @('Checked current chunks', "$($local.chunks.checked_chunks) / $($local.chunks.total_current_chunks)")
            Add-ClientRow 'Status' @('Unavailable in sample', $local.chunks.unavailable_chunks.Count)
            if ($local.entries_truncated -or $local.snapshots_truncated -or $local.conflict_admissions_truncated) {
                Add-ClientRow 'Status' @('Display limit', 'Some lists are truncated.')
            }
            foreach ($row in $local.entries) { Add-ClientRow 'Files' @($row.path, $row.kind, $row.logical_bytes) }
            foreach ($row in $local.snapshots) { Add-ClientRow 'History' @($row.snapshot_id, $row.state, $row.current) }
            foreach ($row in $local.conflict_admissions) {
                $state = if ($row.resolution_applied) { 'Committed' } else { 'Pending' }
                Add-ClientRow 'Conflicts' @($row.transaction_id, $state, $row.worktree_materialized)
            }
            foreach ($id in $local.chunks.unavailable_chunks) { Add-ClientRow 'Unavailable chunks' @($id) }
        }
        if ($current.storage) {
            $storage = $current.storage.actual
            Add-ClientRow 'Status' @('Storage node', $storage.role)
            Add-ClientRow 'Status' @('Physical CAS / limit', "$($storage.physical_cas_bytes) / $($storage.stored_byte_limit)")
        }
        if ($current.webdav) {
            Add-ClientRow 'Status' @('WebDAV accounts', ($current.webdav.accounts -join ', '))
            foreach ($row in $current.webdav.exports) {
                $access = if ($row.writable) { 'Read / write' } else { 'Read only' }
                Add-ClientRow 'WebDAV' @($row.url, $access, $row.max_upload_bytes)
            }
        } else {
            Add-ClientRow 'Status' @('WebDAV', 'No active gateway in this deployment')
        }
        $testButton.Enabled = [bool]($gatewayPath -and $current.webdav)
        $stopButton.Enabled = $current.stop_allowed
    } catch {
        $script:current = $null
        foreach ($list in $lists.Values) { $list.Items.Clear() }
        $summary.Text = 'Could not read the deployment status. Start the service and check the profile credentials.'
    } finally { $form.UseWaitCursor = $false }
}

$null = Add-ClientButton 'Refresh' { Update-Client }
$stopButton = Add-ClientButton 'Stop deployment' {
    if (!$script:current) { return }
    $choice = [Windows.Forms.MessageBox]::Show($form, 'Stop this local deployment?', 'SyncExtend', 'YesNo', 'Question')
    if ($choice -ne 'Yes') { return }
    try {
        $null = Invoke-SyncExtendJson $binaryPath @('management-stop', '--config', $managementPath,
            '--owner-generation', $script:current.owner_generation, '--request-id', [Guid]::NewGuid().ToString('N'))
        foreach ($list in $lists.Values) { $list.Items.Clear() }
        $script:current = $null
        $stopButton.Enabled = $false
        $testButton.Enabled = $false
        $summary.Text = 'Stop accepted. The deployment is now shutting down.'
    } catch { $summary.Text = 'The stop was refused. Refresh before trying again.' }
}
$testButton = Add-ClientButton 'Test selected WebDAV export' {
    $list = $lists['WebDAV']
    if ($list.SelectedIndices.Count -ne 1) {
        $tabs.SelectedTab = $list.Parent
        $summary.Text = 'Select a WebDAV export to test.'
        return
    }
    try {
        $selected = $script:current.webdav.exports[$list.SelectedIndices[0]]
        $gateway = Invoke-SyncExtendJson $binaryPath @('webdav-check', '--config', $gatewayPath)
        $account = $gateway.accounts | Where-Object { $_.exports -contains $selected.name } | Select-Object -First 1
        if (!$account) { throw 'No configured account can access this export.' }
        $result = Invoke-SyncExtendJson $binaryPath @('webdav-connection-test', '--config', $gatewayPath,
            '--username', $account.username, '--export', $selected.name)
        $summary.Text = "Authenticated as $($result.username)`r`n$($result.url)"
    } catch { $summary.Text = 'The selected WebDAV export did not pass its connection test.' }
}
$null = Add-ClientButton 'Open profile folder' {
    Invoke-Item -LiteralPath ([IO.Path]::GetDirectoryName((Resolve-SyncExtendPath $Deployment -File)))
}

$stopButton.Enabled = $false
$testButton.Enabled = $false
$form.Add_Shown({ Update-Client })
try { [void]$form.ShowDialog() }
finally { $form.Dispose() }
