#Requires -Version 7.0
[CmdletBinding()]
param(
    [string]$Deployment = (Join-Path $env:LOCALAPPDATA 'SyncExtend\client\deployment.json'),
    [string]$Binary = (Join-Path $PSScriptRoot 'syncd.exe'),
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'SyncExtend\install'),
    [ValidateRange(1024, 65535)][int]$WebdavPort = 17842,
    [string]$StorageConfig,
    [string]$AttemptPolicy,
    [switch]$Managed,
    [switch]$Snapshot
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-common.ps1')
. (Join-Path $PSScriptRoot 'client-view.ps1')
$binaryPath = Resolve-SyncExtendPath $Binary -File
$deploymentPath = Resolve-SyncExtendPath $Deployment -File
$deploymentFile = Read-SyncExtendJson $deploymentPath
$managementPath = Resolve-SyncExtendPath $deploymentFile.management -File
if ([bool]$StorageConfig -ne [bool]$AttemptPolicy) {
    throw 'Specify both -StorageConfig and -AttemptPolicy for the independent read-only budget view.'
}
$script:budgetConfig = $StorageConfig
$script:budgetPolicy = $AttemptPolicy
$script:busy = $false

function Get-ClientSnapshot {
    Invoke-SyncExtendJson $binaryPath @('management-dashboard', '--config', $managementPath)
}

function Get-ClientBudgetRows {
    if (!$script:budgetConfig -or !$script:budgetPolicy) {
        return ,@('显式拉取预算', '未指定预算文件；可通过“查看拉取预算”只读检查已初始化的账本')
    }
    try {
        $configuration = Read-SyncExtendJson $script:budgetConfig
        $policy = Read-SyncExtendJson $script:budgetPolicy 16384
        $status = Invoke-SyncExtendJson $binaryPath @('storage-pull-budget-status', '--config',
            (Resolve-SyncExtendPath $script:budgetConfig -File), '--policy',
            (Resolve-SyncExtendPath $script:budgetPolicy -File))
        New-SyncExtendPullBudgetView $status $policy $configuration ([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
    } catch {
        return @(
            ,@('预算读取', '被拒绝；没有可验证的预算样本')
            ,@('检查配置', '请选择匹配的存储配置和显式策略，确认账本已初始化且当前可只读访问')
            ,@('额度状态', '未知；读取失败不会初始化、重置账本或退还既有预留')
        )
    }
}

if ($Snapshot) {
    $value = Get-ClientSnapshot
    $null = New-SyncExtendClientView $value
    if ($script:budgetPolicy) { $value.client_pull_budget = @(Get-ClientBudgetRows) }
    $value | ConvertTo-Json -Depth 12 -Compress
    return
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
$form = [Windows.Forms.Form]::new()
$form.Text = 'SyncExtend'
$form.StartPosition = 'CenterScreen'
$form.MinimumSize = [Drawing.Size]::new(900, 550)
$form.Size = [Drawing.Size]::new(980, 650)
$form.Font = [Drawing.Font]::new('Segoe UI', 10)
$form.BackColor = [Drawing.Color]::White

$layout = [Windows.Forms.TableLayoutPanel]::new()
$layout.ColumnCount = 1
$layout.RowCount = 4
$layout.Dock = 'Fill'
$layout.Padding = [Windows.Forms.Padding]::new(18, 14, 18, 14)
foreach ($height in @(46, 66, 82)) {
    [void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new('Absolute', $height))
}
[void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new('Percent', 100))
$form.Controls.Add($layout)

$heading = [Windows.Forms.Label]::new()
$heading.Text = 'SyncExtend  /  本机客户端'
$heading.Font = [Drawing.Font]::new('Segoe UI', [single]20, [Drawing.FontStyle]::Bold)
$heading.ForeColor = [Drawing.Color]::FromArgb(22, 63, 57)
$heading.Dock = 'Fill'
$layout.Controls.Add($heading, 0, 0)

$summary = [Windows.Forms.Label]::new()
$summary.Dock = 'Fill'
$summary.Text = '正在读取本机服务。'
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
    param([string]$Name, [string[]]$Names, [int[]]$Widths, [string]$Caption = $Name)
    $page = [Windows.Forms.TabPage]::new($Caption)
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

Add-ColumnsTab 'Status' @('项目', '状态') @(225, 665) '本机状态'
Add-ColumnsTab 'Files' @('相对路径', '类型', '逻辑大小') @(480, 95, 230) '工作区'
Add-ColumnsTab 'History' @('快照', '状态', '当前') @(530, 145, 100) '本机历史'
Add-ColumnsTab 'Conflicts' @('事务', '处置', '文件已物化') @(510, 130, 130) '冲突'
Add-ColumnsTab 'Unavailable chunks' @('样本来源', '不可读取块') @(150, 670) '缺块'
Add-ColumnsTab 'WebDAV' @('导出地址', '配置权限', '上传上限') @(470, 140, 200)
Add-ColumnsTab 'Storage' @('项目', '状态') @(225, 665) '存储与暂存'
Add-ColumnsTab 'Storage snapshots' @('来源设备', '快照报告', '报告时间') @(360, 360, 190) '存储报告'
Add-ColumnsTab 'Network' @('项目', '状态') @(225, 665) '连接与路径'
Add-ColumnsTab 'Pull budget' @('项目', '状态') @(225, 665) '拉取预算'
$lists['WebDAV'].MultiSelect = $false

function Add-ClientRow {
    param([string]$Tab, [object[]]$Values)
    $item = [Windows.Forms.ListViewItem]::new([string]$Values[0])
    for ($index = 1; $index -lt $Values.Count; $index++) {
        [void]$item.SubItems.Add([string]$Values[$index])
    }
    [void]$lists[$Tab].Items.Add($item)
}

function Clear-Client {
    $script:current = $null
    foreach ($list in $lists.Values) { $list.Items.Clear() }
    $stopButton.Enabled = $false
    $testButton.Enabled = $false
    if ($Managed) {
        $gatewayButton.Enabled = $false
        $startButton.Enabled = $false
    }
}

function Show-ClientUnavailable {
    Clear-Client
    $summary.Text = '无法读取或验证本机状态。请检查服务和当前用户的配置凭据。'
    if ($Managed) {
        try {
            $status = & (Join-Path $PSScriptRoot 'manage-user.ps1') status -InstallRoot $InstallRoot
            if ($status.state -ceq 'stopped' -and !$status.process_active) {
                $summary.Text = "本机服务已停止。可启动原来选定的已安装版本。`r`n工作树、历史与配置继续保留。"
                Add-ClientRow 'Status' @('本机服务', '已停止')
                Add-ClientRow 'Status' @('已选版本', $status.version)
                Add-ClientRow 'Status' @('WebDAV 运行状态', '已停止；配置保留')
                $startButton.Enabled = $true
            } elseif (!$status.process_active) {
                Add-ClientRow 'Status' @('已记录状态', $status.state)
                Add-ClientRow 'Status' @('后续操作', '检查配置和日志；异常或卸载状态不会自动启动')
            }
        } catch { }
    }
    Add-ClientRow 'Network' @('实际路径与流量', '无可验证的运行样本')
}

function Update-Client {
    if ($script:busy) { return }
    $script:busy = $true
    $form.UseWaitCursor = $true
    Clear-Client
    $form.Refresh()
    try {
        $script:current = Get-ClientSnapshot
        $view = New-SyncExtendClientView $script:current
        $summary.Text = $view.Summary
        foreach ($tab in $view.Rows.Keys) {
            foreach ($row in $view.Rows[$tab]) { Add-ClientRow $tab $row }
        }
        $lists['Pull budget'].Items.Clear()
        foreach ($row in @(Get-ClientBudgetRows)) { Add-ClientRow 'Pull budget' $row }
        $profile = Read-SyncExtendJson $deploymentPath
        $role = $profile.role
        $script:gatewayPath = if ($role.kind -ceq 'webdav_client') {
            Resolve-SyncExtendPath $role.gateway_config -File
        }
        $script:gatewayEnabled = $false
        if ($script:gatewayPath) {
            $configuration = Invoke-SyncExtendJson $binaryPath @('deployment-check', '--config', $deploymentPath, '--describe-webdav')
            $script:gatewayEnabled = $configuration.webdav.enabled
        }
        if ($current.webdav) {
            Add-ClientRow 'Status' @('WebDAV 配置', $(if ($script:gatewayEnabled) { '已开启；可选择导出进行认证连接测试' } else { '当前配置已关闭；运行观察可能来自更早的配置' }))
        } elseif ($script:gatewayEnabled) {
            Add-ClientRow 'Status' @('WebDAV 配置', '已开启，但没有活动监听观察；请检查服务资源和端口')
        } elseif ($script:gatewayPath) {
            Add-ClientRow 'Status' @('WebDAV 配置', '已关闭；导出与凭据继续保留')
        } else {
            Add-ClientRow 'Status' @('WebDAV 配置', '尚未配置本机网关')
        }
        $testButton.Enabled = [bool]($script:gatewayPath -and $script:gatewayEnabled -and $current.webdav -and
            $current.resources_ready -and $current.webdav.scheme -ceq 'http')
        if ($current.webdav.scheme -ceq 'https') {
            Add-ClientRow 'Status' @('HTTPS 连接测试', '请在已信任证书的本机应用中测试此导出')
        }
        $stopButton.Enabled = $view.StopAllowed
        if ($Managed) {
            $gatewayButton.Text = if ($script:gatewayEnabled) { '关闭 WebDAV' } else { '开启只读 WebDAV' }
            $gatewayButton.Enabled = [bool]($view.StopAllowed -and $current.resources_ready -and
                ($role.kind -ceq 'local_polling' -or ($role.kind -ceq 'webdav_client' -and $role.scan_interval_secs)))
        }
    } catch {
        Show-ClientUnavailable
    } finally { $form.UseWaitCursor = $false; $script:busy = $false }
}

$null = Add-ClientButton '刷新状态' { Update-Client }
if ($Managed) {
    $startButton = Add-ClientButton '启动已停止服务' {
        if ($script:busy -or $script:current) { return }
        $script:busy = $true
        $startButton.Enabled = $false
        $form.UseWaitCursor = $true
        $summary.Text = '正在启动已选定的安装版本…'
        $form.Refresh()
        $failure = $false
        try {
            $null = & (Join-Path $PSScriptRoot 'manage-user.ps1') resume -InstallRoot $InstallRoot -Deployment $deploymentPath
        } catch { $failure = $true }
        finally { $script:busy = $false; $form.UseWaitCursor = $false }
        Update-Client
        if ($failure) { $summary.Text = '启动被拒绝。请确认服务已正常停止，当前配置和已安装版本均未被替换。' }
    }
    $startButton.Enabled = $false
}
$stopButton = Add-ClientButton '停止本机服务' {
    if ($script:busy -or !$script:current) { return }
    $choice = [Windows.Forms.MessageBox]::Show($form, '停止当前本机服务？目录扫描和该服务提供的 WebDAV 都会暂停。', 'SyncExtend', 'YesNo', 'Question')
    if ($choice -ne 'Yes') { return }
    $script:busy = $true
    try {
        if ($Managed) {
            $null = & (Join-Path $PSScriptRoot 'manage-user.ps1') stop -InstallRoot $InstallRoot -Deployment $deploymentPath `
                -OwnerGeneration $script:current.owner_generation
        } else {
            $null = Invoke-SyncExtendJson $binaryPath @('management-stop', '--config', $managementPath,
                '--owner-generation', $script:current.owner_generation, '--request-id', [Guid]::NewGuid().ToString('N'))
        }
        Show-ClientUnavailable
        if (!$Managed) { $summary.Text = '停止请求已接受，服务正在退出。确认退出前不表示已停止。' }
    } catch {
        Clear-Client
        $summary.Text = '停止请求被拒绝或未确认。请刷新当前属主状态后重试。'
    } finally { $script:busy = $false }
}
$testButton = Add-ClientButton '测试选中 WebDAV 导出' {
    if ($script:busy -or !$script:current) { return }
    $list = $lists['WebDAV']
    if ($list.SelectedIndices.Count -ne 1) {
        $tabs.SelectedTab = $list.Parent
        $summary.Text = '请先在 WebDAV 页选中一个导出。'
        return
    }
    try {
        $selected = $script:current.webdav.exports[$list.SelectedIndices[0]]
        $gateway = Invoke-SyncExtendJson $binaryPath @('webdav-check', '--config', $script:gatewayPath)
        $account = $gateway.accounts | Where-Object { $_.exports -contains $selected.name } | Select-Object -First 1
        if (!$account) { throw 'No configured account can access this export.' }
        $result = Invoke-SyncExtendJson $binaryPath @('webdav-connection-test', '--config', $script:gatewayPath,
            '--username', $account.username, '--export', $selected.name)
        if ($result.url -cne $selected.url) { throw 'The running export differs from this configuration.' }
        if ($result.remote_backup_complete -cne $false -or $result.export_accessible -cne $true) { throw 'The connection result cannot be verified.' }
        $summary.Text = "已验证本机认证账号：$($result.username)`r`n$($result.url)；远端备份状态尚未确认。"
    } catch { $summary.Text = '此导出没有通过认证连接测试。请刷新状态并检查账号、配置和活动监听。' }
}
if ($Managed) {
    $gatewayButton = Add-ClientButton '开启只读 WebDAV' {
        if ($script:busy -or !$script:current) { return }
        $enable = !$script:gatewayEnabled
        $question = if (!$enable) {
            '关闭 WebDAV 并短暂重启本机服务？目录扫描随后恢复。'
        } elseif ($script:gatewayPath) {
            '开启已有 WebDAV 导出并短暂重启本机服务？现有账号与导出权限继续生效。'
        } else {
            '为当前工作树开启有认证的只读 WebDAV，并短暂重启本机服务？'
        }
        $choice = [Windows.Forms.MessageBox]::Show($form, $question, 'SyncExtend', 'YesNo', 'Question')
        if ($choice -ne 'Yes') { return }
        $gatewayButton.Enabled = $false
        $form.UseWaitCursor = $true
        $summary.Text = '正在应用 WebDAV 配置…'
        $form.Refresh()
        $failure = $null
        try {
            $action = if ($enable) { 'webdav-enable' } else { 'webdav-disable' }
            $null = & (Join-Path $PSScriptRoot 'manage-user.ps1') $action -InstallRoot $InstallRoot -Deployment $deploymentPath `
                -WebdavPort $WebdavPort -OwnerGeneration $script:current.owner_generation
        } catch { $failure = $_.Exception.Message }
        Update-Client
        if ($failure) { $summary.Text = $failure }
    }
    $gatewayButton.Enabled = $false
}
$null = Add-ClientButton '查看拉取预算' {
    if ($script:busy) { return }
    $picker = [Windows.Forms.OpenFileDialog]::new()
    $picker.Filter = 'JSON files (*.json)|*.json'
    try {
        $picker.Title = '选择要只读检查的存储配置'
        if ($picker.ShowDialog($form) -ne 'OK') { return }
        $configuration = $picker.FileName
        $picker.Title = '选择对应的显式拉取预算策略'
        $picker.FileName = ''
        if ($picker.ShowDialog($form) -ne 'OK') { return }
        $script:budgetConfig = $configuration
        $script:budgetPolicy = $picker.FileName
        $lists['Pull budget'].Items.Clear()
        foreach ($row in @(Get-ClientBudgetRows)) { Add-ClientRow 'Pull budget' $row }
        $tabs.SelectedTab = $lists['Pull budget'].Parent
    } finally { $picker.Dispose() }
}
$null = Add-ClientButton '打开配置目录' {
    Invoke-Item -LiteralPath ([IO.Path]::GetDirectoryName($deploymentPath))
}

$stopButton.Enabled = $false
$testButton.Enabled = $false
$form.Add_Shown({ Update-Client })
try { [void]$form.ShowDialog() }
finally { $form.Dispose() }
