#Requires -Version 7.0
[CmdletBinding()]
param(
    [string]$Deployment = (Join-Path $env:LOCALAPPDATA 'SyncExtend\client\deployment.json'),
    [string]$Binary = (Join-Path $PSScriptRoot 'syncd.exe'),
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'SyncExtend\install'),
    [ValidateRange(1024, 65535)][int]$WebdavPort = 17842,
    [string]$StorageConfig,
    [string]$AttemptPolicy,
    [string]$RestoreBudgets,
    [switch]$ProtectedDeployment,
    [switch]$Managed,
    [switch]$Snapshot,
    [string]$LayoutProbe
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows-common.ps1')
. (Join-Path $PSScriptRoot 'client-view.ps1')
. (Join-Path $PSScriptRoot 'protected-deployment-client.ps1')
$binaryPath = if ($LayoutProbe) {
    Join-Path $PSScriptRoot 'layout-probe-syncd.exe'
} else {
    Resolve-SyncExtendPath $Binary -File
}
if ($ProtectedDeployment) {
    if ($Snapshot) { throw '-ProtectedDeployment opens the interactive deployment control window.' }
    Show-SyncExtendProtectedDeploymentClient $binaryPath
    return
}
if ($LayoutProbe) {
    # The hidden structural probe never opens or verifies a deployment.
    $deploymentPath = Join-Path $PSScriptRoot 'layout-probe-deployment.json'
    $managementPath = Join-Path $PSScriptRoot 'layout-probe-management.json'
} else {
    $deploymentPath = Resolve-SyncExtendPath $Deployment -File
    $deploymentFile = Read-SyncExtendJson $deploymentPath
    $managementPath = Resolve-SyncExtendPath $deploymentFile.management -File
}
if ([bool]$StorageConfig -ne [bool]$AttemptPolicy) {
    throw 'Specify both -StorageConfig and -AttemptPolicy for the independent read-only budget view.'
}
$script:budgetConfig = $StorageConfig
$script:budgetPolicy = $AttemptPolicy
$script:busy = $false
$script:restoreWorker = $null
$script:pendingRestore = $null
$script:restoreRequest = $null
$script:restorePreviewDigest = $null
$script:restorePreviewAtMs = 0
$script:restoreBudgets = $RestoreBudgets
$script:protectedClient = $null

function Get-ClientSnapshot {
    Invoke-SyncExtendJson $binaryPath @('management-dashboard', '--config', $managementPath)
}

function Get-ClientRestoreContext([string]$SpaceId) {
    $arguments = @('management-restore-preview', '--config', $managementPath, '--context')
    if ($SpaceId) { $arguments += @('--space-id', $SpaceId) }
    Invoke-SyncExtendJson $binaryPath $arguments
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
$form.MinimumSize = [Drawing.Size]::new(900, 780)
$form.Size = [Drawing.Size]::new(1120, 900)
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
    $list.Scrollable = $true
    $list.GridLines = $true
    $list.FullRowSelect = $true
    $list.ShowItemToolTips = $true
    for ($index = 0; $index -lt $Names.Length; $index++) {
        $headerWidth = [Windows.Forms.TextRenderer]::MeasureText($Names[$index], $form.Font).Width + 24
        [void]$list.Columns.Add($Names[$index], [Math]::Max($Widths[$index], $headerWidth))
    }
    $page.Controls.Add($list)
    $tabs.TabPages.Add($page)
    $lists[$Name] = $list
}

Add-ColumnsTab 'Status' @('项目', '状态') @(225, 665) '本机状态'
Add-ColumnsTab 'Files' @('相对路径', '类型', '逻辑大小', '源修改时间（UTC）', '只读属性', '元数据能力', '时间精度') `
    @(360, 70, 170, 275, 85, 240, 100) '工作区'
Add-ColumnsTab 'History' @('快照', '原状态', '快照创建时间', '当前 / 锁定', '内容状态', '裁剪时间') @(275, 100, 180, 140, 150, 180) '本机历史'
Add-ColumnsTab 'Pruned history' @('快照', '原状态', '快照创建时间', '当前 / 锁定', '内容状态', '裁剪时间') @(275, 100, 180, 140, 150, 180) '裁剪审计'
Add-ColumnsTab 'Recovery' @('项目', '只读观察与手动入口') @(230, 800) '恢复与预览'
Add-ColumnsTab 'Selection preview' @('历史源路径', '实际目标路径', '差异', '新操作描述', '历史逻辑大小', '当前逻辑大小', '冲突路径') @(230, 250, 150, 180, 140, 140, 220) '选择恢复预览'
Add-ColumnsTab 'Conflicts' @('事务', '处置', '文件已物化') @(510, 130, 130) '冲突'
Add-ColumnsTab 'Unavailable chunks' @('样本来源', '不可读取块') @(150, 670) '缺块'
Add-ColumnsTab 'WebDAV' @('导出地址', '配置权限', '上传上限') @(470, 140, 200)
Add-ColumnsTab 'Storage' @('项目', '状态') @(225, 665) '存储与暂存'
Add-ColumnsTab 'Storage snapshots' @('来源设备', '快照报告', '报告时间') @(360, 360, 190) '存储报告'
Add-ColumnsTab 'Network' @('项目', '状态') @(225, 665) '连接与路径'
Add-ColumnsTab 'Pull budget' @('项目', '状态') @(225, 665) '拉取预算'
Add-ColumnsTab 'Native audit' @('项目', '只读摘要') @(210, 830) '原生历史审计'
$lists['WebDAV'].MultiSelect = $false
$lists['Selection preview'].Name = 'RestorePreviewRows'

$restorePage = $lists['Selection preview'].Parent
$restoreLayout = [Windows.Forms.TableLayoutPanel]::new()
$restoreLayout.Dock = 'Fill'
$restoreLayout.ColumnCount = 1
$restoreLayout.RowCount = 3
[void]$restoreLayout.RowStyles.Add([Windows.Forms.RowStyle]::new('Absolute', 292))
[void]$restoreLayout.RowStyles.Add([Windows.Forms.RowStyle]::new('Percent', 100))
[void]$restoreLayout.RowStyles.Add([Windows.Forms.RowStyle]::new('Absolute', 153))
$restorePanel = [Windows.Forms.TableLayoutPanel]::new()
$restorePanel.Dock = 'Fill'
$restorePanel.Padding = [Windows.Forms.Padding]::new(8)
$restorePanel.ColumnCount = 4
$restorePanel.RowCount = 7
foreach ($style in @(
        [Windows.Forms.ColumnStyle]::new('Absolute', 90),
        [Windows.Forms.ColumnStyle]::new('Percent', 50),
        [Windows.Forms.ColumnStyle]::new('Absolute', 90),
        [Windows.Forms.ColumnStyle]::new('Percent', 50))) { [void]$restorePanel.ColumnStyles.Add($style) }
foreach ($height in @(30, 30, 30, 64, 34, 34, 42)) {
    [void]$restorePanel.RowStyles.Add([Windows.Forms.RowStyle]::new('Absolute', $height))
}
function Add-RestoreLabel([string]$Text, [int]$Column, [int]$Row) {
    $label = [Windows.Forms.Label]::new()
    $label.Text = $Text
    $label.Dock = 'Fill'
    $label.TextAlign = 'MiddleLeft'
    $restorePanel.Controls.Add($label, $Column, $Row)
}
function New-RestoreChoice([string]$Name, [object[]]$Choices) {
    $choice = [Windows.Forms.ComboBox]::new()
    $choice.Name = $Name
    $choice.Dock = 'Fill'
    $choice.DropDownStyle = 'DropDownList'
    $choice.DropDownWidth = 620
    if ($Choices.Count) { $choice.Items.AddRange($Choices); $choice.SelectedIndex = 0 }
    return $choice
}
Add-RestoreLabel 'owner 空间' 0 0
$restoreSpace = New-RestoreChoice 'RestoreOwnerSpace' @()
$restorePanel.Controls.Add($restoreSpace, 1, 0)
$restorePanel.SetColumnSpan($restoreSpace, 3)
Add-RestoreLabel '历史快照' 0 1
$restoreSnapshot = New-RestoreChoice 'RestoreSnapshot' @()
$restoreSnapshot.DisplayMember = 'Label'
$restorePanel.Controls.Add($restoreSnapshot, 1, 1)
$restorePanel.SetColumnSpan($restoreSnapshot, 3)
Add-RestoreLabel '选择范围' 0 2
$restoreMode = New-RestoreChoice 'RestoreSelectionMode' @('完整快照', '单个文件', '目录子树', '多个明确路径')
$restorePanel.Controls.Add($restoreMode, 1, 2)
Add-RestoreLabel '目标前缀' 2 2
$restorePrefix = [Windows.Forms.TextBox]::new()
$restorePrefix.Name = 'RestoreDestinationPrefix'
$restorePrefix.Dock = 'Fill'
$restorePrefix.MaxLength = 4096
$restorePrefix.PlaceholderText = '可留空；如 archive/2026，完整源路径保留在其下'
$restorePanel.Controls.Add($restorePrefix, 3, 2)
Add-RestoreLabel '源相对路径' 0 3
$restorePaths = [Windows.Forms.TextBox]::new()
$restorePaths.Name = 'RestoreSourcePaths'
$restorePaths.Dock = 'Fill'
$restorePaths.Multiline = $true
$restorePaths.ScrollBars = 'Vertical'
$restorePaths.MaxLength = 16384
$restorePaths.PlaceholderText = '文件或目录填写一个路径；多路径逐行填写。使用 /，不得填写主机绝对路径。'
$restorePanel.Controls.Add($restorePaths, 1, 3)
$restorePanel.SetColumnSpan($restorePaths, 3)
Add-RestoreLabel '当前额外项' 0 4
$restoreExtra = New-RestoreChoice 'RestoreCurrentExtraPolicy' @('保留当前额外项（默认）', '描述删除选中范围中的额外项')
$restorePanel.Controls.Add($restoreExtra, 1, 4)
Add-RestoreLabel '目标已占用' 2 4
$restoreOccupied = New-RestoreChoice 'RestoreOccupiedTargetPolicy' @('报告已有文件冲突（默认）', '描述新的文件覆盖操作')
$restorePanel.Controls.Add($restoreOccupied, 3, 4)
$restoreButton = [Windows.Forms.Button]::new()
$restoreButton.Name = 'RestorePreviewButton'
$restoreButton.Text = '生成预览'
$restoreButton.Dock = 'Fill'
$restoreButton.Enabled = $false
$restorePanel.Controls.Add($restoreButton, 0, 5)
$restoreExecute = [Windows.Forms.Button]::new()
$restoreExecute.Name = 'RestoreExecuteButton'
$restoreExecute.Text = '停止并恢复所选内容'
$restoreExecute.Dock = 'Fill'
$restoreExecute.Enabled = $false
$restorePanel.Controls.Add($restoreExecute, 1, 5)
$restoreResume = [Windows.Forms.Button]::new()
$restoreResume.Name = 'RestoreResumeButton'
$restoreResume.Text = '继续原事务'
$restoreResume.Dock = 'Fill'
$restoreResume.Enabled = $false
$restorePanel.Controls.Add($restoreResume, 2, 5)
$restoreGuide = [Windows.Forms.Label]::new()
$restoreGuide.Text = if ($Managed) { '恢复产生新历史；失败保持 pending，请继续原事务。' } else { '原生执行需要 Windows 托管本机客户端。' }
$restoreGuide.Dock = 'Fill'
$restoreGuide.TextAlign = 'MiddleLeft'
$restorePanel.Controls.Add($restoreGuide, 3, 5)
Add-RestoreLabel '恢复预算' 0 6
$restoreBudgetButton = [Windows.Forms.Button]::new()
$restoreBudgetButton.Name = 'RestoreBudgetsButton'
$restoreBudgetButton.Text = '选择 TREE 恢复预算…'
$restoreBudgetButton.Dock = 'Fill'
$restoreBudgetButton.Enabled = [bool]$Managed
$restorePanel.Controls.Add($restoreBudgetButton, 1, 6)
$restoreBudgetNote = [Windows.Forms.Label]::new()
$restoreBudgetNote.Name = 'RestoreBudgetsSelection'
$restoreBudgetNote.Text = if ($script:restoreBudgets) { [IO.Path]::GetFileName($script:restoreBudgets) } else { '先选择显式恢复预算，再生成预览。' }
$restoreBudgetNote.Dock = 'Fill'
$restoreBudgetNote.TextAlign = 'MiddleLeft'
$restorePanel.Controls.Add($restoreBudgetNote, 2, 6)
$restorePanel.SetColumnSpan($restoreBudgetNote, 2)
$restoreNotes = [Windows.Forms.Label]::new()
$restoreNotes.Name = 'RestorePreviewSummary'
$restoreNotes.Dock = 'Fill'
$restoreNotes.Padding = [Windows.Forms.Padding]::new(8)
$restoreNotes.Text = '等待当前 owner 的已鉴权历史列表。'
$restorePage.Controls.Remove($lists['Selection preview'])
$restoreLayout.Controls.Add($restorePanel, 0, 0)
$restoreLayout.Controls.Add($lists['Selection preview'], 0, 1)
$restoreLayout.Controls.Add($restoreNotes, 0, 2)
$restorePage.Controls.Add($restoreLayout)
$script:restoreContext = $null

function Set-ClientRestoreBusy([bool]$Value) {
    $protectedActive = Test-SyncExtendProtectedClientActive $script:protectedClient
    $available = [bool](!$Value -and !$protectedActive -and !$script:pendingRestore -and $script:restoreContext -and $script:restoreContext.available)
    $restoreSpace.Enabled = [bool](!$Value -and !$protectedActive -and !$script:pendingRestore -and $script:restoreContext -and $script:restoreContext.spaces.Count)
    foreach ($control in @($restoreSnapshot, $restoreMode, $restorePrefix, $restoreExtra, $restoreOccupied, $restoreButton)) {
        $control.Enabled = $available
    }
    $restorePaths.Enabled = $available -and $restoreMode.SelectedIndex -ne 0
    $age = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() - $script:restorePreviewAtMs
    $restoreExecute.Enabled = [bool]($Managed -and $available -and $script:restoreRequest -and
        $script:restorePreviewDigest -and $script:restoreBudgets -and $age -ge 0 -and $age -le 10000)
    $restoreResume.Enabled = [bool]($Managed -and !$Value -and !$protectedActive -and $script:pendingRestore -and !$script:pendingRestore.helper_active)
    $restoreBudgetButton.Enabled = [bool]($Managed -and !$Value -and !$protectedActive -and !$script:pendingRestore)
}

function Reset-ClientRestorePreview {
    $script:restoreRequest = $null
    $script:restorePreviewDigest = $null
    $script:restorePreviewAtMs = 0
    $restoreExecute.Enabled = $false
}

function Set-ClientPendingRestore($Pending) {
    $script:pendingRestore = $Pending
    if (!$Pending) { Set-ClientRestoreBusy $script:busy; return }
    Reset-ClientRestorePreview
    $view = New-SyncExtendPendingRestoreView $Pending
    $restoreNotes.Text = $view.Summary
    $lists['Recovery'].Items.Clear()
    foreach ($row in $view.Rows) { Add-ClientRow 'Recovery' $row }
    if ($Managed) {
        $startButton.Enabled = $false
        $gatewayButton.Enabled = $false
    }
    $stopButton.Enabled = $false
    Set-ClientRestoreBusy $script:busy
}

function Start-ClientRestoreWorker([string]$Kind, $Inputs) {
    if ($script:busy -or $script:restoreWorker) { throw 'A client operation is already running.' }
    $worker = [Management.Automation.PowerShell]::Create()
    try {
        if ($Kind -ceq 'preview') {
            $null = $worker.AddScript({
                param($Common, $Image, $Arguments)
                $ErrorActionPreference = 'Stop'
                . $Common
                Invoke-SyncExtendJson $Image $Arguments
            }.ToString()).AddArgument((Join-Path $PSScriptRoot 'windows-common.ps1')).AddArgument($binaryPath).
                AddArgument([string[]]$Inputs.Arguments)
        } else {
            $null = $worker.AddCommand((Join-Path $PSScriptRoot 'manage-user.ps1'))
            foreach ($key in $Inputs.Parameters.Keys) { $null = $worker.AddParameter($key, $Inputs.Parameters[$key]) }
        }
        $script:busy = $true
        Set-ClientRestoreBusy $true
        $startButtonForRestore = if ($Managed) { $startButton }
        foreach ($button in @($stopButton, $gatewayButton, $startButtonForRestore)) {
            if ($button) { $button.Enabled = $false }
        }
        $form.UseWaitCursor = $true
        $handle = $worker.BeginInvoke()
        $script:restoreWorker = @{ Instance = $worker; Handle = $handle; Kind = $Kind; Inputs = $Inputs }
    } catch {
        $worker.Dispose()
        $script:busy = $false
        $form.UseWaitCursor = $false
        Set-ClientRestoreBusy $false
        throw
    }
}

$restoreWorkerTimer = [Windows.Forms.Timer]::new()
$restoreWorkerTimer.Interval = 200
$restoreWorkerTimer.Add_Tick({
    $currentWorker = $script:restoreWorker
    if (!$currentWorker) {
        if ($script:restorePreviewAtMs -gt 0 -and !$script:busy) { Set-ClientRestoreBusy $false }
        return
    }
    if (!$currentWorker.Handle.IsCompleted) { return }
    $failure = $null
    $result = $null
    try {
        # EndInvoke waits this exact original invocation and surfaces its failure.
        $output = $currentWorker.Instance.EndInvoke($currentWorker.Handle)
        if ($currentWorker.Instance.HadErrors -or $output.Count -ne 1) { throw 'The original client helper did not return one verified result.' }
        $result = $output[0].PSObject.BaseObject
    } catch { $failure = $_.Exception.Message }
    finally {
        $currentWorker.Instance.Dispose()
        $script:restoreWorker = $null
        $script:busy = $false
        $form.UseWaitCursor = $false
    }
    if ($currentWorker.Kind -ceq 'preview') {
        try {
            if ($failure) { throw $failure }
            $request = $currentWorker.Inputs.Request
            if (!$script:current -or $script:current.owner_generation -cne $request.owner_generation) {
                throw 'The displayed owner changed while previewing.'
            }
            $view = New-SyncExtendRestorePreviewView $result $request
            foreach ($row in $view.Rows) { Add-ClientRow 'Selection preview' $row }
            $restoreNotes.Text = $view.Summary
            Reset-ClientRestorePreview
            try {
                $script:restorePreviewDigest = Get-SyncExtendRestorePreviewBinding $result $request
                $script:restoreRequest = $request
                $script:restorePreviewAtMs = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
                if ($Managed) { $restoreNotes.Text += "`r`n执行前会再次核对当前属主和完整范围；预览有效期为10秒。" }
            } catch { $restoreNotes.Text += "`r`n当前选择不满足执行前提；请检查冲突、源保留状态和当前基线。" }
        } catch {
            Clear-ClientRestore
            $restoreNotes.Text = '预览被拒绝或当前属主已变化。请刷新状态，检查选择后重试。'
        }
        Set-ClientRestoreBusy $false
        return
    }
    Update-Client
    if ($failure) {
        $summary.Text = '恢复未完成。请查看原服务和持久事务状态，解决拒绝后继续原事务。'
        if ($script:pendingRestore) { $tabs.SelectedTab = $restorePage }
    } else {
        if ($result.restored -cne $true -or $result.owner_cleanup_complete -cne $true -or
            $result.same_journal_reopened -cne $true -or !$result.new_owner_generation) {
            $summary.Text = '无法验证完整恢复结果，请读取持久事务状态。'
        } else {
            $summary.Text = "已完成恢复事务 $($result.transaction_id)。`r`n新的本机历史：$($result.snapshot_id)。原配置服务已重新启动；远端备份状态尚未确认。"
        }
    }
})
$restoreWorkerTimer.Start()

function Clear-ClientRestore {
    Reset-ClientRestorePreview
    if ($restoreSnapshot.SelectedItem) { $script:restoreRememberedSnapshot = $restoreSnapshot.SelectedItem.Id }
    if ($restoreSpace.SelectedItem) { $script:restoreRememberedSpace = [string]$restoreSpace.SelectedItem }
    $script:restoreContext = $null
    $restoreSnapshot.Items.Clear()
    $restoreSpace.Items.Clear()
    $lists['Selection preview'].Items.Clear()
    $restoreNotes.Text = '当前没有可验证的恢复预览；请选择当前 owner 历史后生成。'
    Set-ClientRestoreBusy $false
}

function Set-ClientRestoreContext($Context) {
    Assert-SyncExtendRestoreContext $Context
    if ($Context.owner_generation -cne $script:current.owner_generation) {
        throw 'Restore context owner changed.'
    }
    $script:restoreContext = $Context
    $script:settingRestoreContext = $true
    $restoreSpace.Items.Clear()
    $restoreSnapshot.Items.Clear()
    foreach ($space in $Context.spaces) { [void]$restoreSpace.Items.Add($space) }
    if ($Context.space_id) { $restoreSpace.SelectedItem = $Context.space_id }
    foreach ($snapshot in $Context.snapshots) {
        $label = "$($snapshot.snapshot_id) · $($snapshot.state)"
        if ($snapshot.current) { $label += ' · 当前' }
        if ($snapshot.locked) { $label += ' · 锁定' }
        if (!$snapshot.content_retained) { $label += ' · 已裁剪' }
        [void]$restoreSnapshot.Items.Add([pscustomobject]@{ Id = $snapshot.snapshot_id; Label = $label })
    }
    if ($restoreSnapshot.Items.Count) {
        $restoreSnapshot.SelectedIndex = 0
        for ($index = 0; $index -lt $restoreSnapshot.Items.Count; $index++) {
            if ($restoreSnapshot.Items[$index].Id -ceq $script:restoreRememberedSnapshot) {
                $restoreSnapshot.SelectedIndex = $index; break
            }
        }
    }
    $restoreNotes.Text = if ($Context.available) {
        '选择快照、范围和可选目标前缀。已有文件默认报告冲突，当前额外项默认保留。'
    } else { '该服务当前没有可验证的 owner 历史，预览不可用。' }
    if ($Context.snapshots_truncated) { $restoreNotes.Text += "`r`n历史下拉列表已按显示预算截断。" }
    if ($Context.spaces_truncated) { $restoreNotes.Text += "`r`n空间下拉列表已按注册上限截断。" }
    $script:settingRestoreContext = $false
    Set-ClientRestoreBusy $false
}

$restoreSpace.Add_SelectedIndexChanged({
    if ($script:busy -or $script:settingRestoreContext -or !$restoreSpace.SelectedItem -or
        $restoreSpace.SelectedItem -ceq $script:restoreContext.space_id) { return }
    $script:busy = $true
    Set-ClientRestoreBusy $true
    $lists['Selection preview'].Items.Clear()
    try { Set-ClientRestoreContext (Get-ClientRestoreContext ([string]$restoreSpace.SelectedItem)) }
    catch {
        Clear-ClientRestore
        $restoreNotes.Text = '选中空间的当前 owner 上下文不可用，请刷新状态后重试。'
    } finally { $script:busy = $false; Set-ClientRestoreBusy $false }
})

foreach ($control in @($restoreSnapshot, $restoreMode, $restoreExtra, $restoreOccupied)) {
    $control.Add_SelectedIndexChanged({
        Reset-ClientRestorePreview
        $lists['Selection preview'].Items.Clear()
        $restoreNotes.Text = '选择已改变；请重新生成只读预览。'
        Set-ClientRestoreBusy $script:busy
    })
}
foreach ($control in @($restorePrefix, $restorePaths)) {
    $control.Add_TextChanged({
        Reset-ClientRestorePreview
        $lists['Selection preview'].Items.Clear()
        $restoreNotes.Text = '路径已改变；请重新生成只读预览。'
    })
}
$restoreButton.Add_Click({
    if ($script:busy -or !$script:restoreContext -or !$restoreSnapshot.SelectedItem) { return }
    Reset-ClientRestorePreview
    $lists['Selection preview'].Items.Clear()
    $restoreNotes.Text = '正在请求当前 owner 的同事务历史元数据…'
    try {
        $request = New-SyncExtendRestoreRequest $script:restoreContext $restoreSnapshot.SelectedItem.Id `
            (@('full', 'file', 'directory', 'paths')[$restoreMode.SelectedIndex]) $restorePaths.Text $restorePrefix.Text `
            (@('preserve', 'replace_selected_scope')[$restoreExtra.SelectedIndex]) `
            (@('report_conflicts', 'replace_files')[$restoreOccupied.SelectedIndex])
        $hex = Get-SyncExtendRestoreRequestHex $request
        Start-ClientRestoreWorker 'preview' @{
            Request = $request
            Arguments = @('management-restore-preview', '--config', $managementPath, '--request-hex', $hex)
        }
    } catch {
        Clear-ClientRestore
        $restoreNotes.Text = '预览被拒绝或当前属主已变化。请刷新状态，检查所选相对路径和请求大小后重试。'
    }
})

$restoreBudgetButton.Add_Click({
    if ($script:busy -or !$Managed -or $script:pendingRestore) { return }
    $picker = [Windows.Forms.OpenFileDialog]::new()
    $picker.Filter = 'JSON files (*.json)|*.json'
    $picker.Title = '选择明确限制计划、历史、原生执行、保留原件和清理费用的 TREE 预算'
    try {
        if ($picker.ShowDialog($form) -ne 'OK') { return }
        $path = Resolve-SyncExtendPath $picker.FileName -File
        Assert-SyncExtendRestoreBudgets (Read-SyncExtendJson $path 65536)
        $script:restoreBudgets = $path
        $restoreBudgetNote.Text = [IO.Path]::GetFileName($path)
        Reset-ClientRestorePreview
        $restoreNotes.Text = '预算已选定，请重新生成当前范围的预览。执行使用预算文件的原字节。'
    } catch { $restoreNotes.Text = '预算文件被拒绝，请选择匹配原生 TREE 合同的显式 JSON。' }
    finally { $picker.Dispose(); Set-ClientRestoreBusy $false }
})

$restoreExecute.Add_Click({
    if ($script:busy -or !$Managed -or !$restoreExecute.Enabled -or $script:pendingRestore) { return }
    $request = $script:restoreRequest
    $choice = [Windows.Forms.MessageBox]::Show($form,
        "停止本机服务并恢复刚预览的内容？`r`n这会按明确选择创建新的历史，保留未选区域；覆盖和选区删除遵循所选策略。恢复不是原子操作，中途失败将保持停止，只能继续原事务。`r`n新历史、清理和重新打开核验完成后，使用原配置启动服务。",
        'SyncExtend 恢复所选内容', 'YesNo', 'Warning')
    if ($choice -ne 'Yes') { return }
    $age = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() - $script:restorePreviewAtMs
    if ($age -lt 0 -or $age -gt 10000) {
        Reset-ClientRestorePreview
        $restoreNotes.Text = '预览已超过10秒，请重新生成后执行。'
        return
    }
    $restoreNotes.Text = '正在核对当前属主并停止原服务；恢复完成前请保持窗口打开。'
    Start-ClientRestoreWorker 'restore' @{
        Parameters = @{
            Action = 'restore'; InstallRoot = $InstallRoot; Deployment = $deploymentPath
            OwnerGeneration = $request.owner_generation; RestoreRequestHex = Get-SyncExtendRestoreRequestHex $request
            RestorePreviewDigest = $script:restorePreviewDigest; RestorePreviewAtMs = $script:restorePreviewAtMs
            RestoreBudgets = $script:restoreBudgets; AllowIrreversibleAdmission = $true; AllowNonAtomicTree = $true
        }
    }
})

$restoreResume.Add_Click({
    if ($script:busy -or !$Managed -or !$script:pendingRestore -or !$restoreResume.Enabled) { return }
    $transaction = $script:pendingRestore.transaction_id
    $choice = [Windows.Forms.MessageBox]::Show($form,
        "继续恢复事务 $transaction？`r`n使用原请求、原预算和原生执行记录；不会重新创建已有恢复属主。核验失败时服务仍保持停止。", 'SyncExtend 继续原恢复', 'YesNo', 'Warning')
    if ($choice -ne 'Yes') { return }
    $restoreNotes.Text = "正在继续原恢复事务 $transaction。"
    Start-ClientRestoreWorker 'resume' @{
        Parameters = @{
            Action = 'restore-resume'; InstallRoot = $InstallRoot; Deployment = $deploymentPath
            RestoreTransaction = $transaction; AllowIrreversibleAdmission = $true; AllowNonAtomicTree = $true
        }
    }
})

function Add-ClientRow {
    param([string]$Tab, [object[]]$Values)
    $item = [Windows.Forms.ListViewItem]::new([string]$Values[0])
    for ($index = 1; $index -lt $Values.Count; $index++) {
        [void]$item.SubItems.Add([string]$Values[$index])
    }
    $item.ToolTipText = ($Values -join "`r`n")
    if ($Tab -ceq 'Files') {
        foreach ($index in @(3, 5, 6)) {
            $textWidth = [Windows.Forms.TextRenderer]::MeasureText([string]$Values[$index], $lists[$Tab].Font).Width + 24
            $lists[$Tab].Columns[$index].Width = [Math]::Max($lists[$Tab].Columns[$index].Width, $textWidth)
        }
    }
    [void]$lists[$Tab].Items.Add($item)
}

function Clear-Client {
    $script:current = $null
    foreach ($list in $lists.Values) { $list.Items.Clear() }
    Clear-ClientRestore
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
            Set-ClientPendingRestore $status.pending_restore
            if ($status.pending_restore) {
                $summary.Text = (New-SyncExtendPendingRestoreView $status.pending_restore).Summary
                $tabs.SelectedTab = $restorePage
            } elseif (Test-SyncExtendVerifiedStopStatus $status) {
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
    Add-ClientRow 'Recovery' @('历史恢复元数据', '无可验证的当前样本；停止后历史内容仍须独立核对')
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
        try {
            $context = try { Get-ClientRestoreContext $script:restoreRememberedSpace }
                catch { Get-ClientRestoreContext }
            Set-ClientRestoreContext $context
        }
        catch {
            Clear-ClientRestore
            $restoreNotes.Text = '当前服务的选择预览不可用。需要已启用 dashboard 权限且资源就绪的同一 owner。'
        }
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
            $managedStatus = & (Join-Path $PSScriptRoot 'manage-user.ps1') status -InstallRoot $InstallRoot -Deployment $deploymentPath
            Set-ClientPendingRestore $managedStatus.pending_restore
        }
    } catch {
        Show-ClientUnavailable
    } finally { $form.UseWaitCursor = $false; $script:busy = $false; Set-ClientRestoreBusy $false }
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
$null = Add-ClientButton '恢复与预览说明' {
    $tabs.SelectedTab = $lists['Recovery'].Parent
}
$null = Add-ClientButton '原生历史只读审计…' {
    if ($script:busy) { return }
    $picker = [Windows.Forms.OpenFileDialog]::new()
    $picker.Filter = 'JSON files (*.json)|*.json'
    $picker.Title = '选择显式 schema69 原生历史审计请求'
    try {
        if ($picker.ShowDialog($form) -ne 'OK') { return }
        $requestPath = Resolve-SyncExtendPath $picker.FileName -File
        $request = Read-SyncExtendJson $requestPath 65536
        Assert-SyncExtendNativeHistoryAuditRequest $request
        $null = Resolve-SyncExtendPath ([string]$request.image) -File
        $lists['Native audit'].Items.Clear()
        Add-ClientRow 'Native audit' @('读取状态', '正在执行有界只读审计…')
        $audit = Invoke-SyncExtendJson $binaryPath @('native-history-audit', '--request', $requestPath)
        $requestDigest = (Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($audit.request_sha256 -cne $requestDigest) {
            throw 'Native history audit response is not bound to this request file.'
        }
        $view = New-SyncExtendNativeHistoryAuditView $audit $request
        $lists['Native audit'].Items.Clear()
        foreach ($row in $view.Rows) { Add-ClientRow 'Native audit' $row }
        $summary.Text = $view.Summary
        $tabs.SelectedTab = $lists['Native audit'].Parent
    } catch {
        $lists['Native audit'].Items.Clear()
        Add-ClientRow 'Native audit' @('读取状态', '拒绝或无法验证；旧审计结果未保留')
        Add-ClientRow 'Native audit' @('限制', '本页不授权恢复、清理、native 写入或原始行显示')
        $summary.Text = '原生历史只读审计被拒绝。请检查显式 image、摘要、space、root 映射和预算。'
        $tabs.SelectedTab = $lists['Native audit'].Parent
    } finally {
        $picker.Dispose()
    }
}
$null = Add-ClientButton '打开配置目录' {
    Invoke-Item -LiteralPath ([IO.Path]::GetDirectoryName($deploymentPath))
}

$stopButton.Enabled = $false
$testButton.Enabled = $false
function Test-ClientProtectedBlocked {
    return [bool]($script:busy -or $script:restoreWorker -or $script:pendingRestore)
}
function Set-ClientProtectedFence([bool]$Active) {
    if ($Active) {
        foreach ($control in @($stopButton, $gatewayButton, $startButton, $testButton)) {
            if ($control) { $control.Enabled = $false }
        }
    }
    Set-ClientRestoreBusy $script:busy
}
if (!$LayoutProbe) {
    $script:protectedClient = New-SyncExtendProtectedClient -Form $form -Tabs $tabs -Image $binaryPath `
        -IsBlocked { Test-ClientProtectedBlocked } -OnActivity { param($Active) Set-ClientProtectedFence $Active }
}
if ($LayoutProbe) {
    $outputPath = Resolve-SyncExtendPath $LayoutProbe
    $form.ShowInTaskbar = $false
    $form.StartPosition = 'Manual'
    $form.Location = [Drawing.Point]::new(-32000, -32000)
    $form.Size = [Drawing.Size]::new(1120, 900)
    $form.CreateControl()
    $tabs.SelectedTab = $restorePage
    $form.PerformLayout()
    $form.Show()
    [Windows.Forms.Application]::DoEvents()
    $bitmap = [Drawing.Bitmap]::new($form.Width, $form.Height)
    try {
        $form.DrawToBitmap($bitmap, [Drawing.Rectangle]::new(0, 0, $bitmap.Width, $bitmap.Height))
        $bitmap.Save($outputPath, [Drawing.Imaging.ImageFormat]::Png)
    } finally {
        $bitmap.Dispose()
    }
    $restoreList = $lists['Selection preview']
    $controls = @($restorePanel, $restoreList, $restoreNotes)
    $bounds = foreach ($control in $controls) {
        [ordered]@{
            name = $control.Name
            type = $control.GetType().FullName
            x = $control.Left; y = $control.Top; width = $control.Width; height = $control.Height
            parent_width = $control.Parent.ClientSize.Width
            parent_height = $control.Parent.ClientSize.Height
            visible = $control.Visible
        }
    }
    $overlap = {
        param($left, $right)
        $left.Right -gt $right.Left -and $right.Right -gt $left.Left -and
            $left.Bottom -gt $right.Top -and $right.Bottom -gt $left.Top
    }
    $panelListOverlap = & $overlap $restorePanel.Bounds $restoreList.Bounds
    $listNotesOverlap = & $overlap $restoreList.Bounds $restoreNotes.Bounds
    $columns = foreach ($column in $restoreList.Columns) {
        [ordered]@{
            text = $column.Text
            width = $column.Width
            measured_header_plus_24 = [Windows.Forms.TextRenderer]::MeasureText($column.Text, $form.Font).Width + 24
        }
    }
    $probe = [ordered]@{
        probe = 'sync_extend_windows_hidden_form_layout'
        screenshot = $outputPath
        screenshot_bytes = (Get-Item -LiteralPath $outputPath).Length
        form = [ordered]@{ width = $form.Width; height = $form.Height; minimum_width = $form.MinimumSize.Width; minimum_height = $form.MinimumSize.Height }
        tabs = [ordered]@{ width = $tabs.Width; height = $tabs.Height; page_count = $tabs.TabPages.Count }
        restore_page = [ordered]@{ width = $restorePage.ClientSize.Width; height = $restorePage.ClientSize.Height }
        restore_controls = @($bounds)
        panel_list_overlap = $panelListOverlap
        list_notes_overlap = $listNotesOverlap
        list_scrollable = $restoreList.Scrollable
        columns = @($columns)
        passed = (!$panelListOverlap -and !$listNotesOverlap -and $restoreList.Scrollable -and
            @($columns | Where-Object { $_.width -lt $_.measured_header_plus_24 }).Count -eq 0)
    }
    $form.Dispose()
    $probe | ConvertTo-Json -Depth 8 -Compress
    return
}
$form.Add_Shown({ Update-Client })
$form.Add_FormClosing({
    param($sender, $event)
    if (Request-SyncExtendProtectedClientClose $script:protectedClient) { $event.Cancel = $true }
    if ($script:restoreWorker -or $script:busy) {
        $event.Cancel = $true
        $summary.Text = '当前操作仍在运行。完成实际等待并记录结果前，窗口将保持打开。'
    }
})
try { [void]$form.ShowDialog() }
finally {
    Close-SyncExtendProtectedClient $script:protectedClient
    $restoreWorkerTimer.Stop()
    $restoreWorkerTimer.Dispose()
    if ($script:restoreWorker) {
        try { $null = $script:restoreWorker.Instance.EndInvoke($script:restoreWorker.Handle) }
        finally { $script:restoreWorker.Instance.Dispose(); $script:restoreWorker = $null }
    }
    $form.Dispose()
}
