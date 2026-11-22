#Requires -Version 7.0
. (Join-Path $PSScriptRoot 'protected-deployment-owner.ps1')

function Test-SyncExtendProtectedClientActive($Client) {
    return [bool]($Client -and ($Client.Worker -or
        ($Client.Owner -and !$Client.Owner.Terminal)))
}

function Add-SyncExtendProtectedClientRow($Client, [string]$Name, [string]$Value) {
    $item = [Windows.Forms.ListViewItem]::new($Name)
    [void]$item.SubItems.Add($Value)
    [void]$Client.Rows.Items.Add($item)
}

function Update-SyncExtendProtectedClientControls($Client) {
    $active = Test-SyncExtendProtectedClientActive $Client
    $blocked = [bool]($Client.Closing -or $Client.Worker -or (& $Client.IsBlocked))
    foreach ($control in @($Client.Descriptor, $Client.Mapping, $Client.Output,
            $Client.DescriptorPicker, $Client.MappingPicker, $Client.OutputPicker,
            $Client.Inspect, $Client.Capture, $Client.Map, $Client.Install)) {
        $control.Enabled = !$active -and !$blocked
    }
    $owner = $Client.Owner
    $ready = [bool]($owner -and !$owner.Terminal -and !$owner.ProtocolFailure -and
        $owner.Startup -and !$owner.Pending -and !$owner.EndOfStream -and !$owner.Native.Original.HasExited)
    $Client.Run.Enabled = [bool]($ready -and !$blocked -and
        $owner.LastState.state -ceq 'installed')
    $Client.Status.Enabled = $ready -and !$blocked
    $Client.Stop.Enabled = [bool]($ready -and !$blocked -and
        $owner.LastState.state -in @('running', 'uncertain'))
    $Client.Close.Enabled = [bool]($owner -and !$owner.Terminal -and !$Client.Worker -and
        !$Client.Closing -and !$owner.Pending)
    & $Client.OnActivity $active
}

function Show-SyncExtendProtectedPublicResult($Client, [string]$Kind, $Value) {
    if ($Value -isnot [Collections.IDictionary]) {
        throw 'The deployment helper did not return a JSON object.'
    }
    $Client.Rows.Items.Clear()
    Add-SyncExtendProtectedClientRow $Client '操作' $Kind
    # Only public scalar summaries from the native response enter the page.
    # Raw descriptors, credentials, private keys and arbitrary nested JSON
    # never become a preview or exception message.
    foreach ($field in @('format_version', 'bundle_sha256', 'mapping_sha256',
            'artifact_count', 'node_count', 'section_count', 'bytes', 'total_bytes',
            'source_same_user', 'same_user_verified', 'native_files_verified',
            'native_node_restores_closed', 'services_started')) {
        if (!$Value.Contains($field)) { continue }
        $public = $Value[$field]
        if ($public -is [string] -and $public.Length -le 128 -or
            $public -is [bool] -or $public -is [long] -or $public -is [int] -or $public -is [bigint]) {
            Add-SyncExtendProtectedClientRow $Client $field ([string]$public)
        }
    }
    $Client.Notes.Text = switch ($Kind) {
        'inspect' { '已完成只读检查。请核对显式输入和原生检查结果，再进行捕获或映射。' }
        'capture' { '已完成显式捕获。输出文件由原生私有文件创建流程保护；请妥善保存。' }
        'map' { '已完成目标映射检查。安装仍需单独点击，安装后服务保持关闭。' }
        default { '已取得原生公开检查结果。' }
    }
}

function Start-SyncExtendProtectedClientWorker($Client, [string]$Kind) {
    if (Test-SyncExtendProtectedClientActive $Client) {
        throw 'Wait for the original deployment operation to close.'
    }
    if ($Client.Closing -or (& $Client.IsBlocked)) { throw 'Another client operation is still active.' }
    $descriptor = Resolve-SyncExtendPath $Client.Descriptor.Text -File
    $mapping = if ($Kind -in @('map', 'install')) {
        Resolve-SyncExtendPath $Client.Mapping.Text -File
    } else { $null }
    $output = if ($Kind -ceq 'capture') {
        $target = Resolve-SyncExtendPath $Client.Output.Text
        if (Test-Path -LiteralPath $target) { throw 'Choose a new capture output file.' }
        $target
    } else { $null }
    $worker = [Management.Automation.PowerShell]::Create()
    try {
        $null = $worker.AddScript({
            param($Common, $OwnerModule, $Image, $Descriptor, $Mapping, $Output, $Kind)
            $ErrorActionPreference = 'Stop'
            . $Common
            . $OwnerModule
            if ($Kind -ceq 'install') {
                try {
                    $owner = New-SyncExtendProtectedOwner -Image $Image -Descriptor $Descriptor -Mapping $Mapping
                    return [pscustomobject]@{ Owner = $owner; Failed = $false }
                } catch {
                    # Carry the exact original back to the window even when
                    # its startup observation failed. A saved receipt cannot
                    # substitute for this live object.
                    return [pscustomobject]@{
                        Owner = $_.Exception.Data['SyncExtendOriginalProtectedOwner']
                        Failed = $true
                    }
                }
            }
            $arguments = @('protected-deployment', '--descriptor', $Descriptor, $Kind)
            if ($Kind -ceq 'capture') { $arguments += @('--output', $Output) }
            if ($Kind -ceq 'map') { $arguments += @('--mapping', $Mapping) }
            # Capture may include a bounded complete archive. Its original
            # process and stream tasks use the same common lifetime contract.
            Invoke-SyncExtendJson $Image $arguments -TimeoutMs 180000
        }.ToString()).AddArgument((Join-Path $PSScriptRoot 'windows-common.ps1')).
            AddArgument((Join-Path $PSScriptRoot 'protected-deployment-owner.ps1')).
            AddArgument($Client.Image).AddArgument($descriptor).AddArgument($mapping).
            AddArgument($output).AddArgument($Kind)
        $handle = $worker.BeginInvoke()
        $Client.Worker = @{ Instance = $worker; Handle = $handle; Kind = $Kind }
        $Client.Notes.Text = '正在等待本次原生操作。窗口会保持响应，并在原进程和输出任务关闭后显示结果。'
        Update-SyncExtendProtectedClientControls $Client
    } catch {
        $worker.Dispose()
        throw
    }
}

function Send-SyncExtendProtectedClientCommand($Client, [string]$Command) {
    if (!$Client.Owner -or $Client.Worker -or $Client.Closing -or (& $Client.IsBlocked)) {
        throw 'The original deployment control process is unavailable for this request.'
    }
    if ($Command -ceq 'close' -and !$Client.Owner.Startup) {
        Close-SyncExtendProtectedOwnerInput $Client.Owner
        $Client.InputClosed = $true
    } else {
        Send-SyncExtendProtectedOwnerCommand -Owner $Client.Owner -Command $Command
    }
    $Client.Notes.Text = switch ($Command) {
        'run' { '正在等待本次部署实际取得运行资源并就绪。' }
        'stop' { '正在等待本次部署关闭实际运行资源。' }
        'close' { '正在等待本次控制进程关闭及原始输出任务完成。' }
        default { '正在读取同一个控制进程的实际状态。' }
    }
    Update-SyncExtendProtectedClientControls $Client
}

function Update-SyncExtendProtectedClient($Client) {
    $current = $Client.Worker
    if ($current -and $current.Handle.IsCompleted) {
        $output = $null
        $failed = $false
        try {
            $output = $current.Instance.EndInvoke($current.Handle)
            if ($current.Instance.HadErrors -or $output.Count -ne 1) {
                throw 'The original deployment helper did not return one result.'
            }
            $result = $output[0].PSObject.BaseObject
            if ($current.Kind -ceq 'install') {
                $Client.Owner = $result.Owner
                $Client.InputClosed = $false
                if ($result.Failed -or !$Client.Owner) { throw 'The original installation owner could not be observed.' }
                $Client.Rows.Items.Clear()
                Add-SyncExtendProtectedClientRow $Client '安装' '正在核验实际文件和原生节点关闭记录'
                $Client.Notes.Text = '正在安装完整部署。服务尚未启动；安装核验通过后可单独点击“启动部署”。'
            } else { Show-SyncExtendProtectedPublicResult $Client $current.Kind $result }
        } catch {
            $failed = $true
            $Client.Notes.Text = '本次部署操作被拒绝。请检查显式输入、源用户、目标空槽和原生预算；已创建的实际前缀由原生记录保留。'
        } finally {
            $current.Instance.Dispose()
            $Client.Worker = $null
        }
        $Client.LastWorkerReceipt = @{
            kind = $current.Kind; original_async_invocation_EndInvoke = $true
            original_invocation_handle_completed = $current.Handle.IsCompleted
            accepted = !$failed
        }
    }
    $owner = $Client.Owner
    if ($owner -and !$owner.Terminal) {
        if ($Client.Closing -and !$Client.InputClosed) {
            try { Close-SyncExtendProtectedOwnerInput $owner; $Client.InputClosed = $true }
            catch { $Client.Notes.Text = '原控制进程的输入关闭尚未确认；窗口将继续等待。' }
        }
        try {
            for ($frameIndex = 0; $frameIndex -lt 8; $frameIndex++) {
                $event = Read-SyncExtendProtectedOwnerEvent $owner
                if (!$event) { break }
                $value = $event.Value
                $Client.LastFrameReceipt = @{
                    bytes = $event.actual_original_stdout_frame_bytes
                    sha256 = $event.actual_original_stdout_frame_sha256
                }
                $Client.Rows.Items.Clear()
                Add-SyncExtendProtectedClientRow $Client '原控制进程' ([string]$owner.Identity.pid)
                Add-SyncExtendProtectedClientRow $Client '部署状态' ([string]$value.state)
                Add-SyncExtendProtectedClientRow $Client 'Bundle SHA-256' $value.bundle_sha256
                Add-SyncExtendProtectedClientRow $Client 'Mapping SHA-256' $value.mapping_sha256
                if ($value.event -ceq 'installed') {
                    Add-SyncExtendProtectedClientRow $Client '私有文件核验' '已完成'
                    Add-SyncExtendProtectedClientRow $Client '原生节点关闭核验' '已完成'
                    $Client.Notes.Text = '完整部署安装已核验，服务保持关闭。点击“启动部署”后，将由本次原控制进程取得新的运行资源。'
                } else {
                    Add-SyncExtendProtectedClientRow $Client '运行代次' ([string]$value.generation)
                    Add-SyncExtendProtectedClientRow $Client '资源就绪' ([string]$value.resources_ready)
                    Add-SyncExtendProtectedClientRow $Client '服务启动' ([string]$value.services_started)
                    if ($value.event -ceq 'response' -and !$value.accepted) {
                        Add-SyncExtendProtectedClientRow $Client '拒绝类别' $value.error
                        $Client.Notes.Text = '原控制进程拒绝了本次请求。请根据公开拒绝类别处理后，在同一控制进程中重试或关闭。'
                    } else {
                        $Client.Notes.Text = switch ($value.state) {
                            'running' { '本次部署已实际就绪。停止后可在同一个控制进程中重新启动。' }
                            'installed' { '本次运行资源已关闭；保留已核验安装，可再次显式启动。' }
                            'closed' { '实际资源已关闭，正在等待原控制进程和原始输出任务退出。' }
                            default { '原生状态仍不确定；请读取实际状态或关闭本次控制进程。' }
                        }
                    }
                }
            }
            $exit = Complete-SyncExtendProtectedOwner $owner
            if ($exit) {
                $Client.ExitReceipt = $exit
                Add-SyncExtendProtectedClientRow $Client '原进程实际退出码' ([string]$exit.actual_original_exit_code)
                Add-SyncExtendProtectedClientRow $Client '原始输出 EOF / 错误任务' '已实际消费'
                $Client.Notes.Text = if ($owner.ProtocolFailure -or $exit.actual_original_exit_code -ne 0) {
                    '原控制进程已退出并消费输出。本次部署未取得完整成功核验；请检查原生记录和输入。'
                } else { '原控制进程已退出，原始输出任务已关闭。' }
            }
        } catch {
            $Client.Notes.Text = '原控制响应无法核验。已向同一个原进程关闭输入，正在等待其实际资源、退出和输出任务。'
        }
    }
    Update-SyncExtendProtectedClientControls $Client
    if ($Client.Closing -and !(Test-SyncExtendProtectedClientActive $Client) -and
        !(& $Client.IsBlocked) -and !$Client.Form.IsDisposed) {
        $Client.Form.Close()
    }
}

function Request-SyncExtendProtectedClientClose($Client) {
    if (!(Test-SyncExtendProtectedClientActive $Client)) { return $false }
    $Client.Closing = $true
    $Client.Notes.Text = '正在关闭本次部署。完成原进程实际等待和原始输出任务后，窗口会关闭。'
    Update-SyncExtendProtectedClientControls $Client
    return $true
}

function Close-SyncExtendProtectedClient($Client) {
    if (!$Client) { return }
    if (Test-SyncExtendProtectedClientActive $Client) {
        $Client.Closing = $true
        while (Test-SyncExtendProtectedClientActive $Client) {
            Update-SyncExtendProtectedClient $Client
            [Windows.Forms.Application]::DoEvents()
            [Threading.Thread]::Sleep(10)
        }
    }
    $Client.Timer.Stop()
    $Client.Timer.Dispose()
}

function New-SyncExtendProtectedClient {
    param(
        [Parameter(Mandatory)]$Form,
        [Parameter(Mandatory)]$Tabs,
        [Parameter(Mandatory)][string]$Image,
        [scriptblock]$IsBlocked = { $false },
        [scriptblock]$OnActivity = { param($Active) }
    )
    Initialize-SyncExtendProtectedOwner
    $page = [Windows.Forms.TabPage]::new('受保护部署')
    $page.Name = 'ProtectedDeploymentPage'
    $layout = [Windows.Forms.TableLayoutPanel]::new()
    $layout.Dock = 'Fill'
    $layout.Padding = [Windows.Forms.Padding]::new(12)
    $layout.ColumnCount = 3
    $layout.RowCount = 6
    [void]$layout.ColumnStyles.Add([Windows.Forms.ColumnStyle]::new('Absolute', 125))
    [void]$layout.ColumnStyles.Add([Windows.Forms.ColumnStyle]::new('Percent', 100))
    [void]$layout.ColumnStyles.Add([Windows.Forms.ColumnStyle]::new('Absolute', 86))
    foreach ($height in @(38, 38, 38, 76, 110)) {
        [void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new('Absolute', $height))
    }
    [void]$layout.RowStyles.Add([Windows.Forms.RowStyle]::new('Percent', 100))
    $page.Controls.Add($layout)
    $Tabs.TabPages.Add($page)
    $client = @{
        Form = $Form; Page = $page; Image = (Resolve-SyncExtendPath $Image -File)
        Owner = $null; Worker = $null; Closing = $false; InputClosed = $false
        IsBlocked = $IsBlocked; OnActivity = $OnActivity
        ExitReceipt = $null; LastFrameReceipt = $null; LastWorkerReceipt = $null
    }
    $row = 0
    foreach ($input in @(
        @{name='Descriptor';caption='描述文件';save=$false}
        @{name='Mapping';caption='目标映射文件';save=$false}
        @{name='Output';caption='捕获输出文件';save=$true})) {
        $label = [Windows.Forms.Label]::new()
        $label.Text = $input.caption
        $label.Dock = 'Fill'
        $label.TextAlign = 'MiddleLeft'
        $text = [Windows.Forms.TextBox]::new()
        $text.Name = 'Protected' + $input.name
        $text.Dock = 'Fill'
        $text.Margin = [Windows.Forms.Padding]::new(3, 7, 3, 3)
        $pickerButton = [Windows.Forms.Button]::new()
        $pickerButton.Text = '选择…'
        $pickerButton.Dock = 'Fill'
        $pickerButton.Name = 'Protected' + $input.name + 'Picker'
        $taskText = $text
        $taskSave = $input.save
        $taskForm = $Form
        $pickerButton.Add_Click({
            $picker = if ($taskSave) { [Windows.Forms.SaveFileDialog]::new() } else {
                [Windows.Forms.OpenFileDialog]::new()
            }
            try {
                $picker.Filter = if ($taskSave) { 'Private bundle|*.bundle|All files|*.*' } else {
                    'JSON descriptor / mapping|*.json|All files|*.*'
                }
                if ($taskSave) { $picker.OverwritePrompt = $true }
                if ($picker.ShowDialog($taskForm) -eq 'OK') { $taskText.Text = $picker.FileName }
            } finally { $picker.Dispose() }
        }.GetNewClosure())
        $layout.Controls.Add($label, 0, $row)
        $layout.Controls.Add($text, 1, $row)
        $layout.Controls.Add($pickerButton, 2, $row)
        $client[$input.name] = $text
        $client[$input.name + 'Picker'] = $pickerButton
        $row++
    }
    $actions = [Windows.Forms.FlowLayoutPanel]::new()
    $actions.Dock = 'Fill'
    $layout.Controls.Add($actions, 0, 3)
    $layout.SetColumnSpan($actions, 3)
    foreach ($action in @(
        @{name='Inspect';caption='只读检查';kind='inspect';owner=$false}
        @{name='Capture';caption='显式捕获';kind='capture';owner=$false}
        @{name='Map';caption='检查目标映射';kind='map';owner=$false}
        @{name='Install';caption='安装并保持关闭';kind='install';owner=$false}
        @{name='Run';caption='启动部署';kind='run';owner=$true}
        @{name='Status';caption='读取部署状态';kind='status';owner=$true}
        @{name='Stop';caption='停止部署';kind='stop';owner=$true}
        @{name='Close';caption='关闭部署';kind='close';owner=$true})) {
        $button = [Windows.Forms.Button]::new()
        $button.Name = 'Protected' + $action.name + 'Button'
        $button.Text = $action.caption
        $button.AutoSize = $true
        $button.Height = 31
        $taskClient = $client
        $taskKind = $action.kind
        $taskOwnerCommand = $action.owner
        $button.Add_Click({
            try {
                if ($taskOwnerCommand) { Send-SyncExtendProtectedClientCommand $taskClient $taskKind }
                else { Start-SyncExtendProtectedClientWorker $taskClient $taskKind }
            } catch {
                $taskClient.Notes.Text = '操作未开始或被原控制进程拒绝。请检查选中的绝对路径及当前实际状态。'
                Update-SyncExtendProtectedClientControls $taskClient
            }
        }.GetNewClosure())
        $actions.Controls.Add($button)
        $client[$action.name] = $button
    }
    $notes = [Windows.Forms.Label]::new()
    $notes.Name = 'ProtectedDeploymentNotes'
    $notes.Dock = 'Fill'
    $notes.Text = '选择显式描述文件和目标映射。安装将核验完整引用图与私有文件，完成后服务保持关闭。启动、停止和再次启动均由同一个本次控制进程执行。'
    $layout.Controls.Add($notes, 0, 4)
    $layout.SetColumnSpan($notes, 3)
    $rows = [Windows.Forms.ListView]::new()
    $rows.Name = 'ProtectedDeploymentRows'
    $rows.Dock = 'Fill'
    $rows.View = 'Details'
    $rows.FullRowSelect = $true
    $rows.GridLines = $true
    [void]$rows.Columns.Add('项目', 240)
    [void]$rows.Columns.Add('原生公开状态', 680)
    $layout.Controls.Add($rows, 0, 5)
    $layout.SetColumnSpan($rows, 3)
    $client.Notes = $notes
    $client.Rows = $rows
    $timer = [Windows.Forms.Timer]::new()
    $timer.Interval = 100
    $taskClient = $client
    $timer.Add_Tick({ Update-SyncExtendProtectedClient $taskClient }.GetNewClosure())
    $client.Timer = $timer
    Update-SyncExtendProtectedClientControls $client
    $timer.Start()
    return $client
}

function Show-SyncExtendProtectedDeploymentClient([string]$Image) {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [Windows.Forms.Application]::EnableVisualStyles()
    $form = [Windows.Forms.Form]::new()
    $form.Text = 'SyncExtend / 受保护部署'
    $form.StartPosition = 'CenterScreen'
    $form.MinimumSize = [Drawing.Size]::new(900, 700)
    $form.Size = [Drawing.Size]::new(1120, 800)
    $form.Font = [Drawing.Font]::new('Segoe UI', 10)
    $tabs = [Windows.Forms.TabControl]::new()
    $tabs.Dock = 'Fill'
    $form.Controls.Add($tabs)
    $client = New-SyncExtendProtectedClient -Form $form -Tabs $tabs -Image $Image
    $taskClient = $client
    $form.Add_FormClosing({
        param($Sender, $Event)
        if (Request-SyncExtendProtectedClientClose $taskClient) { $Event.Cancel = $true }
    }.GetNewClosure())
    try { [void]$form.ShowDialog() }
    finally {
        Close-SyncExtendProtectedClient $client
        $form.Dispose()
    }
}
