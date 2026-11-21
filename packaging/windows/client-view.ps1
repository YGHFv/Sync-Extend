#Requires -Version 7.0
# Pure display projection. This file never opens a workspace or a ledger.

function Assert-SyncExtendViewObject($Value) {
    if ($Value -isnot [Collections.IDictionary]) { throw 'The local observation has an invalid object.' }
}

function Assert-SyncExtendViewFlag($Value) {
    if ($Value -isnot [bool]) { throw 'The local observation has an invalid flag.' }
}

function Get-SyncExtendViewInteger($Value) {
    if (($Value -isnot [int] -and $Value -isnot [long] -and $Value -isnot [uint32] -and
            $Value -isnot [uint64]) -or $Value -lt 0 -or [decimal]$Value -gt [long]::MaxValue) {
        throw 'The local observation has an invalid integer.'
    }
    return [long]$Value
}

function Assert-SyncExtendViewId($Value, [int]$Length = 64) {
    if ($Value -isnot [string] -or $Value.Length -ne $Length -or $Value -cnotmatch '\A[0-9a-f]+\z') {
        throw 'The local observation has an invalid identifier.'
    }
}

function Assert-SyncExtendViewText($Value, [int]$MaxLength = 4096) {
    if ($Value -isnot [string] -or $Value.Length -eq 0 -or $Value.Length -gt $MaxLength -or
        $Value.IndexOf([char]0) -ge 0) { throw 'The local observation has invalid text.' }
}

function Assert-SyncExtendViewList($Value, [int]$Maximum) {
    if ($Value -isnot [Array] -or $Value.Count -gt $Maximum) {
        throw 'The local observation exceeds its display limit.'
    }
}

function Format-SyncExtendViewBytes([long]$Value) {
    if ($Value -lt 1024) { return "$Value B" }
    $unit = if ($Value -ge 1GB) { 'GiB' } elseif ($Value -ge 1MB) { 'MiB' } else { 'KiB' }
    $divisor = switch ($unit) { 'GiB' { 1GB } 'MiB' { 1MB } default { 1KB } }
    return ('{0:N2} {1} ({2:N0} B)' -f ([decimal]$Value / $divisor), $unit, $Value)
}

function Format-SyncExtendViewTime([long]$Milliseconds) {
    try { return [DateTimeOffset]::FromUnixTimeMilliseconds($Milliseconds).UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss UTC') }
    catch [ArgumentOutOfRangeException] { return "$Milliseconds ms (Unix epoch)" }
}

function Add-SyncExtendViewRow($View, [string]$Tab, [object[]]$Values) {
    [void]$View.Rows[$Tab].Add($Values)
}

function New-SyncExtendConnectionView($Observation) {
    Assert-SyncExtendViewObject $Observation
    $age = Get-SyncExtendViewInteger $Observation.age_ms
    $staleAfter = Get-SyncExtendViewInteger $Observation.stale_after_ms
    Assert-SyncExtendViewFlag $Observation.current
    $sample = $Observation.actual
    Assert-SyncExtendViewObject $sample
    foreach ($key in @('observation_format_version', 'udp_sent_bytes', 'udp_received_bytes',
            'udp_sent_datagrams', 'udp_received_datagrams', 'rtt_us', 'path_lost_packets', 'path_lost_bytes')) {
        $null = Get-SyncExtendViewInteger $sample[$key]
    }
    foreach ($key in @('active', 'initiated')) { Assert-SyncExtendViewFlag $sample[$key] }
    Assert-SyncExtendViewId $sample.peer_device
    Assert-SyncExtendViewId $sample.space_id 32
    Assert-SyncExtendViewId $sample.session_binding
    if ($sample.observation_format_version -ne 1 -or
        $sample.sample_scope -cne 'latest_authenticated_connection' -or
        $sample.meter_unit -cne 'inner_quic_udp_payload_bytes' -or
        $sample.route_attribution -cne 'unknown' -or
        $null -ne $sample.outer_wire_bytes -or $null -ne $sample.billing_bytes -or
        $staleAfter -ne 30000 -or $Observation.current -cne ($age -le $staleAfter) -or
        $sample.lifecycle -cnotin @('active', 'finished', 'failed', 'dropped', 'stale') -or
        $sample.active -cne ($sample.lifecycle -ceq 'active') -or
        ($sample.active -and !$Observation.current) -or
        ($sample.lifecycle -ceq 'stale' -and $Observation.current) -or
        $sample.local_socket_scope -cnotin @('endpoint_bind', 'connection_local_ip')) {
        throw 'The authenticated connection sample cannot be verified.'
    }
    foreach ($key in @('local_socket', 'remote_socket')) {
        if ($null -eq $sample[$key] -and $key -ceq 'local_socket') { continue }
        Assert-SyncExtendViewText $sample[$key] 128
        $endpoint = [Net.IPEndPoint]::Parse($sample[$key])
        if ($endpoint.Port -eq 0) { throw 'The observed UDP endpoint cannot be verified.' }
    }
    $state = switch ($sample.lifecycle) {
        'active' { '采样时会话活动；当前可达性未测试' }
        'finished' { '传输已结束；样本已失活' }
        'failed' { '传输失败；样本已失活' }
        'dropped' { '会话已释放；结束结果未知' }
        'stale' { '样本过旧；当前连接状态未知' }
    }
    return @(
        ,@('连接样本范围', '最近一次已鉴权会话；不代表所有连接')
        ,@('样本状态', $state)
        ,@('采样距今 / 过旧门槛', "$age ms / $staleAfter ms")
        ,@('对端设备', $sample.peer_device)
        ,@('空间', $sample.space_id)
        ,@('会话绑定标识', $sample.session_binding)
        ,@('连接方向', $(if ($sample.initiated) { '本机发起' } else { '本机接入' }))
        ,@('本机 UDP 端点', $(if ($sample.local_socket) { "$($sample.local_socket) ($($sample.local_socket_scope))" } else { '未观察到' }))
        ,@('对端 UDP 端点', $sample.remote_socket)
        ,@('内层 UDP 发送载荷', (Format-SyncExtendViewBytes $sample.udp_sent_bytes))
        ,@('内层 UDP 接收载荷', (Format-SyncExtendViewBytes $sample.udp_received_bytes))
        ,@('发送 / 接收 UDP 报文', "$($sample.udp_sent_datagrams) / $($sample.udp_received_datagrams)")
        ,@('QUIC RTT（微秒）', "$($sample.rtt_us) us")
        ,@('当前 QUIC 路径丢包', "$($sample.path_lost_packets) 报文 / $($sample.path_lost_bytes) B")
        ,@('计量范围', 'QUINN 内层 UDP 载荷，含协议开销和重传；不是外层 wire 或费用')
    )
}

function New-SyncExtendEasyTierView($Observation) {
    Assert-SyncExtendViewObject $Observation
    $age = Get-SyncExtendViewInteger $Observation.age_ms
    $staleAfter = Get-SyncExtendViewInteger $Observation.stale_after_ms
    Assert-SyncExtendViewFlag $Observation.current
    $sample = $Observation.actual
    Assert-SyncExtendViewObject $sample
    foreach ($key in @('observation_format_version', 'child_pid', 'peer_count')) {
        $null = Get-SyncExtendViewInteger $sample[$key]
    }
    foreach ($key in @('owner_bound', 'peers_truncated', 'authenticated_sync_device')) {
        Assert-SyncExtendViewFlag $sample[$key]
    }
    Assert-SyncExtendViewId $sample.generation 32
    Assert-SyncExtendViewId $sample.process_start 16
    foreach ($key in @('core_pin', 'cli_pin', 'config_pin')) { Assert-SyncExtendViewId $sample[$key] }
    Assert-SyncExtendViewList $sample.peers 4
    Assert-SyncExtendViewText $sample.rpc_portal 128
    $endpoint = [Net.IPEndPoint]::Parse($sample.rpc_portal)
    if ($sample.observation_format_version -ne 1 -or
        $sample.sample_scope -cne 'managed_easytier_peers' -or
        $sample.pinned_version -cne '2.6.4' -or $sample.child_pid -eq 0 -or
        $sample.child_pid -gt [uint32]::MaxValue -or $sample.peer_count -gt 4096 -or
        ![Net.IPAddress]::IsLoopback($endpoint.Address) -or $endpoint.Port -eq 0 -or
        $sample.authenticated_sync_device -cne $false -or
        $sample.route_attribution -cne 'unassociated_with_sync_connection' -or
        $null -ne $sample.outer_wire_bytes -or $null -ne $sample.billing_bytes -or
        $staleAfter -ne 10000 -or $Observation.current -cne ($age -le $staleAfter) -or
        $sample.lifecycle -cnotin @('available', 'unavailable', 'stale') -or
        $sample.owner_bound -cne ($sample.lifecycle -ceq 'available') -or
        ($sample.owner_bound -and (!$Observation.current -or $sample.process_start -ceq '0000000000000000')) -or
        ($sample.lifecycle -ceq 'stale' -and $Observation.current) -or
        ($sample.owner_bound -and $null -ne $sample.unavailable_reason) -or
        $sample.peers.Count -ne [Math]::Min(4, $sample.peer_count) -or
        $sample.peers_truncated -cne ($sample.peer_count -gt 4) -or
        (!$sample.owner_bound -and ($sample.peer_count -ne 0 -or $sample.peers.Count -ne 0))) {
        throw 'The managed EasyTier sample cannot be verified.'
    }
    if (!$sample.owner_bound -and $sample.unavailable_reason -cnotin @('rpc_not_observed',
            'configuration_pin_unavailable', 'rpc_ownership_unavailable', 'rpc_query_unavailable',
            'rpc_ownership_changed', 'rpc_listener_changed', 'configuration_pin_changed',
            'rpc_window_expired', 'observation_clock_unavailable', 'invalid_peer_output',
            'sampler_unavailable', 'process_owner_unavailable', 'sample_stale')) {
        throw 'The managed EasyTier unavailable state cannot be verified.'
    }
    if ($sample.lifecycle -ceq 'stale' -and $sample.unavailable_reason -cne 'sample_stale') {
        throw 'The managed EasyTier freshness cannot be verified.'
    }
    $rows = [Collections.Generic.List[object]]::new()
    [void]$rows.Add(@('EasyTier 样本范围', '本机受管启动代的 overlay peer；未关联到同步连接'))
    [void]$rows.Add(@('EasyTier 状态', $(switch ($sample.lifecycle) {
        'available' { '采样时已验证当前子进程与 RPC 属主；当前链路可达性未测试' }
        'unavailable' { '子进程、RPC 或采样无法验证；旧 peer 已清除' }
        'stale' { '样本过旧；旧 peer 已清除' }
    })))
    [void]$rows.Add(@('EasyTier 采样距今 / 门槛', "$age ms / $staleAfter ms"))
    [void]$rows.Add(@('EasyTier 受管启动代 / PID', "$($sample.generation) / $($sample.child_pid)"))
    [void]$rows.Add(@('EasyTier RPC 端点', $sample.rpc_portal))
    [void]$rows.Add(@('EasyTier 固定版本', $sample.pinned_version))
    [void]$rows.Add(@('EasyTier peer 显示', "$($sample.peers.Count) / $($sample.peer_count)$(if ($sample.peers_truncated) { '（已截取）' })"))
    $ids = [Collections.Generic.HashSet[long]]::new()
    foreach ($peer in $sample.peers) {
        Assert-SyncExtendViewObject $peer
        $peerId = Get-SyncExtendViewInteger $peer.overlay_peer_id
        if ($peerId -gt [uint32]::MaxValue -or !$ids.Add($peerId)) { throw 'Invalid EasyTier overlay ID.' }
        $address = '未观察到 IPv4'
        if ($null -ne $peer.ipv4) {
            Assert-SyncExtendViewText $peer.ipv4 15
            $ip = [Net.IPAddress]::Parse($peer.ipv4)
            if ($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { throw 'Invalid EasyTier overlay IPv4.' }
            $address = $peer.ipv4
        }
        $path = switch -CaseSensitive ($peer.path) {
            'local' { '本机 overlay' }
            'p2p' { 'overlay P2P' }
            'unknown' { 'overlay 路径未知' }
            default {
                Assert-SyncExtendViewObject $peer.path
                Assert-SyncExtendViewObject $peer.path.relay
                $hops = Get-SyncExtendViewInteger $peer.path.relay.hops
                if ($peer.path.Count -ne 1 -or $peer.path.relay.Count -ne 1 -or $hops -lt 2 -or $hops -gt 64) {
                    throw 'Invalid EasyTier overlay path.'
                }
                "overlay 中继（$hops 跳）"
            }
        }
        [void]$rows.Add(@("EasyTier overlay peer $peerId", "$address；$path"))
    }
    [void]$rows.Add(@('EasyTier 身份与计量', 'overlay ID 不是 SyncExtend 设备身份；不授予 P2P 费用豁免；外层 wire 和费用未知'))
    return $rows.ToArray()
}

function Get-SyncExtendOptionalRecoveryFlag($Value, [string]$Name) {
    if (!$Value.Contains($Name)) { return $null }
    Assert-SyncExtendViewFlag $Value[$Name]
    return $Value[$Name]
}

function Get-SyncExtendOptionalRecoveryCount($Value, [string]$Name) {
    if (!$Value.Contains($Name)) { return $null }
    return Get-SyncExtendViewInteger $Value[$Name]
}

function New-SyncExtendSnapshotView($Snapshot, $Seen, [bool]$Pruned = $false) {
    Assert-SyncExtendViewObject $Snapshot
    Assert-SyncExtendViewId $Snapshot.snapshot_id
    Assert-SyncExtendViewText $Snapshot.state 64
    Assert-SyncExtendViewFlag $Snapshot.current
    if (!$Seen.Add($Snapshot.snapshot_id)) { throw 'The history repeats a snapshot identifier.' }
    $created = Get-SyncExtendOptionalRecoveryCount $Snapshot 'created_at_ms'
    $locked = Get-SyncExtendOptionalRecoveryFlag $Snapshot 'locked'
    $retained = Get-SyncExtendOptionalRecoveryFlag $Snapshot 'content_retained'
    $prunedAt = if ($Snapshot.Contains('pruned_at_ms') -and $null -ne $Snapshot.pruned_at_ms) {
        Get-SyncExtendViewInteger $Snapshot.pruned_at_ms
    }
    if (($retained -ceq $true -and $null -ne $prunedAt) -or
        ($retained -ceq $false -and ($Snapshot.current -or $locked -ceq $true)) -or
        ($Snapshot.Contains('pruned_at_ms') -and $retained -ceq $false -and $null -eq $prunedAt) -or
        ($null -ne $prunedAt -and ($Snapshot.current -or $locked -ceq $true)) -or
        ($null -ne $created -and $null -ne $prunedAt -and $created -gt $prunedAt) -or
        ($Pruned -and ($Snapshot.current -or $retained -ceq $true -or $locked -ceq $true)) -or
        (!$Pruned -and $retained -ceq $false)) {
        throw 'The history retention metadata is contradictory.'
    }
    $retention = if ($retained -ceq $true) { '已保留；内容未验' } elseif ($retained -ceq $false) {
        '内容已修剪'
    } else { '保留状态未知' }
    return ,@($Snapshot.snapshot_id, $Snapshot.state,
        $(if ($null -ne $created) { Format-SyncExtendViewTime $created } else { '未知' }),
        "$(if ($Snapshot.current) { '当前' } else { '历史' }) / $(if ($null -eq $locked) { '锁定未知' } elseif ($locked) { '锁定' } else { '未锁定' })",
        $retention,
        $(if ($null -ne $prunedAt) { Format-SyncExtendViewTime $prunedAt } elseif ($Snapshot.Contains('pruned_at_ms')) { '未裁剪' } else { '未知' }))
}

function Add-SyncExtendRecoveryView($View, $Local, [long]$Age, $Seen) {
    Add-SyncExtendViewRow $View 'Recovery' @('元数据采样距今', "$Age ms；不代表当前内容可恢复")
    $recovery = $Local.recovery
    if ($null -eq $recovery) {
        Add-SyncExtendViewRow $View 'Recovery' @('历史恢复元数据', '旧版本未提供；保留、裁剪、锁定及历史内容验证均未知')
    } else {
        Assert-SyncExtendViewObject $recovery
        $retained = Get-SyncExtendOptionalRecoveryCount $recovery 'retained_snapshots'
        $pruned = Get-SyncExtendOptionalRecoveryCount $recovery 'pruned_snapshots'
        $consistent = Get-SyncExtendOptionalRecoveryFlag $recovery 'metadata_snapshot_consistent'
        foreach ($name in @('historical_content_hashes_verified', 'restoration_performed',
                'native_authority', 'cleanup_authority', 'pending_resume_authority')) {
            $flag = Get-SyncExtendOptionalRecoveryFlag $recovery $name
            if ($flag -ceq $true) { throw 'The recovery observation grants an unsupported claim.' }
        }
        if ($null -ne $retained -and ($retained -ne $Local.total_snapshots -or
            $Local.snapshots.Count -ne [Math]::Min(128, $retained) -or
            $Local.snapshots_truncated -cne ($retained -gt 128))) {
            throw 'The retained snapshot count differs from the history.'
        }
        Add-SyncExtendViewRow $View 'Recovery' @('保留 / 内容已修剪快照',
            "$(if ($null -eq $retained) { '未知' } else { $retained }) / $(if ($null -eq $pruned) { '未知' } else { $pruned })")
        Add-SyncExtendViewRow $View 'Recovery' @('元数据一致性',
            $(if ($consistent -ceq $true) { '同一元数据快照；历史内容未验' } else { '未知；未确认同一元数据快照' }))
        Add-SyncExtendViewRow $View 'Recovery' @('历史内容 hash',
            $(if ($recovery.Contains('historical_content_hashes_verified')) { '未验证；保留不等于已验证可恢复' } else { '未知；旧载荷未提供验证信息' }))
        Add-SyncExtendViewRow $View 'Recovery' @('恢复 / 原生 / 清理 / pending 权限',
            $(if (@('restoration_performed', 'native_authority', 'cleanup_authority', 'pending_resume_authority').Where({ !$recovery.Contains($_) }).Count) {
                '未知；本页不执行任何恢复或清理'
            } else { '未执行 / 无 / 无 / 无' }))
        $truncated = Get-SyncExtendOptionalRecoveryFlag $recovery 'pruned_history_truncated'
        if ($recovery.Contains('pruned_history')) {
            Assert-SyncExtendViewList $recovery.pruned_history 16
            if ($null -ne $pruned -and ($recovery.pruned_history.Count -gt $pruned -or
                    ($null -ne $truncated -and ($truncated -cne ($pruned -gt $recovery.pruned_history.Count) -or
                    $recovery.pruned_history.Count -ne [Math]::Min(16, $pruned))))) {
                throw 'The pruned history count or truncation cannot be verified.'
            }
            foreach ($snapshot in $recovery.pruned_history) {
                $row = New-SyncExtendSnapshotView $snapshot $Seen $true
                Add-SyncExtendViewRow $View 'Pruned history' $row
            }
        }
        Add-SyncExtendViewRow $View 'Recovery' @('裁剪审计列表',
            $(if (!$recovery.Contains('pruned_history')) { '未知；旧载荷未提供列表' } elseif ($truncated -ceq $true) {
                '最多 16 条；列表已截取，内容已修剪'
            } elseif ($null -eq $truncated) { '最多 16 条；是否截取未知' } else { '最多 16 条；内容已修剪' }))
        foreach ($name in @('restore_command', 'whole_tree_restore_command', 'recovered_archive_command')) {
            if (!$recovery.Contains($name)) { continue }
            $expected = switch ($name) { 'restore_command' { 'restore' } 'whole_tree_restore_command' { 'tree-prepare' } default { 'recovered-local' } }
            if ($null -ne $recovery[$name] -and $recovery[$name] -cne $expected) {
                throw 'The manual recovery command name cannot be verified.'
            }
        }
        if ($recovery.whole_tree_restore_command -ceq 'tree-prepare') {
            Add-SyncExtendViewRow $View 'Recovery' @('Windows 整树恢复',
                '独立终端 tree-prepare 需原基线、目标和显式预算；会写入预备状态，不是只读预览')
        }
        if ($recovery.recovered_archive_command -ceq 'recovered-local') {
            Add-SyncExtendViewRow $View 'Recovery' @('Windows 归档预检',
                '独立终端：syncd recovered-local --descriptor <归档描述文件> inspect；仅检查原归档')
        }
    }
    Add-SyncExtendViewRow $View 'Recovery' @('历史来源选择', '在快照历史页人工选择保留来源，再核对内容；裁剪审计不提供恢复内容')
    Add-SyncExtendViewRow $View 'Recovery' @('单文件恢复（手动）', '独立终端：syncd restore --data-dir <数据目录> --snapshot <保留快照> --path <相对文件>')
    Add-SyncExtendViewRow $View 'Recovery' @('执行前', '正常停止当前资源属主，再显式执行新恢复操作；占用路径保留冲突副本')
    Add-SyncExtendViewRow $View 'Recovery' @('完整只读恢复预览', '当前尚未提供；本页只预览历史元数据，不检查历史内容、不创建恢复预备状态')
}

function New-SyncExtendClientView($Dashboard) {
    Assert-SyncExtendViewObject $Dashboard
    $null = Get-SyncExtendViewInteger $Dashboard.dashboard_format_version
    Assert-SyncExtendViewFlag $Dashboard.remote_backup_complete
    if ($Dashboard.dashboard_format_version -ne 1 -or $Dashboard.remote_backup_complete -cne $false) {
        throw 'The local dashboard format or backup status cannot be verified.'
    }
    Assert-SyncExtendViewFlag $Dashboard.resources_ready
    Assert-SyncExtendViewFlag $Dashboard.stop_allowed
    if ($null -ne $Dashboard.owner_generation) { Assert-SyncExtendViewId $Dashboard.owner_generation 32 }
    $view = @{
        Rows = @{}; Exports = @()
        StopAllowed = ($Dashboard.stop_allowed -and $null -ne $Dashboard.owner_generation)
        Summary = if ($Dashboard.resources_ready) { '本机资源已就绪。' } else { '本机资源尚未就绪。' }
    }
    foreach ($tab in @('Status', 'Files', 'History', 'Conflicts', 'Unavailable chunks', 'WebDAV',
            'Storage', 'Storage snapshots', 'Network', 'Pull budget', 'Recovery', 'Pruned history')) {
        $view.Rows[$tab] = [Collections.Generic.List[object]]::new()
    }
    $view.Summary += "`r`n远端备份状态尚未确认。"
    Add-SyncExtendViewRow $view 'Status' @('本机资源', $(if ($Dashboard.resources_ready) { '已就绪' } else { '尚未就绪' }))
    Add-SyncExtendViewRow $view 'Status' @('远端备份', '尚未确认')

    if ($null -ne $Dashboard.observation) {
        $observation = $Dashboard.observation
        Assert-SyncExtendViewObject $observation
        $age = Get-SyncExtendViewInteger $observation.age_ms
        $local = $observation.local
        Assert-SyncExtendViewObject $local
        Assert-SyncExtendViewId $local.space_id 32
        Assert-SyncExtendViewId $local.device_id
        if ($null -ne $local.snapshot_id) { Assert-SyncExtendViewId $local.snapshot_id }
        Assert-SyncExtendViewFlag $local.remote_backup_complete
        if ($local.remote_backup_complete -cne $false) { throw 'The local backup claim cannot be verified.' }
        foreach ($key in @('total_entries', 'total_snapshots', 'outstanding_mutations', 'outstanding_publications')) {
            $null = Get-SyncExtendViewInteger $local[$key]
        }
        foreach ($key in @('entries', 'snapshots', 'conflict_admissions')) {
            Assert-SyncExtendViewList $local[$key] 128
            Assert-SyncExtendViewFlag $local["${key}_truncated"]
        }
        if ($local.entries.Count -gt $local.total_entries -or $local.snapshots.Count -gt $local.total_snapshots -or
            (!$local.entries_truncated -and $local.entries.Count -ne $local.total_entries) -or
            (!$local.snapshots_truncated -and $local.snapshots.Count -ne $local.total_snapshots)) {
            throw 'The local inventory counts cannot be verified.'
        }
        Add-SyncExtendViewRow $view 'Status' @('空间', $local.space_id)
        Add-SyncExtendViewRow $view 'Status' @('设备', $local.device_id)
        Add-SyncExtendViewRow $view 'Status' @('当前快照', $(if ($local.snapshot_id) { $local.snapshot_id } else { '尚无快照' }))
        Add-SyncExtendViewRow $view 'Status' @('空间采样距今', "$age ms")
        Add-SyncExtendViewRow $view 'Status' @('路径 / 历史快照总数', "$($local.total_entries) / $($local.total_snapshots)")
        Add-SyncExtendViewRow $view 'Status' @('待处理文件 / 发布', "$($local.outstanding_mutations) / $($local.outstanding_publications)")
        foreach ($entry in $local.entries) {
            Assert-SyncExtendViewObject $entry
            Assert-SyncExtendViewText $entry.path
            Assert-SyncExtendViewText $entry.kind 64
            $bytes = if ($null -ne $entry.logical_bytes) { Format-SyncExtendViewBytes (Get-SyncExtendViewInteger $entry.logical_bytes) } else { '—' }
            Add-SyncExtendViewRow $view 'Files' @($entry.path, $entry.kind, $bytes)
        }
        $seenSnapshots = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($snapshot in $local.snapshots) {
            $row = New-SyncExtendSnapshotView $snapshot $seenSnapshots
            Add-SyncExtendViewRow $view 'History' $row
        }
        Add-SyncExtendRecoveryView $view $local $age $seenSnapshots
        foreach ($conflict in $local.conflict_admissions) {
            Assert-SyncExtendViewObject $conflict
            Assert-SyncExtendViewId $conflict.transaction_id 32
            Assert-SyncExtendViewFlag $conflict.resolution_applied
            Assert-SyncExtendViewFlag $conflict.worktree_materialized
            Add-SyncExtendViewRow $view 'Conflicts' @($conflict.transaction_id,
                $(if ($conflict.resolution_applied) { '已提交' } else { '待处理' }),
                $(if ($conflict.worktree_materialized) { '是' } else { '否' }))
        }
        $chunks = $local.chunks
        Assert-SyncExtendViewObject $chunks
        foreach ($key in @('checked_chunks', 'checked_bytes', 'total_current_chunks')) { $null = Get-SyncExtendViewInteger $chunks[$key] }
        Assert-SyncExtendViewFlag $chunks.all_current_chunks_checked
        Assert-SyncExtendViewList $chunks.unavailable_chunks 64
        if ($chunks.checked_chunks -gt 64 -or $chunks.checked_bytes -gt 16MB -or
            $chunks.checked_chunks -gt $chunks.total_current_chunks -or $chunks.unavailable_chunks.Count -gt $chunks.checked_chunks -or
            $chunks.all_current_chunks_checked -ne ($chunks.checked_chunks -eq $chunks.total_current_chunks)) {
            throw 'The current chunk sample cannot be verified.'
        }
        Add-SyncExtendViewRow $view 'Status' @('当前块检查覆盖', "$($chunks.checked_chunks) / $($chunks.total_current_chunks)")
        Add-SyncExtendViewRow $view 'Status' @('块检查范围', $(if ($chunks.all_current_chunks_checked) { '覆盖当前块；不代表远端备份完成' } else { '部分抽样；未检查内容保持未知' }))
        Add-SyncExtendViewRow $view 'Status' @('已检查字节', (Format-SyncExtendViewBytes $chunks.checked_bytes))
        Add-SyncExtendViewRow $view 'Status' @('样本内不可读取块', $chunks.unavailable_chunks.Count)
        foreach ($chunk in $chunks.unavailable_chunks) {
            Assert-SyncExtendViewId $chunk
            Add-SyncExtendViewRow $view 'Unavailable chunks' @('本机空间', $chunk)
        }
        $leases = $local.read_leases
        Assert-SyncExtendViewObject $leases
        foreach ($key in @('total', 'active', 'expired_pending_recovery')) { $null = Get-SyncExtendViewInteger $leases[$key] }
        Assert-SyncExtendViewFlag $leases.explicit_recovery_required
        if ($leases.active -gt $leases.total -or $leases.expired_pending_recovery -gt $leases.active -or
            $leases.explicit_recovery_required -ne ($leases.expired_pending_recovery -gt 0)) {
            throw 'The read lease counts cannot be verified.'
        }
        Add-SyncExtendViewRow $view 'Status' @('读租约：总 / 活跃 / 到期', "$($leases.total) / $($leases.active) / $($leases.expired_pending_recovery)")
        Add-SyncExtendViewRow $view 'Status' @('租约回收', $(if ($leases.explicit_recovery_required) { '需要显式回收；当前引用继续受保护' } else { '无到期待回收租约' }))
        $truncated = @('entries', 'snapshots', 'conflict_admissions') | Where-Object { $local["${_}_truncated"] }
        if ($truncated.Count) { Add-SyncExtendViewRow $view 'Status' @('展示上限', '路径、历史或冲突列表有截取；每类最多 128 行') }
    } else {
        Add-SyncExtendViewRow $view 'Status' @('工作区观察', '当前角色没有可用的工作区样本')
        Add-SyncExtendViewRow $view 'Recovery' @('历史恢复元数据', '当前没有可验证的工作区样本；旧历史观测已清除')
    }

    if ($null -ne $Dashboard.storage) {
        Assert-SyncExtendViewObject $Dashboard.storage
        $age = Get-SyncExtendViewInteger $Dashboard.storage.age_ms
        $storage = $Dashboard.storage.actual
        Assert-SyncExtendViewObject $storage
        Assert-SyncExtendViewId $storage.space_id 32
        Assert-SyncExtendViewId $storage.device_id
        Assert-SyncExtendViewFlag $storage.backup_complete
        Assert-SyncExtendViewFlag $storage.content_complete_certified
        if ($storage.role -cnotin @('full', 'staging') -or $storage.backup_complete -cne $false -or
            $storage.content_complete_certified -cne $false) { throw 'The storage status cannot be verified.' }
        foreach ($key in @('protected_chunks', 'protected_bytes', 'physical_cas_bytes', 'stored_byte_limit',
                'request_byte_limit', 'charged_logical_delivery_bytes', 'traffic_byte_limit', 'checked_chunks',
                'checked_bytes', 'total_snapshot_reports')) { $null = Get-SyncExtendViewInteger $storage[$key] }
        foreach ($key in @('expired', 'all_protected_chunks_checked', 'snapshot_reports_truncated',
                'journal_snapshot_consistent', 'cross_database_snapshot_consistent')) { Assert-SyncExtendViewFlag $storage[$key] }
        Assert-SyncExtendViewList $storage.unavailable_chunks 64
        Assert-SyncExtendViewList $storage.snapshot_reports 128
        if ($storage.checked_chunks -gt 64 -or $storage.checked_bytes -gt 16MB -or
            $storage.checked_chunks -gt $storage.protected_chunks -or $storage.unavailable_chunks.Count -gt $storage.checked_chunks -or
            $storage.all_protected_chunks_checked -ne ($storage.checked_chunks -eq $storage.protected_chunks) -or
            $storage.snapshot_reports.Count -gt $storage.total_snapshot_reports -or
            (!$storage.snapshot_reports_truncated -and $storage.snapshot_reports.Count -ne $storage.total_snapshot_reports)) {
            throw 'The storage sample cannot be verified.'
        }
        Add-SyncExtendViewRow $view 'Storage' @('空间', $storage.space_id)
        Add-SyncExtendViewRow $view 'Storage' @('设备', $storage.device_id)
        Add-SyncExtendViewRow $view 'Storage' @('角色', $(if ($storage.role -ceq 'staging') { '暂存' } else { '完整存储角色（完整性未认证）' }))
        Add-SyncExtendViewRow $view 'Storage' @('采样距今', "$age ms")
        Add-SyncExtendViewRow $view 'Storage' @('受保护内容', (Format-SyncExtendViewBytes $storage.protected_bytes))
        Add-SyncExtendViewRow $view 'Storage' @('实际块文件 / 容量上限', "$(Format-SyncExtendViewBytes $storage.physical_cas_bytes) / $(Format-SyncExtendViewBytes $storage.stored_byte_limit)")
        Add-SyncExtendViewRow $view 'Storage' @('单次请求上限', (Format-SyncExtendViewBytes $storage.request_byte_limit))
        Add-SyncExtendViewRow $view 'Storage' @('逻辑交付累计 / 额度', "$(Format-SyncExtendViewBytes $storage.charged_logical_delivery_bytes) / $(Format-SyncExtendViewBytes $storage.traffic_byte_limit)")
        Add-SyncExtendViewRow $view 'Storage' @('逻辑计量说明', '按请求、内容和方向去重；不等于重试字节或中继计费')
        Add-SyncExtendViewRow $view 'Storage' @('存储策略', $(if ($storage.expired) { '已到期；新接收会拒绝，已有保护不会自动清理' } else { '尚未到期' }))
        Add-SyncExtendViewRow $view 'Storage' @('受保护块检查覆盖', "$($storage.checked_chunks) / $($storage.protected_chunks)")
        Add-SyncExtendViewRow $view 'Storage' @('已检查字节', (Format-SyncExtendViewBytes $storage.checked_bytes))
        Add-SyncExtendViewRow $view 'Storage' @('块检查范围', $(if ($storage.all_protected_chunks_checked) { '已覆盖受保护块；完整备份仍未认证' } else { '部分抽样；未检查内容保持未知' }))
        Add-SyncExtendViewRow $view 'Storage' @('样本内不可读取块', $storage.unavailable_chunks.Count)
        Add-SyncExtendViewRow $view 'Storage' @('快照报告', "$($storage.snapshot_reports.Count) / $($storage.total_snapshot_reports)$(if ($storage.snapshot_reports_truncated) { '（已截取）' })")
        Add-SyncExtendViewRow $view 'Storage' @('读取一致性', $(if ($storage.cross_database_snapshot_consistent) { '跨数据库一致样本' } else { '独立数据库分别采样；不代表跨库原子快照' }))
        Add-SyncExtendViewRow $view 'Storage' @('日志样本一致性', $(if ($storage.journal_snapshot_consistent) { '同一日志读事务' } else { '尚未确认' }))
        foreach ($report in $storage.snapshot_reports) {
            Assert-SyncExtendViewObject $report
            Assert-SyncExtendViewId $report.origin_device
            Assert-SyncExtendViewId $report.snapshot_id
            $null = Get-SyncExtendViewInteger $report.reported_at_ms
            Add-SyncExtendViewRow $view 'Storage snapshots' @($report.origin_device, $report.snapshot_id,
                (Format-SyncExtendViewTime $report.reported_at_ms))
        }
        foreach ($chunk in $storage.unavailable_chunks) {
            Assert-SyncExtendViewId $chunk
            Add-SyncExtendViewRow $view 'Unavailable chunks' @('存储节点', $chunk)
        }
    } else {
        Add-SyncExtendViewRow $view 'Storage' @('存储节点', '当前角色没有可用的存储样本')
    }
    if ($null -ne $Dashboard.connection) {
        foreach ($row in @(New-SyncExtendConnectionView $Dashboard.connection)) {
            Add-SyncExtendViewRow $view 'Network' $row
        }
    } else {
        Add-SyncExtendViewRow $view 'Network' @('连接观测', '当前没有经过鉴权的连接样本')
    }
    if ($null -ne $Dashboard.easytier) {
        foreach ($row in @(New-SyncExtendEasyTierView $Dashboard.easytier)) {
            Add-SyncExtendViewRow $view 'Network' $row
        }
    } else {
        Add-SyncExtendViewRow $view 'Network' @('EasyTier 受管观测', '当前没有本机子进程与 RPC 属主绑定的样本')
    }
    Add-SyncExtendViewRow $view 'Network' @('同步连接实际路径', '未知；尚未把 overlay peer 关联到已鉴权的同步连接')
    Add-SyncExtendViewRow $view 'Network' @('外层 wire / 中继费用', '尚未计量；逻辑交付与请求预留分别展示')
    Add-SyncExtendViewRow $view 'Pull budget' @('显式拉取预算', '未指定预算文件；可通过“查看拉取预算”只读检查已初始化的账本')

    if ($null -ne $Dashboard.webdav) {
        $gateway = $Dashboard.webdav
        Assert-SyncExtendViewObject $gateway
        Assert-SyncExtendViewFlag $gateway.listening
        Assert-SyncExtendViewFlag $gateway.authenticated
        if ($gateway.listening -cne $true -or $gateway.authenticated -cne $true -or
            $gateway.scheme -cnotin @('http', 'https')) { throw 'The gateway observation cannot be verified.' }
        Assert-SyncExtendViewText $gateway.address 128
        $endpoint = [Net.IPEndPoint]::Parse($gateway.address)
        Assert-SyncExtendViewList $gateway.exports 128
        Assert-SyncExtendViewList $gateway.accounts 128
        foreach ($account in $gateway.accounts) { Assert-SyncExtendViewText $account 128 }
        foreach ($export in $gateway.exports) {
            Assert-SyncExtendViewObject $export
            if ($export.name -isnot [string] -or $export.name -cnotmatch '\A[A-Za-z0-9_-]{1,64}\z') { throw 'The export name cannot be verified.' }
            Assert-SyncExtendViewFlag $export.writable
            $null = Get-SyncExtendViewInteger $export.max_upload_bytes
            $address = [Uri]$export.url
            $exportHost = [Net.IPAddress]::Parse($address.DnsSafeHost)
            if (!$address.IsAbsoluteUri -or $address.Scheme -cne $gateway.scheme -or
                !$exportHost.Equals($endpoint.Address) -or $address.Port -ne $endpoint.Port -or
                $address.UserInfo -or $address.Query -or $address.Fragment -or
                $address.AbsolutePath -cne "/$($export.name)/") { throw 'The export address cannot be verified.' }
            Add-SyncExtendViewRow $view 'WebDAV' @($export.url,
                $(if ($export.writable) { '配置允许读写' } else { '只读' }), (Format-SyncExtendViewBytes $export.max_upload_bytes))
        }
        $view.Exports = $gateway.exports
        Add-SyncExtendViewRow $view 'Status' @('WebDAV 运行观察', '监听已登记；导出可访问性需连接测试')
        Add-SyncExtendViewRow $view 'Status' @('WebDAV 授权账号', ($gateway.accounts -join '、'))
    }
    return $view
}

function New-SyncExtendPullBudgetView($Status, $Policy, $Configuration, [long]$ObservedAtMs) {
    foreach ($value in @($Status, $Policy, $Configuration)) { Assert-SyncExtendViewObject $value }
    Assert-SyncExtendViewId $Status.budget_id 32
    Assert-SyncExtendViewId $Status.policy_fingerprint
    Assert-SyncExtendViewFlag $Status.automatic_rollover
    if ($Status.meter_unit -cne 'requested_block_payload_reserved_bytes' -or $Status.route_scope -cne 'all_paths' -or
        $Status.automatic_rollover -cne $false -or $null -ne $Status.actual_wire_bytes -or
        $Status.budget_id -cne $Policy.budget_id -or $Policy.space_id -cne $Configuration.space_id) {
        throw 'The explicit budget identity or meter cannot be verified.'
    }
    Assert-SyncExtendViewId $Policy.space_id 32
    Assert-SyncExtendViewId $Policy.storage_device
    foreach ($key in @('period_start_ms', 'period_end_ms', 'reserved_payload_bytes', 'remaining_payload_bytes',
            'attempt_entries', 'remaining_attempt_entries', 'clock_high_water_ms')) { $null = Get-SyncExtendViewInteger $Status[$key] }
    foreach ($key in @('max_reserved_payload_bytes', 'max_attempt_entries')) { $null = Get-SyncExtendViewInteger $Policy[$key] }
    if ($Status.period_start_ms -ne $Policy.period_start_ms -or $Status.period_end_ms -ne $Policy.period_end_ms -or
        $Status.period_start_ms -ge $Status.period_end_ms -or
        [decimal]$Status.reserved_payload_bytes + $Status.remaining_payload_bytes -ne $Policy.max_reserved_payload_bytes -or
        [decimal]$Status.attempt_entries + $Status.remaining_attempt_entries -ne $Policy.max_attempt_entries) {
        throw 'The explicit budget bounds cannot be verified.'
    }
    $state = if ($ObservedAtMs -lt $Status.clock_high_water_ms) {
        '本机时钟早于账本水位；新增请求会拒绝'
    } elseif ($ObservedAtMs -lt $Status.period_start_ms) {
        '窗口尚未开始；新增请求会拒绝'
    } elseif ($ObservedAtMs -ge $Status.period_end_ms) {
        '固定窗口已到期；新增请求会拒绝'
    } elseif ($Status.remaining_payload_bytes -eq 0 -or $Status.remaining_attempt_entries -eq 0) {
        '额度或条数已耗尽；新增请求会拒绝'
    } else { '固定窗口内；每次请求仍须通过准入检查' }
    return @(
        ,@('只读检查', '指定存储配置的独立拉取预算；不代表所有同步或中继的额度')
        ,@('预算', $Status.budget_id)
        ,@('空间 / 存储设备', "$($Policy.space_id) / $($Policy.storage_device)")
        ,@('计量单位', 'requested_block_payload_reserved_bytes（请求块载荷的保守预留字节）')
        ,@('路径范围', 'all_paths（所有路径统一预留）')
        ,@('窗口起点', (Format-SyncExtendViewTime $Status.period_start_ms))
        ,@('窗口终点（不含）', (Format-SyncExtendViewTime $Status.period_end_ms))
        ,@('当前状态', $state)
        ,@('已预留 / 剩余', "$(Format-SyncExtendViewBytes $Status.reserved_payload_bytes) / $(Format-SyncExtendViewBytes $Status.remaining_payload_bytes)")
        ,@('已记录尝试 / 剩余条数', "$($Status.attempt_entries) / $($Status.remaining_attempt_entries)")
        ,@('账本时钟水位', (Format-SyncExtendViewTime $Status.clock_high_water_ms))
        ,@('读取时间', (Format-SyncExtendViewTime $ObservedAtMs))
        ,@('失败与重开', '请求失败或中断不退预留；重开保持占额')
        ,@('周期与费用', '不自动跨期重置；实际 wire 字节和自然月中继费用尚未计量')
    )
}
