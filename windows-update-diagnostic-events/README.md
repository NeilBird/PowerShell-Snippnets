# Get-ClusterWindowsUpdateHistory

## Overview

`Get-ClusterWindowsUpdateHistory` is a PowerShell function that identifies who initiated Windows Update actions on a Windows Server Failover Cluster by correlating event logs across all cluster nodes.

## Purpose

This tool helps administrators answer the question: **"Who started Windows Updates on my cluster?"**

It queries and correlates multiple event sources across cluster nodes:
- Windows Update Client events (downloads, installations)
- Security audit logs (process creation events)
- Task Scheduler events (scheduled update tasks)
- System reboot events

## Features

- **Parallel Execution**: Queries all cluster nodes simultaneously for fast results
- **Performance Optimized**: 
  - Limited event retrieval (max 10,000 Security events per node)
  - XPath filtering for efficient event log queries
  - Pre-compiled regex for process filtering
- **Real-time Progress**: Shows job progress and timing information
- **Comprehensive Diagnostics**: Displays event counts and correlation statistics
- **Flexible Parameters**: Configurable cluster name and time range

## Requirements

- **Administrator privileges** on all cluster nodes
- **PowerShell Remoting** enabled on all cluster nodes
- **FailoverClusters PowerShell module** installed
- **Process Creation Auditing** (Event ID 4688) enabled in Security logs for best results

### Enable Process Creation Auditing

To enable Event 4688 (Process Creation), run this on each cluster node:

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
```

Or via Group Policy: `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Detailed Tracking > Audit Process Creation`

## Installation

1. Download the script file
2. Place it in a directory accessible from your cluster nodes
3. Run as Administrator

## Usage

### Basic Usage (Local Cluster)

```powershell
.\windows-update-diagnostic-events.ps1
```

or after dot-sourcing:

```powershell
. .\windows-update-diagnostic-events.ps1
Get-ClusterWindowsUpdateHistory
```

### Query Specific Time Range

```powershell
Get-ClusterWindowsUpdateHistory -DaysBack 14
```

### Query Specific Cluster

```powershell
Get-ClusterWindowsUpdateHistory -ClusterName "MyCluster" -DaysBack 30
```

## Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `ClusterName` | String | No | Local cluster | Name of the cluster to query |
| `DaysBack` | Int | No | 7 | Number of days to look back for events |

## Output

The function displays:

1. **Script execution timing** - Start time, end time, total duration
2. **Per-node results** including:
   - Diagnostic information (event counts)
   - Reboot history with initiators
   - Windows Update events with:
     - Event ID and timestamp
     - Update information
     - Initiating user/process
     - Related Task Scheduler activities

### Sample Output

```
========================================
Script Start Time: 2025-12-15 10:12:14
========================================
Checking Windows Update history on cluster MyCluster (2 x nodes)...

[1/2] Starting query on Node01...
[2/2] Starting query on Node02...

Progress: 2 completed, 0 running, 0 failed - Elapsed: 00:45

========================================
Node: Node01
========================================

Windows Update Diagnostic Information:
  Update Events Found: 20
  Process Creation Events: 0
  Update-Related Processes: 0
  Task Scheduler Events: 2

Windows Update Events (with initiating user/process):

EventId EventTime              InitiatedBy       RelatedTasks UpdateInfo
------- ---------              -----------       ------------ ----------
     41 12/15/2025 12:22:55 AM DOMAIN\user01    NT AUTHORITY\SYSTEM An update was downloaded.
     19 12/14/2025 6:31:03 PM  Not found        None         Installation Successful: ...
```

## Event IDs Queried

| Event ID | Log | Description |
|----------|-----|-------------|
| 19 | WindowsUpdateClient/Operational | Installation Successful |
| 41 | WindowsUpdateClient/Operational | Installation Started |
| 43 | WindowsUpdateClient/Operational | Installation Completed |
| 4688 | Security | Process Creation |
| 1074 | System | System Shutdown/Restart |
| 106, 200, 201 | TaskScheduler/Operational | Task events |

## Troubleshooting

### "No process creation events found"

Process Creation auditing (Event 4688) is not enabled in the Security log. Enable it using:

```powershell
auditpol /set /subcategory:"Process Creation" /success:enable
```

### "InitiatedBy: Not found" for all events

This typically means:
1. Process Creation auditing is not enabled, OR
2. The correlation time window (10 minutes) didn't capture the initiating process, OR
3. Updates were triggered by the system automatically (not user-initiated)

### Script hangs on Security log query

The script limits Security log queries to 10,000 events maximum per node. If it still hangs:
- Reduce the `DaysBack` parameter (e.g., `-DaysBack 3`)
- Check network connectivity to cluster nodes
- Verify WinRM/PowerShell remoting is working

### "No cluster nodes found"

Ensure you're running the script from a cluster node or specify `-ClusterName` explicitly.

## Performance Notes

- **Execution time**: Typically 30-60 seconds per node when run in parallel
- **Event filtering**: XPath and regex filtering significantly reduces data transfer
- **Network impact**: Minimal - only retrieves filtered event log entries
- **Memory usage**: Low - processes events in streaming fashion

## Limitations

- Only queries the last N days (default 7, configurable)
- Limited to 500 Windows Update events per node
- Limited to 10,000 Security log events per node
- Time correlation window is fixed at 10 minutes

## Author

**Neil Bird**  
Generated with assistance from Claude Sonnet 4.5  
Date: December 15, 2025

## License

THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.

This sample is not supported under any Microsoft standard support program or service.

## Contributing

This is a personal snippet repository. Feel free to fork and modify for your own use.

## See Also

- [Windows Update Event IDs](https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-logs)
- [Security Audit Events](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-process-creation)
- [PowerShell Remoting](https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands)
