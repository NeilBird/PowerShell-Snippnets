<#
.SYNOPSIS
    Identifies who initiated Windows Update actions on a Windows Server Failover Cluster.

.DESCRIPTION
    This script queries Windows Update event logs, Security logs, and Task Scheduler logs across
    all cluster nodes to correlate Windows Update installations with the users and processes that
    triggered them. It runs queries in parallel for performance and provides detailed diagnostic
    information about update events, reboots, and the initiating identities.
    
    The script correlates multiple event sources:
    - Windows Update Client events (installation, download)
    - Security audit events (process creation)
    - Task Scheduler events (scheduled update tasks)
    - System reboot events
    
    Performance optimized with:
    - Parallel execution across cluster nodes
    - Limited event retrieval (max 10,000 Security events per node)
    - XPath filtering for fast event log queries
    - Pre-compiled regex for efficient process filtering

.PARAMETER ClusterName
    The name of the cluster to query. If not specified, uses the local cluster.

.PARAMETER DaysBack
    Number of days to look back for Windows Update events. Default is 7 days.

.NOTES
    Author: Neil Bird, Claude Sonnet v4.5 Generated Script
    Date: December 15, 2025
    Requires: Administrator privileges, Failover Clustering PowerShell module, and PowerShell remoting enabled
    
    Requirements:
    - Expected to execute from a node in a Windows Server Failover Cluster environment
    - Must be run with permissions to query event logs on all cluster nodes
    - Process Creation auditing (Event 4688) should be enabled in Security logs for best results
    - PowerShell remoting must be enabled on all cluster nodes
    
    Event IDs queried:
    - 19, 41, 43: Windows Update Client events
    - 4688: Process creation (Security log)
    - 1074: System shutdown/reboot
    - 106, 200, 201: Task Scheduler events

.EXAMPLE
    Get-ClusterWindowsUpdateHistory
    Queries all nodes in the local cluster for Windows Update events from the last 7 days.

.EXAMPLE
    Get-ClusterWindowsUpdateHistory -DaysBack 14
    Queries all nodes in the local cluster for Windows Update events from the last 14 days.

.EXAMPLE
    Get-ClusterWindowsUpdateHistory -ClusterName "MyCluster" -DaysBack 30
    Queries all nodes in the specified cluster for Windows Update events from the last 30 days.

    THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
    FITNESS FOR A PARTICULAR PURPOSE.

    This sample is not supported under any Microsoft standard support program or service. 
    The script is provided AS IS without warranty of any kind. Microsoft further disclaims all
    implied warranties including, without limitation, any implied warranties of merchantability
    or of fitness for a particular purpose. The entire risk arising out of the use or performance
    of the sample and documentation remains with you. In no event shall Microsoft, its authors,
    or anyone else involved in the creation, production, or delivery of the script be liable for 
    any damages whatsoever (including, without limitation, damages for loss of business profits, 
    business interruption, loss of business information, or other pecuniary loss) arising out of 
    the use of or inability to use the sample or documentation, even if Microsoft has been advised 
    of the possibility of such damages, rising out of the use of or inability to use the sample script, 
    even if Microsoft has been advised of the possibility of such damages. 

#>

function Get-ClusterWindowsUpdateHistory {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$false)]
    [string]$ClusterName,
    
    [Parameter(Mandatory=$false)]
    [int]$DaysBack = 7
  )

    [ScriptBlock]$ScriptBlock = {
    param($DaysBack = 7)
    
    $start = (Get-Date).AddDays(-$DaysBack)
    $windowSeconds = 600  # 10 minutes
    
    # Get Windows Update events - these logs are usually small
    $wuEvents = @()
    foreach($eventId in @(19, 41, 43)) {
        $events = Get-WinEvent -FilterHashtable @{ 
        LogName='Microsoft-Windows-WindowsUpdateClient/Operational'
        Id=$eventId
        StartTime=$start 
        } -ErrorAction SilentlyContinue -MaxEvents 500
        if($events) { $wuEvents += $events }
    }

    # Get reboot events
    $reboots = Get-WinEvent -FilterHashtable @{ 
        LogName='System'
        Id=1074
        StartTime=$start 
    } -ErrorAction SilentlyContinue -MaxEvents 100

    # Get Task Scheduler events - limit to prevent hanging
    $taskEventsRaw = Get-WinEvent -FilterHashtable @{ 
        LogName='Microsoft-Windows-TaskScheduler/Operational'
        Id=106,200,201
        StartTime=$start 
    } -ErrorAction SilentlyContinue -MaxEvents 1000
    
    $taskEvents = $taskEventsRaw | Where-Object { 
        $_.Message -match 'Update|USO|Windows Update' 
    }
    
    # CRITICAL FIX: Only query Security log if we have update events to correlate
    # Use time-filtered query to avoid retrieving millions of events
    if($wuEvents.Count -gt 0) {
        # Simple XPath with just time and event ID filtering
        $xpath = "*[System[(EventID=4688) and TimeCreated[@SystemTime >= '$($start.ToUniversalTime().ToString('o'))']]]"
        
        # Query with MaxEvents to prevent hanging on huge logs
        $allProcCreates = Get-WinEvent -LogName 'Security' -FilterXPath $xpath -ErrorAction SilentlyContinue -MaxEvents 10000
        
        if($allProcCreates) {
        # Filter by process name in PowerShell - more reliable than XPath
        $updateRegex = [regex]::new('usoclient\.exe|uso\.exe|wuauclt\.exe|tiworker\.exe|trustedinstaller\.exe|wusa\.exe|msiexec\.exe', 'IgnoreCase')
        $updateProcCreates = @($allProcCreates).Where({ 
            $procPath = $_.Properties[5].Value
            $updateRegex.IsMatch($procPath)
        })
        } else {
        $updateProcCreates = @()
        }
    } else {
        $updateProcCreates = @()
    }
    
    # Track total process events for diagnostics
    $totalProcEvents = if($updateProcCreates) { $updateProcCreates.Count } else { 0 }
    
    # Build results with enhanced correlation
    $summary = foreach ($wu in $wuEvents) {
        # Find processes near this update event
        $nearProc = $updateProcCreates.Where({ 
        [Math]::Abs(($_.TimeCreated - $wu.TimeCreated).TotalSeconds) -le $windowSeconds 
        })
        
        # Find task scheduler events near this update
        $nearTasks = $taskEvents.Where({ 
        [Math]::Abs(($_.TimeCreated - $wu.TimeCreated).TotalSeconds) -le $windowSeconds 
        })
        
        # Extract user information from Security events (4688)
        $userInfo = @()
        foreach($proc in $nearProc) {
        try {
            # For Event 4688: SubjectDomainName = Properties[2], SubjectUserName = Properties[1]
            $domain = $proc.Properties[2].Value
            $user = $proc.Properties[1].Value
            $processName = Split-Path $proc.Properties[5].Value -Leaf
            $userInfo += "$domain\$user ($processName)"
        } catch {
            $userInfo += "Error parsing event"
        }
        }
        
        # Extract task information
        $taskInfo = @()
        foreach($task in $nearTasks) {
        try {
            # Task scheduler events often have user in the message
            if($task.Message -match 'User:\s+([^\r\n]+)') {
            $taskInfo += $matches[1]
            }
        } catch {}
        }
        
        [PSCustomObject]@{
        Node = $env:COMPUTERNAME
        EventId = $wu.Id
        EventTime = $wu.TimeCreated
        UpdateInfo = $wu.Message.Split("`n")[0].Trim()
        InitiatedBy = if($userInfo) { ($userInfo | Select-Object -Unique) -join '; ' } else { "Not found" }
        RelatedTasks = if($taskInfo) { ($taskInfo | Select-Object -Unique) -join '; ' } else { "None" }
        ProcessCount = $nearProc.Count
        TaskCount = $nearTasks.Count
        }
    }
    
    if($reboots){
        $rebootsInfo = foreach($reboot in $reboots) {
        [PSCustomObject]@{
            Node = $env:COMPUTERNAME
            RebootTime = $reboot.TimeCreated
            Initiator = if($reboot.Message -match 'User:\s+([^\r\n]+)') { $matches[1] } else { "System" }
            Reason = $reboot.Message.Split("`n")[0]
        }
        }
    } else {
        $rebootsInfo = @()
    }
    
    # Return structured data
    [PSCustomObject]@{
        Node = $env:COMPUTERNAME
        Reboots = $rebootsInfo
        Updates = $summary
        DiagnosticInfo = [PSCustomObject]@{
        TotalUpdateEvents = $wuEvents.Count
        TotalProcessEvents = $totalProcEvents
        FilteredProcessEvents = $updateProcCreates.Count
        TaskSchedulerEvents = $taskEvents.Count
        }
    }
    }

    # Get Cluster Name
    if($ClusterName) {
    Write-Host "Using specified cluster name: $ClusterName" -ForegroundColor Green
    } else {
    try {
        $localCluster = Get-Cluster -ErrorAction Stop
        $ClusterName = $localCluster.Name
        Write-Host "Detected local cluster name: $ClusterName" -ForegroundColor Green
    } catch {
        Write-Host "Error: No cluster name specified and unable to detect local cluster. Ensure this script is run on a Windows Server Failover Cluster node." -ForegroundColor Red
        return
    }
    }

    # Get cluster nodes
    if($ClusterName) {
    [array]$ClusterNodes = Get-ClusterNode -Cluster $ClusterName | Select-Object -ExpandProperty Name
    } else {
    [array]$ClusterNodes = Get-ClusterNode | Select-Object -ExpandProperty Name
    }

    if(-not $ClusterNodes -or $ClusterNodes.Count -eq 0) {
    Write-Host "Error: No cluster nodes found. Ensure this script is run on a Windows Server Failover Cluster node." -ForegroundColor Red
    return
    }

    $startTime = Get-Date
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Script Start Time: $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Checking Windows Update history on cluster $ClusterName ($($ClusterNodes.Count) x nodes)..." -ForegroundColor Cyan
    Write-Host "(Querying event logs - this may take 30-60 seconds per node)`n" -ForegroundColor Yellow

    # Use jobs for better progress monitoring
    $jobs = @()
    $jobIndex = 0
    foreach($node in $ClusterNodes) {
    $jobIndex++
    Write-Host "[$jobIndex/$($ClusterNodes.Count)] Starting query on $node..." -ForegroundColor Cyan
    $jobs += Invoke-Command -ComputerName $node -ScriptBlock $ScriptBlock -ArgumentList $DaysBack -AsJob -JobName "WU_$node"
    }

    # Monitor job progress
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Host "`nWaiting for jobs to complete..." -ForegroundColor Cyan

    while($jobs | Where-Object {$_.State -eq 'Running'}) {
    $completed = ($jobs | Where-Object {$_.State -eq 'Completed'}).Count
    $running = ($jobs | Where-Object {$_.State -eq 'Running'}).Count
    $failed = ($jobs | Where-Object {$_.State -eq 'Failed'}).Count
    
    Write-Host "`rJob(s) Progress: $completed completed, $running running, $failed failed - Elapsed: $($stopwatch.Elapsed.ToString('mm\:ss'))" -NoNewline -ForegroundColor Green
    Start-Sleep -Seconds 2
    }

    Write-Host "`n`nAll jobs completed. Retrieving results...`n" -ForegroundColor Green

    # Get results
    $results = $jobs | Receive-Job
    $jobs | Remove-Job

    $stopwatch.Stop()

    # Display results
    foreach($result in $results) {
    # Use PSComputerName which is automatically added by Invoke-Command
    $nodeName = if($result.PSComputerName) { $result.PSComputerName } else { $result.Node }
    
    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "Node: $nodeName" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    
    # Show diagnostic info
    Write-Host "`nWindows Update Diagnostic Information:" -ForegroundColor Cyan
    Write-Host "  Update Events Found: $($result.DiagnosticInfo.TotalUpdateEvents)"
    Write-Host "  Process Creation Events: $($result.DiagnosticInfo.TotalProcessEvents)"
    Write-Host "  Update-Related Processes: $($result.DiagnosticInfo.FilteredProcessEvents)"
    Write-Host "  Task Scheduler Events: $($result.DiagnosticInfo.TaskSchedulerEvents)"
    
    if($result.Reboots.Count -gt 0) {
        Write-Host "`nReboots in the last $DaysBack days:" -ForegroundColor Yellow
        # Add node name to output if missing
        $result.Reboots | Select-Object @{N='Node';E={if($_.Node){$_.Node}else{$nodeName}}}, RebootTime, Initiator, Reason | 
        Format-Table -AutoSize -Wrap
    } else {
        Write-Host "`nNo reboots recorded in the last $DaysBack days." -ForegroundColor Gray
    }
    
    if($result.Updates.Count -gt 0) {
        Write-Host "`nWindows Update Events (with initiating user/process):" -ForegroundColor Yellow
        # Add node name to output if missing
        $result.Updates | Select-Object @{N='Node';E={if($_.Node){$_.Node}else{$nodeName}}}, EventId, EventTime, InitiatedBy, RelatedTasks, UpdateInfo | 
        Format-Table -AutoSize -Wrap
    } else {
        Write-Host "`nNo Windows Update events found in the last $DaysBack days." -ForegroundColor Gray
    }
    }

    $endTime = Get-Date
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Script End Time: $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
    Write-Host "Total Execution Time: $($stopwatch.Elapsed.ToString('mm\:ss\.fff'))" -ForegroundColor Green
    Write-Host "Average Time Per Node: $(($stopwatch.Elapsed.TotalSeconds / $ClusterNodes.Count).ToString('F2')) seconds" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan

} # end function

# Import necessary modules
#region Helper Functions
function Test-IsAdmin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
#endregion

#region Pre-flight Checks
# Check if running as Administrator
if (-not (Test-IsAdmin)) {
    Write-Host "This script must be run as Administrator!" -ForegroundColor Red
    exit 1
}
# Check if Failover Clustering module is available
if (-not (Get-Module -ListAvailable -Name FailoverClusters)) {
    Write-Host "Failover Clustering PowerShell module is not installed!" -ForegroundColor Red
    exit 1
}

# If script is run directly (not dot-sourced), execute the function
if ($MyInvocation.InvocationName -ne '.') {
  Get-ClusterWindowsUpdateHistory
} else {
    Write-Host "Get-ClusterWindowsUpdateHistory function loaded. You can now call it with desired parameters." -ForegroundColor Green
}