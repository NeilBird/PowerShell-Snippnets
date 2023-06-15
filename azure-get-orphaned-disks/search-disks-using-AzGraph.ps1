
Install-Module -Name Az.ResourceGraph

$resourceType = 'Microsoft.Compute/disks'
# $query = "where type =~ '$resourceType' | where managedBy == '$null' and name !endswith 'ASRReplica' | project name, location, subscriptionId"
$query = "where type =~ '$resourceType' | where managedBy == '$null' and name !endswith 'ASRReplica'" #| project name, location, subscriptionId"
$OrphanedMDs = Search-AzGraph -Query $query

$OrphanedMDs.Count

$OrphanedMDs[0] | Format-List *
