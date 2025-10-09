# Author: Neil Bird, MSFT
# Date:   2025-10-09
# Description: PowerShell script to retrieve effective access permissions for Active Directory objects.
# Licensed under the MIT License.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

<#
.SYNOPSIS
    Gets effective access permissions for Active Directory objects, with support for user-specific effective permissions analysis.

.DESCRIPTION
    This function can operate in three modes:
    1. Get all permissions for an AD object (default behavior)
    2. Calculate effective permissions for a specific user SID, including permissions inherited through group memberships
    3. Calculate effective permissions for a specific user by SAMAccountName, including permissions inherited through group memberships

    When a UserSID or UserName            if ($effectiveUserSID) {
                # Return effective permissions for the specified user
                $userPermissions = Get-UserEffectivePermissions -UserSID $effectiveUserSID -ADObject $object -GUIDMap $GUIDMap -Server $Server
                
                # Check for required permissions
                if ($userPermissions -and $userPermissions.Count -gt 0) {
                    $permissionCheck = Test-RequiredPermissions -EffectivePermissions $userPermissions
                    Write-Verbose "Permission Check Results:"
                    Write-Verbose "  CreateDeleteComputerObjects: $($permissionCheck.CreateDeleteComputerObjects)"
                    Write-Verbose "  ReadPropertyAllObjects: $($permissionCheck.ReadPropertyAllObjects)"
                    Write-Verbose "  GenericAllRecoveryInfo: $($permissionCheck.GenericAllRecoveryInfo)"
                    Write-Verbose "  All Required Permissions Present: $($permissionCheck.AllRequiredPermissionsPresent)"
                    
                    # Add the permission check results as a property to each permission object
                    foreach ($perm in $userPermissions) {
                        $perm | Add-Member -NotePropertyName 'RequiredPermissionCheck' -NotePropertyValue $permissionCheck -Force
                    }
                }
                
                return $userPermissions
            }provided, the function analyzes the user's direct permissions and all permissions inherited 
    through group memberships (including nested groups) to provide a comprehensive view of effective access.

.PARAMETER Object
    The Distinguished Name of the Active Directory object to analyze permissions for.

.PARAMETER UserSID
    The Security Identifier (SID) of a user for whom to calculate effective permissions. When provided, the function
    will analyze both direct user permissions and permissions inherited through all group memberships.

.PARAMETER UserName
    The SAMAccountName of a user for whom to calculate effective permissions. The function will resolve this to a SID
    and then analyze both direct user permissions and permissions inherited through all group memberships.

.PARAMETER Server
    The Active Directory server to query. If not specified, uses the current domain.

.EXAMPLE
    Get-EffectiveAccess -ADObject "CN=TestUser,CN=Users,DC=contoso,DC=com"
    
    Gets all permissions for the specified AD object.

.EXAMPLE
    Get-EffectiveAccess -ADObject "CN=TestOU,OU=TestOUs,DC=contoso,DC=com" -UserSID "S-1-5-21-1234567890-1234567890-1234567890-1001"
    
    Calculates the effective permissions for the specified user SID on the given AD object, including permissions 
    inherited through group memberships.

.EXAMPLE
    Get-EffectiveAccess -ADObject "CN=TestOU,OU=TestOUs,DC=contoso,DC=com" -UserName "jdoe"
    
    Calculates the effective permissions for user 'jdoe' on the given AD object, including permissions 
    inherited through group memberships.

.EXAMPLE
    Get-EffectiveAccess -ADObject "CN=TestComputer,CN=Computers,DC=contoso,DC=com" -UserName "jsmith" -Server "dc01.contoso.com"
    
    Calculates effective permissions for user 'jsmith' on a specific server.

.EXAMPLE
    Get-UserEffectivePermissions -UserSID "S-1-5-21-1234567890-1234567890-1234567890-1001" -ADObject $adObject -Server "dc01.contoso.com"
    Calculates effective permissions for the specified user SID on the provided AD object, including permissions 
    inherited through group memberships. The GUID map will be automatically built if not provided.

.EXAMPLE
    Get-UserEffectivePermissions -UserSID "S-1-5-21-1234567890-1234567890-1234567890-1001" -ADObject $adObject -GUIDMap $GUIDMap -Server "dc01.contoso.com"
    Calculates effective permissions for the specified user SID on the provided AD object using a pre-built GUID map 
    for better performance when calling the function multiple times.

.NOTES
    When using UserSID or UserName parameter:
    - The function recursively resolves all group memberships including nested groups
    - Permission precedence follows AD rules (Deny takes precedence over Allow)
    - Results include source attribution showing whether permissions come from direct assignment or group membership
    - Uses tokenGroups for comprehensive group membership resolution including domain local groups from trusted domains
    - UserName parameter is resolved to SID using the samAccountName attribute
#>

# Helper function to resolve username to SID
function Resolve-UserNameToSID {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $UserName,
        
        [Parameter()]
        [string] $Server
    )
    
    try {
        $userParams = @{
            Filter = "samAccountName -eq '$UserName'"
            Properties = 'objectSID'
            ErrorAction = 'Stop'
        }
        if ($Server) { $userParams['Server'] = $Server }
        
        $user = Get-ADUser @userParams
        
        if ($user -and $user.objectSID) {
            return $user.objectSID.Value
        } else {
            throw "User not found or SID could not be retrieved"
        }
    }
    catch {
        throw "Failed to resolve username '$UserName' to SID: $($_.Exception.Message)"
    }
}

# Helper function to get all group memberships recursively
function Get-UserGroupMemberships {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $UserSID,
        
        [Parameter()]
        [string] $Server,
        
        [Parameter()]
        [hashtable] $ProcessedGroups = @{}
    )
    
    $allGroups = @()
    
    try {
        # Get the user object first - we need to find the user by SID first
        $userParams = @{
            Filter = "objectSID -eq '$UserSID'"
            Properties = 'memberOf'
            ErrorAction = 'Stop'
        }
        if ($Server) { $userParams['Server'] = $Server }
        
        $user = Get-ADUser @userParams
        
        if (-not $user) {
            throw "User with SID $UserSID not found"
        }
        
        # Now get the user with tokenGroups using the Identity (DN or GUID)
        $tokenGroupsParams = @{
            Identity = $user.ObjectGUID
            Properties = 'tokenGroups'
            ErrorAction = 'Stop'
        }
        if ($Server) { $tokenGroupsParams['Server'] = $Server }
        
        $userWithTokenGroups = Get-ADUser @tokenGroupsParams
        
        # Use tokenGroups for more comprehensive group membership (includes domain local groups from trusted domains)
        if ($userWithTokenGroups.tokenGroups) {
            foreach ($groupSID in $userWithTokenGroups.tokenGroups) {
                $sidString = $groupSID.Value
                
                if (-not $ProcessedGroups.ContainsKey($sidString)) {
                    $ProcessedGroups[$sidString] = $true
                    
                    try {
                        # Try to resolve the SID to get group information
                        $groupParams = @{
                            Filter = "objectSID -eq '$sidString'"
                            Properties = 'memberOf', 'samAccountName', 'distinguishedName'
                        }
                        if ($Server) { $groupParams['Server'] = $Server }
                        
                        $group = Get-ADGroup @groupParams -ErrorAction SilentlyContinue
                        
                        if ($group) {
                            $allGroups += [PSCustomObject]@{
                                SID = $sidString
                                Name = $group.samAccountName
                                DistinguishedName = $group.distinguishedName
                            }
                            
                            # Recursively get nested groups
                            if ($group.memberOf) {
                                foreach ($nestedGroupDN in $group.memberOf) {
                                    try {
                                        $nestedGroupParams = @{
                                            Identity = $nestedGroupDN
                                            Properties = 'objectSID'
                                        }
                                        if ($Server) { $nestedGroupParams['Server'] = $Server }
                                        
                                        $nestedGroup = Get-ADGroup @nestedGroupParams -ErrorAction SilentlyContinue
                                        if ($nestedGroup -and $nestedGroup.objectSID) {
                                            $nestedSID = $nestedGroup.objectSID.Value
                                            if (-not $ProcessedGroups.ContainsKey($nestedSID)) {
                                                $nestedGroups = Get-UserGroupMemberships -UserSID $nestedSID -Server $Server -ProcessedGroups $ProcessedGroups
                                                $allGroups += $nestedGroups
                                            }
                                        }
                                    }
                                    catch {
                                        Write-Verbose "Could not process nested group: $nestedGroupDN"
                                    }
                                }
                            }
                        }
                    }
                    catch {
                        Write-Verbose "Could not resolve SID: $sidString"
                    }
                }
            }
        }
    }
    catch {
        Write-Error "Failed to get user information for SID: $UserSID. Error: $($_.Exception.Message)"
    }
    
    return $allGroups
}

# Helper function to calculate effective permissions for a specific user
function Get-UserEffectivePermissions {
    [CmdletBinding(DefaultParameterSetName = 'BySID')]
    param(
        [Parameter(ParameterSetName = 'BySID', Mandatory)]
        [string] $UserSID,
        
        [Parameter(ParameterSetName = 'ByUserName', Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $UserName,
        
        [Parameter(Mandatory)]
        [object] $ADObject,
        
        [Parameter()]
        [hashtable] $GUIDMap = $null,
        
        [Parameter()]
        [string] $Server
    )
    
    # Resolve the actual SID to use
    $effectiveUserSID = $null
    
    if ($PSCmdlet.ParameterSetName -eq 'BySID') {
        # check the SID format is valid using try/catch approach
        try {
            $testSid = New-Object System.Security.Principal.SecurityIdentifier($UserSID)
            $effectiveUserSID = $UserSID
        }
        catch {
            throw "Invalid UserSID format: $UserSID"
        }
    } elseif ($PSCmdlet.ParameterSetName -eq 'ByUserName') {
        Write-Verbose "Resolving username '$UserName' to SID..."
        $effectiveUserSID = Resolve-UserNameToSID -UserName $UserName -Server $Server
        Write-Verbose "Resolved '$UserName' to SID: $effectiveUserSID"
    } else {
        throw "Either UserSID or UserName parameter must be provided"
    }
    
    # If GUIDMap is not provided, build it automatically
    if (-not $GUIDMap) {
        Write-Verbose "Building GUID map automatically..."
        $GUIDMap = @{}
        
        # Get domain information
        if ($Server) {
            $domain = Get-ADRootDSE -Server $Server
        } else {
            $domain = Get-ADRootDSE
        }
        
        # Build schema GUID map
        $schemaParams = @{
            SearchBase  = $domain.schemaNamingContext
            LDAPFilter  = '(schemaIDGUID=*)'
            Properties  = 'name', 'schemaIDGUID'
            ErrorAction = 'SilentlyContinue'
        }
        if ($Server) { $schemaParams['Server'] = $Server }
        
        $schemaIDs = Get-ADObject @schemaParams
        foreach ($schema in $schemaIDs) {
            if (-not $GUIDMap.ContainsKey([guid] $schema.schemaIDGUID)) {
                $GUIDMap.Add([guid] $schema.schemaIDGUID, $schema.name)
            }
        }
        
        # Build extended rights GUID map
        $extendedParams = @{
            SearchBase  = "CN=Extended-Rights,$($domain.configurationNamingContext)"
            LDAPFilter  = '(objectClass=controlAccessRight)'
            Properties  = 'name', 'rightsGUID'
            ErrorAction = 'SilentlyContinue'
        }
        if ($Server) { $extendedParams['Server'] = $Server }
        
        $extendedRights = Get-ADObject @extendedParams
        foreach ($right in $extendedRights) {
            if (-not $GUIDMap.ContainsKey([guid] $right.rightsGUID)) {
                $GUIDMap.Add([guid] $right.rightsGUID, $right.name)
            }
        }
        
        Write-Verbose "Built GUID map with $($GUIDMap.Count) entries"
    }
    
    $effectivePermissions = @{}
    $permissionSources = @{}
    
    # Get all groups the user belongs to
    $userGroups = Get-UserGroupMemberships -UserSID $effectiveUserSID -Server $Server
    $allSIDs = @($effectiveUserSID) + $userGroups.SID
    
    Write-Verbose "Analyzing permissions for user $effectiveUserSID and $($userGroups.Count) groups"
    Write-Verbose "User and group SIDs: $($allSIDs -join ', ')"
    $adObjParams['Identity'] = $ADObject
    $ADObjectProperties = Get-ADObject @adObjParams
    Write-Verbose "Processing $($ADObjectProperties.nTSecurityDescriptor.Access.Count) ACEs"

    # Process each ACE in the security descriptor
    foreach ($acl in $ADObjectProperties.nTSecurityDescriptor.Access) {
        # Convert IdentityReference to SID if needed
        $aclSID = $acl.IdentityReference.Value
        if ($acl.IdentityReference -is [System.Security.Principal.NTAccount]) {
            try {
                $aclSID = $acl.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            }
            catch {
                Write-Verbose "Could not translate ACE identity: $($acl.IdentityReference.Value)"
                continue  # Skip if we can't resolve the SID
            }
        }
        
        Write-Verbose "Processing ACE for: $aclSID (Rights: $($acl.ActiveDirectoryRights), Type: $($acl.AccessControlType))"
        
        # Check if this ACE applies to our user or any of their groups
        if ($aclSID -in $allSIDs) {
            Write-Verbose "MATCH FOUND: ACE applies to user/group - $aclSID"
            # Determine the source of the permission
            $source = if ($aclSID -eq $effectiveUserSID) {
                "Direct User Assignment"
            } else {
                $groupInfo = $userGroups | Where-Object { $_.SID -eq $aclSID } | Select-Object -First 1
                "Group: $($groupInfo.Name)"
            }
            
            # Create a unique key for this permission combination
            $permKey = "$($acl.ActiveDirectoryRights)|$($acl.ObjectType)|$($acl.InheritedObjectType)|$($acl.InheritanceType)"
            
            # Handle permission aggregation (Deny takes precedence over Allow)
            if (-not $effectivePermissions.ContainsKey($permKey)) {
                $effectivePermissions[$permKey] = @{
                    Rights = $acl.ActiveDirectoryRights
                    ObjectType = $acl.ObjectType
                    InheritedObjectType = $acl.InheritedObjectType
                    InheritanceType = $acl.InheritanceType
                    AccessControlType = $acl.AccessControlType
                    IsInherited = $acl.IsInherited
                    InheritanceFlags = $acl.InheritanceFlags
                    PropagationFlags = $acl.PropagationFlags
                    Sources = @($source)
                }
            } else {
                # If we already have this permission, check for Deny vs Allow precedence
                $existing = $effectivePermissions[$permKey]
                
                # Add the source
                $existing.Sources += $source
                
                # Deny takes precedence over Allow
                if ($acl.AccessControlType -eq 'Deny') {
                    $existing.AccessControlType = 'Deny'
                }
            }
        }
    }
    
    Write-Verbose "Found $($effectivePermissions.Count) unique effective permissions"
    
    # Convert to output format
    $results = @()
    foreach ($permKey in $effectivePermissions.Keys) {
        $perm = $effectivePermissions[$permKey]
        
        # Resolve object type names
        $guid = [guid]::Empty
        if ($guid.Equals($perm.ObjectType)) {
            $objectType = 'All Objects (Full Control)'
        } elseif ($GUIDMap.ContainsKey($perm.ObjectType)) {
            $objectType = $GUIDMap[$perm.ObjectType]
        } else {
            $objectType = $perm.ObjectType
        }
        
        if ($guid.Equals($perm.InheritedObjectType)) {
            $inheritedObjType = 'Applied to Any Inherited Object'
        } elseif ($GUIDMap.ContainsKey($perm.InheritedObjectType)) {
            $inheritedObjType = $GUIDMap[$perm.InheritedObjectType]
        } else {
            $inheritedObjType = $perm.InheritedObjectType
        }
        
        $results += [PSCustomObject]@{
            DistinguishedName     = $ADObjectProperties.DistinguishedName
            Name                  = $ADObjectProperties.Name
            ObjectClass           = $ADObjectProperties.ObjectClass
            ObjectGUID            = $ADObjectProperties.ObjectGUID
            UserSID               = $effectiveUserSID
            EffectiveRights       = $perm.Rights
            AccessControlType     = $perm.AccessControlType
            ObjectType            = $objectType
            ObjectTypeGUID        = $perm.ObjectType
            InheritedObjectType   = $inheritedObjType
            InheritedObjectTypeGUID = $perm.InheritedObjectType
            InheritanceType       = $perm.InheritanceType
            IsInherited           = $perm.IsInherited
            InheritanceFlags      = $perm.InheritanceFlags
            PropagationFlags      = $perm.PropagationFlags
            PermissionSources     = ($perm.Sources -join '; ')
        }
    }
    
    return $results

}

# Helper function to check for specific required permissions
function Test-RequiredPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]] $EffectivePermissions
    )
    
    # Define the required permissions to check for
    $adRight = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild -bor [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild
    $genericAllRight = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
    $readPropertyRight = [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty
    
    # Define object type GUIDs
    $allObjectType = [System.Guid]::Empty
    $computersObjectType = [System.Guid]::New('bf967a86-0de6-11d0-a285-00aa003049e2')
    $msfveRecoveryGuid = [System.Guid]::New('ea715d30-8f53-40d0-bd1e-6109186d782c')
    
    # Check for Rule 1: CreateChild/DeleteChild on computer objects
    $hasRule1 = $false
    foreach ($perm in $EffectivePermissions) {
        if ($perm.AccessControlType -eq 'Allow' -and 
            ($perm.EffectiveRights -band $adRight) -eq $adRight -and
            $perm.ObjectTypeGUID -eq $computersObjectType) {
            $hasRule1 = $true
            Write-Verbose "Found Rule 1: CreateChild/DeleteChild on computer objects"
            break
        }
    }
    
    # Check for Rule 2: ReadProperty on all objects
    $hasRule2 = $false
    foreach ($perm in $EffectivePermissions) {
        if ($perm.AccessControlType -eq 'Allow' -and 
            ($perm.EffectiveRights -band $readPropertyRight) -eq $readPropertyRight -and
            ($perm.ObjectTypeGUID -eq $allObjectType -or $perm.InheritedObjectTypeGUID -eq $allObjectType)) {
            $hasRule2 = $true
            Write-Verbose "Found Rule 2: ReadProperty on all objects"
            break
        }
    }
    
    # Check for Rule 3: GenericAll on msFVE-RecoveryInformation objects
    $hasRule3 = $false
    foreach ($perm in $EffectivePermissions) {
        if ($perm.AccessControlType -eq 'Allow' -and 
            ($perm.EffectiveRights -band $genericAllRight) -eq $genericAllRight -and
            $perm.InheritedObjectTypeGUID -eq $msfveRecoveryGuid) {
            $hasRule3 = $true
            Write-Verbose "Found Rule 3: GenericAll on msFVE-RecoveryInformation objects"
            break
        }
    }
    
    # Return the results
    return [PSCustomObject]@{
        "CreateDeleteComputerObjects" = $hasRule1
        "ReadPropertyAllObjects" = $hasRule2
        "ms-FVE-RecoveryInformation" = $hasRule3
        "AllRequiredPermissionsPresent" = ($hasRule1 -and $hasRule2 -and $hasRule3)
    }
}

function Get-EffectiveAccess {
    [CmdletBinding(DefaultParameterSetName = 'AllPermissions')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidatePattern('(?:(CN=([^,]*)),)?(?:((?:(?:CN|OU)=[^,]+,?)+),)?((?:DC=[^,]+,?)+)$')]
        [alias('DistinguishedName')]
        [string] $ADObject,

        [Parameter(ParameterSetName = 'UserSIDEffectivePermissions', Mandatory)]
        [ValidatePattern('^S-\d-\d+-(\d+-){1,14}\d+$')]
        [string] $UserSID,

        [Parameter(ParameterSetName = 'UserNameEffectivePermissions', Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $UserName,

        [parameter()]
        [alias('Domain')]
        [string] $Server
    )

    begin {
        $guid    = [guid]::Empty
        $GUIDMap = @{}

        if($PSBoundParameters.ContainsKey('Server')) {
            $domain = Get-ADRootDSE -Server $Server
        }
        else {
            $domain = Get-ADRootDSE
        }

        $params = @{
            SearchBase  = $domain.schemaNamingContext
            LDAPFilter  = '(schemaIDGUID=*)'
            Properties  = 'name', 'schemaIDGUID'
            ErrorAction = 'SilentlyContinue'
        }
        $adObjParams = @{
            Properties = 'nTSecurityDescriptor'
        }

        if($PSBoundParameters.ContainsKey('Server')) {
            $params['Server']  = $Server
            $adObjParams['Server'] = $Server
        }
        $schemaIDs = Get-ADObject @params

        $params['SearchBase'] = "CN=Extended-Rights,$($domain.configurationNamingContext)"
        $params['LDAPFilter'] = '(objectClass=controlAccessRight)'
        $params['Properties'] = 'name', 'rightsGUID'
        $extendedRights = Get-ADObject @params

        foreach($i in $schemaIDs) {
            if(-not $GUIDMap.ContainsKey([guid] $i.schemaIDGUID)) {
                $GUIDMap.Add([guid] $i.schemaIDGUID, $i.name)
            }
        }
        foreach($i in $extendedRights) {
            if(-not $GUIDMap.ContainsKey([guid] $i.rightsGUID)) {
                $GUIDMap.Add([guid] $i.rightsGUID, $i.name)
            }
        }
    }

    process {
        try {
            $adObjParams['Identity'] = $ADObject
            $ADObjectProperties = Get-ADObject @adObjParams

            Write-Verbose "Retrieved AD object: $($ADObjectProperties.DistinguishedName)"
            Write-Verbose "Object class: $($ADObjectProperties.ObjectClass)"
            Write-Verbose "Has nTSecurityDescriptor: $($null -ne $ADObjectProperties.nTSecurityDescriptor)"
            if ($ADObjectProperties.nTSecurityDescriptor) {
                Write-Verbose "Security descriptor has $($ADObjectProperties.nTSecurityDescriptor.Access.Count) ACEs"
            } else {
                Write-Warning "Security descriptor is null or missing for object: $($ADObjectProperties.DistinguishedName)"
                Write-Warning "This usually means insufficient permissions to read the security descriptor"
            }

            # Resolve the actual SID to use for effective permissions calculation
            $effectiveUserSID = $null
            
            # Check if we're calculating effective permissions for a specific user
            if ($PSBoundParameters.ContainsKey('UserSID')) {
                $effectiveUserSID = $UserSID
            }
            elseif ($PSBoundParameters.ContainsKey('UserName')) {
                Write-Verbose "Resolving username '$UserName' to SID..."
                $effectiveUserSID = Resolve-UserNameToSID -UserName $UserName -Server $Server
                Write-Verbose "Resolved '$UserName' to SID: $effectiveUserSID"
            }

            if ($effectiveUserSID) {
                # Return effective permissions for the specified user
                return Get-UserEffectivePermissions -UserSID $effectiveUserSID -ADObject $ADObjectProperties -GUIDMap $GUIDMap -Server $Server
            }
            else {
                # Original functionality - return all permissions
                foreach($acl in $ADObjectProperties.nTSecurityDescriptor.Access) {
                    if($guid.Equals($acl.ObjectType)) {
                        $objectType = 'All Objects (Full Control)'
                    }
                    elseif($GUIDMap.ContainsKey($acl.ObjectType)) {
                        $objectType = $GUIDMap[$acl.ObjectType]
                    }
                    else {
                        $objectType = $acl.ObjectType
                    }

                    if($guid.Equals($acl.InheritedObjectType)) {
                        $inheritedObjType = 'Applied to Any Inherited Object'
                    }
                    elseif($GUIDMap.ContainsKey($acl.InheritedObjectType)) {
                        $inheritedObjType = $GUIDMap[$acl.InheritedObjectType]
                    }
                    else {
                        $inheritedObjType = $acl.InheritedObjectType
                    }

                    # Convert IdentityReference to SID if it's not already in SID format
                    $identitySID = $acl.IdentityReference.Value
                    if ($acl.IdentityReference -is [System.Security.Principal.NTAccount]) {
                        try {
                            $identitySID = $acl.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                        }
                        catch {
                            # If translation fails, keep the original value
                            $identitySID = $acl.IdentityReference.Value
                        }
                    }

                    [PSCustomObject]@{
                        DistinguishedName     = $ADObjectProperties.DistinguishedName
                        Name                  = $ADObjectProperties.Name
                        ObjectClass           = $ADObjectProperties.ObjectClass
                        ObjectGUID            = $ADObjectProperties.ObjectGUID
                        IdentitySID           = $identitySID
                        IdentityReference     = $acl.IdentityReference
                        AccessControlType     = $acl.AccessControlType
                        ActiveDirectoryRights = $acl.ActiveDirectoryRights
                        ObjectType            = $objectType
                        ObjectTypeGUID        = $acl.ObjectType
                        InheritedObjectType   = $inheritedObjType
                        InheritedObjectTypeGUID = $acl.InheritedObjectType
                        InheritanceType       = $acl.InheritanceType
                        IsInherited           = $acl.IsInherited
                        InheritanceFlags      = $acl.InheritanceFlags
                        PropagationFlags      = $acl.PropagationFlags
                    }
                }
            }
        }
        catch {
            $PSCmdlet.WriteError($_)
        }
    }
}