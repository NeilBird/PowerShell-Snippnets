# Active Directory Effective Permissions

This folder contains PowerShell scripts for analyzing effective permissions on Active Directory objects, with advanced support for user-specific permission analysis and group membership resolution.

## Overview

The `Get-EffectiveAccess.ps1` script provides comprehensive functionality to:

- Retrieve all permissions for any Active Directory object
- Calculate effective permissions for a specific user, including permissions inherited through group memberships
- Analyze permission inheritance through nested group structures
- Check for specific required permissions (BitLocker recovery, computer object management)

## Prerequisites

### Required PowerShell Module

This script requires the **Active Directory PowerShell module** to be installed and imported.

To install the module:

#### On Windows Server

```powershell
# Install RSAT-AD-PowerShell feature
Install-WindowsFeature RSAT-AD-PowerShell
```

#### On Windows 10/11

```powershell
# Install RSAT tools
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

#### Alternative: Install from PowerShell Gallery

```powershell
# Install the ActiveDirectory module from PowerShell Gallery
Install-Module -Name ActiveDirectory -Force -AllowClobber
```

### Required Permissions

- **Read permissions** on Active Directory objects you want to analyze
- **Access to security descriptors** (typically requires Domain Admin or delegated permissions)
- **Network connectivity** to domain controllers

## Files

### Get-EffectiveAccess.ps1

Main script containing the `Get-EffectiveAccess` function and supporting helper functions.

## Functions

### Get-EffectiveAccess

Primary function that operates in three modes:

1. **All Permissions Mode (Default)**: Returns all ACEs for an AD object
2. **User SID Mode**: Calculates effective permissions for a specific user SID
3. **Username Mode**: Calculates effective permissions for a specific username (SAMAccountName)

#### Parameters

- `ADObject` (Mandatory): Distinguished Name of the AD object to analyze
- `UserSID` (Optional): Security Identifier of user for effective permissions calculation
- `UserName` (Optional): SAMAccountName of user for effective permissions calculation
- `Server` (Optional): Specific domain controller to query

#### Key Features

- **Comprehensive Group Resolution**: Uses `tokenGroups` for complete group membership including domain local groups from trusted domains
- **Nested Group Support**: Recursively resolves all group memberships including nested groups
- **Permission Precedence**: Properly handles Deny vs Allow permission precedence
- **Source Attribution**: Shows whether permissions come from direct assignment or group membership
- **GUID Resolution**: Automatically resolves schema and extended rights GUIDs to human-readable names
- **BitLocker Permission Checking**: Includes specialized checking for BitLocker recovery permissions

### Helper Functions

#### Resolve-UserNameToSID

Converts a SAMAccountName to a Security Identifier (SID).

#### Get-UserGroupMemberships

Recursively retrieves all group memberships for a user, including nested groups.

#### Get-UserEffectivePermissions

Core function that calculates effective permissions by analyzing user and group ACEs.

#### Test-RequiredPermissions

Checks for specific required permissions including:

- CreateChild/DeleteChild on computer objects
- ReadProperty on all objects
- GenericAll on BitLocker recovery information objects

## Usage Examples

### Basic Permission Analysis

```powershell
# Import the script
. .\Get-EffectiveAccess.ps1

# Get all permissions for a user object
Get-EffectiveAccess -ADObject "CN=TestUser,CN=Users,DC=contoso,DC=com"

# Get all permissions for an OU
Get-EffectiveAccess -ADObject "OU=TestOU,DC=contoso,DC=com"
```

### User-Specific Effective Permissions

```powershell
# Calculate effective permissions by user SID
Get-EffectiveAccess -ADObject "CN=TestOU,OU=TestOUs,DC=contoso,DC=com" -UserSID "S-1-5-21-1234567890-1234567890-1234567890-1001"

# Calculate effective permissions by username
Get-EffectiveAccess -ADObject "CN=TestOU,OU=TestOUs,DC=contoso,DC=com" -UserName "jdoe"

# Use specific domain controller
Get-EffectiveAccess -ADObject "CN=TestComputer,CN=Computers,DC=contoso,DC=com" -UserName "jsmith" -Server "dc01.contoso.com"
```

### Validate Azure Local permissions for OU

Example to test Azure Local OU has required permissions delagated for the LifeCycle Manager (LCM) user (deployment user) account:

```PowerShell
$results = Get-EffectiveAccess -ADObject "CN=AzureLocalOU,DC=contoso,DC=com" -UserName "LCM-User"

Test-RequiredPermissions $result


CreateDeleteComputerObjects ReadPropertyAllObjects ms-FVE-RecoveryInformation AllRequiredPermissionsPresent
--------------------------- ---------------------- -------------------------- -----------------------------
                       True                   True                       True                          True
```

### Advanced Analysis

```powershell
# Get effective permissions with verbose output for troubleshooting
Get-EffectiveAccess -ADObject "CN=TestOU,OU=TestOUs,DC=contoso,DC=com" -UserName "serviceaccount" -Verbose

# Check permissions for multiple objects
$objects = @(
    "CN=Computer1,CN=Computers,DC=contoso,DC=com",
    "CN=Computer2,CN=Computers,DC=contoso,DC=com"
)
$objects | ForEach-Object { Get-EffectiveAccess -ADObject $_ -UserName "admin" }
```

## Output Properties

### Standard Mode Output

- `DistinguishedName`: Full DN of the AD object
- `Name`: Name of the AD object
- `ObjectClass`: Class of the AD object
- `ObjectGUID`: Unique identifier
- `IdentitySID`: SID of the identity with permissions
- `IdentityReference`: Name of the identity
- `AccessControlType`: Allow or Deny
- `ActiveDirectoryRights`: Specific permissions
- `ObjectType`: Human-readable object type
- `InheritanceType`: How permissions are inherited

### Effective Permissions Mode Output

- `UserSID`: SID of the user being analyzed
- `EffectiveRights`: Calculated effective permissions
- `PermissionSources`: Shows whether permissions come from user or group assignment
- `RequiredPermissionCheck`: Results of BitLocker/computer object permission analysis

## Notes

- When using UserSID or UserName parameters, the function analyzes both direct user permissions and all permissions inherited through group memberships
- Permission precedence follows Active Directory rules where Deny takes precedence over Allow
- The script uses `tokenGroups` for comprehensive group membership resolution including domain local groups from trusted domains
- GUID maps are automatically built for schema and extended rights resolution
- Verbose mode provides detailed troubleshooting information about group resolution and permission calculation

## Troubleshooting

### Common Issues

1. **"Access Denied" errors**: Ensure you have sufficient permissions to read security descriptors
2. **Module not found**: Install the Active Directory PowerShell module
3. **User not found**: Verify the username/SID exists and is accessible
4. **Slow performance**: Consider using the `-Server` parameter to specify a closer domain controller

### Performance Tips

- Use the `-Server` parameter to specify a nearby domain controller
- When analyzing multiple objects for the same user, the GUID map is cached for better performance
- Verbose mode helps identify bottlenecks in group resolution

## License

This script is licensed under the MIT License. See the script header for full license text.
