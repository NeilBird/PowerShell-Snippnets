# AzureLocalVM PowerShell Module

## Overview

PowerShell module for creating and managing Azure Local (Azure Stack HCI) VMs, and testing functionality such as adding VHD Sets (shared data disks), see reference documentation: [Create Hyper-V VHD Set files](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/create-vhdset-file)

Note: This module is NOT support under any Microsoft support agreement or contract. The code in this module is provided as-is, and should be consider demo / example code only.

## Installation

Example commands to download the module, import it and use it for Azure Local VMs:

```PowerShell
# Download the module files directly from GitHub:
Invoke-WebRequest -UseBasicParsing -Uri 'https://raw.githubusercontent.com/NeilBird/PowerShell-Snippnets/refs/heads/main/AzureLocalVM/AzureLocalVM.psm1' -OutFile .\AzureLocalVM.psm1
Invoke-WebRequest -UseBasicParsing -Uri 'https://raw.githubusercontent.com/NeilBird/PowerShell-Snippnets/refs/heads/main/AzureLocalVM/AzureLocalVM.psd1' -OutFile .\AzureLocalVM.psd1
# Import the module:
Import-Module .\AzureLocalVM.psd1
```

### Install Required PowerShell Modules

```powershell
# Requires Az.StackHCIVM, Az.CustomLocation, Az.Accounts, and Az.KeyVault modules - These will be installed automatically if needed

# Verify installation. these are verified and installed by the Test-Prerequisites function.
Get-Module Az.StackHCIVM, Az.CustomLocation, Az.Accounts, Az.KeyVault -ListAvailable

# Connect to Azure
Connect-AzAccount

# Verify current subscription
Get-AzContext
```

## Example end to end commands

For a complete end-to-end workflow demonstrating VM creation with Key Vault secrets, shared disks, and data disk management, see the [SharedDisks-Test-Workflows.ps1](SharedDisks-Test-Workflows.ps1) script.

````powershell
$SubscriptionId = '<subscription-id-guid>'
$resourceGroup = '<resource-group>'
$clusterName = '<cluster-name>'
$customLocationId = Get-CustomLocationIdForCluster -ClusterName $clusterName -SubscriptionId $SubscriptionId -ResourceGroup $resourceGroup

New-AzureLocalLogicalNetwork -NetworkName "lnet-dhcp-500" -SubscriptionId $SubscriptionId -ResourceGroup $resourceGroup -CustomLocationId $customLocationId -VirtualSwitchName 'ConvergedSwitch(compute_management)' -IpAllocationMethod 'Dynamic' -vlanId "500"

New-AzureLocalVM -VMName "TestVM-01" -SubscriptionId $SubscriptionId -ResourceGroup $resourceGroup -CustomLocationId $customLocationId -NicName "TestVM01-nic" -VMSize "Standard_D2s_v3" -VMImage "2022-datacenter-azure-edition-01" -AdminUsername "vmadmin" -KeyVaultSecretId "https://alcss15cl-hcikv.vault.azure.net/secrets/vmpassword"
New-AzureLocalVM -VMName "TestVM-02" -SubscriptionId $SubscriptionId -ResourceGroup $resourceGroup -CustomLocationId $customLocationId -NicName "TestVM02-nic" -VMSize "Standard_D2s_v3" -VMImage "2022-datacenter-azure-edition-01" -AdminUsername "vmadmin" -KeyVaultSecretId "https://alcss15cl-hcikv.vault.azure.net/secrets/vmpassword"

$vhdSetPath = New-HyperVVHDSet -TargetCluster $clusterName -ClusterSharedVolume "C:\ClusterStorage\UserStorage_1\VHDs" -VHDName "SQLSharedDisk01.vhds" -VHDSizeGB 20 -VHDType Dynamic

Add-VHDSetToAzureLocalVM -TargetCluster $clusterName -VMNames @("TestVM-01", "TestVM-02") -VHDSetPath $vhdSetPath -ControllerType SCSI -ControllerNumber 0 -ControllerLocation -1

#Add a 100GB dynamic data disk
Add-AzureLocalVMDataDisk -VMName "TestVM-01" -SubscriptionId $subscriptionId -ResourceGroup $resourceGroup -DiskName "TestVM-01-datadisk01" -DiskSizeGB 100 -Dynamic -CustomLocationId $customLocationId

# Remove a data disk from a VM
Remove-AzureLocalVMDataDisk -VMName "TestVM-01" -SubscriptionId $subscriptionId -ResourceGroup $resourceGroup -DiskName "TestVM-01-datadisk01" -DeleteDisk

# Remove a VM
Remove-AzureLocalVM -VMName "TestVM-02" -SubscriptionId $subscriptionId -ResourceGroup $resourceGroup -Force
````

## Available Functions

### Helper Functions

- `Write-Log` - Write timestamped, colored log messages
- `Invoke-WithRetry` - Execute commands with retry logic
- `Test-Prerequisites` - Validate PowerShell version, Az modules, and authentication

### Azure Local Functions

- `Get-CustomLocationIdForCluster` - Retrieve custom location from cluster name
- `Test-AzureLocalLogicalNetwork` - Check if logical network exists
- `Test-AzureLocalVMImage` - Validate VM image availability with optional marketplace download prompt
- `New-AzureLocalLogicalNetwork` - Create logical networks (Static or Dynamic)
- `New-AzureLocalVNIC` - Create virtual network interfaces (now created automatically during VM creation)
- `New-AzureLocalVM` - Create virtual machines with interactive image download from marketplace (supports Azure CLI for reliable downloads)
- `Get-CSVWithMostFreeSpace` - Find CSV with most free space on cluster
- `New-HyperVVHDSet` - Create shared VHD Sets
- `Add-VHDSetToAzureLocalVM` - Attach VHD Sets to VMs (supports cluster-wide VM discovery)
- `Add-AzureLocalVMDataDisk` - Add data disks to existing VMs using Azure control plane
- `Remove-AzureLocalVMDataDisk` - Remove data disks from VMs (optionally delete the disk)
- `Remove-AzureLocalVM` - Delete Azure Local VMs using Azure control plane

## Usage Examples

### Get Custom Location ID for an Azure Local instance

```powershell
$customLocation = Get-CustomLocationIdForCluster `
    -ClusterName "myCluster" `
    -SubscriptionId "12345-..." `
    -ResourceGroup "myRG"
```

### Create a Logical Network

#### Static IP Allocation (with address pool)

```powershell
New-AzureLocalLogicalNetwork `
    -NetworkName "myVM-network" `
    -SubscriptionId "12345-..." `
    -ResourceGroup "myRG" `
    -CustomLocationId "/subscriptions/.../customLocations/..." `
    -VirtualSwitchName "ConvergedSwitch(compute_management)" `
    -IpAllocationMethod Static `
    -AddressPrefix "10.0.0.0/24" `
    -DnsServers "10.0.0.1,10.0.0.2" `
    -DefaultGateway "10.0.0.1"
```

#### Dynamic IP Allocation (DHCP)

```powershell
New-AzureLocalLogicalNetwork `
    -NetworkName "dhcp-network" `
    -SubscriptionId "12345-..." `
    -ResourceGroup "myRG" `
    -CustomLocationId "/subscriptions/.../customLocations/..." `
    -VirtualSwitchName "ConvergedSwitch(compute_management)" `
    -IpAllocationMethod Dynamic
```

### Create a Virtual Network Interface

**Note:** Virtual network interfaces are now created automatically during VM creation. You typically don't need to call this function directly unless creating NICs for other purposes.

```powershell
New-AzureLocalVNIC `
    -NicName "myVM01-nic" `
    -SubscriptionId "12345-..." `
    -ResourceGroup "myRG" `
    -CustomLocationId "/subscriptions/.../customLocations/..." `
    -LogicalNetworkName "myVM-network"
```

### Create a Virtual Machine

#### Using Admin Password

```powershell
$adminPassword = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force

New-AzureLocalVM `
    -VMName "myVM01" `
    -SubscriptionId "12345-..." `
    -ResourceGroup "myRG" `
    -CustomLocationId "/subscriptions/.../customLocations/..." `
    -NicName "myVM01-nic" `
    -VMSize "Standard_D2s_v3" `
    -VMImage "Windows Server 2022 Datacenter: Azure Edition" `
    -AdminUsername "admin" `
    -AdminPassword $adminPassword
```

**Note:** If the specified VM image doesn't exist, you'll be prompted to download it from Azure Marketplace:

```text
[2025-12-03 ...] [Warning] VM image not found: Windows Server 2022 Datacenter: Azure Edition
[2025-12-03 ...] [Info] Available images in resource group:
[2025-12-03 ...] [Info]   [1] Ubuntu Server 20.04 LTS
Would you like to download an image from Azure Marketplace? (Y/N): Y
[2025-12-03 ...] [Info] Available marketplace images:
[2025-12-03 ...] [Info]   [1] Windows Server 2022 Datacenter: Azure Edition
[2025-12-03 ...] [Info]   [2] Windows Server 2022 Datacenter: Azure Edition Hotpatch - Gen2
[2025-12-03 ...] [Info]   [3] Windows Server 2019 Datacenter
[2025-12-03 ...] [Info]   [4] Ubuntu Server 22.04 LTS
[2025-12-03 ...] [Info]   [5] Ubuntu Server 20.04 LTS
[2025-12-03 ...] [Info]   [0] Cancel
Select an image to download (enter number): 1
[2025-12-03 ...] [Info] Downloading image: Windows Server 2022 Datacenter: Azure Edition
[2025-12-03 ...] [Success] Successfully initiated image download
```

#### Using Azure Key Vault Secret

```powershell
# Store password in Key Vault (one-time setup)
$password = Read-Host -Prompt "Enter VM admin password" -AsSecureString
Set-AzKeyVaultSecret -VaultName "myKeyVault" -Name "vmadminpassword" -SecretValue $password

# Create VM using Key Vault secret
New-AzureLocalVM `
    -VMName "myVM01" `
    -SubscriptionId "12345-..." `
    -ResourceGroup "myRG" `
    -CustomLocationId "/subscriptions/.../customLocations/..." `
    -NicName "myVM01-nic" `
    -VMSize "Standard_D2s_v3" `
    -VMImage "Windows Server 2022 Datacenter: Azure Edition" `
    -AdminUsername "admin" `
    -KeyVaultSecretId "https://myKeyVault.vault.azure.net/secrets/vmadminpassword"
```

### Create Shared VHD Set

`-ClusterSharedVolume` is optional. If not specified, the function will identify the CSV with the most free space.

```powershell
# Let function auto-select CSV
$vhdSetPath = New-HyperVVHDSet `
    -TargetCluster "myCluster" `
    -VHDName "sql-shared-disk.vhds" `
    -VHDSizeGB 500 `
    -VHDType "Dynamic"

# Or specify a specific CSV path
$vhdSetPath = New-HyperVVHDSet `
    -TargetCluster "myCluster" `
    -ClusterSharedVolume "C:\ClusterStorage\UserStorage_1\VHDs" `
    -VHDName "sql-shared-disk.vhds" `
    -VHDSizeGB 500 `
    -VHDType "Dynamic"
```

### Attach VHD Set to VMs

The function automatically discovers VMs across the cluster and attaches the shared disk to the correct cluster node where each VM is running.

**Important:** VM names must not contain underscores. Use hyphens instead (e.g., `TestVM-01` not `TestVM_01`).

```powershell
# Using path from New-HyperVVHDSet
$vhdSetPath = New-HyperVVHDSet -TargetCluster "myCluster" -VHDName "shared-disk.vhds" -VHDSizeGB 100
Add-VHDSetToAzureLocalVM `
    -TargetCluster "myCluster" `
    -VMNames @("TestVM-01", "TestVM-02") `
    -VHDSetPath $vhdSetPath `
    -ControllerType "SCSI" `
    -ControllerNumber 0 `
    -ControllerLocation -1  # -1 = auto-select next available location

# Using explicit local path
Add-VHDSetToAzureLocalVM `
    -TargetCluster "myCluster" `
    -VMNames @("TestVM-01", "TestVM-02") `
    -VHDSetPath "C:\ClusterStorage\Volume1\shared-disk.vhds" `
    -ControllerType "SCSI" `
    -ControllerNumber 0 `
    -ControllerLocation -1
```

### Add Data Disk to Existing VM

Add data disks to existing Azure Local VMs using the Azure control plane (recommended method).

```powershell
# Add a 100GB dynamic data disk
Add-AzureLocalVMDataDisk `
    -VMName "TestVM-01" `
    -SubscriptionId "12345-..." `
    -ResourceGroup "myRG" `
    -CustomLocationId "/subscriptions/.../customLocations/..." `
    -DiskName "TestVM-01-datadisk01" `
    -DiskSizeGB 100 `
    -Dynamic

# Add a 500GB fixed data disk
Add-AzureLocalVMDataDisk `
    -VMName "TestVM-01" `
    -SubscriptionId "12345-..." `
    -ResourceGroup "myRG" `
    -CustomLocationId "/subscriptions/.../customLocations/..." `
    -DiskName "TestVM-01-datadisk02" `
    -DiskSizeGB 500

# Add disk with specific storage path
Add-AzureLocalVMDataDisk `
    -VMName "TestVM-01" `
    -SubscriptionId "12345-..." `
    -ResourceGroup "myRG" `
    -CustomLocationId "/subscriptions/.../customLocations/..." `
    -DiskName "TestVM-01-datadisk03" `
    -DiskSizeGB 200 `
    -StoragePathId "/subscriptions/.../storageContainers/..." `
    -Dynamic
```

### Remove Data Disk from Existing VM

Remove data disks from Azure Local VMs using the Azure control plane.

```powershell
# Detach a data disk (keeps the disk resource)
Remove-AzureLocalVMDataDisk `
    -VMName "TestVM-01" `
    -SubscriptionId "12345-..." `
    -ResourceGroup "myRG" `
    -DiskName "TestVM-01-datadisk01"

# Detach and delete a data disk
Remove-AzureLocalVMDataDisk `
    -VMName "TestVM-01" `
    -SubscriptionId "12345-..." `
    -ResourceGroup "myRG" `
    -DiskName "TestVM-01-datadisk01" `
    -DeleteDisk

# Remove disk by ID
Remove-AzureLocalVMDataDisk `
    -VMName "TestVM-01" `
    -SubscriptionId "12345-..." `
    -ResourceGroup "myRG" `
    -DiskId "/subscriptions/.../virtualHardDisks/TestVM-01-datadisk01" `
    -DeleteDisk
```

### Remove Azure Local VM

Delete Azure Local VMs using the Azure control plane.

```powershell
# Remove a VM (with confirmation prompt)
Remove-AzureLocalVM `
    -VMName "TestVM-01" `
    -SubscriptionId "12345-..." `
    -ResourceGroup "myRG"

# Remove a VM without confirmation
Remove-AzureLocalVM `
    -VMName "TestVM-01" `
    -SubscriptionId "12345-..." `
    -ResourceGroup "myRG" `
    -Force
```

## Requirements

- PowerShell 5.1 or later
- Az PowerShell modules: Az.StackHCIVM, Az.CustomLocation, Az.Accounts, Az.KeyVault (authenticated with `Connect-AzAccount`)
- **Optional but recommended:** Azure CLI for reliable marketplace image downloads
- Appropriate Azure permissions within the Subscription
- Appropriate permissions to the Azure Local cluster / nodes

## Important Notes

- **VM Naming:** VM names cannot contain underscores. Use hyphens instead (e.g., `TestVM-01` not `TestVM_01`)
- **vNIC Creation:** Virtual network interfaces are now created automatically during VM creation
- **Marketplace Images:** If Azure CLI is installed, it will be used for more reliable marketplace image downloads. Otherwise, REST API is used as a fallback
- **Shared Disks:** VHD Sets are automatically attached to the correct cluster node where each VM is running

## Author

Neil Bird, PM in Azure Edge Infra team at Microsoft.
