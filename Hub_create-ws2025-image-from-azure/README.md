> **Disclaimer:** This is provided as an **example only** and is **not a supported service offering**. It is provided under the [MIT License](https://opensource.org/licenses/MIT) on an **"as-is" basis, without warranty of any kind**, express or implied. Use at your own risk.

# Windows Server 2025 Image for Azure Stack Hub

Scripts to download a **Windows Server 2025 Datacenter** GEN1 VHD from the Azure Marketplace and register it as a platform image in **Azure Stack Hub**.

## Overview

Azure Stack Hub operators who cannot use the built-in Marketplace syndication (e.g., disconnected or partially-connected environments) can use these scripts to manually obtain and import the WS2025 image.

### Workflow

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│  PUBLIC AZURE                                                                   │
│                                                                                 │
│  Step 1 ─ Install Az & AzureStack PowerShell modules                            │
│                                                                                 │
│  Step 2 ─ Log in via Azure CLI (device-code flow)                               │
│           Query Marketplace for latest WS2025 Gen1 image URN                    │
│                                                                                 │
│  Step 3 ─ Create a temporary managed disk from the Marketplace image            │
│           Grant read access → generate SAS URL                                  │
│           Download the VHD to the local machine using AzCopy                    │
│           Revoke disk access                                                    │
│                              │                                                  │
└──────────────────────────────┼──────────────────────────────────────────────────┘
                               │  Save VHD file on local disk, and transfer
                               ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  AZURE STACK HUB (Admin ARM Endpoint)                                           │
│                                                                                 │
│  Step 4 ─ Register the Hub environment & connect as Service Admin               │
│                                                                                 │
│  Step 5 ─ Create a storage account on the Hub Admin                             │
│           Upload the VHD with Add-AzVhd                                         │
│                                                                                 │
│  Step 6 ─ Register the VHD as a platform image (Add-AzsPlatformImage)           │
│           Verify the image appears in the Hub Marketplace                       │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

| Step | Environment | What happens | Tools used |
|------|-------------|-------------|------------|
| **1** | Local machine | Installs the required PowerShell modules (`Az` 2020-09-01-hybrid profile, `AzureStack 2.4.0`). | `Install-Module` |
| **2** | Public Azure | Logs in via Azure CLI with device-code auth, then queries the Marketplace for the latest **Windows Server 2025 Datacenter Gen1** image URN (excluding Gen2 & Upgrade SKUs). | `az login`, `az vm image list` |
| **3** | Public Azure → Local | Creates a temporary **managed disk** from the Marketplace image, grants read access to obtain a SAS URL, and downloads the disk as a fixed-size VHD using **AzCopy v10**. Revokes disk access when done. | `az disk create`, `az disk grant-access`, AzCopy |
| **4** | Azure Stack Hub | Registers the Hub's Admin ARM endpoint as a PowerShell environment and authenticates as the **Service Admin**. | `Add-AzEnvironment`, `Connect-AzAccount` |
| **5** | Azure Stack Hub | Creates a resource group and storage account on the Hub, then uploads the local VHD using `Add-AzVhd`. | `New-AzStorageAccount`, `Add-AzVhd` |
| **6** | Azure Stack Hub | Registers the uploaded VHD as a **platform image** (publisher: `MicrosoftWindowsServer`, offer: `WindowsServer`, SKU: `2025-Datacenter`) and verifies it is available in the Hub Marketplace for tenant use. | `Add-AzsPlatformImage`, `Get-AzsPlatformImage` |

## Prerequisites

| Requirement | Details |
|---|---|
| **OS** | Windows (scripts use PowerShell 5.1+) |
| **Azure CLI** | Required for marketplace image discovery and disk operations. Install with `_Pre-req_Install_AzCLI.ps1`. |
| **Azure subscription** | Needed temporarily to create a managed disk from the marketplace image. |
| **Azure Stack Hub admin access** | Service Admin credentials and the Admin ARM endpoint. |
| **Disk space** | ~30 GB for the full-disk VHD, ~10 GB for small-disk. |
| **PowerShell modules** | Installed automatically by the script: `Az` (2020-09-01-hybrid profile), `AzureStack 2.4.0`. |

## Scripts

### `_Pre-req_Install_AzCLI.ps1`

Installs Azure CLI on Windows and adds it to the system PATH. Run this first if Azure CLI is not already installed.

```powershell
# Run as Administrator
.\_Pre-req_Install_AzCLI.ps1
```

### `Hub_WS2025-create-image-from-Azure.ps1`

Main script that performs the full end-to-end workflow. **Before running**, open the script and update the parameters in the `PARAMETERS` section at the top:

| Parameter | Description | Example |
|---|---|---|
| `$AzureResourceGroup` | Temp resource group in Azure for the managed disk | `ws2025-image-rg` |
| `$VhdDownloadPath` | Local path to save the VHD | `C:\VHDs\WS2025-datacenter.vhd` |
| `$AdminArmEndpoint` | Azure Stack Hub admin ARM endpoint | `https://adminmanagement.local.azurestack.external` |
| `$TenantID` | Azure AD tenant ID | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| `$HubLocation` | Azure Stack Hub region name | `local` |
| `$StorageEndpointDnsSuffix` | External domain suffix | `local.azurestack.external` |
| `$ServiceAdminUserName` | Service admin UPN | `admin@contoso.onmicrosoft.com` |
| `$HubResourceGroup` | Resource group on the Hub for storage | `ws2025-image-rg` |
| `$HubStorageAccountName` | Storage account name on the Hub | `ws2025vhds` |

```powershell
# Run as Administrator
.\Hub_WS2025-create-image-from-Azure.ps1
```

The script will prompt for the service admin password interactively.

## VM Licensing: Windows Server on Azure Stack Hub

The `LicenseType` ARM property is set **per-VM** at deployment time — it is **not** part of the platform image.

> **Note:** Azure Stack Hub is considered **on-premises hardware** for licensing purposes. Azure Hybrid Use Benefit (AHUB) is **not required** to use your own Windows Server licenses on Azure Stack Hub (see the [Azure Stack Hub Licensing Guide](https://go.microsoft.com/fwlink/?LinkId=2273601&clcid=0x409) FAQ).

### Pay-as-you-use billing model

In the pay-as-you-use model, Azure Stack Hub meters each VM and reports usage to Azure Commerce. The `LicenseType` property controls which meter is used:

| `LicenseType` value | Meter used | When to use |
|---|---|---|
| *Not set* (default) | **Windows Server VM meter** — Windows license cost is included in the per-vCPU/min rate. | You do not have your own Windows Server licenses. |
| `"Windows_Server"` | **Base VM meter** only — lower rate, no Windows license cost included. | You are bringing your own on-premises Windows Server licenses covering all physical cores in the Azure Stack Hub region. |

**Default (Windows Server PAYG VM meter):**

```powershell
# No LicenseType — Windows license included in billing
New-AzVM -ResourceGroupName "myRG" -Name "myVM" `
    -Image "MicrosoftWindowsServer:WindowsServer:2025-Datacenter:latest" `
    -Location "local" `
    -Credential (Get-Credential)
```

**Using your own Windows Server license (Base VM meter):**

```powershell
# LicenseType = "Windows_Server" — bring your own license, billed at Base VM rate
New-AzVM -ResourceGroupName "myRG" -Name "myVM" `
    -Image "MicrosoftWindowsServer:WindowsServer:2025-Datacenter:latest" `
    -LicenseType "Windows_Server" `
    -Location "local" `
    -Credential (Get-Credential)
```

**ARM Template (under `Microsoft.Compute/virtualMachines` properties):**

```json
{
  "type": "Microsoft.Compute/virtualMachines",
  "properties": {
    "licenseType": "Windows_Server",
    ...
  }
}
```

**Update an existing VM:**

```powershell
$vm = Get-AzVM -ResourceGroupName "myRG" -Name "myVM"
$vm.LicenseType = "Windows_Server"
Update-AzVM -ResourceGroupName "myRG" -VM $vm
```

> **Important:** When bringing your own Windows Server licenses, you must have enough Windows Server core licenses (Datacenter recommended) to cover **all physical cores** in the Azure Stack Hub region, regardless of how many Windows Server VMs are actually deployed.

### Capacity billing model

In the capacity model, Windows Server guest licenses are **not included** in the annual per-core subscription fee. You must have separate Windows Server Volume Licensing (VL) licenses covering all physical cores in the Azure Stack Hub region. The `LicenseType` property has no billing effect in this model since usage is not reported to Azure Commerce.

For official information, refer to the [Azure Stack Hub Licensing, Packaging & Pricing Guide](https://go.microsoft.com/fwlink/?LinkId=2273601&clcid=0x409).

## Windows Server 2025 Activation on Azure Stack Hub

**KMS activation is required** for Windows Server 2025 guest VMs on Azure Stack Hub. Automatic Virtual Machine Activation (AVMA) is **not compatible** with Windows Server 2025 guests on Azure Stack Hub.

Ensure your environment has access to a KMS host (e.g., an on-premises KMS server or the Azure Stack Hub infrastructure KMS endpoint) so that WS2025 VMs can activate after deployment.

> **Important — KMS is activation, not licensing:** Using KMS to activate Windows Server 2025 VMs does **not** remove or bypass the requirement to properly license Windows Server for the underlying physical CPU cores in the Azure Stack Hub scale unit. KMS is only an **activation mechanism** — it confirms the OS is genuine and enables full functionality, but it does not grant a license entitlement. You must still hold valid Windows Server licenses (e.g., Datacenter or Standard with Software Assurance) that cover every physical core in the scale unit, per your licensing agreement.

## Notes

- The script downloads **AzCopy v10** automatically — no manual installation needed.
- Only **Gen1** (non-Gen2) images are selected, as Azure Stack Hub requires Gen1 VHDs.
- After the image is registered, it appears in the Azure Stack Hub Marketplace and can be used by tenant subscriptions to create VMs.
- To clean up the temporary Azure resources after the VHD is downloaded, delete the resource group specified in `$AzureResourceGroup`.

## License

MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

**THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.**
