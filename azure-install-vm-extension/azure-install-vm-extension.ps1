##########################################################################################################
<#
.SYNOPSIS
    Automates the installation of VM Extensions on VMs in an Azure Subscription.
    Performs checks to ensure VM is in the correct state to install an extension.
    
.DESCRIPTION
    Script framework to install Extensions on All of the VMs in a subscription.
    The Extension "Type" and "Publisher" are specified as parameters.
    
    If these parameters are NOT specified at execution, the script defaults to installing the "BGInfo" Extension on Windows VMs.

    The script performs the following checks to ensure a VM is in the "correct state" to install the extension:

        1) VM is Running (NOT deallocated / stopped).
        2) VM is using an Operating System that is compatible with the Extension (configured as parameters).
        3) VM does not currently have the extension installed.

.PARAMETER SubscriptionName
   Mandatory parameter. This can be configured in the script Params section or by passing as a pipeline parameter.

   The Name of the Azure Subscription you wish to process. 

.PARAMETER VMExtensionName 
   Mandatory parameter with default of "BGInfo".

   The Name (Type) of the VM Extension you wish to install. 
   
   This parameter is Case Sensitive, due to the comparison used to test if the Extension is already installed.
   
   The PowerShell code below can be used to obtain a full list of the VM Extensions that are available in an Azure region.

        # Edit the $location variable with your target region
        [string]$location = "uksouth"
        Get-AzureRmVmImagePublisher -Location $location | `
        Get-AzureRmVMExtensionImageType | `
        Get-AzureRmVMExtensionImage | Select Type, PublisherName | ft *

.PARAMETER VMExtensionPublisher 
   Mandatory parameter with default of "Microsoft.Compute".

   The Publisher of the VM Extension you wish to install.

.PARAMETER ProcessAllVMs
    Include this parameter if you would like to "Process ALL VMs in the subscription".

    If this parameter is NOT included the script will only process the first 3 x VMs in the subscription.

    This is a safety measure to prevent unintentionally installing the Extension on ALL VMs.

.LINK
    https://blogs.technet.microsoft.com/ukplatforms/2017/07/31/azure-resource-manager-arm-automate-installation-of-vm-extensions-using-powershell-and-json

.EXAMPLE
    .\azure-install-vm-extension.ps1 -SubscriptionName "Visual Studio Enterprise"
    
    Installs the default VM Extension configured in the script parameters (BGInfo) on first 3 x Windows VMs in the "Visual Studio Enterprise" subscription.

.EXAMPLE
    .\azure-install-vm-extension.ps1 -SubscriptionName "Visual Studio Enterprise" -ProcessAllVMs
    
    Installs the default VM Extension configured in the script parameters (BGInfo) on ALL of the Windows VMs in the "Visual Studio Enterprise" subscription.

.EXAMPLE
    .\azure-install-vm-extension.ps1 -SubscriptionName "Visual Studio Enterprise" `
                                     -VMExtensionName "IaaSAntimalware" `
                                     -VMExtensionPublisher "Microsoft.Azure.Security" `
                                     -VMExtensionWindowsCompatible $true `
                                     -VMExtensionLinuxCompatible $false `
                                     -VMExtensionSettingsFilePath "C:\scripts\IaaSAntimalware-Config.json" `
                                     -ProcessAllVMs

    Installs the "IaaSAntimalware" VM Extension on ALL of the Windows VMs in the "Visual Studio Enterprise" subscription.

    Configures the "IaaSAntimalware" Extension settings using the configuration in the "C:\scripts\IaaSAntimalware-Config.json" file.

    Example JSON Schema for "Microsoft Antimalware" Extension, "C:\scripts\IaaSAntimalware-Config.json" file:

        {
            "AntimalwareEnabled": true,
            "RealtimeProtectionEnabled": true,
            "ScheduledScanSettings": {
                "isEnabled": true,
                "day": "7",
                "time": "120",
                "scanType": "Quick"
            },
            "Exclusions": {
                "Extensions": "",
                "Paths": "%windir%\\SoftwareDistribution\\Datastore\\DataStore.edb;%windir%\\SoftwareDistribution\\Datastore\\Logs\\Edb.chk",
                "Processes": ""
            }
        }
    
    For full details on how to configure the "Microsoft Antimalware Extension" settings including file exclusions, see the following article: 
    
    "Microsoft Antimalware for Azure Cloud Services and Virtual Machines"
    (https://docs.microsoft.com/enus/azure/security/azure-security-antimalware)

.NOTES
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
##########################################################################################################

###############################
## SCRIPT OPTIONS & PARAMETERS
###############################

#Requires -Version 3
#Requires -Modules AzureRM

#Version: 1.2
<# - 03/08/2017
     * improvements to Add-AzureRMAccount process to "detect" if an existing session is valid.
     * added a function to Try / Catch errors with Azure Auth and Subscription selection.

   Version 1.1
   - 28/07/2017
     * added progress bar and confirmation prompt.
     * added "-ProcessAllVMs" switch, without this script only processes 3 x VMs by default.
     * added parameter to specify a "SettingString" configuration file for Extension settings.
     * added counters to provide an "installation results" report when the script completes.  

   Version: 1.0
   - 14/07/2017
     * initial script creation.

#>

# Define and validate mandatory parameters
[CmdletBinding()]
Param(
	  # Azure Subscription Name
	  [parameter(Position=1)]
	  [string]$SubscriptionName = "SUBSCRIPTION NAME",
	  # ***** EDIT ABOVE WITH YOUR SUBSCRIPTION NAME, OR PASS AS SCRIPT PARAMETER *****
	  
	  # VM Extension Name (Case sensitive for "Extensions.id.Contains" comparison)
	  [parameter(Position=2)]
	  [string]$VMExtensionName = "BGInfo",

	  # VM Extension Publisher
	  [parameter(Position=3)]
	  [string]$VMExtensionPublisher = "Microsoft.Compute",

	  # VM Extension Windows OS Compatible
	  [parameter(Position=4)]
	  [bool]$VMExtensionWindowsCompatible = $true,

	  # VM Extension Linux OS Compatible
	  [parameter(Position=5)]
      [bool]$VMExtensionLinuxCompatible = $false,

	  # VM Extension JSON Settings File Path
	  [parameter(Position=6)]
	  [string]$VMExtensionSettingsFilePath = "",

      # Process All VMs in Subscription Switch, if not present script only processes first 3 VMs
      [parameter(Position=7)]
      [switch]$ProcessAllVMs
	)

# Set strict mode to identify typographical errors
Set-StrictMode -Version Latest

# Make the script verbose by default
$VerbosePreference = "Continue"

##########################################################################################################

#######################################
## FUNCTION 1 - Get-Azure-PSConnection
#######################################

Function Get-Azure-PSConnection {

    
    # Ensure $SubscriptionName Parameter has been Passed or edited in the script Params.
    if($SubscriptionName -eq "SUBSCRIPTION NAME") {
    
        Try {

            $AzureRMContext = (Get-AzureRmSubscription -ErrorAction Stop | Out-GridView `
            -Title "Select a Subscription/Tenant ID for $($VMExtensionName) Extension Deployment..." `
            -PassThru)
            
            Try {
                Set-AzureRmContext -TenantId $AzureRMContext.TenantID -SubscriptionName $AzureRMContext.Name -ErrorAction Stop -WarningAction Stop    
            } Catch [System.Management.Automation.PSInvalidOperationException] {
                Write-Error "Error: $($error[0].Exception)"
                Exit
            }

        } Catch {
            
            # If not logged into Azure
            if($error[0].Exception.ToString().Contains("Run Login-AzureRmAccount to login.")) {
                    
                # Login to Azure
                Add-AzureRMAccount -ErrorAction Stop
                
                # Show Out-GridView for a pick list of Tenants / Subscriptions
                $AzureRMContext = (Get-AzureRmSubscription -ErrorAction Stop | Out-GridView `
                -Title "Select a Subscription/Tenant ID for $($VMExtensionName) Extension Deployment..." `
                -PassThru)
                
                Try {
                    Set-AzureRmContext -TenantId $AzureRMContext.TenantID -SubscriptionName $AzureRMContext.Name -ErrorAction Stop -WarningAction Stop    
                } Catch [System.Management.Automation.PSInvalidOperationException] {
                    Write-Error "Error: $($error[0].Exception)"
                    Exit
                }

            } else { # EndIf Not Logged In
    
                Write-Error "Error: $($error[0].Exception)"
                Exit

            }
        }
    
    } else { # $SubscriptionName has been set
    
        # Check if we are already logged into Azure...
        Try {
                
            # Set Azure RM Context to -SubscriptionName, On Error Continue, so we can Catch the Error.
            Set-AzureRmContext -SubscriptionName $SubscriptionName -WarningAction Stop -ErrorAction Stop
    
        } Catch [System.Management.Automation.PSInvalidOperationException] {
    
            # If not logged into Azure
            if($error[0].Exception.ToString().Contains("Run Login-AzureRmAccount to login.")) {

                # Connect to Azure, as no existing connection.
                Write-Host "`nPrompting for Azure Credentials and Authenticating..."
    
                # Login to Azure Resource Manager (ARM), if this fails, stop script.
                try {
                    Add-AzureRmAccount -SubscriptionName $SubscriptionName -ErrorAction Stop
                } catch {

                    Write-Host -ForegroundColor Red "Error: Unable to access Azure Subscription: '$($SubscriptionName)', please check this is the correct name and/or that your account has access.`n"
                    Write-Host "`nDisplaying GUI to select the correct subscription...."
                    
                    Add-AzureRMAccount -ErrorAction Stop
                    
                    $AzureRMContext = (Get-AzureRmSubscription -ErrorAction Stop | Out-GridView `
                    -Title "Select a Subscription/Tenant ID for $($VMExtensionName) Extension Deployment..." `
                    -PassThru)

                    Try {
                        Set-AzureRmContext -TenantId $AzureRMContext.TenantID -SubscriptionName $AzureRMContext.Name -ErrorAction Stop -WarningAction Stop    
                    } Catch [System.Management.Automation.PSInvalidOperationException] {
                        Write-Error "Error: $($error[0].Exception)"
                        Exit
                    }                  
                }

    
            # Already logged into Azure, but Subscription does NOT exist.
            } elseif($error[0].Exception.ToString().Contains("does not exist")) {
                
                Write-Host -ForegroundColor Red "Error: You are logged into Azure with account: '$((Get-AzureRmContext).Account.id)', but the Subscription: '$($SubscriptionName)' does not exist, or this account does not have access to it.`n"
                
                Write-Host "`nDisplaying GUI to select the correct subscription...."
                $AzureRMContext = (Get-AzureRmSubscription -ErrorAction Stop | Out-GridView `
                -Title "Select a Subscription/Tenant ID for $($VMExtensionName) Extension Deployment..." `
                -PassThru)
    
                Try {
                    Set-AzureRmContext -TenantId $AzureRMContext.TenantID -SubscriptionName $AzureRMContext.Name -ErrorAction Stop -WarningAction Stop    
                } Catch [System.Management.Automation.PSInvalidOperationException] {
                    Write-Error "Error: $($error[0].Exception)"
                    Exit
                }     
                
            # Already authenticated with Azure, but does not have access to subscription.
            } elseif($error[0].Exception.ToString().Contains("does not have access to subscription name")) {
    
                Write-Host -ForegroundColor Red "Error: Unable to access Azure Subscription: '$($SubscriptionName)', please check this is the correct name and/or that account '$((Get-AzureRmContext).Account.id)' has access.`n"
                Exit
    
            # All other errors.
            } else {
            
                Write-Error "Error: $($error[0].Exception)"
                Exit
    
            } # EndIf Checking for $error[0] conditions
    
        } # End Catch
    
    } # EndIf $SubscriptionName has been set
    
    # Successfully logged into AzureRM
    Write-Host "SUCCESS: " -ForegroundColor Green -nonewline; `
    Write-host "Logged into Azure using Account ID: " -NoNewline; `
    Write-Host (Get-AzureRmContext).Account.Id -ForegroundColor Green
    Write-Host "Subscription Name: "  -NoNewline; `
    Write-Host (Get-AzureRmContext).Subscription.Name -ForegroundColor Green
    Write-Host "Subscription ID: "  -NoNewline; `
    Write-Host (Get-AzureRmContext).Subscription.Id "`n" -ForegroundColor Green

} # End of function Login-To-Azure


#######################################
## FUNCTION 2 - Install-VMExtension
#######################################

Function Install-VMExtension {

    # Get all ARM VMs in the Subscription
    [array]$VMs = Get-AzureRMVM -Status -ErrorAction Stop

    # Counter for Progress bar and $ProcessAllVMs switch
    $VMsProcessed = 0
        
    # Loop through all VMs in the Subscription
    ForEach ($VM in $VMs) {

        # Check if the ProcessAllVMs switch has NOT been set
        if(!$ProcessAllVMs.IsPresent) {

            # We are NOT Processing All VMs (switch NOT present), stop after first 3 x VMs 
            if($VMsProcessed -eq 3) {

                # Write informational message about use of the -ProcessAllVMs switch
                Write-Host "`nINFO: Script Stopping."
                Write-Host 'INFO: To process more than the first 3 x VMs in a subscription, Set the -ProcessAllVMs parameter when executing the script.'
                # Break out of the ForEach Loop to stop processing
                Break
            }
        }

        # Show the Progress bar for number of VMs Processed...
        $VMsProcessed++    
        Write-Progress -Activity "Processing VMs in Subscription: ""$($SubscriptionName)""..." `
        -Status "Processed: $VMsProcessed of $($VMs.count)" `
        -PercentComplete (($VMsProcessed / $VMs.Count)*100)
        
        # Ensure the VM OS is Compatible with Extension
        if(($VM.OSProfile.WindowsConfiguration -and $VMExtensionWindowsCompatible) `
        -or ($VM.OSProfile.LinuxConfiguration -and $VMExtensionLinuxCompatible)) {
        
            # Ensure the Extension is NOT already installed
            if(($VM.Extensions.count -eq 0) -or (!(Split-Path -Leaf $VM.Extensions.id).Contains($VMExtensionName))) {

                # If VM is Running
                if($VM.PowerState -eq 'VM running') {

                    # Output the VM Name
                    Write-Host "$($VM.Name): requires $($VMExtensionName), installing..."
                    
                    # Get the latest version of the Extension in the VM's Location:
                    [version]$ExtensionVersion = (Get-AzureRmVMExtensionImage -Location $VM.Location `
                    -PublisherName $VMExtensionPublisher -Type $VMExtensionName).Version `
                    | ForEach-Object { New-Object System.Version ($PSItem)} | `
                    Sort-Object -Descending | Select-Object -First 1
                    [string]$ExtensionVersionMajorMinor = "{0}.{1}" -F $ExtensionVersion.Major,$ExtensionVersion.Minor

                    # If the $VMExtensionSettingFilePath parameter has been specified and the file exists
                    if(($VMExtensionSettingsFilePath -ne "") -and (Test-Path $VMExtensionSettingsFilePath)) {
                                                
                        # Import Extension Config File
                        $VMExtensionConfigfile = Get-Content $VMExtensionSettingsFilePath -Raw
                        
                        # Install the Extension with SettingString parameter
                        $ExtensionInstallResult = Set-AzureRmVMExtension -ExtensionName $VMExtensionName `
                        -Publisher $VMExtensionPublisher -TypeHandlerVersion $ExtensionVersionMajorMinor -ExtensionType $VMExtensionName `
                        -Location $VM.Location -ResourceGroupName $VM.ResourceGroupName `
                        -SettingString $VMExtensionConfigfile -VMName $VM.Name

                    } else { # $VMExtensionSettingFilePath does NOT exist

                        # Install the Extension WITHOUT SettingString parameter
                        $ExtensionInstallResult = Set-AzureRmVMExtension -ExtensionName $VMExtensionName `
                        -Publisher $VMExtensionPublisher -TypeHandlerVersion $ExtensionVersionMajorMinor -ExtensionType $VMExtensionName `
                        -Location $VM.Location -ResourceGroupName $VM.ResourceGroupName `
                        -VMName $VM.Name

                    } # Install Extension with SettingString parameter if file specified and exists

                    # Installation finished, check the return status code
                    if($ExtensionInstallResult.IsSuccessStatusCode -eq $true) {

                        # Installation Succeeded
                        Write-Host "SUCCESS: " -ForegroundColor Green -nonewline; `
                        Write-host "$($VM.Name): Extension installed successfully"
                        $Global:SuccessCount++

                    } else {

                        # Installation Failed
                        Write-Host "ERROR: " -ForegroundColor Red -nonewline; `
                        Write-Host "$($VM.Name): Failed - Status Code: $($ExtensionInstallResult.StatusCode)"
                        $Global:FailedCount++
                    }

                } else {

                    # VM is NOT Running
                    Write-Host "WARN: " -ForegroundColor Yellow -nonewline; `
                    Write-Host "$($VM.Name): Unable to install $($VMExtensionName) - VM is NOT Running"
                    $Global:VMsNotRunningCount++
                    # Could use "Start-AzureRmVM -ResourceGroupName $vm.ResourceGroupName -Name $VM.Name",
                    # wait for VM to start and Install extension, possible improvement for future version.
                }

            } else {

                # VM already has the Extension installed.
                Write-Host "INFO: $($VM.Name): Already has the $($VMExtensionName) Extension Installed"
                $Global:AlreadyInstalledCount++
            }

            
        # Extension NOT Compatible with VM OS, as defined in Script Parameters boolean values
        } else {

            # Linux
            if($VM.OSProfile.LinuxConfiguration -and (!$VMExtensionLinuxCompatible)) {

                # VM is running Linux distro and $VMExtensionLinuxCompatible = $false
                Write-Host "INFO: $($VM.Name): Is running a Linux OS, extension $($VMExtensionName) is not compatible, skipping..."
                $Global:OSNotCompatibleCount++
            
            # Windows	
            } elseif ($VM.OSProfile.WindowsConfiguration -and (!$VMExtensionWindowsCompatible)) {

                # VM is running Windows $VMExtensionWindowsCompatible = $false
                Write-Host "INFO: $($VM.Name): Is running a Windows OS, extension $($VMExtensionName) is not compatible, skipping..."
                $Global:OSNotCompatibleCount++

            # Error VM does NOT have a Windows or Linux Configuration
            } else {

                # Unexpected condition, VM does not have a Windows or Linux Configuration
                Write-Host "ERROR: " -ForegroundColor Red -nonewline; `
                Write-Host "$($VM.Name): Does NOT have a Windows or Linux OSProfile!?"
                
            }

        } # Extension OS Compatibility

    } # ForEach VM Loop

} # End of Function Install-VMExtension

##########################################################################################################
# Script Start Location
##########################################################################################################

# Setup counters for Extension installation results
[double]$Global:SuccessCount = 0
[double]$Global:FailedCount = 0
[double]$Global:AlreadyInstalledCount = 0
[double]$Global:VMsNotRunningCount = 0
[double]$Global:OSNotCompatibleCount = 0

[string]$DateTimeNow = get-date -Format "dd/MM/yyyy - HH:mm:ss"
Write-Host "`n========================================================================`n"
Write-Host "$($DateTimeNow) - Install VM Extension Script Starting...`n"
Write-Host "========================================================================`n"

# Prompt for confirmation...
if($ProcessAllVMs.IsPresent) {
    [string]$VMTargetCount = "ALL of the"
} else {
    [string]$VMTargetCount = "the first 3 x"
}

# User prompt confirmation before processing
[string]$UserPromptMessage = "Do you want to install the ""$($VMExtensionName)"" Extension on $($VMTargetCount) VMs in the ""$($SubscriptionName)"" Subscription?"
if(!$ProcessAllVMs.IsPresent) {
    $UserPromptMessage = $UserPromptMessage + "`n`nNote: use the ""-ProcessAllVMs"" switch to install the Extension on ALL VMs."
}
$UserPromptMessage = $UserPromptMessage + "`n`nType ""yes"" to confirm....`n`n`t"
[string]$UserConfirmation = Read-Host -Prompt $UserPromptMessage
if($UserConfirmation.ToLower() -ne 'yes') {
    
    # Abort script, user reponse was NOT "yes"
    Write-Host "`nUser typed ""$($UserConfirmation)"", Aborting script...`n`n" -ForegroundColor Red
    Exit

} else {

    # Continue, user responded "yes" to confirm
    Write-Host "`nUser typed 'yes' to confirm...." -ForegroundColor Green
    Write-Host "Connecting to Azure...`n"

    # Call Function to Login To Azure
    Get-Azure-PSConnection

    # Call Function to Install Extension on VMs
    Install-VMExtension

}

# Add up all of the counters
[double]$TotalVMsProcessed = $Global:SuccessCount + $Global:FailedCount + $Global:AlreadyInstalledCount `
+ $Global:VMsNotRunningCount + $Global:OSNotCompatibleCount

# Output Extension Installation Results
Write-Host "`n"
Write-Host "========================================================================"
Write-Host "`tExtension $($VMExtensionName) - Installation Results`n"
Write-Host "Installation Successful:`t`t$($Global:SuccessCount)"
Write-Host "Already Installed:`t`t`t$($Global:AlreadyInstalledCount)"
Write-Host "Installation Failed:`t`t`t$($Global:FailedCount)"
Write-Host "VMs Not Running:`t`t`t$($Global:VMsNotRunningCount)"
Write-Host "Extension Not Compatible with OS:`t$($Global:OSNotCompatibleCount)`n"
Write-Host "Total VMs Processed:`t`t`t$($TotalVMsProcessed)"
Write-Host "========================================================================`n`n"

Write-Host "========================================================================`n"
[string]$DateTimeNow = get-date -Format "dd/MM/yyyy - HH:mm:ss"
Write-Host "$($DateTimeNow) - Install VM Extension Script Complete."
Write-Host "`n========================================================================"