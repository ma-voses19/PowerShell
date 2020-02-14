# Automate Config Mgr Software Update Deployment

Automate software deployments via PowerShell. This code creates the Software Update Group (SUG), adds update to the SUG, creates the deployment package, downloads the content and finally creates the deployment.

Script must be executed on a central administration site or primary site server of you Configuration Manager hierarchy

The following code aims to provide basics on how to fully deploy software updates, please use it as a base sample and modify where required.

```powershell
<#
    .NOTES
    ===========================================================================
     Created on:   Feb/12/2020
     Version :     1.0, Initial Release
     Created by:   Vinicio Oses
     Organization: System Center Configuration Manager Costa Rica
     Filename:     New-SUG.ps1
     ===========================================================================
     .DESCRIPTION
             Automate software deployments via PowerShell. This code creates the Software Update Group (SUG), 
             adds update to the SUG, creates the deployment package, downloads the content and finally creates the deployment.
             Script must be executed on a central administration site or primary site server of you Configuration Manager hierarchy
             The following code aims to provide basics on how to fully deploy software updates, please use it as a base sample and modify where required.
#>

#To find more information about the commands used, please visit https://docs.microsoft.com/en-us/powershell/sccm/overview?view=sccm-ps and consult them

#Define time range, the following sample is to limit for all updates delivered in May 2019
 
$DateMin = "05/01/2019"
 
$DateMax = "05/31/2019"
 
#The following definition generates the list of updates that you want to include on the updates list, make sure to modify it on the way that better serves your needs.
 
#Here is an example of a definition to:
# Exclude: Definition updates, x86 (x32), and Feature Updates
# Include: Server, 2016
 
$Query = (Get-CMSoftwareUpdate -Fast -DatePostedMin $DateMin -DatePostedMax $DateMax -IsSuperseded $False -IsExpired $False | `
Where-Object { ( $_.LocalizedDisplayName -notlike '*Defender*' ) -AND ( $_.LocalizedDisplayName -notlike '*Endpoint*') -AND ( $_.LocalizedDisplayName -notlike '*FeatureUpdate*') `
-AND ( $_.LocalizedDisplayName -notlike '*x86*' ) `
-AND ( $_.LocalizedDisplayName -like '*Server*' ) `
-AND ( $_.LocalizedDisplayName -like '*2016*' ) `
} )
 
#Other parameters you may want to use may include 'Windows 10' or '1803' or '2012', remember to modify the like or not like to match your needs
 
#The following query will give you a list of the updates to be added and ask for confirmation
 
$Updates = $null; $Updates = @()
ForEach ( $Update in $Query ) {
    Write-Host $Update.LocalizedDisplayName
    $Updates += $Update.CI_ID
}
 
Function Confirm () {
    $Confirmation = $null
    While ( $Confirmation -notmatch "[y|n]" ) { $Confirmation = read-host "`nAre these the expected results? Do you want to continue? (Y/N)" }
    if ($Confirmation -eq "y"){ Write-Host "`nWill continue with script execution..."; Start-Sleep 3 }
    else { Write-Host "`nNo changes"; $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyUp") > $null; exit } }
 
Confirm

#Enter the name of the update that will be contained on the Software Update Group (SUG)

$UpdateName = "Update Name Here"

#Extract the update CI ID

$UpdateCI_ID = (Get-CMSoftwareUpdate -Name $UpdateName).CI_ID

#Enter the name for the Software Update Group (SUG)

$SUGName = "Software Update Group Name Here"

#Create new Software Update Group (SUG)

New-CMSoftwareUpdateGroup -Name $SUGName

#Add update to Software Update Group (SUG)

Add-CMSoftwareUpdateToGroup -SoftwareUpdateGroupName $SUGName -SoftwareUpdateId $UpdateCI_ID

#Enter the name of the deployment package that will contain the updates

$DeploymentPackageName = "Deployment Package Name Here"

#Create deployment package for Software Update Group (SUG)

New-CMSoftwareUpdateDeploymentPackage -Name $DeploymentPackageName -Path "UNC Path"

#Download the contents of the updates

Save-CMSoftwareUpdate -SoftwareUpdateGroupName $SUGName -DeploymentPackageName $DeploymentPackageName

#Get the package ID for the deployment package

$DeploymentPackageID = (Get-CMSoftwareUpdateDeploymentPackage -Name $DeploymentPackageName).PackageID

#Enter the name of the collection 

$CollectionName = "Collection Name Here"

#Enter the name for the deployment

$DeploymentName = "Deployment Name Here"

#This section contains all the paratemers required for the new deployment

#Deployment type, possible values: Available or Required, remove one as needed

$DeployType = "Available"

$DeployType = "Required"

#Available Date and Time, format Month/Day/Year 00:00 AM or PM, example 5/4/2019 05:00 AM (May 4th, 2019 at 5 AM)

$AvailableDate = "05/04/2019 05:00 AM"

#Deadline Date and Time, format Month/Day/Year 00:00 AM or PM, example 5/6/2019 09:00 PM (May 6th, 2019 at 9 PM )

$DeadlineDate = "05/06/2019 09:00 PM"

#Restart Server, suppress server restart, possible values: TRUE or FALSE, remove one as needed

$RestartServer = $True

$RestartServer = $False

#Restart Workstation, suppress workstation restart, possible values: TRUE or FALSE, remove one as needed

$RestartWorkstation = $True

$RestartWorkstation = $False

#Install updates outside of maintenance windows, possible values: TRUE or FALSE, remove one as needed

$MWInstall = $True

$MWInstall = $False

#Restart systems outside of maintenance windows, possible values: TRUE or FALSE, remove one as needed

$MWRestart = $True

$MWRestart = $False

#Before creating the deployment, here is a brief explanation of the parameters being used by the script:

#PersistOnWriteFilterDevice: Commit changes at deadline or during a maintenance window (requires restarts), if this option is not selected, content will be applied on the overlay and committed later.
#SendWakeUpPacket: Use Wake-on-LAN to wake up client for required deployments
#VerbosityLevel: You can specify the state message detail level returned by clients for the software update deployment, Values AllMessages, OnlySuccessAndErrorMessages, OnlyErrorMessages
#TimeBasedOn: Values LocalTime, Utc
#UserNotification: Values DisplayAll, DisplaySoftwareCenterOnly, HideAll
#GenerateSuccessAlert: Generate success alerts
#DisableOperationsManagerAlert: Disable Operations Manager alerts while software updates run
#GenerateOperationsManagerAlert: Generate Operations Manager alerts when a software update installation fails
#ProtectedType: Values NoInstall, RemoteDistributionPoint
#UseBranchCache:
#DownloadFromMicrosoftUpdate: If software updates are not available on DPs or other neighbors, download content from Microsoft Update
#UseMeteredNetwork: Allow clients on a metered internet connection to download content after the installation deadline.
#RequirePostRebootFullScan: If any update in this deployment requires a system restart, run updates deployment evaluation cycle after restart

#Create the deployment for the newly created Software Update Group

New-CMSoftwareUpdateDeployment -SoftwareUpdateGroupName $SUGName -CollectionName $CollectionName -SavedPackageId $DeploymentPackageID `
-DeploymentName $DeploymentName -DeploymentType $DeployType -AvailableDateTime $AvailableDate  -DeadlineDateTime $DeadlineDate `
-SoftwareInstallation $MWInstall -AvailableDateTime $AvailableDate  -DeadlineDateTime $DeadlineDate -SoftwareInstallation $MWInstall `
-AllowRestart $MWRestart -RestartServer $RestartServer -RestartWorkstation $RestartWorkstation `
-PersistOnWriteFilterDevice $False -SendWakeUpPacket $False -VerbosityLevel AllMessages -TimeBasedOn LocalTime -UserNotification DisplayAll `
-GenerateSuccessAlert $false -DisableOperationsManagerAlert $false -GenerateOperationsManagerAlert $false `
-ProtectedType RemoteDistributionPoint -UseBranchCache $false -DownloadFromMicrosoftUpdate $false -UseMeteredNetwork $false -RequirePostRebootFullScan $True
```
