<#
    .NOTES
    ===========================================================================
     Created on:   Feb/12/2020
     Version :     1.0, Initial Release
     Created by:   Vinicio Oses
     Organization: System Center Configuration Manager Costa Rica
     Filename:     Update-CollectionType.ps1
     ===========================================================================
     .DESCRIPTION
             Poor performance some times is faced on Config Mgr environments where the usage of incremental updates for collections is extensively used.
             More than 200 collections using the type 4 "Use incremental updates for this collection" or 6 "Use incremental updates for this collection with Schedule a full update on this collection"
             The following code helps to update the previously mentioned update types to type 2 "Schedule a full update on this collection"
#>

#Function to load Config Mgr Cmdlets

Function Load-ConfigMgrCmdlets () {
    $script:initParams = @{}
    if((Get-Module ConfigurationManager) -eq $null) {
        If ( $ENV:SMS_ADMIN_UI_PATH -ne $null ) {
            Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" @initParams -ErrorAction SilentlyContinue
            If ( $? ) { } else { Write-Warning "Couldnt load Config Mgr modules with error: "; Write-Warning $Error[0].Exception.Message; Read-Host; Exit  }  
         } else { Write-Warning "Missing Config Mgr Cmdlets (script needs to be run on the top of the hirarchy)"; Write-Warning $Error[0].Exception.Message; Read-Host; Exit } } }

#Funtion to connect to the site's drive if it is not already present

Function ConnectToSite {
    $SiteCode = (Get-WmiObject -Namespace ROOT\sms -Class SMS_ProviderLocation).SiteCode
    $ProviderMachineName = ( [System.Net.Dns]::GetHostByName(($env:computerName)) ).HostName
    if((Get-PSDrive -Name $SiteCode -PSProvider CMSite -ErrorAction SilentlyContinue) -eq $null) {
        New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $ProviderMachineName @initParams }
    #Set the current location to be the site code.
    Set-Location "$($SiteCode):\" @initParams
    If ( $? ) { } else { Write-Warning "Couldnt connect to site with error: "; Write-Warning $Error[0].Exception.Message; Read-Host; Exit } }

Load-ConfigMgrCmdlets

ConnectToSite

Write-Host "`nThis script automatically changes Config Mgr collections from type 4 (Use incremental updates for this collection) and 6 (Use incremental updates for this collection with Schedule a full update on this collection) to 2 (Schedule a full update on this collection)`n"

Function Change-Type {
   
    param( [Parameter(Mandatory=$True, ValueFromPipeline=$False)][ValidateSet("4","6")] [String]$Type )

    $AllCollections = Get-CMDeviceCollection | Select -Property Name, CollectionID,RefreshType | Where-Object { ( $_.Refreshtype -eq $Type ) -and ( $_.Name -ne "All Systems" ) -and ( $_.Name -ne "All Unknown Computers" )-and ( $_.Name -ne "All Mobile Devices" )-and ( $_.Name -ne "All Desktop and Server Clients" ) }

    If ( $AllCollections.Count -le 0 ) { Write-Host "No collections of type $Type were detected `n" }
    Else {

        Write-Host "Collection(s) of type $Type ("$AllCollections.Count")`n"

        ForEach ( $X in $AllCollections ) { Write-Host $X.Name, $X.CollectionID, $X.RefreshType }

        $Flag = 0

        Do { $vOption = Read-Host "`nWould you like to change them (y/n)"
            $vOption = $vOption.ToLower()
            Switch ( $vOption ) {
                "y" { $Flag = 1; break }
                "yes" { $Flag = 1; break }
                "n" { $Flag = 2; break }
                "no" { $Flag = 2; break }
                Default { Write-Host "Invalid option`n" } } } While ( $Flag -eq 0 )

        If ( $Flag -eq 1 ) {
            ForEach ( $X in $AllCollections ) {
                $CollectionID = $X.CollectionID
                Set-CMCollection -CollectionId $CollectionID -RefreshType Periodic  } }
        ElseIf ( $Flag -eq 2 ) { Write-Host "`nNo changes will be applied to type $Type collections`n" } } }

Change-Type -Type 4

Change-Type -Type 6