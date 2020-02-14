<#
    .NOTES
    ===========================================================================
     Created on:   Feb/12/2020
     Version :     1.0, Initial Release
     Created by:   Vinicio Oses
     Organization: System Center Configuration Manager Costa Rica
     Filename:     Increase-WMIQuota.ps1
     ===========================================================================
     .DESCRIPTION
             Some times we run into Config Mgr console performance issues and a good approach to the
             problem is to double the default size of the MemoryPerHost (which is 536870912) and we have to be extra careful while doing so.
             The following PowerShell code doubles the size of MemoryPerHost safety.
             This codes creates a log file WMIQuotaValues.txt under C:\Temp to keep track of the changes 
             and then it will detect the current value for MemoryPerHost and then determine whether it can to 
             be doubled, if is already been doubled or also if it has a different custom value
#>

#Validate PowerShell being executed as administrator
 
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
If ( ( $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) ) -eq $false ) { Write-Warning "PowerShell must be executed as administrator"; $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyUp") > $null; exit }
 
#Create Temp folder under C:\ in case that it doesnt exist, this to place the log file
 
If ( ( Test-Path C:\Temp ) -eq $false ) { New-Item -Path C:\ -Name Temp -ItemType Directory }
 
#Create log file WMIQuotaValues.txt within C:\Temp
 
New-Item -Path C:\Temp\ -Name WMIQuotaValues.txt -ItemType File -Force
 
#Get current date
 
$Date = Get-Date
 
#Add a line on the log file with the date and capturing the current quota values
 
Add-Content -Value "$Date - Values before change" -Path C:\Temp\WMIQuotaValues.txt
Get-WmiObject -Class "__ProviderHostQuotaConfiguration" -Namespace Root | Select-Object HandlesPerHost, MemoryAllHosts, MemoryPerHost, ProcessLimitAllHosts, ThreadsPerHost | Format-Table | Out-File -FilePath C:\Temp\WMIQuotaValues.txt -Encoding utf8 -Append
 
#Retrieve MemoryPerHost host value to see if we need to double it, check if it has already been doubled or detect any custom configuration
 
$MemoryPerHost = (Get-WmiObject -Class "__ProviderHostQuotaConfiguration" -Namespace Root).MemoryPerHost
 
If ( $MemoryPerHost -eq 536870912 ) { #First condition is to detect if the default value of 536870912 is in place and proceed to double it in case of positive

    Write-Host "`nMemoryPerHost detected to be on default value 536870912, proceeding with change"
    $MemoryPerHost = $MemoryPerHost * 2
    $Path = (Get-WmiObject -Class "__ProviderHostQuotaConfiguration" -Namespace Root).__path
    Set-WmiInstance -Path $Path -Argument @{MemoryPerHost=$MemoryPerHost}
    Add-Content -Value "Values after change" -Path C:\Temp\WMIQuotaValues.txt
    Get-WmiObject -Class "__ProviderHostQuotaConfiguration" -Namespace Root | Select-Object HandlesPerHost, MemoryAllHosts, MemoryPerHost, ProcessLimitAllHosts, ThreadsPerHost | Format-Table | Out-File -FilePath C:\Temp\WMIQuotaValues.txt -Encoding utf8 -Append
    Write-Warning "Need to restart the machine for the change to take place" }
ElseIf ( $MemoryPerHost -eq 1073741824 ) {  #Second condition is to detect if the default value has already been doubled and leave it like that

    Write-Host "`nMemoryPerHost detected to be have already been doubled to 1073741824, not making any changes"
    Add-Content -Path C:\Temp\WMIQuotaValues.txt -Value "MemoryPerHost detected to be have already been doubled to 1073741824, not making any changes" }
Else { # Third condition is to detect if any other custom value is in place, this case the admin would have to review why it is like this because it means that other admins were already looking into WMI quotas

    Write-Warning "`nMemoryPerHost detected to be have a custom value of $MemoryPerHost (default value is 536870912), not making any changes"
    Add-Content -Path C:\Temp\WMIQuotaValues.txt -Value "MemoryPerHost detected to be have a custom value of $MemoryPerHost (default value is 536870912), not making any changes" }
 
#Throw a message on screen with the log location
 
Write-Host "`n`nLog file C:\Temp\WMIQuotaValues.txt"