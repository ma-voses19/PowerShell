<#
    .NOTES
    ===========================================================================
     Created on:   Feb/12/2020
     Version :     1.0, Initial Release
     Created by:   Vinicio Oses
     Organization: System Center Configuration Manager Costa Rica
     Filename:     Enable-TLS.ps1
     ===========================================================================
     .DESCRIPTION
             Old operating systems (Win 7, Win 8, W2K8, W2K8 R2 and W2K12) do not have TLS 1.1 or 1.2 enabled 
             by default and Config Mgr requires it to be enabled starting from 1802.
             The overall process to enable TLS 1.2 can be found on https://docs.microsoft.com/en-us/sccm/core/plan-design/security/enable-tls-1-2 but sometimes Cx's CSS have a hard time configuring this properly for Config Mgr as clients.
             If you need to enable TLS on site systems or other infrastructure components (such as databases, MPs, DPs and others) you MUST review the link above because this code will not complete all steps for them.
             This code aims to ease the process of enabling the protocol on old OSs.
#>

#Confirm PowerShell running as administrator
 
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
If ( ( $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) ) -eq $false ) { Write-Warning "PowerShell must be executed as administrator"; $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyUp") > $null; exit }
 
#Confirm OS version
 
$OSVersion = [Environment]::OSVersion.Version | % {"{0}.{1}" -f $_.Major,$_.Minor}
$OS = (Get-WmiObject -Class Win32_OperatingSystem).Caption
If ( ( $OSVersion -like "6.3" ) -OR ( $OSVersion -like "10.0" ) ) { Write-Warning "OS Version: $OS, script not designed for this OS"; $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyUp") > $null; exit }
Else { Write-Host "OS Version: $OS, script will now continue"; Start-Sleep 3 }
 
#Provider Keys
 
$Script:ProtocolsKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
 
Function ModifyProvider {
 
If ( ( Test-Path -Path $KeyTLS ) -eq $False ) { New-Item -Path $ProtocolsKey -Name $TLSVersion -Force }
 
If ( ( Test-Path -Path $KeyTLSSub ) -eq $False ) { New-Item -Path $KeyTLS -Name $Type -Force }
 
If ( Get-ItemProperty -Path $KeyTLSSub -Name DisabledByDefault  ) {
    If ( ( ( Get-Item -Path $KeyTLSSub ).GetValueKind('DisabledByDefault') -ne "DWord" ) ) { 
        Remove-ItemProperty -Path $KeyTLSSub -Name DisabledByDefault -Force
        New-ItemProperty -Path $KeyTLSSub -Name DisabledByDefault -PropertyType DWORD -Value $DisabledByDefault -Force }
    else { Set-ItemProperty -Path $KeyTLSSub -Name DisabledByDefault -Value $DisabledByDefault -Force } }
else { New-ItemProperty -Path $KeyTLSSub -Name DisabledByDefault -Value $DisabledByDefault -PropertyType DWORD -Force }
 
If ( Get-ItemProperty -Path $KeyTLSSub -Name Enabled ) {
    If ( ( ( Get-Item -Path $KeyTLSSub ).GetValueKind('Enabled') -ne "DWord" ) ) { 
        Remove-ItemProperty -Path $KeyTLSSub -Name Enabled -Force
        New-ItemProperty -Path $KeyTLSSub -Name Enabled -PropertyType DWORD -Value $Enabled -Force }
    else { Set-ItemProperty -Path $KeyTLSSub -Name Enabled -Value $Enabled -Force } }
else { New-ItemProperty -Path $KeyTLSSub -Name Enabled -Value $Enabled -PropertyType DWORD -Force } }
 
$ErrorActionPreference = "SilentlyContinue"

#Disable TLS 1.0 as client
 
$Script:TLSVersion = "TLS 1.0"
$Script:KeyTLS = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\"+$TLSVersion
$Script:Type = "Client"
$Script:KeyTLSSub = $KeyTLS+"\"+$Type
$Script:DisabledByDefault = 1
$Script:Enabled = 0
 
ModifyProvider
 
#Disable TLS 1.0 as server
 
$Script:Type = "Server"
$Script:KeyTLSSub = $KeyTLS+"\"+$Type
 
ModifyProvider
 
#Enable TLS 1.1 as client
 
$Script:TLSVersion = "TLS 1.1"
$Script:KeyTLS = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\"+$TLSVersion
$Script:Type = "Client"
$Script:KeyTLSSub = $KeyTLS+"\"+$Type
$Script:DisabledByDefault = 0
$Script:Enabled = 1
 
ModifyProvider
 
#Enable TLS 1.1 as server
 
$Script:Type = "Server"
$Script:KeyTLSSub = $KeyTLS+"\"+$Type
 
ModifyProvider
 
#Enable TLS 1.2 as client
 
$Script:TLSVersion = "TLS 1.2"
$Script:KeyTLS = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\"+$TLSVersion
$Script:Type = "Client"
$Script:KeyTLSSub = $KeyTLS+"\"+$Type
 
ModifyProvider
 
#Enable TLS 1.2 as server
 
$Script:Type = "Server"
$Script:KeyTLSSub = $KeyTLS+"\"+$Type
 
ModifyProvider
 
#.Net
 
$NetKeys = $null; $NetKeys = @()
$NetKeys += ( Get-ChildItem "HKLM:\SOFTWARE\Microsoft\.NETFramework" | Where-Object { ( $_.Name -like "*v*" ) -AND ( $_.Name -notlike "*v1*" ) } ).Name
$NetKeys += ( Get-ChildItem "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework" | Where-Object { ( $_.Name -like "*v*" ) -AND ( $_.Name -notlike "*v1*" ) } ).Name
 
$Script:NetKeysFormated = $null; $Script:NetKeysFormated = @()
ForEach ( $Key in $NetKeys ) {
    $Script:NetKeysFormated += $Key -replace "HKEY_LOCAL_MACHINE","HKLM:" }
 
ForEach ( $Key in $NetKeysFormated ) {
    If ( Get-ItemProperty -Path $Key -Name SchUseStrongCrypto  ) {
        If ( ( ( Get-Item -Path $Key ).GetValueKind('SchUseStrongCrypto') -ne "DWord" ) ) { 
            Remove-ItemProperty -Path $Key -Name SchUseStrongCrypto -Force
            New-ItemProperty -Path $Key -Name SchUseStrongCrypto -PropertyType DWORD -Value 1 -Force }
        else { Set-ItemProperty -Path $Key -Name SchUseStrongCrypto -Value 1 -Force } }
    else { New-ItemProperty -Path $Key -Name SchUseStrongCrypto -Value 1 -PropertyType DWORD -Force }
 
    If ( Get-ItemProperty -Path $Key -Name SystemDefaultTlsVersions  ) {
        If ( ( ( Get-Item -Path $Key ).GetValueKind('SystemDefaultTlsVersions') -ne "DWord" ) ) { 
            Remove-ItemProperty -Path $Key -Name SystemDefaultTlsVersions -Force
            New-ItemProperty -Path $Key -Name SystemDefaultTlsVersions -PropertyType DWORD -Value 1 -Force }
        else { Set-ItemProperty -Path $Key -Name SystemDefaultTlsVersions -Value 1 -Force } }
    else { New-ItemProperty -Path $Key -Name SystemDefaultTlsVersions -Value 1 -PropertyType DWORD -Force } }
   
#WINHTTP
 
$InternetSettingsKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
If ( Get-ItemProperty -Path $InternetSettingsKey -Name SecureProtocols  ) {
        If ( ( ( Get-Item -Path $InternetSettingsKey ).GetValueKind('SecureProtocols') -ne "DWord" ) ) { 
            Remove-ItemProperty -Path $InternetSettingsKey -Name SecureProtocols -Force
            New-ItemProperty -Path $InternetSettingsKey -Name SecureProtocols -PropertyType DWORD -Value 2688 -Force }
        else { Set-ItemProperty -Path $InternetSettingsKey -Name SecureProtocols -Value 2688 -Force } }
    else { New-ItemProperty -Path $InternetSettingsKey -Name SecureProtocols -Value 2688 -PropertyType DWORD -Force }
 
$InternetSettingsWinHttp = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
If ( Get-ItemProperty -Path $InternetSettingsWinHttp -Name DefaultSecureProtocols  ) {
        If ( ( ( Get-Item -Path $InternetSettingsWinHttp ).GetValueKind('DefaultSecureProtocols') -ne "DWord" ) ) { 
            Remove-ItemProperty -Path $InternetSettingsWinHttp -Name DefaultSecureProtocols -Force
            New-ItemProperty -Path $InternetSettingsWinHttp -Name DefaultSecureProtocols -PropertyType DWORD -Value 2720 -Force }
        else { Set-ItemProperty -Path $InternetSettingsWinHttp -Name DefaultSecureProtocols -Value 2720 -Force } }
    else { New-ItemProperty -Path $InternetSettingsWinHttp -Name DefaultSecureProtocols -Value 2720 -PropertyType DWORD -Force }
 
$InternetSettingsWinHttpWow = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
If ( Get-ItemProperty -Path $InternetSettingsWinHttpWow -Name DefaultSecureProtocols  ) {
        If ( ( ( Get-Item -Path $InternetSettingsWinHttpWow ).GetValueKind('DefaultSecureProtocols') -ne "DWord" ) ) { 
            Remove-ItemProperty -Path $InternetSettingsWinHttpWow -Name DefaultSecureProtocols -Force
            New-ItemProperty -Path $InternetSettingsWinHttpWow -Name DefaultSecureProtocols -PropertyType DWORD -Value 2720 -Force }
        else { Set-ItemProperty -Path $InternetSettingsWinHttpWow -Name DefaultSecureProtocols -Value 2720 -Force } }
    else { New-ItemProperty -Path $InternetSettingsWinHttpWow -Name DefaultSecureProtocols -Value 2720 -PropertyType DWORD -Force }
 
$ErrorActionPreference = "Continue"

#Check if KB3140245 is installed https://support.microsoft.com/en-us/help/3140245/update-to-enable-tls-1-1-and-tls-1-2-as-default-secure-protocols-in-wi

Write-Host "Checking if KB3140245 is installed, wait..."
 
$objSession = New-Object -ComObject Microsoft.Update.Session
$objSearcher = $objSession.CreateUpdateSearcher()
$objResults = $objSearcher.Search("IsInstalled = 1")
$X = $null; $X = @()
Foreach($Update in $objResults.Updates) { $X += $Update.Title }
 
$X += (Get-HotFix).HotFixID
 
$Y = Get-WmiObject -Namespace Root\CCM\SoftwareUpdates\UpdatesStore -Class CCM_UpdateStatus
ForEach ( $Z in $Y ) { If ( $Z.Status -eq "Installed" ) { $X += "KB"+$Z.Article } }
 
#KB Number Here
 
$KB = "KB3140245"
$Counter = 0
 
Foreach ( $A in $X ) { If ( $A -Like "*$KB*" ) { Write-Host "$KB found, please restart the computer for changes to take effect"; break } else { $Counter++; If ( $Counter -eq $X.Count ) { Write-Warning "$KB needs to be installed, restart the computer upon installation" } } }