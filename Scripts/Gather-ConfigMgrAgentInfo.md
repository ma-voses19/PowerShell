# Gather general Config Mgr client information and run connectivity test

The intend of this PowerShell code is to ease the retrieval of the following information from any Windows OS acting as a Config Mgr client when troubleshooting:
- Current executing user, time and pending restarts.
- Machine (Name, Domain, Manufacturer, Model, Memory, Num of Physical Proc, Num of Logical Proc)
- OS (Version, Architecture, Install Date, Boot Time, Time Zone)
- Network (IP Address, Alias, Description, Gateway)
- Proxy
- DC and AD Site
- Computer secure channel test
- Config Mgr Agent (Site Code, Version, GUID, PKI, MPs)
- MPs connectivity test (ping, reverse, forward, port 80 and 443)
- Cache (Size, Location, Contents)
- Maintenance Windows (with schedules)
- Business Hours
- Deployments:
- Compliance (DCM)
- Applications
- Packages
- Task Sequences
- Updates
- Installed Updates
- Device drivers
- Devices with problems
- Antivirus or AntiSpyware 
- Mini filter drivers
- Installed programs
- Running processes
- Services
- Firewall profiles status
- GPResult
- All WMI instances for all classes of the Root\CCM namespace
- MSINFO32
- SystemInfo
- IPConfig
- BITSAdmin
- CCM related registries export
- Backup logs folders: CCM, CCMSetup, WindowsUpdate, Windows upgrade logs and event logs.

1. Copy the code and save it to the remote machine.
2. Run a PowerShell as administrator.
3. Execute the script.
4. Grab the generated file from C:\Temp\, file name under the format Info-YYYY-MM-DD-hh-mm.txt
5. Grab the generated GPResult from C:\Temp\, file name under the format Info-YYYY-MM-DD-hh-mm.html

```powershell
<#
    .NOTES
    ===========================================================================
     Created on:   Feb/12/2020
     Version :     1.2, Added more commands to retrieve more data
        Feb/12/2020 1.0, Initial Release
        Abr/09/2020 1.1, Added Azure AD validation, added retrieval of client settings, added Win7 compatibility for commands not available on that OS.
        Jul/29/2020 1.2, Added code to retrieve all WMI instances for all classes within the Root\CCM namespace instead of retriving WMI info on client settings.
                         Added MSINFO32, SystemInfo, IPConfig, BITSAdmin, key Config mgr registry, MDM report exports.
                         Added code to backup CCM, CCMSetup, WindowsUpdate, Windows upgrade logs and event logs.
                         Output files are now saved on a folder under C:\Temp with the name "ComputerName"-YY-MM-DD-HH-mm (and a .zip file with the same name for Windows 10)
     Created by:   Vinicio Oses
     Organization: System Center Configuration Manager Costa Rica
     Filename:     Gather-ConfigMgrAgentInfo.ps1
     ===========================================================================
     .DESCRIPTION
             The intend of this PowerShell code is to ease the retrieval of the following 
             information from any Windows OS acting as a Config Mgr client when troubleshooting:
                Current executing user, time and pending restarts.
                Machine (Name, Domain, Manufacturer, Model, Memory, Num of Physical Proc, Num of Logical Proc)
                OS (Version, Architecture, Install Date, Boot Time, Time Zone)
                Network (IP Address, Alias, Description, Gateway)
                Proxy
                DC and AD Site
                Computer secure channel test
                Config Mgr Agent (Site Code, Version, GUID, PKI, MPs)
                MPs connectivity test (ping, reverse, forward, port 80 and 443)
                Cache (Size, Location, Contents)
                Maintenance Windows (with schedules)
                Business Hours
                Deployments:
                Compliance (DCM)
                Applications
                Packages
                Task Sequences
                Updates
                Installed Updates
                Device drivers
                Devices with problems
                Antivirus or AntiSpyware 
                Mini filter drivers
                Installed programs
                Running processes
                Services
                Firewall profiles status
                GPResult
                All WMI instances for all classes of the Root\CCM namespace
                MSINFO32
                SystemInfo
                IPConfig
                BITSAdmin
                CCM related registries export
                Backup logs folders: CCM, CCMSetup, WindowsUpdate, Windows upgrade logs and event logs.
#>

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
If ( ( $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) ) -eq $false ) { Write-Warning "PowerShell must be executed as administrator";  $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyUp") > $null; exit }

If ( ( Test-Path -Path C:\Temp ) -ne $true ) { New-Item -Path "C:\" -Name Temp -ItemType Directory -Force }

$CurrentDate = (Get-Date -Format "yyyy-MM-dd-HH-mm")

$NewFolderName = $env:ComputerName+"-"+$CurrentDate

New-Item -Path C:\Temp -ItemType Directory -Name $NewFolderName -Force -Confirm:$False

$Filename = "General_Machine_Information.txt"

New-Item -Path C:\Temp\$NewFolderName -Name $Filename -ItemType File  -Force

$FullFileName = "C:\Temp\"+$NewFolderName+"\"+$Filename

Function ChangeDateFormat () {
    Param(     [String[]] $Date )
    If ( $Date -ne $null ) {
        $Output = $Date.Substring(0,4)+"/"+$Date.Substring(4,2)+"/"+$Date.Substring(6,2)+" "+$Date.Substring(8,2)+":"+$Date.Substring(10,2)+":"+$Date.Substring(12,2)
        Return $Output }
    Else { Return "N/A" } }

Function AddSpaceOnFile () {
    Param( [Int] $Number )
    [Int]$Cont = 0
    While ( $Cont -lt $Number ) { Add-Content -Path $FullFileName -Value ""; $Cont++ } }

Function Phrase () {
    Param(     [String[]] $String )
    $String | Add-Content $FullFileName }

MSINFO32 /NFO C:\Temp\$NewFolderName\MSINFO32.NFO

Start-Sleep 10

AddSpaceOnFile -Number 1

$CurrentTime = Get-Date

If ( ( ( Invoke-WmiMethod -Class CCM_ClientUtilities -Namespace ROOT\ccm\ClientSDK -Name DetermineIfRebootPending ).RebootPending ) -eq $true ) { $Restart = "restart pending" }
ElseIf ( ( Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction SilentlyContinue ) -eq $true ) { $Restart = "restart pending" }
ElseIf ( ( Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue ) -eq $true ) { $Restart = "restart pending" }
ElseIf ( ( Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue ) -eq $true ) { $Restart = "restart pending" }
Else { $Restart = "no pending restart" }

$Out = "Executing user "+$env:USERNAME+", current time "+$CurrentTime+", "+$Restart

Phrase -String $Out

AddSpaceOnFile -Number 2

$Out = "PowerShell version "+$PSVersionTable.PSVersion

Phrase -String $Out

AddSpaceOnFile -Number 2

Get-WmiObject -Class Win32_ComputerSystem | Select-Object Name, Domain, Manufacturer, Model, @{Name="Memory"; Expression={ $PhysicalMemory } }, NumberOfProcessors, NumberOfLogicalProcessors| Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append

$Version = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ReleaseId).ReleaseId

$TimeZone = ([System.TimeZone]::CurrentTimeZone).StandardName

Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption, @{Name="Version"; Expression={ $Version } } , OSArchitecture, @{Name="InstallDate"; Expression={ ChangeDateFormat $_.InstallDate } }, @{Name="LastBootUpTime"; Expression={ ChangeDateFormat $_.LastBootUpTime } }, @{Name="Time Zone"; Expression={ $TimeZone } } | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append

If ( ( [System.Environment]::OSVersion.Version ).Major -ge 10 ) { $OSVer = 10 } Else { $OSVer = 7 }

Switch ( $OSVer ) {
    10 { dsregcmd /status | Out-File -FilePath $FullFileName -Encoding utf8 -Append }
    7  { $Out = "To validate AzureAD status on Windows 7 you need to download Microsoft Workplace Join for non-Windows 10 computers from https://www.microsoft.com/en-us/download/details.aspx?id=53554"; Phrase -String $Out; AddSpaceOnFile -Number 2 } }

Switch ( $OSVer ) {
    10 { Get-NetIPConfiguration | Select-Object -Property InterfaceAlias, InterfaceDescription, @{Name="IP Address"; Expression={ If ( $_.IPv4Address -ne $null ) { $_.IPv4Address } else { $_.IPv6Address } } }, @{Name="Gateway"; Expression={ $X = ($_.IPv4DefaultGateway).NextHop; if ( $X -eq $null ) { $X = ($_.IPv6DefaultGateway).NextHop; $X } else { $X } }  } | Out-File -FilePath $FullFileName -Encoding utf8 -Append }
    7  { $Out = IPConfig /all; Phrase -String $Out; AddSpaceOnFile -Number 2 } }

$Out = netsh winhttp show proxy

Phrase -String $Out

AddSpaceOnFile -Number 2

$Domain = (Get-WmiObject -Class Win32_ComputerSystem).Domain

$Out = NLTest /dsgetdc:$Domain

Phrase -String $Out

AddSpaceOnFile -Number 3

If ( Test-ComputerSecureChannel ) { $Out  = "ComputerSecureChannel: True" } else { $Out  = "ComputerSecureChannel: False" }

Phrase -String $Out

AddSpaceOnFile -Number 2

Invoke-WmiMethod -Class SMS_Client -Namespace ROOT\ccm -Name GetAssignedSite | Select-Object  @{Name="Site Code"; Expression={ $_.sSiteCode } } | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append

Get-WmiObject -Class SMS_Client -Namespace ROOT\ccm | Select-Object ClientVersion | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append

Get-WmiObject -Class CCM_Client -Namespace ROOT\ccm | Select-Object ClientId, PreviousClientId, ClientIdChangeDate | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append

Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\CCM | Select-Object PKICertReady, CMGFQDNs, DisAllowCMG | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append

Get-ChildItem -Path CERT:\LocalMachine\My | Select-Object @{Name="Certificate Thumbprint"; Expression={ $_.Thumbprint } }, NotAfter, Issuer, Subject | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append

Get-WmiObject -Class SMS_LookupMP -Namespace ROOT\ccm | Select-Object @{Name="Management Point(s)"; Expression={ $_.Name } } | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append

$MPs = Get-WmiObject -Class SMS_LookupMP -Namespace ROOT\ccm | Select-Object Name

Phrase -String "Testing connectivity against MP(s)"

ForEach ( $MP in $MPs ) {

    AddSpaceOnFile -Number 2

    Switch ( $OSVer ) {
        10 {    If ( Test-Connection -ComputerName $MP.Name ) {
                Test-Connection -ComputerName $MP.Name | Select-Object PSComputerName, Address, ProtocolAddress, BufferSize, ResponseTime | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append }
                else { $Error[0].Exception.Message | Add-Content $FullFileName } }
        7  {    $Ping = Ping $MP.Name -4; Phrase -String $Ping; AddSpaceOnFile -Number 2 } }

    Phrase -String "Forward lookup"
    AddSpaceOnFile -Number 1

    Switch ( $OSVer ) {
        10 {    If ( Resolve-DnsName -Name $MP.Name -Type A ) {
                Resolve-DnsName -Name $MP.Name -Type A | Select-Object Name, Type, Address | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append }
                else { $Error[0].Exception.Message | Add-Content $FullFileName } }
        7  { $Out = NSLookup $MP.Name; Phrase -String $Out; AddSpaceOnFile -Number 2 } }

    Switch ( $OSVer ) {
        10 {    $IP = ( Resolve-DnsName -Name $MP.Name -Type A ).IPAddress }
        7  {    $IP = [regex]$rx = "(\d{1,3}(\.?)){4}"; $rx.matches($PING[1]).Value } }

    Phrase -String "Reverse lookup"
    AddSpaceOnFile -Number 2

    Switch ( $OSVer ) {
        10 { 
                If ( Resolve-DnsName -Name $IP ) {
                Resolve-DnsName -Name $IP | Select-Object Name, Type, Address | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append }
                else { $Error[0].Exception.Message | Add-Content $FullFileName } }
        7  { $Out = "Reverse NsLookup does not work well with earlier versions of Windows"; Phrase -String $Out; AddSpaceOnFile -Number 2 } }

    AddSpaceOnFile -Number 2
    Phrase -String "Ports"
    AddSpaceOnFile -Number 1

    Function Test-Ports-Win-7 ( ) {
        param ( [Parameter(Mandatory=$True,ValueFromPipeline=$True)] [String]$RemotePCName,
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)] [Int]$Port )
        $Socket = New-Object Net.Sockets.TcpClient; $Socket.Connect($RemotePCName, $Port)
        If ( $Socket.Connected -eq "True" ) { $Socket.Close(); return $True } Else { Return $false } }

    Switch ( $OSVer ) {
    10 { Test-NetConnection -ComputerName $MP.Name -Port 80 | Select-Object SourceAddress, RemoteAddress, RemotePort, TcpTestSucceeded | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append }
    7  { If ( ( Test-Ports-Win-7 -RemotePCName $MP.Name -Port 80 ) -eq $true ) { $Out = "Port 80 connected on "+$MP.Name; Phrase -String $Out } Else { $Out = "Unable to connect on port 80 on "+$MP.Name; Phrase -String $Out } } }

    Switch ( $OSVer ) {
    10 { Test-NetConnection -ComputerName $MP.Name -Port 443 | Select-Object SourceAddress, RemoteAddress, RemotePort, TcpTestSucceeded | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append }
    7  { If ( ( Test-Ports-Win-7 -RemotePCName $MP.Name -Port 443 ) -eq $true ) { $Out = "Port 443 connected on "+$MP.Name; Phrase -String $Out } Else { $Out = "Unable to connect on port 443 on "+$MP.Name; Phrase -String $Out } } }
    
    Switch ( $OSVer ) {
    10 { Test-NetConnection -ComputerName $MP.Name -Port 10123 | Select-Object SourceAddress, RemoteAddress, RemotePort, TcpTestSucceeded | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append }
    7  { If ( ( Test-Ports-Win-7 -RemotePCName $MP.Name -Port 10123 ) -eq $true ) { $Out = "Port 10123 connected on "+$MP.Name; Phrase -String $Out } Else { $Out = "Unable to connect on port 10123 on "+$MP.Name; Phrase -String $Out } } }

     }

Get-WmiObject -Class CacheConfig -Namespace ROOT\ccm\SoftMgmtAgent | Select-Object  @{Name="CCMCache Size"; Expression={ $_.Size } }, Location | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append

Get-WmiObject -Class CacheInfoEx -Namespace ROOT\ccm\SoftMgmtAgent | Select-Object CacheId, ContentComplete, ContentId, ContentSize, ContentVer, @{Name="LastReferenced"; Expression={ ChangeDateFormat $_.LastReferenced } }, Location, PeerCaching | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append

Phrase -String "Maintenance Windows"

AddSpaceOnFile -Number 2

Function ServiceWindowType () {
    Param(     [Parameter(Mandatory=$true)]
    [String[]] $ServiceWindowType )
    Switch ( $ServiceWindowType ) {
            1 { $Output = "$ServiceWindowType (All Programs Service Window)" }
            2 { $Output = "$ServiceWindowType (Program Service Window)" }
            3 { $Output = "$ServiceWindowType (Reboot Required Service Window)" }
            4 { $Output = "$ServiceWindowType (Software Update Service Window)" }
            5 { $Output = "$ServiceWindowType (OSD Service Window)" }
            6 { $Output = "$ServiceWindowType (Business Hours) (User Defined)" } }
    Return $Output }

Function Schedules () {
    Param(     [Parameter(Mandatory=$true)] $Hex )
            $Values = $null; $Values = @{}

            [String]$Binary = $null
            For ( $X = 0; $X -lt 16; $X++ ) {
            Switch ( $Hex[$X] ) {
                0 { [String]$Binary += "0000" }
                1 { [String]$Binary += "0001" }
                2 { [String]$Binary += "0010" }
                3 { [String]$Binary += "0011" }
                4 { [String]$Binary += "0100" }
                5 { [String]$Binary += "0101" }
                6 { [String]$Binary += "0110" }
                7 { [String]$Binary += "0111" }
                8 { [String]$Binary += "1000" }
                9 { [String]$Binary += "1001" }
                A { [String]$Binary += "1010" }
                B { [String]$Binary += "1011" }
                C { [String]$Binary += "1100" }
                D { [String]$Binary += "1101" }
                E { [String]$Binary += "1110" }
                F { [String]$Binary += "1111" } } }

            $StartM = $Binary.Substring(0,6)  
            $StartM = [convert]::ToInt32($StartM,2)
            If ( $StartM -lt 10 ) { [String]$StartMinute = "0"+[convert]::ToString($StartM) }

            $StartH =  $Binary.Substring(6,5)
            $StartH = [convert]::ToInt32($StartH,2)
            If ( $StartH -lt 10 ) { [String]$StartHour = "0"+[convert]::ToString($StartH) }

            $StartDay = $Binary.Substring(11,5)
            $StartDay = [convert]::ToInt32($StartDay,2)

            $StartK = $Binary.Substring(16,4)
            $StartK = [convert]::ToInt32($StartK,2)
            Switch ( $StartK ) {
                1 { [String]$StartMonth = "January" }
                2 { [String]$StartMonth = "February" }
                3 { [String]$StartMonth = "March" }
                4 { [String]$StartMonth = "April" }
                5 { [String]$StartMonth = "May" }
                6 { [String]$StartMonth = "June" }
                7 { [String]$StartMonth = "July" }
                8 { [String]$StartMonth = "August" }
                9 { [String]$StartMonth = "September" }
                10 { [String]$StartMonth = "October" }
                11 { [String]$StartMonth = "November" }
                12 { [String]$StartMonth = "December" } }

            $StartYear = $Binary.Substring(20,6)
            $StartYear = [convert]::ToInt32($StartYear,2)
            $StartYear = $StartYear+1970

            $DurationM = $Binary.Substring(26,6)
            $DurationM = [convert]::ToInt32($DurationM,2)
            If ( $DurationM -lt 10 ) { [String]$DurationMinutes = "0"+[convert]::ToString($DurationM) }

            $DurationH = $Binary.Substring(32,5)
            $DurationH = [convert]::ToInt32($DurationH,2)
            If ( $DurationH -lt 10 ) { [String]$DurationHours = "0"+[convert]::ToString($DurationH) }

            $DurationD = $Binary.Substring(37,5)
            $DurationD = [convert]::ToInt32($DurationD,2)
            If ( $DurationD -lt 10 ) { [String]$DurationDays = "0"+[convert]::ToString($DurationD) }

            [String]$Schedule = $StartMonth+" "+[convert]::ToString($StartDay)+", "+[convert]::ToString($StartYear)+" at "+[convert]::ToString($StartHour)+":"+[convert]::ToString($StartMinute)+" | Duration (DD:HH:MM) "+[convert]::ToString($DurationDays)+":"+[convert]::ToString($DurationHours)+":"+[convert]::ToString($DurationMinutes)
           
            $Values.Schedule = $Schedule

            $RecurringInterval = $Binary.Substring(42,3)
            $RecurringInterval = [convert]::ToInt32($RecurringInterval)
            Switch ( $RecurringInterval ) {
                1 { #SCHED_TOKEN_RECUR_NONE
                      [String]$Pattern = "Not recurring."
                      $Values.Pattern = $Pattern }
                10 { #SCHED_TOKEN_RECUR_INTERVAL
                      $NumberofMinutes = $Binary.Substring(45,6)
                      $NumberofMinutes = [convert]::ToInt32($NumberofMinutes,2)
                      $NumberofHours = $Binary.Substring(51,5)
                      $NumberofHours = [convert]::ToInt32($NumberofHours,2)
                      $NumberofDays = $Binary.Substring(56,5)
                      $NumberofDays = [convert]::ToInt32($NumberofDays,2)
                      [String]$Pattern = "Custom interval | Every $NumberofDays day(s), $NumberofHours hour(s) and $NumberofMinutes minute(s)."
                      $Values.Pattern = $Pattern}
                11 { #SCHED_TOKEN_RECUR_WEEKLY
                      $WeekDay = $Binary.Substring(45,3)
                      $WeekDay = [convert]::ToInt32($WeekDay,2)
                      Switch ( $WeekDay ) {  
                        1 { $Day = "Sunday" }
                        2 { $Day = "Monday" }
                        3 { $Day = "Tuesday" }
                        4 { $Day = "Wednesday" }
                        5 { $Day = "Thursday" }
                        6 { $Day = "Friday" }
                        7 { $Day = "Saturday" } }
                      $NumberofWeeks = $Binary.Substring(48,3)
                      $NumberofWeeks = [convert]::ToInt32($NumberofWeeks,2)
                      [String]$Pattern = "Weekly | Every $NumberofWeeks week(s) on $Day."
                      $Values.Pattern = $Pattern }
                100 { #SCHED_TOKEN_RECUR_MONTHLY_BY_WEEKDAY
                      $WeekDay = $Binary.Substring(45,3)
                      $WeekDay = [convert]::ToInt32($WeekDay,2)
                      Switch ( $WeekDay ) {  
                        1 { $Day = "Sunday" }
                        2 { $Day = "Monday" }
                        3 { $Day = "Tuesday" }
                        4 { $Day = "Wednesday" }
                        5 { $Day = "Thursday" }
                        6 { $Day = "Friday" }
                        7 { $Day = "Saturday" } }
                      $NumberofMonths = $Binary.Substring(48,4)
                      $NumberofMonths = [convert]::ToInt32($NumberofMonths,2)
                      $WeekOrder = $Binary.Substring(52,3)
                      $WeekOrder = [convert]::ToInt32($WeekOrder,2)
                      Switch ( $WeekOrder ) {  
                        1 { $Order = "first" }
                        2 { $Order = "second" }
                        3 { $Order = "third" }
                        4 { $Order = "fourth" }
                        5 { $Order = "last" } }
                      [String]$Pattern = "Monthly by weekday | Every $NumberofMonths month(s) on the $Order $Day."
                      $Values.Pattern = $Pattern }
                101 { #SCHED_TOKEN_RECUR_MONTHLY_BY_DATE
                      $Date = $Binary.Substring(45,5)
                      $Date = [convert]::ToInt32($Date,2)
                      $NumberofMonths = $Binary.Substring(50,4)
                      $NumberofMonths = [convert]::ToInt32($NumberofMonths,2)
                      If ( $Date -eq 0 ) { [String]$Pattern = "Monthly by date | Every $NumberofMonths month(s) on the last day of the month."
                      $Values.Pattern = $Pattern }
                      Else { [String]$Pattern = "Monthly by date | Every $NumberofMonths month(s) on the day $Date."
                      $Values.Pattern = $Pattern } } }
    Return $Values }

If ( ( Get-WmiObject -Namespace ROOT\ccm\Policy\Machine\ActualConfig -Class CCM_ServiceWindow | Where-Object { $_.ServiceWindowType -ne "6"} ) -eq $null ) { Phrase -String "No maintenance windows"; AddSpaceOnFile -Number 3 }
Else { Get-WmiObject -Namespace ROOT\ccm\Policy\Machine\ActualConfig -Class CCM_ServiceWindow | Where-Object { $_.ServiceWindowType -ne "6"} | Sort-Object ServiceWindowType  | Select-Object ServiceWindowID, @{Name="ServiceWindowType"; Expression={ServiceWindowType $_.ServiceWindowType } }, @{Name="Effective on"; Expression={$X = Schedules -Hex $_.Schedules; $X.Schedule} }, @{Name="Pattern"; Expression={$X = Schedules -Hex $_.Schedules; $X.Pattern } } | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append }

Phrase -String "Business Hours"

AddSpaceOnFile -Number 2

$WorkingDays = ( Invoke-WmiMethod -Class CCM_ClientUXSettings -Name GetBusinessHours -Namespace ROOT\ccm\ClientSDK ).WorkingDays
$Days = @()

While ( $WorkingDays -ne 0 ) {
    If ( $WorkingDays -ge 64 ) { $Days += "Saturday"; $WorkingDays = $WorkingDays - 64 }
    ElseIf ( $WorkingDays -ge 32 ) { $Days += "Friday"; $WorkingDays = $WorkingDays - 32 }
    ElseIf ( $WorkingDays -ge 16 ) { $Days += "Thursday"; $WorkingDays = $WorkingDays - 16 }
    ElseIf ( $WorkingDays -ge 8 ) { $Days += "Wednesday"; $WorkingDays = $WorkingDays - 8 }
    ElseIf ( $WorkingDays -ge 4 ) { $Days += "Tuesday"; $WorkingDays = $WorkingDays - 4 }
    ElseIf ( $WorkingDays -ge 2 ) { $Days += "Monday"; $WorkingDays = $WorkingDays - 2 }
    ElseIf ( $WorkingDays -ge 1 ) { $Days += "Sunday"; $WorkingDays = $WorkingDays - 1 } }

[array]::Reverse($Days)

$StartTime = $BH.StartTime
$EndTime = $BH.EndTime

Invoke-WmiMethod -Class CCM_ClientUXSettings -Name GetBusinessHours -Namespace ROOT\ccm\ClientSDK | Select-Object StartTime, EndTime, @{Name="Days"; Expression={"$Days"} } | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append

Phrase -String "DCM Deployments"

AddSpaceOnFile -Number 2

If ( ( Get-WmiObject -Class CCM_DCMCIAssignment -Namespace ROOT\ccm\Policy\Machine\ActualConfig ) -eq $null ) { Phrase -String "No DCM Deployments" ; AddSpaceOnFile -Number 3}
Else { Get-WmiObject -Class CCM_DCMCIAssignment -Namespace ROOT\ccm\Policy\Machine\ActualConfig | Sort-Object AssignmentID | Select-Object AssignmentID, @{Name="AssignmentName"; Expression={ $_.AssignmentName } }, AssignmentAction, @{Name="StartTime"; Expression={ ChangeDateFormat $_.StartTime } }, @{Name="EnforcementDeadline"; Expression={ ChangeDateFormat $_.EnforcementDeadline } }, NotifyUser, OverrideServiceWindows, RebootOutsideOfServiceWindows | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append }

Phrase -String "Application Deployments"

AddSpaceOnFile -Number 2

If ( ( Get-WmiObject -Class CCM_ApplicationCIAssignment -Namespace ROOT\ccm\Policy\Machine\ActualConfig  ) -eq $null ) { Phrase -String "No Application Deployments"  ; AddSpaceOnFile -Number 3}
Else { Get-WmiObject -Class CCM_ApplicationCIAssignment -Namespace ROOT\ccm\Policy\Machine\ActualConfig | Sort-Object AssignmentID | Select-Object AssignmentID, @{Name="AssignmentName"; Expression={ $_.AssignmentName } }, AssignmentAction, @{Name="StartTime"; Expression={ ChangeDateFormat $_.StartTime } }, @{Name="EnforcementDeadline"; Expression={ ChangeDateFormat $_.EnforcementDeadline } }, NotifyUser, OverrideServiceWindows, RebootOutsideOfServiceWindows | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append }

Phrase -String "Package Deployments"

AddSpaceOnFile -Number 2

If ( ( Get-WmiObject -Class CCM_SoftwareDistribution -Namespace ROOT\ccm\Policy\Machine\ActualConfig | Where-Object { $_.__CLASS -eq "CCM_SoftwareDistribution" } ) -eq $null ) { Phrase -String "No Package Deployments"  ; AddSpaceOnFile -Number 3}
Else { Get-WmiObject -Class CCM_SoftwareDistribution -Namespace ROOT\ccm\Policy\Machine\ActualConfig | Where-Object { $_.__CLASS -eq "CCM_SoftwareDistribution" } | Sort-Object ADV_AdvertisementID | Select-Object @{Name="AdvertisementID"; Expression={ $_.ADV_AdvertisementID } }, @{Name="PackageID"; Expression={ $_.PKG_PackageID } }, @{Name="Name"; Expression={ $_.PKG_Name } }, @{Name="ActiveTime"; Expression={ ChangeDateFormat $_.ADV_ActiveTime } } , @{Name="MandatoryAssignments"; Expression={ $_.ADV_MandatoryAssignments } }, @{Name="RepeatRunBehavior"; Expression={ $_.ADV_RepeatRunBehavior } }, @{Name="MaxDuration"; Expression={ $_.PRG_MaxDuration } }, @{Name="CommandLine"; Expression={ $_.PRG_CommandLine } }, @{Name="InstallFromLocalDP"; Expression={ $_.ADV_RCF_InstallFromLocalDPOptions } }, @{Name="InstallFromRemoteDP"; Expression={ $_.ADV_RCF_InstallFromRemoteDPOptions  } } | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append }

Phrase -String "Task Sequence Deployments"

AddSpaceOnFile -Number 2

If ( ( Get-WmiObject -Class CCM_SoftwareDistribution -Namespace ROOT\ccm\Policy\Machine\ActualConfig | Where-Object { $_.__CLASS -eq "CCM_TaskSequence" } ) -eq $null ) { Phrase -String "No Task Sequence Deployments"  ; AddSpaceOnFile -Number 3}
Else { Get-WmiObject -Class CCM_SoftwareDistribution -Namespace ROOT\ccm\Policy\Machine\ActualConfig | Where-Object { $_.__CLASS -eq "CCM_TaskSequence" } | Sort-Object ADV_AdvertisementID  | Select-Object @{Name="AdvertisementID"; Expression={ $_.ADV_AdvertisementID } }, @{Name="PackageID"; Expression={ $_.PKG_PackageID } }, @{Name="Name"; Expression={ $_.PKG_Name } }, @{Name="ActiveTime"; Expression={ ChangeDateFormat $_.ADV_ActiveTime } } , @{Name="MandatoryAssignments"; Expression={ $_.ADV_MandatoryAssignments } }, @{Name="RepeatRunBehavior"; Expression={ $_.ADV_RepeatRunBehavior } }, @{Name="MaxDuration"; Expression={ $_.PRG_MaxDuration } }, @{Name="InstallFromLocalDP"; Expression={ $_.ADV_RCF_InstallFromLocalDPOptions } }, @{Name="InstallFromRemoteDP"; Expression={ $_.ADV_RCF_InstallFromRemoteDPOptions  } }, @{Name="BootImageID"; Expression={ $_.TS_BootImageID } } | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append }

Phrase -String "Update Deployments"

AddSpaceOnFile -Number 2

If ( ( Get-WmiObject -Class CCM_UpdateCIAssignment -Namespace ROOT\ccm\Policy\Machine\ActualConfig ) -eq $null ) { Phrase -String "No Update Deployments"  ; AddSpaceOnFile -Number 3}
Else { Get-WmiObject -Class CCM_UpdateCIAssignment -Namespace ROOT\ccm\Policy\Machine\ActualConfig | Sort-Object AssignmentID | Select-Object AssignmentID, @{Name="AssignmentName"; Expression={ $_.AssignmentName } }, AssignmentAction, @{Name="StartTime"; Expression={ ChangeDateFormat $_.StartTime } }, @{Name="EnforcementDeadline"; Expression={ ChangeDateFormat $_.EnforcementDeadline } }, NotifyUser, OverrideServiceWindows, RebootOutsideOfServiceWindows | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append }

Phrase -String "Updates"

AddSpaceOnFile -Number 2

If ( ( Get-WmiObject -Class CCM_UpdateStatus -Name ROOT\ccm\SoftwareUpdates\UpdatesStore ) -eq $null ) { Phrase -String "No Updates"  ; AddSpaceOnFile -Number 3}
Else { Get-WmiObject -Class CCM_UpdateStatus -Name ROOT\ccm\SoftwareUpdates\UpdatesStore | Sort-Object UniqueId | Select-Object UniqueId, Title, Status | Out-File -FilePath $FullFileName -Encoding utf8 -Append  }

Phrase -String "Other updates installed"

$objSession = New-Object -ComObject Microsoft.Update.Session
$objSearcher = $objSession.CreateUpdateSearcher()
$objResults = $objSearcher.Search("IsInstalled = 1")

AddSpaceOnFile -Number 2

If ( $objResults -ne $null )  { Foreach($Update in $objResults.Updates) { Phrase -String $Update.Title } AddSpaceOnFile -Number 3 }
Else { Phrase -String "No other updates detected"; AddSpaceOnFile -Number 3 }

Phrase -String "HotFixes"

AddSpaceOnFile -Number 2

If ( ( Get-HotFix ) -eq $null ) { Phrase -String "No HotFixes"; AddSpaceOnFile -Number 3}
Else { Get-HotFix | Sort-Object HotFixID | Select-Object HotFixID, Description, InstalledBy, InstalledOn | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append  }

Get-WmiObject Win32_PnPSignedDriver | Select-Object @{Name="Driver device name"; Expression={ $_.DeviceName } }, Manufacturer, DriverVersion | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append

Phrase -String "Devices with problems"

AddSpaceOnFile -Number 2

If ( ( Get-WmiObject Win32_PNPEntity | Where-Object { $_.ConfigManagerErrorcode -ne 0 } ) -eq $null ) { Phrase -String "No devices with problems detected"; AddSpaceOnFile -Number 3 }
else { Get-WmiObject Win32_PNPEntity | Where-Object { $_.ConfigManagerErrorcode -ne 0 } | Select-Object Name, Description, DeviceID, ConfigManagerErrorcode, ErrorDescription, Service, Status | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append }

Get-WmiObject -Class AntiSpywareProduct -Namespace ROOT\SecurityCenter | Select-Object @{Name="AntiSpyware Security Center"; Expression={ $_.displayName } } | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append

Get-WmiObject -Class AntiVirusProduct -Namespace ROOT\SecurityCenter | Select-Object @{Name="AntiVirus Security Center"; Expression={ $_.displayName } } | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append

Get-WmiObject -Class AntiSpywareProduct -Namespace ROOT\SecurityCenter2 | Select-Object @{Name="AntiSpyware Security Center 2"; Expression={ $_.displayName } } | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append

Get-WmiObject -Class AntiVirusProduct -Namespace ROOT\SecurityCenter2 | Select-Object @{Name="AntiVirus Security Center 2"; Expression={ $_.displayName } } | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append

$Out = FLTMC

Phrase -String "Mini filter drivers"

AddSpaceOnFile -Number 2

Phrase -String $Out

Get-WmiObject -Class Win32_Product | Select-Object @{Name="Installed program name"; Expression={ $_.Name } }, InstallSource, InstallLocation | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append

Get-CimInstance Win32_Process | Select-Object ProcessName, ProcessId, CommandLine | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append

Get-Service | Sort-Object Name | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append

Function Get-FirewallState {
Try {
$FirewallBlock = {
$content = netsh advfirewall show allprofiles
If ($domprofile = $content | Select-String 'Domain Profile' -Context 2 | Out-String)
{ $domainpro = ($domprofile.Substring($domprofile.Length - 9)).Trim()}
Else { $domainpro = $null }
If ($priprofile = $content | Select-String 'Private Profile' -Context 2 | Out-String)
{ $privatepro = ($priprofile.Substring($priprofile.Length - 9)).Trim()}
Else { $privatepro = $null }
If ($pubprofile = $content | Select-String 'Public Profile' -Context 2 | Out-String)
{ $publicpro = ($pubprofile.Substring($pubprofile.Length - 9)).Trim()}
Else { $publicpro = $null }

$FirewallObject = New-Object PSObject
Add-Member -inputObject $FirewallObject -memberType NoteProperty -name "FirewallDomain" -value $domainpro
Add-Member -inputObject $FirewallObject -memberType NoteProperty -name "FirewallPrivate" -value $privatepro
Add-Member -inputObject $FirewallObject -memberType NoteProperty -name "FirewallPublic" -value $publicpro
$FirewallObject
}
 
Return Invoke-Command -command $FirewallBlock | Select-Object FirewallDomain, FirewallPrivate, FirewallPublic
 
}
Catch
{
       Return ($_.Exception.Message -split ' For')[0]
        }
}

Get-FirewallState | Format-Table | Out-File -FilePath $FullFileName -Encoding utf8 -Append

GPResult -H C:\Temp\$NewFolderName\GPResult.html

New-Item -Path "C:\Temp\$NewFolderName" -Name WMIInfo.txt -ItemType File  -Force

$script:Namespace_List = @()

$script:Namespace_List += "Root\CCM"

Function Get-Namespaces () {

    Param ( [Parameter(Mandatory=$True, ValueFromPipeline=$False)] [String]$Namespace )

    ( Get-WmiObject -Namespace $Namespace -Class __Namespace ).Name | ForEach { 
            
        $SubNamespace = $Namespace+"\"+$_

        $script:Namespace_List += $SubNamespace } }

Get-Namespaces -Namespace Root\CCM

Get-Namespaces -Namespace Root\CCM\Policy\DefaultMachine

Get-Namespaces -Namespace Root\CCM\Policy\DefaultUser

Get-Namespaces -Namespace Root\CCM\Policy\Machine

$SID1 = "Root\CCM\Policy\"+ ( Get-WmiObject -Namespace "Root\CCM\Policy" -Class __Namespace | Where-Object { $_.Name -like "S_1_1*" } ).Name

Get-Namespaces -Namespace $SID1

$SID2 = "Root\CCM\Policy\"+ ( Get-WmiObject -Namespace "Root\CCM\Policy" -Class __Namespace | Where-Object { $_.Name -like "S_1_5*" } ).Name

Get-Namespaces -Namespace $SID2

Get-Namespaces -Namespace Root\CCM\SoftwareUpdates

$script:Namespace_List = $script:Namespace_List | Sort-Object 

ForEach ( $Namespace in $script:Namespace_List ) {

    $Classes = Get-CimClass -Namespace $Namespace -ErrorAction SilentlyContinue | Where-Object { $_.CimClassName -notlike "__*" } | Select-Object CimClassName

    ForEach ( $Class in $Classes ) {
    
    $X = $Class.CimClassName

    Add-Content -Path "C:\Temp\$NewFolderName\WMIInfo.txt" -Value "Namespace $Namespace and class name $X`n"

    Get-CimInstance -Namespace $Namespace -ClassName $X -ErrorAction SilentlyContinue | Out-File -FilePath "C:\Temp\$NewFolderName\WMIInfo.txt" -Encoding utf8 -Append } }

#######################

SystemInfo > C:\Temp\$NewFolderName\SystemInfo.txt

IPConfig /all > C:\Temp\$NewFolderName\IPConfig.txt

BITSadmin /list /allusers /verbose > C:\Temp\$NewFolderName\BITSadmin.txt

Reg Export "HKLM\Software\Microsoft\CCM" C:\Temp\$NewFolderName\RegKey_CCM.txt

Reg Export "HKLM\Software\Microsoft\SMS" C:\Temp\$NewFolderName\RegKey_SMS.txt

Reg Export "HKLM\Software\Microsoft\Windows Defender" C:\Temp\$NewFolderName\RegKey_Windows_Defender.txt

Reg Export "HKLM\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing" C:\Temp\$NewFolderName\RegKey_CBS.txt

Reg Export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" C:\Temp\$NewFolderName\RegKey_WindowsUpdate_1.txt

Reg Export "HKLM\SOFTWARE\Microsoft\WindowsUpdate" C:\Temp\$NewFolderName\RegKey_WindowsUpdate_2.txt

Reg Export "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" C:\Temp\$NewFolderName\RegKey_WindowsUpdate_3.txt

Reg Export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" C:\Temp\$NewFolderName\RegKey_SessionManager.txt

Reg Export "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings" C:\Temp\$NewFolderName\RegKey_HKLM_Internet_Settings.txt

Reg Export "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" C:\Temp\$NewFolderName\RegKey_HKCU_Internet_Settings.txt

Reg Export "HKLM\SOFTWARE\Policies" C:\Temp\$NewFolderName\RegKey_HKLM_Policies.txt

Reg Export "HKCU\SOFTWARE\Policies" C:\Temp\$NewFolderName\RegKey_HKCU_Policies.txt

If ( $OSVer -eq 10 ) { Get-NetFirewallRule > C:\Temp\$NewFolderName\Get-NetFirewallRule.txt }

#Providers, TLS

Reg Export "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" C:\Temp\$NewFolderName\RegKey_TLS_Protocols.txt

#.NET, TLS

Reg Export "HKLM\SOFTWARE\Microsoft\.NETFramework" C:\Temp\$NewFolderName\RegKey_TLS_NETFramework.txt
Reg Export "HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework" C:\Temp\$NewFolderName\RegKey_TLS_NETFramework_x64.txt

#WINHTTP, TLS
 
Reg Export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" C:\Temp\$NewFolderName\RegKey_TLS_InternetSettings.txt
Reg Export "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings" C:\Temp\$NewFolderName\RegKey_TLS_InternetSettings_x64.txt

Reg Export "HKLM\Software\Microsoft\PolicyManager" C:\Temp\$NewFolderName\RegKey_PolicyManager.txt

Reg Export "HKLM\Software\Microsoft\Enrollments" C:\Temp\$NewFolderName\RegKey_Enrollments.txt

Start-Process MdmDiagnosticsTool.exe -Wait -ArgumentList "-out C:\Temp\$NewFolderName\MDMDiag.html" -NoNewWindow

New-Item -Path C:\Temp\$NewFolderName -Name CCM_Logs -ItemType Directory -Force

Copy-Item -Path C:\Windows\CCM\Logs -Destination C:\Temp\$NewFolderName\CCM_Logs -Recurse -Force -Confirm:$False

Copy-Item -Path C:\Windows\CCMSetup\Logs -Destination C:\Temp\$NewFolderName\CCM_Logs -Force -Recurse -Confirm:$false

Switch ( $OSVer ) {
    10 {    Get-WindowsUpdateLog -LogPath C:\Temp\$NewFolderName\CCM_Logs\WindowsUpdate.log -Force -Confirm:$false }
    7  {    Copy-Item -Path C:\Windows\WindowsUpdate.log -Destination C:\Temp\$NewFolderName\CCM_Logs -Force -Confirm:$false } }

New-Item -Path C:\Temp\$NewFolderName -Name Windows_Logs -ItemType Directory -Force

Copy-Item -Path C:\Windows\Logs -Destination C:\Temp\$NewFolderName\Windows_Logs -Force -Recurse -Confirm:$false

Copy-Item -Path C:\Windows\Panther -Destination C:\Temp\$NewFolderName -Force -Recurse -Confirm:$false

$WindowsBT = "C:\"+[CHAR]36+"WINDOWS."+[CHAR]126+"BT"

If ( Test-Path -Path $WindowsBT\Sources\Panther ) {

    If ( ( Test-Path C:\Temp\$NewFolderName\WindowsBT ) -ne $true ) { New-Item -Path C:\Temp\$NewFolderName -Name WindowsBT -ItemType Directory -Force }

    New-Item -Path C:\Temp\$NewFolderName\WindowsBT -Name Panther -ItemType Directory -Force

    Copy-Item -Path $WindowsBT\Sources\Panther -Destination C:\Temp\$NewFolderName\WindowsBT\Panther -Force -Recurse -Confirm:$false }

If ( Test-Path -Path $WindowsBT\Sources\Rollback ) {

    If ( ( Test-Path C:\Temp\$NewFolderName\WindowsBT ) -ne $true ) { New-Item -Path C:\Temp\$NewFolderName -Name WindowsBT -ItemType Directory -Force }

    New-Item -Path C:\Temp\$NewFolderName\WindowsBT -Name Rollback -ItemType Directory -Force

    Copy-Item -Path $WindowsBT\Sources\Rollback -Destination C:\Temp\$NewFolderName\WindowsBT\Rollback -Force -Recurse -Confirm:$false }

Copy-Item -Path C:\Windows\System32\winevt -Destination C:\Temp\$NewFolderName -Force -Recurse -Confirm:$false

If ( $OSVer -eq 10 ) { Compress-Archive -Path C:\Temp\$NewFolderName -DestinationPath C:\Temp\$NewFolderName -Force -Confirm:$false }
```
