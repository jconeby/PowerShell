#Change creds as needed
$Username = 'Admin'
$Password = 'Password'

#Create Credential Object
[SecureString]$secureString = $Password | ConvertTo-SecureString -AsPlainText -Force
[PSCredential]$creds = New-Object System.Management.Automation.PSCredential -ArgumentList $Username, $secureString

<#Import the hunt.psm1 module saved on your desktop
May need to change $Path variable #>


$desktopPath = [string]::Concat($env:HOMEDRIVE,$env:HOMEPATH,'\Desktop\')
$outputFolder = [string]::Concat($env:HOMEDRIVE,$env:HOMEPATH,'\Desktop\Output\')
if(!(Test-Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory
}

Import-Module ($desktopPath + "Hunt.psm1")

$eventCSV = Import-CSV -Path ($desktopPath + "Windows_Event_Log.csv")
$regArray = Get-Content -Path ($desktopPath + "registry_keys.txt")
$regIOCcsv   = Import-CSV -Path ($desktopPath + "registry_IOC.csv")

#Adjust these dates as needed
$After = Get-Date ('08/30/2020')
$Before = Get-Date ('09/01/2020')

#Change targets as needed
$targets = Import-Csv -Path ($desktopPath + "Targets.csv")
$targets = $targets.Hosts
<#Least Frequncy Analysis - Change the threshold
May want to make the threshold a percentage of the $targets.
Example $threshold = (0.10 * $targets.count #>
$threshold = 2


$Process           = Get-WmiProcess -ComputerName $targets -Credential $creds
$ProcessLFA        = Group-ProcessByPath -processObject $Process -Threshold $threshold
$Service           = Get-WmiService -ComputerName $targets -Credential $creds
$OS                = Invoke-Command -ComputerName $targets -Credential $creds -ScriptBlock {Get-WmiObject Win32_OperatingSystem}
$LocalGroups       = Get-LGroup -ComputerName $targets -Credential $creds
$LocalGroupMembers = Get-LGroupMembers -ComputerName $targets -Credential $creds
$Users             = Get-LUser -ComputerName $targets -Credential $creds
$LoggedOnUsers     = Get-LoggedOnUser -ComputerName $targets -Credential $creds
$SchTasks          = Get-SchTask -ComputerName $targets -Credential $creds
$Connections       = Get-Connection -ComputerName $targets -Credential $creds
$Shares            = Invoke-Command -ComputerName $targets -Credential $creds -ScriptBlock {Get-WmiObject -ClassName Win32_Share}
$RegistryStartups  = Get-Registry -regKeyArray $regArray -ComputerName $targets -Credential $creds
$RegistrySchTasks  = Invoke-Command -ComputerName $targets -Credential $creds -ScriptBlock {Get-ChildItem 'HKLM:\HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree' -Recurse | Select Name,PSComputerName}
$RegistryIOC       = Get-RegistryIOC -RegList $regIOCcsv -ComputerName $targets -Credential $creds
$SecurityLog       = Invoke-Command -ComputerName $targets -Credential $creds -ScriptBlock {Get-EventLog -LogName Security -After $Using:After -Before $Using:Before}
$SecurityLogFormat = Format-Events -logs $SecurityLog
$CriticalEvents    = $SecurityLogFormat | Where {$_.AlertMessage -ne $null} | Select Time,IP,Index,EventID,AccountName,AlertMessage | Sort-Object -Property Time | FT
$GroupedEvents     = Group-SecurityEventID -eventRecord $SecurityLogFormat -eventList $eventCSV

#Change the startpath and files modified in the last amount of days as needed
$BaselineHash      = Get-BaselineHash -ComputerName $targets -Credential $creds -StartPath "C:\"
$RecentModFiles    = Get-RecentModFile -ComputerName $targets -Credential $creds -StartPath "C:\" -Days 30
$Firewall          = Survey-Firewall -ComputerName $targets -Credential $creds
$Prefetch          = Get-Prefetch -ComputerName $targets -Credential $creds


#Export the variables to CSV files
$Process | Export-CSV -Path ($outputFolder + "process.csv") -NoTypeInformation
$ProcessLFA | Select Count,FilePath,Name,PSComputerName,Hash | Export-CSV -Path ($outputFolder + "processLFA.csv") -NoTypeInformation
$Service | Export-CSV -Path ($outputFolder + "service.csv") -NoTypeInformation
$OS | Select PSComputerName,CSName,InstallDate,LastBootUpTime,Name,Version | Export-CSV -Path ($outputFolder + "OS.csv") -NoTypeInformation
$LocalGroups | Select PSComputerName,Caption,Name,SID,Description | Export-CSV -Path ($outputFolder + "LocalGroups.csv") -NoTypeInformation
$LocalGroupMembers | Export-CSV -Path ($outputFolder + "LocalGroupMembers.csv") -NoTypeInformation
$Users | Select PSComputerName,Caption,Name,SID | Export-CSV -Path ($outputFolder + "users.csv") -NoTypeInformation
$LoggedOnUsers | Export-CSV -Path ($outputFolder + "LoggedOnUsers.csv") -NoTypeInformation
$SchTasks | Select PSComputerName,TaskName,Author,Date,TaskPath,URI,Description | Export-CSV -Path ($outputFolder + "schtasks.csv") -NoTypeInformation
$Connections | Export-CSV -Path ($outputFolder + "connections.csv") -NoTypeInformation
$Shares | Select PSComputerName,Name,Path,Description | Export-CSV -Path ($outputFolder + "shares.csv") -NoTypeInformation
$RegistryStartups | Export-CSV -Path ($outputFolder + "RegistryStartups.csv") -NoTypeInformation
$RegistryIOC | Select PSComputerName,Key,IOC,Data,Generation,DependOnService,Description,DisplayName,ImagePath | Sort-Object -Property PSComputerName | Export-Csv -Path ($outputFolder + "RegIOC.csv") -NoTypeInformation
Format-Events -logs $SecurityLog | Select IP,Time,EventID,Index,AuthPackage,@{n="ImportantMessage";e={Write-ImportantMessage -EventID $_.EventID -AuthPackage $_.AuthPackage}} | 
Sort-Object -Property IP,Index | Export-Csv -Path ($outputFolder + "Events.csv") -NoTypeInformation
$GroupedEvents | Export-CSV -Path ($outputFolder + "GroupedEvents.csv") -NoTypeInformation
$BaselineHash | Export-CSV -Path ($outputFolder + "BaselineHash.csv") -NoTypeInformation
$RecentModFiles | Export-CSV -Path ($outputFolder + "RecentModFiles.csv") -NoTypeInformation
$Firewall | Select InstanceID,LocalAddress,LocalPort,RemoteAddress,RemotePort,Protocol,Action,PSComputerName | Export-CSV -Path ($outputFolder + "firewall.csv") -NoTypeInformation
$Prefetch | Export-CSV -Path ($outputFolder + "prefetch.csv") -NoTypeInformation


$BaselineInfo = [PSCustomObject] @{
                                
        Process            = $Process
        Service            = $Service
        OS                 = $OS
        LocalGroups        = $LocalGroups
        LocalGroupMembers  = $LocalGroupMembers
        Users              = $Users
        LoggedOnUsers      = $LoggedOnUsers
        SchTasks           = $SchTasks
        Connections        = $Connections
        Shares             = $Shares
        RegistryStartups   = $RegistryStartups
        RegistrySchTasks   = $RegistrySchTasks
        RegistryIOC        = $RegistryIOC
        SecurityLog        = $SecurityLog
        SecurityLogFormat  = $SecurityLogFormat
        CriticalEvents     = $CriticalEvents
        GroupedEvents      = $GroupedEvents
        Baseline           = $Baseline
        RecentModFiles     = $RecentModFiles
        Firewall           = $Firewall 
        Prefetch           = $Prefetch }

$BaselineInfo | Export-Clixml -Path ($outputFolder + "BaselineInfo.xml")

