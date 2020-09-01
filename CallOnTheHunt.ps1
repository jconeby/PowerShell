function Get-HostInfo {

$hostInfo = [PSCustomObject] @{
        Process           = ''
        Service           = ''
        OS                = Get-WmiObject Win32_OperatingSystem
        LocalGroups       = ''
        LocalGroupMembers = ''
        Users             = ''
        LoggedOnUsers     = ''
        Logins            = wmic netlogin get fullname,userid,lastlogon,logonhours,privileges
        SchTasks          = ''
        Connections       = ''
        Shares            = Get-WmiObject -ClassName Win32_Share
        RegistryStartups  = ''
        RegistrySchTasks  = Get-ChildItem 'HKLM:\HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree' -Recurse | Select Name
        CriticalEvents    = ''
        GroupedEvents     = ''
        Baseline          = ''
        RecentModFiles    = ''
        Firewall          = ''
        Prefetch          = ''
        Report            = ''
        }
        
return $hostInfo

}


function Format-Report {
Param([Parameter(Mandatory=$True
,HelpMessage="Error: Please enter an object")]$Object)

 Write-Output "----------------------------Process List---------------------------------"
 Write-Output $Object.Process | FT
 Write-Output " "
 Write-Output "---------------------------Service List----------------------------------------------------------------"
 Write-Output $Object.Service | Select Name,State,ProcessName,ProcessId,Pathname | Sort-Object -Property State,ProcessName | FT
 Write-Output " "
 Write-Output "---------------------------Connections--------------------------------------------"
 Write-Output $Object.Connections | FT
 Write-Output " "
 Write-Output "---------------------------OS--------------------------------------------"
 Write-Output $Object.OS | Select Caption,Version,RegisteredUser,SystemDirectory,SerialNumber | FT
 Write-Output " "
 Write-Output "---------------------------LocalGroups--------------------------------------------"
 Write-Output $Object.LocalGroups | FT
 Write-Output " "
 Write-Output "---------------------------LocalGroupMembers--------------------------------------------"
 Write-Output $Object.LocalGroupMembers | Select GroupName,Member,PSComputerName
 Write-Output " "
 Write-Output "---------------------------Users--------------------------------------------"
 Write-Output $Object.Users | FT
 Write-Output " "
  Write-Output " "
 Write-Output "---------------------------Logged On Users--------------------------------------------"
 Write-Output $Object.LoggedOnUsers | FT
 Write-Output " "
 Write-Output "---------------------------Logins--------------------------------------------"
 Write-Output $Object.Logins | FT
 Write-Output " "
 Write-Output "---------------------------Scheduled Tasks--------------------------------------------"
 Write-Output $Object.SchTasks | FT
 Write-Output " "
 Write-Output "---------------------------Registry Scheduled Tasks--------------------------------------------"
 Write-Output $Object.RegistrySchTasks | FT
 Write-Output " "
 Write-Output "---------------------------Shares--------------------------------------------"
 Write-Output $Object.Shares | FT
 Write-Output " "
 Write-Output "---------------------------Grouped Events--------------------------------------------"
 Write-Output $Object.GroupedEvents | FT
 Write-Output " "
 Write-Output "---------------------------Registry Start Ups--------------------------------------------"
 Write-Output $Object.RegistryStartups | FT
 Write-Output " "
 Write-Output "---------------------------Firewall--------------------------------------------"
 Write-Output $Object.Firewall | Select InstanceID,LocalAddress,LocalPort,RemoteAddress,RemotePort,Direction,Action | FT
 Write-Output " "
 Write-Output "---------------------------Prefetch--------------------------------------------"
 Write-Output $Object.Prefetch | FT

}

#Change creds as needed
$Username = 'Admin'
$Password = 'DomainAdminPassword'

#Create Credential Object
[SecureString]$secureString = $Password | ConvertTo-SecureString -AsPlainText -Force
[PSCredential]$creds = New-Object System.Management.Automation.PSCredential -ArgumentList $Username, $secureString


#import the hunt.psm1 module saved on your desktop
$Path = ($env:HOMEDRIVE + $env:HOMEPATH + '\Desktop\')
Import-Module ($Path + $target + "\Hunt.psm1")


#Will look at desktop for registry list and Windows Event Log
$regArray = Get-Content -Path ($Path + '\registry_keys.txt')
$eventCSV = Import-CSV -Path ($Path + '\Windows_Event_Log.csv')


#Can change this to take content from a text or csv file
$targets = @('192.168.253.145','localhost')

foreach ($target in $targets)
{
    
$machine = Invoke-Command -ComputerName $target -Credential $creds -ScriptBlock ${Function:Get-HostInfo}

#Add additional properties
$machine.Process           = Get-WmiProcess -ComputerName $target -Credential $creds
$machine.Service           = Get-WmiService -ComputerName $target -Credential $creds
$machine.LocalGroups       = Get-LGroup -ComputerName $target -Credential $creds
$machine.Users             = Get-LUser -ComputerName $target -Credential $creds
$machine.LocalGroupMembers = Get-LGroupMembers -ComputerName $target -Credential $creds
$machine.LoggedOnUsers     = Get-LoggedOnUser -ComputerName $target -Credential $creds
$machine.SchTasks          = Get-SchTask -ComputerName $target -Credential $creds
$machine.Connections       = Get-Connection -ComputerName $target -Credential $creds
#Edit the StartPath parameter as needed
$machine.Baseline          = Get-BaselineHash -ComputerName $target -Credential $creds -StartPath "C:\Users\jkcon\OneDrive\Documents"
#Edit the StartPath and Days parameter as needed
$machine.RecentModFiles    = Get-RecentModFile -ComputerName $target -Credential $creds -StartPath "C:\Users\jkcon\OneDrive\Documents" -Days 2
$machine.Firewall          = Survey-Firewall -ComputerName $target -Credential $creds
$machine.LoggedOnUsers     = Get-LoggedOnUser -ComputerName $target -Credential $creds  
$machine.RegistryStartups  = Get-Registry -regKeyArray $regArray -ComputerName $target -Credential $creds
$machine.Prefetch          = Get-Prefetch -ComputerName $target -Credential $creds
$machine.CriticalEvents    = Get-ImportantEvent -EventList $eventCSV -BeginTime (Get-Date '08/25/2020') -EndTime (Get-Date '08/31/2020') -ComputerName $target -Credential $creds
$machine.GroupedEvents     = Group-Event -eventRecord $machine.CriticalEvents -eventList $eventCSV


$machine.Report            = Format-Report -Object $machine

$machine | Export-Clixml -Path ($Path + $target + ".xml")
echo $machine.Report > ($Path + $Target + ".txt")

}

