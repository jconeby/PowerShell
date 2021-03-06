<#function used to convert all elements in an array to lower case.
This can be useful when file paths or program names on different machines have different capitalization #>

function Get-UniqueLower 
{
    [cmdletbinding()]
    Param
    ([Parameter(ValueFromPipeline=$true)]
    [Array]
    $ArrayObject
    )
    
    Process
    {   
     $lowerArray = foreach ($object in $ArrayObject) {
        $object.ToLower() }

      $lowerArray = $lowerArray | Get-Unique
  
      return $lowerArray
    }
}

#Function used to group baseline processes taken on a network.  This can be useful to identify anomolous processes
function Group-ProcessByName 
{
    [cmdletbinding()]
    Param
    ([Parameter(ValueFromPipeline=$true)]
    $processObject
    )
    
    Process
    {   
   $groupProcesses = ($processObject | Group-Object -Property Name | Sort-Object -Property Count )

   $groupProcesses = foreach ($proc in $groupProcesses) {
            [PSCustomObject]@{
                 Count          = $proc.Count
                 Name           = $proc.Name
                 PSComputerName = ([PSCustomObject]@{PSComputerName = ($proc.Group.PSComputerName | Get-Unique) -join ','}).PSComputerName
                 FilePath      = ([PSCustomObject]@{FilePaths = (Get-UniqueLower -arrayObject $proc.Group.Path) -join ','}).FilePaths
                 FilePathCount  = (Get-UniqueLower -arrayObject $proc.Group.Path).Count
                 Hash         = ([PSCustomObject]@{Hashes = ($proc.Group.hash | Sort-Object | Get-Unique) -join ','}).Hashes
                 Group          = $proc.Group

            }
     }

     return $groupProcesses
     }
 }


#Function used to perform least frequency analysis of processes on a network
function Group-ProcessByPath 
{
    [cmdletbinding()]
    Param
    ([Parameter(ValueFromPipeline=$true)]
    $processObject,

    [Int32]
    $Threshold
    )
    
    Process
    {
   $groupProcesses = ($processObject | Sort-Object -Unique pscomputername,path | Group-Object -Property Path | Sort-Object -Property Count )

   $groupProcesses = foreach ($proc in $groupProcesses) {
            [PSCustomObject]@{
                 Count          = $proc.Count
                 FilePath       = $proc.Name
                 Name          = ([PSCustomObject]@{Names = ($proc.Group.Name | Get-Unique) -join ','}).Names
                 PSComputerName = ([PSCustomObject]@{PSComputerName = ($proc.Group.PSComputerName | Get-Unique) -join ','}).PSComputerName
                 Hash           = $proc.Group.hash | Get-Unique
                 Group          = $proc.Group

            }
     }
     if ($Threshold -eq $null)
     {
       return $groupProcesses  
     }
     else
     {
       return ($groupProcesses | Where-Object {$_.Count -le $Threshold})  
     }
     
     }

     }


#Function used to pull processes running on machines on a network
function Get-WmiProcess 
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            Get-WmiObject win32_Process | 
                Select-Object Name, 
                              ProcessID,
                              @{name       ='ParentProcessName'
                                expression ={If ((Get-Process -id $_.ParentProcessID).Name) {(Get-Process -id $_.ParentProcessID).Name}
                                else {Write-Output "?"}}}, 
                                ParentProcessID, 
                                Path, 
                                CommandLine,
                              @{name       = "hash"
                                expression = {If (Get-Command Get-FileHash) {(Get-FileHash -Algorithm MD5 -Path $_.Path).hash}
                                              else {(certutil.exe -hashfile $_.Path SHA256)[1] -replace " ",""}}},
                              @{name       = "Owner"
                                expression = {@($_.getowner().domain, $_.getowner().user) -join "\"}
                              }
                             
                              
        }
    }
} 

#Function used to pull services running on machines on a network
function Get-WmiService 
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    ) 
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            Get-WmiObject win32_Service | 
                Select-Object Name,
                              @{n='PathName';e={($_.PathName.toLower())}},
                              State,
                              StartMode,
                              StartName,
                              ProcessId,
                              @{n='ProcessName';e={(Get-Process -id $_.ProcessId | Select Name).Name}}

        }
    }
}


#Will pull the registry key info for all keys listed in an array.
function Get-Registry 
{
    [cmdletbinding()]
    Param
    (
        [Parameter()]
        [Array[]]
        $regKeyArray,

        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
         Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            foreach ($key in $using:regKeyArray)
                {
                    Get-ItemProperty -Path $key
                }
            
        }
    }   
}



function Get-RegistryIOC 
{
    [cmdletbinding()]
    Param
    (
        [Parameter()]
        [PSCustomObject]
        $RegList,

        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            foreach ($key in $using:RegList.Key)
                {
                   if (Get-ItemProperty -Path $key) {
                        $Content = Get-ItemProperty -Path $key
                        [PSCustomObject]@{ 
                        Key             = $key
                        IOC             = ($using:RegList | Where {$_.Key -eq $key}).IOC 
                        Data            = $Content.Data
                        Generation      = $Content.Generation
                        DependOnService = $Content.DependOnService
                        Description     = $Content.Description
                        DisplayName     = $Content.DisplayName
                        ImagePath       = $Content.ImagePath
                        Content         = $Content }
                   }
                }
        }
              
                            
    }   
}


#Pulls the event logs for all the most important events listed in the CSV file
function Get-ImportantEvent 
{ 
    [cmdletbinding()]
    Param
    (
        [Parameter()]
        [PSCustomObject]
        $EventList,

        [DateTime]
        $BeginTime,

        [DateTime]
        $EndTime,

        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }

    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            foreach ($event in $using:EventList) {
                 Get-WinEvent -FilterHashtable @{ LogName = $event.Event_Log; StartTime=$using:BeginTime; EndTime=$using:EndTime; Id=$event.ID} 
                    }
        }
    }
}


function Group-Event 
{
    [cmdletbinding()]
    Param
    (
        [Parameter()]
        $EventRecord,

        [PSCustomObject]
        $EventList
    )

   Process
   {
       $groupEvents = ($EventRecord | Group-Object -Property ID | Sort-Object -Property Count -Descending)

       $groupEvents = foreach ($event in $groupEvents) {
        
            [pscustomObject]@{
            Count = $event.Count
            ID = $event.Name
            Description = ($eventList | Where-Object {$_.ID -eq $event.Name}).Description
            }

          }
    
        return $groupEvents
   }   
}


function Get-RecentModFile 
{
    [cmdletbinding()]
    Param
    (
        [Parameter()]
        [String]
        $StartPath,

        [Int32]
        $Days,

        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {   
         Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
                $files = Get-ChildItem -File -Path $using:startPath -Recurse | Where-Object {$_.LastWriteTime -gt (get-date).addDays(-($using:Days)) -or $_.CreationTime -gt (get-date).addDays(-($using:Days))}

                foreach ($file in $files) {
                  [PSCustomObject]@{
                    Name = $file.FullName
                    Hash = (Get-FileHash $file.FullName).hash
                   }
                }
    
         }
    }

}

function Get-BaselineHash 
{
    [cmdletbinding()]
    Param
    (
        [Parameter()]
        [String]
        $StartPath,

        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {   
         Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
                $files = Get-ChildItem -File -Path $using:startPath -Recurse

                foreach ($file in $files) {
                  [PSCustomObject]@{
                    Name = $file.FullName
                    Hash = (Get-FileHash $file.FullName).hash }
                }

         }
    }
    
}


function Get-LGroup
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            Get-WmiObject -Class Win32_Group  
        }
    }    
} 


function Get-LUser
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock { 
            Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'"
           
        }
        
    } 
} 



function Get-LGroupMembers
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            try
            {foreach ($name in (Get-WmiObject -Class Win32_Group).Name) {
             [PSCustomObject]@{
             GroupName = $name 
             Member    = (Get-LocalGroupMember $name)}                                   
             }}
      
            catch
            {foreach ($name in (Get-WmiObject -Class Win32_Group).Name) {
             [PSCustomObject]@{
             GroupName = $name 
             Member    = Get-WmiObject win32_groupuser | Where-Object {$_.groupcomponent -like "*$name*"} | ForEach-Object {  
             $_.partcomponent –match ".+Domain\=(.+)\,Name\=(.+)$" > $null  
             $matches[1].trim('"') + "\" + $matches[2].trim('"')  
             }  
   
             }
             }}
        }
        
    } 
} 



function Get-Connection
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            Get-NetTCPConnection -State Established | 
            Select-Object -Property LocalAddress, LocalPort, RemoteAddress, 
            RemotePort, State, OwningProcess, @{name='Process';expression={(Get-Process -Id $_.OwningProcess).Name}}, CreationTime 
        }
     }
        
} 


function Get-SchTask
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock { 
            Get-ScheduledTask
            
        }
    }    
} 


function Get-LoggedOnUser
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            $queryuser     = query user
            $loggedOnUsers = Get-WmiObject win32_loggedonuser
            $sessions      = Get-WmiObject win32_logonsession
            $logons = @()

            foreach ($user in $loggedOnUsers)
            {
                $user.Antecedent -match '.+Domain="(.+)",Name="(.+)"$' > $nul
                $domain = $matches[1]
                $username = $matches[2]
    
                $user.Dependent -match '.+LogonId="(\d+)"$' > $nul
                $LogonId = $matches[1]

                $logons += [PSCustomObject]@{
                    Domain  = $domain
                    User    = $username
                    LogonId = $LogonId
                    }    
            }

            $logonDetail = foreach ($session in $sessions)
            {
            <# Determined what each login id cooresponds too from the link below
            https://social.technet.microsoft.com/Forums/Lync/en-US/ff70e069-5453-4250-b5c7-8d52ce558ce2/logon-types-in-windows-server?forum=winserverDS    
            #>  
                $logonType = switch ($session.LogonType)
                        {
                            1 {"Interactive"}
                            2 {"Network" }
                            3 {"Batch"}
                            4 {"Service"}
                            5 {"Unlock"}
                            6 {"Network Cleartext"}
                            7 {"New Credentials"}
                            8 {"Remote Interactive"}
                            9 {"Cached Interactive"}
                            Default {"Unknown"}
                        }

                                 [PSCustomObject]@{
                                    LogonId     = $session.LogonId
                                    LogonTypeId = $session.LogonType
                                    LogonType   = $logonType
                                    Domain      = ($logons | Where {$_.LogonId -eq $session.LogonId}).Domain
                                    User        = ($logons | Where {$_.LogonId -eq $session.LogonId}).User
                                    StartTime   = [management.managementdatetimeconverter]::todatetime($session.starttime)
                                    }

                }

                [PSCustomObject]@{
                                    QueryUserResults = $queryuser
                                    LogonDetail      = $logonDetail
                                 }
         
         }

           
    }    
} 

function Get-Prefetch 
{
    [cmdletbinding()]
    Param
    (
        [Parameter()]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {   
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            $pfconf = (Get-ItemProperty "hklm:\system\currentcontrolset\control\session manager\memory management\prefetchparameters").EnablePrefetcher 

            Switch -Regex ($pfconf) {
                "[1-3]" {
                    $o = "" | Select-Object FullName, CreationTimeUtc, LastAccessTimeUtc, LastWriteTimeUtc
                    ls $env:windir\Prefetch\*.pf | % {
                        $o.FullName = $_.FullName;
                        $o.CreationTimeUtc = Get-Date($_.CreationTimeUtc) -format o;
                        $o.LastAccesstimeUtc = Get-Date($_.LastAccessTimeUtc) -format o;
                        $o.LastWriteTimeUtc = Get-Date($_.LastWriteTimeUtc) -format o;
                        $o }
                         }
            default {
                Write-Output "Prefetch not enabled on ${env:COMPUTERNAME}."
                    }
            }
        } 

    }
}

#Found Survey-Firwall function at https://github.com/ralphmwr/PowerShell-ThreatHunting/blob/master/Survey.psm1
function Survey-Firewall
{
    [CmdletBinding()]
    param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            $rules         = Get-NetFirewallRule | Where-Object {$_.enabled}
            $portfilter    = Get-NetFirewallPortFilter
            $addressfilter = Get-NetFirewallAddressFilter

            foreach ($rule in $rules) {
                $ruleport    = $portfilter | Where-Object {$_.InstanceID -eq $rule.instanceid}
                $ruleaddress = $addressfilter | Where-Object {$_.InstanceID -eq $rule.instanceid}
                $data = @{
                    InstanceID    = $rule.instanceid.tostring()
                    Direction     = $rule.direction.tostring()
                    Action        = $rule.action.tostring()
                    LocalAddress  = $ruleaddress.LocalAddress.tostring()
                    RemoteAddress = $ruleaddress.RemoteAddress.tostring()
                    Protocol      = $ruleport.Protocol.tostring()
                    LocalPort     = $ruleport.LocalPort -join ","
                    RemotePort    = $ruleport.RemotePort -join ","
                }
                New-Object -TypeName psobject -Property $data
            }
        }
    }
}


function Write-ImportantMessage 
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [Int32]
        $EventID,

        [String]
        $AuthPackage
    )

  Process 
  {

      if ($EventID -eq 4697)
      {
         return 'Service started that could be a malicious script'
      }
      elseif ($EventID -eq 4657)
      {
         return 'A registry value was modified'
      }
      elseif ($EventID -eq 4624 -and $AuthPackage -eq 'NTLM')
      {
         return 'Pass the Hash Attack'
      }
      elseif ($EventId -eq 4698)
      {
        return 'A scheduled task was created'
      }
      elseif ($EventID -eq 4625 -and $AuthPackage -eq 'NTLM')
      {
         return 'Pass the Hash Attack Attempted'
      }

      elseif ($EventID -eq 1102)
      {
         return 'Audit Log was Cleared'
      }

      elseif ($EventID -eq 4728 -or $EventID -eq 4732 -or $EventId -eq 4756)
      {
         return 'User Added to Privileged Group'
      }

  }
 }

 
 function Format-Events 
 {
     [CmdletBinding()]
        param
        (
            [Parameter()]
            $logs
        )

    Process
    {
        $logsObject = ForEach ($log in $logs) {
        [PSCustomObject]@{
             IP           = $log.PSComputerName
             Time         = $log.TimeGenerated
             EventID      = $log.EventID
             Index        = $log.Index
             Message      = $log.Message
             AccountName  = $log.ReplacementStrings[5]
             AuthPackage  = $log.ReplacementStrings[10]
             LogonType    = $log.ReplacementStrings[8]
             AlertMessage = Write-ImportantMessage -EventID $log.EventId -AuthPackage $log.ReplacementStrings[10]}
        }
          return $logsObject

    }

}
 

function Group-SecurityEventID 
{
    [cmdletbinding()]
    Param
    (
        [Parameter()]
        $EventRecord,

        [PSCustomObject]
        $EventList
    )

   Process
   {
       $groupEvents = ($EventRecord | Group-Object -Property EventID | Sort-Object -Property Count -Descending)

       $groupEvents = foreach ($event in $groupEvents) {
        
            [pscustomObject]@{
            Count = $event.Count
            ID = $event.Name
            Description = ($eventList | Where-Object {$_.ID -eq $event.Name}).Description
            }

          }
    
        return $groupEvents
   }   
}


#Function taken from SANS whitepaper "Creating an Active Defense Powershell Framework" Author Kyle Snihur

function Create-Report 
{
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $filename,
        [Parameter(Mandatory = $true)]
        [ValidateSet("json","csv")]
        [string]
        $fileType = "csv",
        [Parameter(Mandatory = $true)]
        $scriptvariable,
        [Parameter(Mandatory = $true)]
        [string]
        $outputFolder
    )


   Process
   {
        if($fileType -eq "json"){
            Invoke-Expression $scriptvariable | Where-Object {$_} | ConvertTo-Json `
            | Out-File -Force ([string]::Concat($outputFolder,$filename,".",$fileType))
        }
        elseif($fileType -eq "csv"){
            Invoke-Expression $scriptvariable | Where-Object {$_} `
            | Export-Csv -Path ([string]::Concat($outputFolder,$filename,".",$fileType)) -NoTypeInformation -Force
        }
    }

}

<#Function created frome code taken from SANS whitepaper "Creating an Active Defense Powershell Framework" Author Kyle Snihur
This function can be usefull for creating a software map for normal application installs on a network.  You could use this in combination with
a Group-Object to determine anomolies #>

function Get-Software 
{
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )

   Process
   {
       $Software = Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\ `
       CurrentVersion\Uninstall\*" | Select DisplayName,DisplayVersion,Publisher,InstallDate,UninstallString,InstallLocation

       $Software += Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" `
       | Select DisplayName,DisplayVersion,Publisher,InstallDate,UninstallString,InstallLocation

       $Software = $Software | Where-Object {[string]::IsNullOrWhiteSpace($_.displayname) -eq $false} `
       | Select-Object @{name="ComputerName";expression={$env:COMPUTERNAME}}, * | Sort-Object DisplayName

       $Software
    }
}


function Get-OSType
{
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        [int] $TTL
    )

   Process
   {
       switch ($TTL)
       {
            {$TTL -lt 65} {return "Linux"}
            {$TTL -in (65..128)} {return "Windows"}
            Default {return "OS Unknown"}
       }
    }
}


<#Function created frome code taken from SANS whitepaper "Creating an Active Defense Powershell Framework" Author Kyle Snihur
This will pull the ARP table from the end point #>
function Get-ARP
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            $arp = arp -a

            foreach ($line in $arp)
            { 
            $line = $line -replace '^\s+',''
            $line = $line -split '\s+'
            if($line[0] -ne $null -and $line[1] -ne $null -and $line[2] -ne $null -and $line[0] -ne "Interface:" `
                -and $line[0] -ne "Internet" ){
                [PSCustomObject]@{
                    ComputerName = $env:COMPUTERNAME
                    Address      = $line[0]
                    MAC          = $line[1]
                    Type         = $line[2] }
                }
            }
        }
    }    
} 

<#I created this function to get additional info from ARP such as OS
The target will ping all the hosts in its ARP cache and check to see
if it is alive, determine if it is Windows or Linux, and tell you if the 
ip addresses are within the list.  This may be able to identify rogue devices. #>

function Get-ARPInfo
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential,

        [PSCustomObject]
        $ARPObject,

        [PSCustomObject]
        $TargetList
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            foreach ($object in $ARP) {
                $pinginfo = Test-Connection -ComputerName $object.Address -Count 1 -ErrorAction SilentlyContinue             
                [PSCustomObject]@{
                    ComputerName = $object.ComputerName
                    Address      = $object.Address
                    MAC          = $object.MAC
                    Type         = $object.Type
                    InTargetList = $object.Address -in $TargetList.IP
                    Alive        = $pinginfo -ne $null
                    OS           = Get-OSType -TTL $pinginfo.TimeToLive
                    }
            }
            
        }
    }    
} 

# NEED TO TEST FUNCTION REMOTELY
#Received database from https://macaddress.io/database-download/csv
#This may be able to identify rougue end points on the network

function Get-VendorInfoFromARP
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential,

        [PSCustomObject]
        $macdb
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            $arp = arp -a

            foreach ($line in $arp)
            { 
            $line = $line -replace '^\s+',''
            $line = $line -split '\s+'
            if($line[0] -ne $null -and $line[1] -ne $null -and $line[2] -ne $null -and $line[0] -ne "Interface:" `
                -and $line[0] -ne "Internet" ){
                [PSCustomObject]@{
                    ComputerName = $env:COMPUTERNAME
                    Address      = $line[0]
                    MAC          = $line[1]
                    Type         = $line[2]
                    Vendor       = ($using:macdb | Where {$_.oui -eq ($line[1][0..7] -join '')}).companyName }
                }
            }
        }
    }    
} 

<#This function will perform a dir walk of hosts on a network
By using the .NET System.IO.Direction, the function is over 100x faster than using Get-ChildItem #>

 function Get-DirWalk
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential,

        [string]
        $path
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            $files = [System.IO.Directory]::EnumerateFiles($using:path,'*.*','AllDirectories')
            
            foreach ($file in $files) {
                
                    [PSCustomObject]@{
                        Name = $file }
            }       
            
        }
    }
        
}

<#This function will take a dir walk and collect hashes
By using the .NET System.IO.Direction, the function is much faster than Get-FileHash #>

function Get-DirWalkHash
{
    [cmdletbinding()]
    Param
    (   [Parameter(ValueFromPipeline=$true)]

        [string[]]
        $ComputerName,

        [pscredential]
        $Credential,

        [string]
        $path,
        
         [string]
        $algorithm = 'SHA1'
    )

    Process
    {   
        
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            $files = [System.IO.Directory]::EnumerateFiles($using:path,'*.*','AllDirectories')
            
            $files = foreach ($file in $files) {
                    [PSCustomObject]@{
                        Name = $file
                        }
                     }
            
            foreach($file in $files) {
               [PSCustomObject]@{
               Name = $file.Name
               Hash = [System.Bitconverter]::ToString([System.Security.Cryptography.HashAlgorithm]::Create('SHA1').ComputeHash([System.Text.Encoding]::UTF8.GetBytes($file[0].Name))) }
            }   

        }
    }
}

 

<# This function will group the dir walks collected from the hosts and perform
least frequency analysis of the hashes found to gather files that are only found a certain
number of hosts determined by the threshold #>

function Group-FilesByHash 
{
    [cmdletbinding()]
    Param
    ([Parameter(ValueFromPipeline=$true)]
    $dirWalk,

     [Int32]
    $threshold
    )
    
    Process
    {   
   $groupFiles = ($dirWalk | Group-Object -Property Hash | Where {$_.Count -le $threshold} )

   $groupFiles = foreach($file in $groupFiles) {
          [PSCustomObject] @{
                Count      = $file.Count
                FullName   = $file.Group.FullName
                Hash       = $file.Group.Hash
                }
             }

     return $groupFiles
     }
 }

<# You can use this function to add a message within a Windows events object
 This can make it much easier to query for a specific item within the message
 field of the event logs.
 Example: Add-Message -Events $baseline.Events
 #>
 
 function Add-Message 
{
    [cmdletbinding()]
    Param
    (
        [Parameter()]
        [PSCustomObject]
        $Events
    )

   Process
   {
        $events = foreach ($event in $events)
            { $event | Add-Member -NotePropertyName SearchMessage -NotePropertyValue ($event.Message -split "`n")}
         
        return $events
   }
   
   function Get-NamedPipe 
{ 
    [cmdletbinding()]
    Param
    (
        [Parameter()]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }

    Process
    {
        $namedPipes = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
            [System.IO.Directory]::GetFiles("\\.\\pipe\\")
        }

        foreach ($pipe in $namedPipes)
        {
            [PSCustomObject]@{
                                Name = $pipe
                                PSComputerName = $pipe.PSComputerName
                             }
        }

    }
}

function Get-Netstat {
$text = netstat -ano
$lines = for($i=4;$i -lt $text.Length;$i++) {$text[$i].Replace('\s','')}
$objects = @()

foreach($line in $lines)
{
  $line = $line.Split(' ')
  $newArray = @()
  
  foreach($char in $line)
  {
    if($char.Length -gt 0)
    {
      $newArray += $char
    }
  }

  $object = [PSCustomObject]@{
                Protocol = $newArray[0]
                LocalAddress = $newArray[1]
                ForeignAddress = $newArray[2]
                State          = If($newArray[0] -eq 'TCP') {$newArray[3]} else {$null}
                PID            = If($newArray[0] -eq 'TCP') {$newArray[4]} else {$newArray[3]}
                ProcessName    = if(($newArray[4] -ne $null) -and ($newArray[0] -eq 'TCP')){(Get-Process -Id $newArray[4]).Name} elseif(($newArray[3] -ne $null) -and ($newArray[0] -eq 'UDP')){(Get-Process -Id $newArray[3]).Name}
               
  }

  $objects += $object

}

return $objects

}

function Get-ServiceInfo
{
    [cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true)]
        [string[]]
        $ComputerName,

        [pscredential]
        $Credential
    )
    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }
    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {
        Get-WmiObject -Class Win32_Service | Select State,Name,DisplayName,ProcessId,
        @{n='ProcessName';e={(Get-WmiObject -Class Win32_Process -Filter "ProcessId='$($_.ProcessId)'").Name}}, 
        @{n='ParentProcessID';e={(Get-WmiObject -Class Win32_Process -Filter "ProcessId='$($_.ProcessId)'").ParentProcessID}},
        @{n='ParentProcessName';e={(Get-Process -ID (Get-WmiObject -Class Win32_Process -Filter "ProcessId='$($_.ProcessId)'").ParentProcessID).Name}}
            
        }                          
                                 
    }
} 

function Export-EventLog
{

[cmdletbinding()]
    Param
    (
        [Parameter(ValueFromPipeline=$true,Mandatory=$true)]
        [string[]]
        $ComputerName,

        [Parameter(Mandatory=$true)]
        [pscredential]
        $Credential,

        [Parameter(Mandatory=$false)]
        [string]
        $LogName='Security',

        [Parameter(Mandatory=$false)]
        [PSCustomObject]
        $EventList,

        [Parameter(Mandatory=$false)]
        [string]
        $StartDate = (Get-Date).AddDays(-1).ToString('MM/dd/yyyy'),

        [Parameter(Mandatory=$false)]
        [string]
        $EndDate = (Get-Date).AddDays(1).ToString('MM/dd/yyyy'),

        [Parameter(Mandatory=$false)]
        [string]
        $Destination = 'C:\Temp\EventLog.evtx',

        [Parameter(Mandatory=$false)]
        [string]
        $LocalPath = 'C:\Temp\EventLog.evtx'

    )

    Begin
    {
        If (!$Credential) {$Credential = Get-Credential}
    }

    Process
    {
        Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock {

        # Test if destination file already exists
        if(Test-Path -Path $using:Destination)
        {
           return Write-Error -Message "File already exists"
        }

        # create time frame
        function GetMilliseconds ($date) {
            $ts = New-TimeSpan -Start $date -End (Get-Date)
            [math]::Round($ts.TotalMilliseconds)
            } # end function

         $StartDate = GetMilliseconds(Get-Date $using:StartDate)
         $EndDate = GetMilliseconds(Get-Date $using:EndDate)
        
        # If an event list is used create a query string for it
        if($using:EventList -ne $null) 
        {
             # Put only the IDs of the selected logName into an array
             $IDs = $using:EventList | Where-Object {$_.Event_Log -eq $using:LogName} | Select ID

            # Create the start of the query string
            $queryString = "("

            # Loop through to add all the Event IDs to query string
            for($i=0;$i -lt ($IDs.Length -1);$i++)
            {
              $nextString = $IDs[$i].ID.ToString()
              $queryString += ("EventID=$nextString" + " or ")

            } #end of loop

            # Handle the last Event ID
            [Int32]$lastNum = ($IDs.Length - 1)
            $lastString = $IDs[$lastNum].ID.ToString()
            $queryString += "EventID=$lastString)"

            # Complete Query string
            $query = "*[System[$queryString and TimeCreated[timediff(@SystemTime) >= $endDate] and TimeCreated[timediff(@SystemTime) <= $startDate]]]"

          } # end of if

          else {
            $query = "*[System[TimeCreated[timediff(@SystemTime) >= $endDate] and TimeCreated[timediff(@SystemTime) <= $startDate]]]"

          } # end of else

        # Create Event Session Object
        $EventSession = New-Object System.Diagnostics.Eventing.Reader.EventLogSession

        # Export filtered event log to destination machine
        $EventSession.ExportLogAndMessages($using:LogName,'LogName',$query,$using:Destination)


    }#End of Script Block

    # Create a session with the remote machine
    $session = New-PSSession -ComputerName $ComputerName -Credential $creds

    # Copy the file from the remote machine to your local machine
    Copy-Item -Path $Destination -Destination $LocalPath -FromSession $session

    # Remove event log from remote machine
    Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock { Remove-Item -Path $using:Destination }

  }#End of Process

}
