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


#Function used to group baseline processes taken on a network.  This can be useful to identify anomolous processes
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
                              PathName,
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
                    Hash = (Get-FileHash $file.FullName).hash
                    
        
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
            RemotePort, State, @{name='Process';expression={(Get-Process -Id $_.OwningProcess).Name}}, CreationTime} 
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
            try
            {query user}
            catch
            {Get-CimInstance -Class Win32_ComputerSystem | Select-Object Username}
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


#Function created frome code taken from SANS whitepaper "Creating an Active Defense Powershell Framework" Author Kyle Snihur
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
if it is alive and the TTL #>

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
        $ARP
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
                    InTargetList = $object.Address -in $targets.IP
                    Alive        = $pinginfo -ne $null
                    OS           = Get-OSType -TTL $pinginfo.TimeToLive
                    }
            }
            
        }
    }    
} 

