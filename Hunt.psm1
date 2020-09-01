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
                 FilePath       = ([PSCustomObject]@{FilePaths = (Get-UniqueLower -arrayObject $proc.Group.Path) -join ','}).FilePaths
                 FilePathCount  = (Get-UniqueLower -arrayObject $proc.Group.Path).Count
                 Hash           = ([PSCustomObject]@{Hashes = ($proc.Group.hash | Sort-Object | Get-Unique) -join ','}).Hashes
                 Group          = $proc.Group

            }
     }

     return $groupProcesses
     }
 }


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
                    Hash = try {(Get-FileHash $file.FullName).hash}
                    catch {(certutil -hashfile $file.FullName)[1]}
                    }}
        
        }
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
                    Hash = try {(Get-FileHash $file.FullName).hash}
                    catch {(certutil -hashfile $file.FullName)[1]}
                    }}
        
        }
    }

}


<# This code comes from https://github.com/davehull/Kansa. I just turned it into a function to
fit our purposes. #>

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
            try
            {Get-WmiObject -Class Win32_Group}
            catch
            {net localgroup administrators}
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
            try
            {Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'"}
            catch
            {wmic useraccount list brief}
        }
        
    } 
} 



function Get-LGroupMember
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
            try
            {Get-NetTCPConnection -State Established | 
            Select-Object -Property LocalAddress, LocalPort, RemoteAddress, 
            RemotePort, State, @{name='Process';expression={(Get-Process -Id $_.OwningProcess).Name}}, CreationTime}
            catch
            {netstat -ano}
        }
    }    
} 


