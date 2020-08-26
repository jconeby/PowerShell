function Get-UniqueLower {
Param([Parameter(Mandatory=$True,HelpMessage="Error: Please enter the array")]$arrayObject)
  $lowerArray = foreach ($object in $arrayObject) {
     $object.ToLower() }

  $uniqueArray = $lowerArray | Get-Unique
  
  return $uniqueArray

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
                 FilePaths      = ([PSCustomObject]@{FilePaths = (Get-UniqueLower -arrayObject $proc.Group.Path) -join ','}).FilePaths
                 FilePathCount  = (Get-UniqueLower -arrayObject $proc.Group.Path).Count
                 Hashes         = ([PSCustomObject]@{Hashes = ($proc.Group.hash | Sort-Object | Get-Unique) -join ','}).Hashes
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
    $processObject
    )
    
    Process
    {
   $groupProcesses = ($processObject | Sort-Object -Unique pscomputername,path | Group-Object -Property Path | Sort-Object -Property Count )

   $groupProcesses = foreach ($proc in $groupProcesses) {
            [PSCustomObject]@{
                 Count          = $proc.Count
                 FilePath       = $proc.Name
                 Names          = ([PSCustomObject]@{Names = ($proc.Group.Name | Get-Unique) -join ','}).Names
                 PSComputerName = ([PSCustomObject]@{PSComputerName = ($proc.Group.PSComputerName | Get-Unique) -join ','}).PSComputerName
                 Hash           = $proc.Group.hash | Get-Unique
                 Group          = $proc.Group

            }
     }

     return $groupProcesses
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
                    Hash = (certutil -hashfile $file.FullName)[1]}}
        
        }
    }

}
