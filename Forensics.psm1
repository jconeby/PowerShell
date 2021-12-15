#---------------------Collection of Windows Forensics Functions-------------------

<# \RecentDocs

HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs

These will show recent files which have been interacted with by the user

#>
function Get-RecentDocs
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

            $files = Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.xlsx

            $files.PSObject.Properties | ForEach-Object {
              if($_.Name -match "^\d+$")
              {
                [PSCustomObject]@{
                              Keyname = $_.Name; 
                              FileName = [System.Text.Encoding]::ASCII.GetString($_.Value)}
              
              } #End of If
            } # End of foreach

               
           }
        
      } 
} 
