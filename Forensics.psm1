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

            Get-ChildItem -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs | ForEach-Object {
 
                 $files = Get-ItemProperty ("HKCU:\" + $_.Name.Substring($_.Name.IndexOf('\')+1))
                 $extension = $_.Name.Substring($_.Name.IndexOf('.')+1)

                     $files.PSObject.Properties | ForEach-Object {
                          if($_.Name -match "^\d+$")
                          {
                              [PSCustomObject]@{
                                               Extension = $extension
                                               FileName = [System.Text.Encoding]::ASCII.GetString($_.Value)
                                               }
                          } #End if
                     } #End ForEach

                } #End ForEach
        
      } #End Invoke

    } #End Process 


}
