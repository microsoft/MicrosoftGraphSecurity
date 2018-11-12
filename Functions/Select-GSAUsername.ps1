function Select-GSAUsername
{
    If ($Global:GSACredential) {
        $Global:GSACredential.GetNetworkCredential().Username
        }
    Else {
        #Write-Error 'No username available. Please check the username of the supplied credential' -ErrorAction Stop
        Get-GSACredential
        $Global:GSACredential.GetNetworkCredential().Username
        }
}
