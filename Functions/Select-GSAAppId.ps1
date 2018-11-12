function Select-GSAAppId
{
    If ($Global:GSACredential) {
        $Global:GSACredential.GetNetworkCredential().Password
        }
    Else {
        #Write-Error 'No AppId available. Please check the AppId of the supplied credential' -ErrorAction Stop
        Get-GSACredential
        $Global:GSACredential.GetNetworkCredential().Password
        }
}
