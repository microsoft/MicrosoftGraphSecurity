function Select-GraphSecurityAppId
{
    If ($Global:GraphSecurityCredential) {
        $Global:GraphSecurityCredential.GetNetworkCredential().Password
        }
    Else {
        #Write-Error 'No AppId available. Please check the AppId of the supplied credential' -ErrorAction Stop
        Get-GraphSecurityCredential
        $Global:GraphSecurityCredential.GetNetworkCredential().Password
        }
}
