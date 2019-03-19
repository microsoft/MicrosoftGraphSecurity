function Select-GraphSecurityUsername
{
    If ($Global:GraphSecurityCredential) {
        $Global:GraphSecurityCredential.GetNetworkCredential().Username
        }
    Else {
        #Write-Error 'No username available. Please check the username of the supplied credential' -ErrorAction Stop
        Get-GraphSecurityCredential
        $Global:GraphSecurityCredential.GetNetworkCredential().Username
        }
}
