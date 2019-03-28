<#
.Synopsis
   Internal function to get the AppId for the Authentication Token for Microsoft Graph Security.

.DESCRIPTION
   Gets the AppId for the Authentication Token for Microsoft Graph Security.

.EXAMPLE
   Select-GraphSecurityAppId

.FUNCTIONALITY
   Select-GraphSecurityAppId is intended as an internal function to get the AppId for Authentication Token.
#>

function Select-GraphSecurityAppId {
    
    #Check for the Credential
    If ($Global:GraphSecurityCredential) {
    
        $Global:GraphSecurityCredential.GetNetworkCredential().Password
    }
    
    Else {
    
        #Write-Error 'No AppId available. Please check the AppId of the supplied credential' -ErrorAction Stop
        Get-GraphSecurityCredential
    
        $Global:GraphSecurityCredential.GetNetworkCredential().Password

    }
}
