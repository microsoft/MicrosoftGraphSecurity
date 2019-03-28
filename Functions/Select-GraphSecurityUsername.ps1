<#
.Synopsis
   Internal function to get the username for the Authentication Token for Microsoft Graph Security.

.DESCRIPTION
   Gets the username for the Authentication Token for Microsoft Graph Security.

.EXAMPLE
   Select-GraphSecurityUsername

.FUNCTIONALITY
   Select-GraphSecurityUsername is intended as an internal function to get the username for Authentication Token.
#>

function Select-GraphSecurityUsername {

    If ($Global:GraphSecurityCredential) {
    
        $Global:GraphSecurityCredential.GetNetworkCredential().Username
    
    }
    
    Else {
    
        #Write-Error 'No username available. Please check the username of the supplied credential' -ErrorAction Stop
    
        Get-GraphSecurityCredential
    
        $Global:GraphSecurityCredential.GetNetworkCredential().Username
    
    }

}
