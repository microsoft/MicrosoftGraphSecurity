<#
.Synopsis
   Internal function to test if the current sessions has a Authentication Token for Microsoft Graph Security.

.DESCRIPTION
   Tests if the current sessions has a Authentication Token for Microsoft Graph Security.

.EXAMPLE
   Test-GraphSecurityAuthToken

.FUNCTIONALITY
   Test-GraphSecurityAuthToken is intended as an internal function to test for Authentication Token.
#>

function Test-GraphSecurityAuthToken {

    # Checking if authToken exists before running authentication
    if($global:GraphSecurityauthHeader){

        # Setting DateTime to Universal time to work in all timezones
        $DateTime = (Get-Date).ToUniversalTime()

        # If the authToken exists checking when it expires
        $TokenExpires = ($GraphSecurityauthHeader.ExpiresOn.datetime - $DateTime).Minutes

        if($TokenExpires -le 0){

            #Token is expired, check for UserName and AppId, and go get a token
            write-warning "Authentication Token expired $TokenExpires minutes ago"

            Try {$Username = Select-GraphSecurityUsername}
                Catch {Throw $_}

            Try {$AppId = Select-GraphSecurityAppId}
                Catch {Throw $_}

            write-warning "Refreshing Auth Token"
            Get-GraphSecurityAuthToken

        }
    }


    # Authentication doesn't exist, calling Get-GSAAuthToken function

    else {

            Try {$Username = Select-GraphSecurityUsername}
                Catch {Throw $_}

            Try {$AppId = Select-GraphSecurityAppId}
                Catch {Throw $_}

            Get-GraphSecurityAuthToken

        }


    }
