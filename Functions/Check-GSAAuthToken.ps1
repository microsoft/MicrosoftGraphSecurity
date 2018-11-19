function Check-GSAAuthToken {

    # Checking if authToken exists before running authentication
    if($global:GSAauthHeader){

        # Setting DateTime to Universal time to work in all timezones
        $DateTime = (Get-Date).ToUniversalTime()

        # If the authToken exists checking when it expires
        $TokenExpires = ($GSAauthHeader.ExpiresOn.datetime - $DateTime).Minutes

        if($TokenExpires -le 0){

            write-warning "Authentication Token expired" $TokenExpires "minutes ago"
            write-host

            Try {$Username = Select-GSAUsername}
                Catch {Throw $_}

            Try {$AppId = Select-GSAAppId}
                Catch {Throw $_}

            Get-GSAAuthToken

            }

            
        }


    # Authentication doesn't exist, calling Get-GSAAuthToken function

    else {

            Try {$Username = Select-GSAUsername}
                Catch {Throw $_}

            Try {$AppId = Select-GSAAppId}
                Catch {Throw $_}

            Get-GSAAuthToken

        }


    }
