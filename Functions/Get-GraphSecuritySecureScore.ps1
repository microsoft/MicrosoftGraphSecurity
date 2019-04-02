<#
.Synopsis
   Gets secure scores in Microsoft Graph Security.

.DESCRIPTION
   Gets secure score in Microsoft Graph Security.

   Without parameters, Get-GraphSecuritySecureScore gets 100 secure scores and associated properties.

.EXAMPLE
   Get-GraphSecuritySecureScore

    This will default grab the Top 100 secure scores.

.FUNCTIONALITY
   Get-GraphSecuritySecureScore is intended to function as a mechanism for getting secure scores using Microsoft Graph Security.
#>
function Get-GraphSecuritySecureScore {
    [CmdletBinding()]
    Param
    (
        # Specifies the maximum number of results to retrieve
        [Parameter(Mandatory = $false)]
        [string]$top = "100",

        #Specifies the API Version
        [Parameter(Mandatory = $false)]
        [ValidateSet("v1", "beta")]
        [string]$Version = "beta"
    )
    Begin {
        Try {Test-GraphSecurityAuthToken}
        Catch {Throw $_}
    }
    Process {
        if ($Version -eq "beta") {
            $Resource = "security/secureScores?`$top=$top"
            try {
            if($Version -eq "beta"){
                $uri = "https://graph.microsoft.com/$Version/$($resource)"
            }
            Else{
                #$uri = "https://graph.microsoft.com/$Version.0/$($resource)"
                Write-Error "Secure Score is not yet implemented in v1.0 API"
                break
            }
                (Invoke-RestMethod -Uri $uri -Headers $GraphSecurityAuthHeader -Method Get).value
            }
            catch {
                $ex = $_.Exception
                $errorResponse = $ex.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($errorResponse)
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd();
                Write-Verbose "Response content:`n$responseBody"
                Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"

                break
            }
        }
        Else {


        }
    }
    End {
        #Do nothing
    }
}