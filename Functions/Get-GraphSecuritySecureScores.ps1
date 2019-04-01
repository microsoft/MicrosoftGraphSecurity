function Get-GraphSecuritySecureScores {
    [CmdletBinding()]
    Param
    (
        # Specifies the maximum number of results to retrieve
        [Parameter(Mandatory = $false)]
        [string]$top = "1",

        #Specifies the API Version
        [Parameter(Mandatory = $false)]
        [ValidateSet("v1", "beta")]
        [string]$Version = "beta"
    )
    Begin {
        Try {Check-GSAAuthToken}
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
                (Invoke-RestMethod -Uri $uri -Headers $GSAAuthHeader -Method Get).value
            }
            catch {
                $ex = $_.Exception
                $errorResponse = $ex.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($errorResponse)
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd();
                Write-Verbose "Response content:`n$responseBody" -f Red
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