function Set-GSAAlert
{
    [CmdletBinding()]
     Param
    (
        # Specifies the alert id
        [Parameter(Mandatory=$false,ValueFromPipeline=$true)]
        [string]$AlertId,

        #Specifies the API Version
        [Parameter(Mandatory=$false)]
        [ValidateSet("v1","Beta")]
        [string]$Version = "v1"
    )
    Begin
    {
        Try {$GSANothing = Check-GSAAuthToken}
            Catch {Throw $_}
    }
    Process
    {
        if($Version -eq "Beta"){
            #Add Beta Here
        }
        Else
        {
            
            $Resource = "security/alerts/{$AlertId}"
            #need to build the body https://developer.microsoft.com/en-us/graph/docs/api-reference/v1.0/api/alert_update
        
            try {
                $uri = "https://graph.microsoft.com/$Version.0/$($resource)"
                (Invoke-RestMethod -Uri $uri -Headers $GSAAuthHeader -Method Patch -Body $Body).value
            } 
            catch {
                $ex = $_.Exception
                $errorResponse = $ex.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($errorResponse)
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd();
                Write-Host "Response content:`n$responseBody" -f Red
                Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
                write-host
                break
            }
        }
    }
    End
    {
        #Do Tnothing
    }
}