function Get-GSAAlerts
{
    [CmdletBinding()]
     Param
    (
        # Specifies the maximum number of results to retrieve
        [Parameter(Mandatory=$false)]
        [string]$top = "10",

        #Specifies the API Version
        [Parameter(Mandatory=$false)]
        [ValidateSet("v1","Beta")]
        [string]$Version = "v1"
    )
    Begin
    {
        Try {Check-GSAAuthToken}
           Catch {Throw $_}
    }
    Process
    {
        if($Version -eq "Beta"){
            #Add Beta Here
        }
        Else
        {
            
            $Resource = "security/alerts?`$top=$top"
            #need something for filters
            #GET /security/alerts?$filter={property} eq '{property-value}'
            #GET /security/alerts?$filter={property} eq '{property-value}'&$top=5
        
            try {
                $uri = "https://graph.microsoft.com/$Version.0/$($resource)"
                (Invoke-RestMethod -Uri $uri -Headers $GSAAuthHeader -Method Get).value
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