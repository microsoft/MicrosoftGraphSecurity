<#
.Synopsis
   Sets the status of alerts in Graph Security API.

.DESCRIPTION
   Sets the status of alerts in Graph Security API.

   There are multiple parameter sets:

   assignedTo: Used for setting the name of the analyst the alert is assigned to for triage, investigation, or remediation.
   closedDateTime: Time at which the alert was closed.
   comments: Analyst comments on the alert.
   feedback: Analyst feedback on the alert. Possible values are: unknown, truePositive, falsePositive, benignPositive.
   status: Alert lifecycle status (stage). Possible values are: unknown, newAlert, inProgress, resolved.
   tags: User-definable labels that can be applied to an alert and can serve as filter conditions.
   vendor: Complex type containing details about the security product/service vendor, provider, and subprovider (for example, vendor=Microsoft)
   provider: Complex type containing details about the security product/service vendor, provider, and subprovider (for example, provider=Windows Defender ATP)
   subProvider: Complex type containing details about the security product/service vendor, provider, and subprovider (for example, subProvider=AppLocker)

   An alert identity is always required to be specified either explicity or implicitly from the pipeline.

.EXAMPLE
   Set-GSAAlert -Id D0ED9BD3-AB24-3E05-A4D3-171280CA3CB9 -Status resolved -Feedback truePositive -Vendor Microsoft -subProvider MCAS

    This marks a single specified alert as 'resolved' and as a 'truePositive'.

.EXAMPLE
   Get-GSAAlert -Id D0ED9BD3-AB24-3E05-A4D3-171280CA3CB9 | Set-GSAAlert -Status inProgress -Assignedto joe@contoso.com

    This will set the status of the specified alert as "inProgress" and who is working it "joe@contoso.com".

.FUNCTIONALITY
   Set-GSAAlert is intended to function as a mechanism for setting the status of alerts using Graph Security API.
#>
function Set-GSAAlert
{
    [CmdletBinding()]
     Param
    (
        # Specifies the alert id
        [Parameter(Mandatory=$false,ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}')]
        [string]$Id,

        #Specifies the API Version
        [Parameter(Mandatory=$false)]
        [ValidateSet("v1","Beta")]
        [string]$Version = "v1",

        #Sets the owner of the alert
        [Parameter(Mandatory=$false)]
        [ValidatePattern("[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*")]
        [string]$assignedTo,

        #Sets the close time
        [Parameter(Mandatory=$false)]
        [DateTime]$closedDateTime = (Get-Date -UFormat '+%Y-%m-%dT%H:%M:%SZ'),

        #Sets any comments
        [Parameter(Mandatory=$false)]
        [string]$comments,

        #Sets the Feedback; 0,1,2,3
        [Parameter(Mandatory=$false)]
        [ValidateSet("unknown","truePositive","falsePositive","benignPositive")]
        [string]$feedback,
   status
   tags
   vendor
   provider
   subProvider

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