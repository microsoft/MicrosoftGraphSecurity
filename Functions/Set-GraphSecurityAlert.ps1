<#
.Synopsis
   Sets the status of alerts in Microsoft Graph Security.

.DESCRIPTION
   Sets the status of alerts in Microsoft Graph Security.

   There are multiple parameter:

   assignedTo: Used for setting the name of the analyst the alert is assigned to for triage, investigation, or remediation.
   closed: Used to close the alert [default is no]
   closedDateTime: Time at which the alert was closed. [default is current date and time]
   comments: Analyst comments on the alert.
   feedback: Analyst feedback on the alert. Possible values are: unknown, truePositive, falsePositive, benignPositive.
   status: Alert lifecycle status (stage). Possible values are: unknown, newAlert, inProgress, resolved.
   tags: User-definable labels that can be applied to an alert and can serve as filter conditions.

   An alert id is always required to be specified either explicity or implicitly from the pipeline.

.EXAMPLE
   Set-GraphSecurityAlert -id D0ED0BD3-AB24-3E05-A4D3-171280CA3CB9 -Status resolved -Feedback truePositive

    This marks a single specified alert as 'resolved' and as a 'truePositive'.

.EXAMPLE
   Get-GraphSecurityAlert -id D0ED0BD3-AB24-3E05-A4D3-171280CA3CB9 | Set-GraphSecurityAlert -Status inProgress -Assignedto joe@contoso.com

    This will set the status of the specified alert as "inProgress" and who is working it "joe@contoso.com".

.FUNCTIONALITY
   Set-GraphSecurityAlert is intended to function as a mechanism for setting the status of alerts using Microsoft Graph Security.
#>

function Set-GraphSecurityAlert {

    [CmdletBinding()]

    Param
    (

        # Specifies the alert id
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [string]$id,

        #Specifies the API Version
        [Parameter(Mandatory = $false)]
        [ValidateSet("v1", "Beta")]
        [string]$Version = "v1",

        #Sets the owner of the alert
        [Parameter(Mandatory = $false)]
        [ValidatePattern("[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*")]
        [string]$assignedTo,

        #sets the alert to closed
        [Parameter(Mandatory = $false)]
        [switch]$Closed,

        #sets the alert to open
        [Parameter(Mandatory = $false)]
        [switch]$Open,

        #Sets the close time
        [Parameter(Mandatory = $false)]
        [datetime]$closedDateTime,

        #Sets any comments
        [Parameter(Mandatory = $false)]
        [string]$comments,

        #Sets the Feedback; 0,1,2,3
        [Parameter(Mandatory = $false)]
        [ValidateSet("unknown", "truePositive", "falsePositive", "benignPositive")]
        [string]$feedback,

        #Sets the Feedback; 0,1,2,3
        [Parameter(Mandatory = $false)]
        [ValidateSet("unknown", "newAlert", "inProgress", "resolved")]
        [string]$Status,

        #Sets any tags
        [Parameter(Mandatory = $false)]
        [string]$Tags

    )

    Begin {

        Try {Test-GraphSecurityAuthToken }
        Catch { Throw $_ }

        If ($Closed -and $Open) {
            Write-Error "You cannot specify open and close parameters at the same time"
            exit
        }

    }

    Process {
        $Resource = "security/alerts/$id"

        if ($Version -eq "Beta") {

            $uri = "https://graph.microsoft.com/beta/$($resource)"

        }

        Else {

            $uri = "https://graph.microsoft.com/$Version.0/$($resource)"

        }

        $alert = Invoke-RestMethod -Uri $uri -Headers $GraphSecurityAuthHeader -Method Get

        $provider = $Alert.vendorInformation.provider

        $Vendor = $Alert.vendorInformation.vendor

        #need to build the body https://developer.microsoft.com/en-us/graph/docs/api-reference/v1.0/api/alert_update
        $baseBody = @"
{
    "vendorInformation": {
        "provider": "$provider",
        "vendor": "$Vendor"
        }
}
"@
        $objBody = ConvertFrom-Json $baseBody

        if ($assignedTo) { $objBody | Add-Member -Type NoteProperty -Name 'assignedTo' -Value "$assignedTo" }

        if ($Closed) {

            $DateTime = (Get-Date -UFormat '+%Y-%m-%dT%H:%M:%SZ')

            $objBody | Add-Member -Type NoteProperty -Name 'closedDateTime' -Value "$DateTime"

        }

        if ($closedDateTime) {

            $closedDateTime = (Get-Date -Date $closedDateTime -UFormat '+%Y-%m-%dT%H:%M:%SZ')

            $objBody | Add-Member -Type NoteProperty -Name 'closedDateTime' -Value "$closedDateTime"

        }

        if ($Open) { $objBody | Add-Member -Type NoteProperty -Name 'closedDateTime' -Value $null }

        if ($comments) { $objBody | Add-Member -Type NoteProperty -Name 'comments' -Value @("$comments") }

        if ($feedback) { $objBody | Add-Member -Type NoteProperty -Name 'feedback' -Value "$feedback" }

        if ($status) { $objBody | Add-Member -Type NoteProperty -Name 'status' -Value "$status" }

        if ($tags) { $objBody | Add-Member -Type NoteProperty -Name 'tags' -Value @("$tags") }

        $Body = ConvertTo-Json $objBody -Depth 5

        try {

            Invoke-RestMethod -Uri $uri -Headers $GraphSecurityAuthHeader -Method Patch -Body $Body

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

    End {

        #Do Nothing
    }

}