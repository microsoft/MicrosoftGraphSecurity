<#
.Synopsis
   Gets alerts in Microsoft Graph Security.

.DESCRIPTION
   Gets alerts in Microsoft Graph Security.

   Without parameters, Get-GraphSecurityAlert gets 100 alerts and associated properties. You can specify a particular alert  to fetch a single alert's information or you can pull a list of activities based on the provided filters.

   There are multiple parameter sets:

.EXAMPLE
   Get-GraphSecurityAlert

    This will default grab the Top 100 alerts.

.EXAMPLE
   Get-GraphSecurityAlert -id D0ED9BD3-AB24-3E05-A4D3-171280CA3CB9 

    This will get a single alert.

.EXAMPLE
   Get-GraphSecurityAlert -provider MCAS -severity high 

    This will get all alerts from MCAS with high severity.

.FUNCTIONALITY
   Get-GraphSecurityAlert is intended to function as a mechanism for getting alerts using Microsoft Graph Security.
#>
function Get-GraphSecurityAlert
{
    [cmdletbinding(DefaultParameterSetName='Default')]
     param
    (
        #Specifies the API Version
        [Parameter(ParameterSetName='Default',Mandatory=$false)]
        [Parameter(ParameterSetName='Fetch',Mandatory=$false)]
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateSet("v1.0","Beta")]
        [string]$Version = "v1.0",

        # Fetches an activity object by its unique identifier.
        [Parameter(ParameterSetName='Fetch', Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$id,

        # Specifies the maximum number of results to retrieve
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateRange(1,1000)]
        [int]$top = "100",

        # Specifies the number of records, from the beginning of the result set, to skip.
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateRange(0, 5000)]
        [int]$skip = 0,

        # Returns the number of alerts to the user
        [Parameter(ParameterSetName='Count', Mandatory=$false)]
        [ValidateSet("true", "false")]
        [string]$count = "false",

        ##### OrderBy Param #####
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateSet("riskScore","tags", "id",
        "azureTenantId","activityGroupName", "assignedTo",
        "category","closedDateTime", "comments",
        "confidence","createdDateTime", "description",
        "detectionIds","eventDateTime", "feedback",
        "lastModifiedDateTime","recommendedActions", "severity",
        "sourceMaterials","status", "title",
        "vendorInformation","cloudAppStates", "fileStates",
        "hostStates","malwareStates", "networkConnections",
        "processes","registryKeyStates", "triggers",
        "userStates","vulnerabilityStates")]
        [string]$orderBy = "none",

        #### OData Query Params #####

        # Provider generated/calculated risk score of the network connection. Recommended value range of 0-1, which equates to a percentage.
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$riskScore,

        # Name or alias of the activity group (attacker) this alert is attributed to.
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$activityGroupName,

        # Name of the analyst the alert is assigned to for triage, investigation, or remediation (supports update).
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$assignedTo,

        # Azure subscription ID, present if this alert is related to an Azure resource.
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$azureSubscriptionId,

        # Azure Active Directory tenant ID. Required.
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$azureTenantId,

        # Category of the alert (for example, credentialTheft, ransomware, etc.).
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$category,

        # Customer-provided comments on alert (for customer alert management) (supports update).
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string[]]$comments,

        # Confidence of the detection logic (percentage between 1-100).
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string[]]$confidence,

        # Alert description.
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$description,

        # Set of alerts related to this alert entity (each alert is pushed to the SIEM as a separate record).
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string[]]$detectionIds,

        # Analyst feedback on the alert.
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("unknown","truePositive", "falsePositive", "begninPostive")]
        [string]$feedback = "none",

        # Vendor/provider recommended action(s) to take as a result of the alert (for example, isolate machine, enforce2FA, reimage host).
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string[]]$recommendedActions,

        # Alert severity - set by vendor/provider.
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("unknown","informational", "low", "medium", "high")]
        [string]$severity = "none",

        # Hyperlinks (URIs) to the source material related to the alert, for example, provider's user interface for alerts or log search, etc.
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string[]]$sourceMaterials,

        # Alert lifecycle status (stage).
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("unknown","newAlert", "inProgress", "resolved")]
        [string]$status = "none",

        # User-definable labels that can be applied to an alert and can serve as filter conditions (for example "HVA", "SAW", etc.) (supports update).
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string[]]$tags,

        # Alert title. Required.
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({$_.Length -ge 5})]
        [string]$title,

        #Vendor Information
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$provider,

        # Threat intelligence pertaining to one or more vulnerabilities related to this alert.
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$vendor


    )

    Begin
    {
        Try {Test-GraphSecurityAuthToken}
           Catch {Throw $_}
    }
    Process
    {
        # Fetch mode should happen once for each item from the pipeline, so it goes in the 'Process' block
        if ($PSCmdlet.ParameterSetName -eq 'Fetch')
        {
            try {
                # Fetch the item by its id
                $resource = "security/alerts/$id"
                $uri = "https://graph.microsoft.com/$Version/$($resource)"
                $response = Invoke-RestMethod -Uri $uri -Headers $GraphSecurityAuthHeader -Method Get
                Write-Verbose "Calling: $uri"
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
            $response
        }
    }
    End
    {

        # After all things have been processed in pipeline
         if ($PSCmdlet.ParameterSetName -eq 'List' -or $PSCmdlet.ParameterSetName -eq 'Default' -and $PSCmdlet.ParameterSetName -ne 'Fetch')
         {

            # List mode logic only needs to happen once, so it goes in the 'End' block for efficiency

            $body = ""

            if($Skip){$body += "`$skip=$Skip"}
            if($top){$body += "?`$top=$top"}
            if($orderBy -ne "none"){$body += "&`$orderBy=$orderBy"}

            # Simple filters

            if ($category){$body += "&`$filter=category+eq+`'$category`'"}
            if ($severity -ne "none"){$body += "&`$filter=severity+eq+`'$severity`'"}
            if ($status -ne "none"){$body += "&`$filter=status+eq+`'$status`'"}
            if ($provider){$body += "&`$filter=vendorInformation/provider+eq+`'$provider`'"}
            if ($vendor){$body += "&`$filter=vendorInformation/vendor+eq+`'$vendor`'"}
            if ($title){$body += "&`$filter=title+eq+`'$title`'"}
            if ($azureTenantId){$body += "&`$filter=azureTenantId+eq+`'$azureTenantId`'"}

            if ($riskScore){$body += "&`$filter=riskScore+eq+$riskScore"}
            if ($tags){$body += "&`$filter=tags+eq+$tags"}
            if ($azureSubscriptionId){$body += "&`$filter=azureSubscriptionId+eq+$azureSubscriptionId"}
            if ($activityGroupName){$body += "&`$filter=activityGroupName+eq+$activityGroupName"}
            if ($assignedTo){$body += "&`$filter=assignedTo+eq+$assignedTo"}
            if ($comments){$body += "&`$filter=comments+eq+$comments"}
            if ($confidence){$body += "&`$filter=confidence+eq+$confidence"}
            if ($description){$body += "&`$filter=description+eq+`'$description`'"}
            if ($detectionIds){$body += "&`$filter=detectionIds+eq+$detectionIds"}
            if ($feedback -ne "none"){$body += "&`$filter=feedback+eq+`'$feedback`'"}
            if ($recommendedActions){$body += "&`$filter=recommendedActions+eq+$recommendedActions"}
            if ($sourceMaterials){$body += "&`$filter=sourceMaterials+eq+$sourceMaterials"}

            Write-Verbose "URI Body: $body"

            #region ----------------------------API CALL----------------------------

            Write-Verbose "In the List"
            try {
                Write-Verbose "Trying List"
                $resource = "security/alerts/"
                $uri = "https://graph.microsoft.com/$Version/$($resource)$body"


                $response = Invoke-RestMethod -Uri $uri -Headers $GraphSecurityAuthHeader -Method Get

                Write-Verbose "Trying List $response"
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
            $response.value
         }

    }
}