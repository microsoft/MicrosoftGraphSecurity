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
function Get-GraphSecurityAlert {
    [cmdletbinding(DefaultParameterSetName = 'Default')]
    param
    (
        #Specifies the API Version
        [Parameter(ParameterSetName = 'Default', Mandatory = $false)]
        [Parameter(ParameterSetName = 'Fetch', Mandatory = $false)]
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateSet("v1.0", "Beta")]
        [string]$Version = "v1.0",

        # Fetches an activity object by its unique identifier.
        [Parameter(ParameterSetName = 'Fetch', Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$id,

        # Specifies the maximum number of results to retrieve
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateRange(1, 1000)]
        [int]$top = "100",

        # Specifies the number of records, from the beginning of the result set, to skip.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateRange(0, 5000)]
        [int]$skip = 0,

        # Returns the number of alerts to the user
        [Parameter(ParameterSetName = 'Count', Mandatory = $false)]
        [ValidateSet("true", "false")]
        [string]$count = "false",

        ##### OrderBy Param #####

        #Currently orderBy Ascending by default
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateSet("riskScore", "tags", "id",
            "azureTenantId", "activityGroupName", "assignedTo",
            "category", "closedDateTime", "comments",
            "confidence", "createdDateTime", "description",
            "detectionIds", "eventDateTime", "feedback",
            "lastModifiedDateTime", "recommendedActions", "severity",
            "sourceMaterials", "status", "title",
            "vendorInformation", "cloudAppStates", "fileStates",
            "hostStates", "malwareStates", "networkConnections",
            "processes", "registryKeyStates", "triggers",
            "userStates", "vulnerabilityStates")]
        [string]$orderBy = "none",

        #### OData Query Params #####

        # Provider generated/calculated risk score of the network connection. Recommended value range of 0-1, which equates to a percentage.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$riskScore,

        # Name or alias of the activity group (attacker) this alert is attributed to.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$activityGroupName,

        # Name of the analyst the alert is assigned to for triage, investigation, or remediation (supports update).
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$assignedTo,

        # Azure subscription ID, present if this alert is related to an Azure resource.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$azureSubscriptionId,

        # Azure Active Directory tenant ID. Required.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$azureTenantId,

        # Category of the alert (for example, credentialTheft, ransomware, etc.).
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$category,

        # Customer-provided comments on alert (for customer alert management) (supports update).
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string[]]$comments,

        # Confidence of the detection logic (percentage between 1-100).
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string[]]$confidence,

        # Set of alerts related to this alert entity (each alert is pushed to the SIEM as a separate record).
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string[]]$detectionIds,

        # Analyst feedback on the alert.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("unknown", "truePositive", "falsePositive", "begninPostive")]
        [string]$feedback = "none",

        # Alert severity - set by vendor/provider.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("unknown", "informational", "low", "medium", "high")]
        [string]$severity = "none",

        # Hyperlinks (URIs) to the source material related to the alert, for example, provider's user interface for alerts or log search, etc.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string[]]$sourceMaterials,

        # Alert lifecycle status (stage).
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("unknown", "newAlert", "inProgress", "resolved")]
        [string]$status = "none",

        # User-definable labels that can be applied to an alert and can serve as filter conditions (for example "HVA", "SAW", etc.) (supports update).
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string[]]$tags,

        # Alert title. Required.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript( { $_.Length -ge 5 })]
        [string]$title,

        ####### Vendor Information ######

        # Specific provider (product/service - not vendor company); for example, WindowsDefenderATP.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$provider,

        # Name of the alert vendor (for example, Microsoft, Dell, FireEye). Required
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$vendor,

        ####### User State Information ######

        # AAD User object identifier (GUID) - represents the physical/multi-account user entity.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$aadUserId,

        # Account name of user account (without Active Directory domain or DNS domain) - (also called mailNickName). Case-Sensitive
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$accountName,

        # For email-related alerts - user account's email 'role'.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$emailRole,

        # User sign-in name - internet format: (user account name)@(user account DNS domain name).
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$userPrincipalName,

        ####### Host Security State Information ######

        <# Needs further testing, omitted for release 1.0

            # # Host FQDN (Fully Qualified Domain Name) (for example, machine.company.com).
            # [Parameter(ParameterSetName='List', Mandatory=$false)]
            # [ValidateNotNullOrEmpty()]
            # [string]$FQDN,

        #>

        <# Needs further testing, omitted for release 1.0

            # # Private (not routable) IPv4 or IPv6 address (see RFC 1918) at the time of the alert.
            # [Parameter(ParameterSetName='List', Mandatory=$false)]
            # [ValidateNotNullOrEmpty()]
            # [string]$privateIpAddress,

        #>

        <# Needs further testing, omitted for release 1.0

            # # Publicly routable IPv4 or IPv6 address (see RFC 1918) at time of the alert.
            # [Parameter(ParameterSetName='List', Mandatory=$false)]
            # [ValidateNotNullOrEmpty()]
            # [string]$publicIpAddress,

        #>

        # ####### File Security State Information ######

        <# Needs further testing, omitted for release 1.0

            # # File name (without path).
            # [Parameter(ParameterSetName='List', Mandatory=$false)]
            # [ValidateNotNullOrEmpty()]
            # [string]$fileName,

        #>

        ####### Date Time Params ######

        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$eventDateTimeAfter = "",

        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$eventDateTimeBefore = "",

        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$createdDateTimeAfter = "",

        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$createdDateTimeBefore = "",

        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$closedDateTimeAfter = "",

        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$closedDateTimeBefore = "",

        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$lastModifiedDateTimeAfter = "",

        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$lastModifiedDateTimeBefore = ""
    )

    Begin {
        Try { Test-GraphSecurityAuthToken }
        Catch { Throw $_ }
    }
    Process {
        # Fetch mode should happen once for each item from the pipeline, so it goes in the 'Process' block
        if ($PSCmdlet.ParameterSetName -eq 'Fetch') {
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
    End {

        # After all things have been processed in pipeline
        if ($PSCmdlet.ParameterSetName -eq 'List' -or $PSCmdlet.ParameterSetName -eq 'Default' -and $PSCmdlet.ParameterSetName -ne 'Fetch') {

            # List mode logic only needs to happen once, so it goes in the 'End' block for efficiency

            $body = "?`$top=$top&`$filter="

            # Simple filters

            if ($category) { $body += "`category+eq+`'$category`' and " }
            if ($severity -ne "none") { $body += "severity+eq+`'$severity`' and " }
            if ($status -ne "none") { $body += "status+eq+`'$status`' and " }
            if ($title) { $body += "title+eq+`'$title`' and " }
            if ($azureTenantId) { $body += "azureTenantId+eq+`'$azureTenantId`' and " }
            if ($riskScore) { $body += "riskScore+eq+`'$riskScore`' and " }
            if ($tags) { $body += "tags+eq+`'$tags`' and " }
            if ($azureSubscriptionId) { $body += "azureSubscriptionId+eq+`'$azureSubscriptionId`' and " }
            if ($activityGroupName) { $body += "activityGroupName+eq+`'$activityGroupName`' and " }
            if ($assignedTo) { $body += "assignedTo+eq+`'$assignedTo`' and " }
            if ($confidence) { $body += "confidence+eq+`'$confidence`' and " }
            if ($detectionIds) { $body += "detectionIds+eq+`'$detectionIds`' and " }
            if ($sourceMaterials) { $body += "sourceMaterials+eq+`'$sourceMaterials`' and " }

            ####### User State Information ######

            if ($aadUserId) { $body += "userStates/any(d:d/aadUserId+eq+`'$aadUserId`') and " }
            if ($accountName) { $body += "userStates/any(d:d/accountName+eq+`'$accountName`') and " }
            if ($userPrincipalName) { $body += "userStates/any(d:d/userPrincipalName+eq+`'$userPrincipalName`') and " }
            if ($domainName) { $body += "userStates/any(d:d/domainName+eq+`'$domainName`') and " }


            <# Needs further testing, omitted for release 1.0

                # if ($FQDN){$body += "hostSecurityState/FQDN+eq+`'$FQDN`'&"}

            #>
            <# Needs further testing, omitted for release 1.0

                # if ($privateIpAddress){$body += "hostSecurityState/privateIpAddress+eq+`'$privateIpAddress`'&"}

            #>
            <# Needs further testing, omitted for release 1.0

                # if ($publicIpAddress){$body += "hostSecurityState/publicIpAddress+eq+`'$publicIpAddress`'&"}

            #>

            ####### File Security State Information ######
            <# Needs further testing, omitted for release 1.0

                # if ($filName){$body += "fileSecurityState/name+eq+`'$fileName`'&"}

            #>

            if ($eventDateTimeAfter) {
                $eventDateTimeAfter = (Get-Date -Date $eventDateTimeAfter -Format "yyyy-MM-ddTHH:mm:ssZ")
                $body += "eventDateTime+gt+$eventDateTimeAfter and "
            }

            if ($eventDateTimeBefore) {
                $eventDateTimeBefore = (Get-Date -Date $eventDateTimeBefore -Format "yyyy-MM-ddTHH:mm:ssZ")
                $body += "eventDateTime+lt+$eventDateTimeBefore and "
            }

            if ($createdDateTimeAfter) {
                $createdDateTimeAfter = (Get-Date -Date $createdDateTimeAfter -Format "yyyy-MM-ddTHH:mm:ssZ")
                $body += "createdDateTime+gt+$createdDateTimeAfter and "
            }

            if ($createdDateTimeBefore) {
                $createdDateTimeBefore = (Get-Date -Date $createdDateTimeBefore -Format "yyyy-MM-ddTHH:mm:ssZ")
                $body += "createdDateTime+lt+$createdDateTimeBefore and "
            }

            if ($closedDateTimeAfter) {
                $closedDateTimeAfter = (Get-Date -Date $closedDateTimeAfter -Format "yyyy-MM-ddTHH:mm:ssZ")
                $body += "closedDateTime+gt+$closedDateTimeAfter and "
            }

            if ($closedDateTimeBefore) {
                $closedDateTimeBefore = (Get-Date -Date $closedDateTimeBefore -Format "yyyy-MM-ddTHH:mm:ssZ")
                $body += "closedDateTime+lt+$closedDateTimeBefore and "
            }

            if ($lastModifiedDateTimeAfter) {
                $lastModifiedDateTimeAfter = (Get-Date -Date $lastModifiedDateTimeAfter -Format "yyyy-MM-ddTHH:mm:ssZ")
                $body += "lastModifiedDateTime+gt+$lastModifiedDateTimeAfter and "
            }

            if ($lastModifiedDateTimeBefore) {
                $lastModifiedDateTimeBefore = (Get-Date -Date $lastModifiedDateTimeBefore -Format "yyyy-MM-ddTHH:mm:ssZ")
                $body += "lastModifiedDateTime+lt+$lastModifiedDateTimeBefore and "
            }

            if ($provider) { $body += "vendorInformation/provider+eq+`'$provider`' and " }
            if ($vendor) { $body += "vendorInformation/vendor+eq+`'$vendor`' and " }

            $body = $body -replace ' and $', ''

            if ($Skip) { $body += "&`$skip=$Skip" }
            if ($orderBy -ne "none") { $body += "&`$orderBy=$orderBy" }

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
                Write-Verbose "Response content:`n$responseBody"
                Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
                break
            }
            $response.value
        }

    }
}