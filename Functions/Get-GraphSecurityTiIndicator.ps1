<#
.Synopsis
   Gets Threat Intelligence Indicators in Microsoft Graph Security.

.DESCRIPTION
   Gets Threat Intelligence Indicators in Microsoft Graph Security.

   Without parameters, Get-GraphSecurityTiIndicator gets 10 indicators and associated properties. You can specify a particular id to fetch a single indicators's information or you can pull a list of indicators based on the provided filters.

.EXAMPLE
   Get-GraphSecurityTiIndicator

    This will default grab the top 10 indicators.

.EXAMPLE
   Get-GraphSecurityTiIndicator -id D0ED9BD3-AB24-3E05-A4D3-171280CA3CB9

    This will get a single indicator.

.EXAMPLE
   Get-GraphSecurityTiIndicator -targetProduct "Azure Sentinel" -action alert

    This will get all indicators targeted for Azure Setinel with the action alert.

.FUNCTIONALITY
   Get-GraphSecurityTiIndicator is intended to function as a mechanism for getting TI Indicators using Microsoft Graph Security.
#>
function Get-GraphSecurityTiIndicator {
    [cmdletbinding(DefaultParameterSetName = 'Default')]
    param
    (
        #Specifies the API Version
        [Parameter(ParameterSetName = 'Default', Mandatory = $false)]
        [Parameter(ParameterSetName = 'Fetch', Mandatory = $false)]
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateSet("v1.0", "beta")]
        [string]$Version = "beta",

        # Fetches an TI indicator object by its unique identifier.
        [Parameter(ParameterSetName = 'Fetch', Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$id,

        # Specifies the maximum number of results to retrieve
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateRange(1, 1000)]
        [int]$top = "10",

        # Specifies the number of records, from the beginning of the result set, to skip.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateRange(0, 5000)]
        [int]$skip = 0,

        # Returns the number of indicators to the user
        [Parameter(ParameterSetName = 'Count', Mandatory = $false)]
        [ValidateSet($true, $false)]
        [boolean]$count = $false,

        #### OData Query Params #####
        
        ##### OrderBy Param #####
        #Currently orderBy Ascending by default
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateSet("action", "activityGroupNames", "additionalInformation",
            "azureTenantId", "confidence", "description", "diamondModel",
            "expirationDateTime", "externalId", "id", "ingestedDateTime",
            "isActive", "killChain", "knownFalsePositives", "lastReportedDateTime",
            "malwareFamilyNames", "passiveOnly", "severity", "tags", "targetProduct",
            "threatType", "tlpLevel")]
        [string]$orderBy = "none",

        # The action to apply if the indicator is matched from within the targetProduct security tool.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateSet("unknown", "allow", "block", "alert")]
        [string]$action,

        # Name or alias of the activity group (attacker) this indicator is attributed to.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$activityGroupNames,

        # A catchall area into which extra data from the indicator not covered by the other tiIndicator properties
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$additionalInformation,

        # Stamped by the system when the indicator is ingested. The Azure Active Directory tenant id of submitting client.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$azureTenantId,

        # An integer representing the confidence the data within the indicator accurately identifies malicious behavior. Acceptable values are 0 – 100 with 100 being the highest.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateRange(0, 100)]
        [int]$confidence,

        # Brief description (100 characters or less) of the threat represented by the indicator.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$description,

        # he area of the Diamond Model in which this indicator exists.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateSet("unknown", "adversary", "capability", "infrastructure", "victim")]
        [string[]]$diamondModel,

        # DateTime string indicating when the Indicator expires.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string[]]$expirationDateTime,

        # An identification number that ties the indicator back to the indicator provider’s system (e.g. a foreign key).
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string[]]$externalId,

        # Stamped by the system when the indicator is ingested.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$ingestedDateTime,

        # Used to deactivate indicators within system.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet($true, $false)]
        [boolean]$isActive = $false,

        # A JSON array of strings that describes which point or points on the Kill Chain this indicator targets.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string[]]$killChain,

        # The last time the indicator was seen.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$lastReportedDateTime,

        # The malware family name associated with an indicator if it exists.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$malwareFamilyNames,

        # Determines if the indicator should trigger an event that is visible to an end-user.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet($true, $false)]
        [boolean]$passiveOnly,

        # An integer representing the severity of the malicious behavior identified by the data within the indicator.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateRange(0, 5)]
        [int]$severity,

        # A JSON array of strings that stores arbitrary tags/keywords.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$tags,

        # Target product for the TI indicator
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateSet("Azure Sentinel")]
        [string]$targetProduct = "Azure Sentinel",

        # Each indicator must have a valid Indicator Threat Type.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateSet("Botnet", "C2", "CryptoMining", "Darknet", "DDoS", "MaliciousUrl", "Malware", "Phishing", "Proxy", "PUA", "WatchList")]
        [string]$threatType,

        # Traffic Light Protocol value for the indicator.
        [Parameter(ParameterSetName = 'List', Mandatory = $false)]
        [ValidateSet("unknown", "white", "green", "amber", "red")]
        [string]$tlpLevel
    )

    Begin {

        Try {Test-GraphSecurityAuthToken}
        Catch {Throw $_}

        #Temp - Stop if Version is 1.0
        if($Version -ne "Beta"){
            Write-Error "Beta is only supported right now"
            break
        }
    }
    Process {
    
    
        # Fetch mode should happen once for each item from the pipeline, so it goes in the 'Process' block
        if ($PSCmdlet.ParameterSetName -eq 'Fetch') {
            try {
                # Fetch the item by its id
                $resource = "security/tiIndicators/$id"
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
            if($action) {$body += "action+eq+`'$action`' and "}
            #needs testing string collection???
            if($activityGroupNames) {$body += "activityGroupNames+eq+`'$activityGroupNames`' and "}
            
            if($additionalInformation) {$body += "additionalInformation+eq+`'$additionalInformation`' and "}
            if($azureTenantId) {$body += "azureTenantId+eq+`'$azureTenantId`' and "}
            if($confidence) {$body += "confidence+eq+`'$confidence`' and "}
            if($description) {$body += "description+eq+`'$description`' and "}
            if($diamondModel) {$body += "diamondModel+eq+`'$diamondModel`' and "}
            if($expirationDateTime) {
                $expirationDateTime = (Get-Date -Date $expirationDateTime -Format "yyyy-MM-ddTHH:mm:ssZ")
                $body += "expirationDateTime+lt+$expirationDateTime and "
            }
            if($externalId) {$body += "externalId+eq+`'$externalId`' and "}
            if($ingestedDateTime) {
                $ingestedDateTime = (Get-Date -Date $ingestedDateTime -Format "yyyy-MM-ddTHH:mm:ssZ")
                $body += "ingestedDateTime+gt+$ingestedDateTime and "
            }
            if($isActive -eq $true) {$body += "isActive+eq+`'true`' and "}
            #if($isActive -eq $false) {$body += "isActive+eq+`'false`' and "}
            
            #needs work killChain

            if($knownFalsePositives) {$body += "knownFalsePositives+eq+`'$knownFalsePositives`' and "}
            if($lastReportedDateTime) {
                $lastReportedDateTime = (Get-Date -Date $lastReportedDateTime -Format "yyyy-MM-ddTHH:mm:ssZ")
                $body += "lastReportedDateTime+gt+$lastReportedDateTime and "
            }
            #needs testing string collection???
            if($malwareFamilyNames) {$body += "malwareFamilyNames+eq+`'$malwareFamilyNames`' and "}

            if($passiveOnly -eq $true) {$body += "passiveOnly+eq+`'true`' and "}
            #if($passiveOnly -eq $false) {$body += "passiveOnly+eq+`'false`' and "}
            if($severity) {$body += "severity+eq+`'$severity`' and "}
            #needs testing string collection???
            if($tags) {$body += "tags+eq+`'$tags`' and "}

            if($targetProduct) {$body += "targetProduct+eq+`'$targetProduct`' and "}
            if($threatType) {$body += "threatType+eq+`'$threatType`' and "}
            if($tlpLevel) {$body += "tlpLevel+eq+`'$tlpLevel`' and "}

            if ($Skip) {$body += "`$skip=$Skip"}
            if ($orderBy -ne "none") {$body += "`$orderBy=$orderBy"}


            $body = $body -replace ' and $', ''
            Write-Verbose "URI Body: $body"

            #region ----------------------------API CALL----------------------------

            Write-Verbose "In the List"
            try {
                Write-Verbose "Trying List"
                $resource = "security/tiIndicators"
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