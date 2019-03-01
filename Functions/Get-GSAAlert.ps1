<#
.Synopsis
   Gets an alert or alerts based on filter
.DESCRIPTION

.EXAMPLE

.FUNCTIONALITY

#>

function Get-GSAAlert
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
        [string]$Identity,

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

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [ValidateRange(1,10)]
        [int]$riskScore,

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$tags,

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [int]$azureTenantId,

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$activityGroupName,

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$assignedTo,

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$category,

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$closedDateTime,

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$comments,

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$confidence,

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$createdDateTime,

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$description,

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$detectionIds,

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$eventDateTime,

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$feedback,

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$lastModifiedDateTime,

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$recommendedActions,

         # Specifies the number of records, from the beginning of the result set, to skip.
         [Parameter(ParameterSetName='List', Mandatory=$false)]
         [ValidateSet("Low","Medium", "High")]
         [string]$severity = "none",

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$sourceMaterials,

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$status,

         # Limits the results by performing a free text search
         [Parameter(ParameterSetName='List', Mandatory=$false)]
         [ValidateNotNullOrEmpty()]
         [ValidateScript({$_.Length -ge 5})]
         [string]$title,

        #Vendor Information
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$provider,

        #Vendor Information
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$vendor,

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$cloudAppStates,

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$fileStates,

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$hostStates,

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$malwareStates,

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$networkConnections,

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$processes,

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$registryKeyStates,

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$triggers,

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$userStates,

        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$vulnerabilityStates
    )

    Begin
    {
        Try {Check-GSAAuthToken}
           Catch {Throw $_}
    }
    Process
    {
        # Fetch mode should happen once for each item from the pipeline, so it goes in the 'Process' block
        if ($PSCmdlet.ParameterSetName -eq 'Fetch')
        {
            try {
                # Fetch the item by its id
                $resource = "security/alerts/$Identity"
                $uri = "https://graph.microsoft.com/$Version/$($resource)"
                $response = Invoke-RestMethod -Uri $uri -Headers $GSAAuthHeader -Method Get
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

            if ($riskScore){$body += "&`$filter=riskScore+eq+$riskScore"}
            if ($tags){$body += "&`$filter=tags+eq+$tags"}
            if ($azureTenantId){$body += "&`$filter=azureTenantId+eq+$azureTenantId"}
            if ($activityGroupName){$body += "&`$filter=activityGroupName+eq+$activityGroupName"}
            if ($assignedTo){$body += "&`$filter=assignedTo+eq+$assignedTo"}
            if ($category){$body += "&`$filter=category+eq+$category"}
            if ($closedDateTime){$body += "&`$filter=closedDateTime+eq+$closedDateTime"}
            if ($comments){$body += "&`$filter=comments+eq+$comments"}
            if ($confidence){$body += "&`$filter=confidence+eq+$confidence"}
            if ($createdDateTime){$body += "&`$filter=createdDateTime+eq+$createdDateTime"}
            if ($description){$body += "&`$filter=description+eq+$description"}
            if ($detectionIds){$body += "&`$filter=detectionIds+eq+$detectionIds"}
            if ($feedback){$body += "&`$filter=feedback+eq+$feedback"}
            if ($lastModifiedDateTime){$body += "&`$filter=lastModifiedDateTime+eq+$lastModifiedDateTime"}
            if ($recommendedActions){$body += "&`$filter=recommendedActions+eq+$recommendedActions"}
            if ($severity -ne "none"){$body += "&`$filter=severity+eq+`'$severity`'"}
            if ($sourceMaterials){$body += "&`$filter=sourceMaterials+eq+$sourceMaterials"}
            if ($status){$body += "&`$filter=status+eq+$status"}
            if ($provider){$body += "&`$filter=vendorInformation/provider+eq+`'$provider`'"}
            if ($vendor){$body += "&`$filter=vendorInformation/vendor+eq+`'$vendor`'"}
            if ($cloudAppStates){$body += "&`$filter=cloudAppStates+eq$cloudAppStates"}
            if ($fileStates){$body += "&`$filter=fileStates+eq$fileStates"}
            if ($hostStates){$body += "&`$filter=hostStates+eq$hostStates"}
            if ($malwareStates){$body += "&`$filter=malwareStates+eq$malwareStates"}
            if ($networkConnections){$body += "&`$filter=networkConnections+eq$networkConnections"}
            if ($processes){$body += "&`$filter=processes+eq$processes"}
            if ($registryKeyStates){$body += "&`$filter=malwareStates+eq$registryKeyStates"}
            if ($triggers){$body += "&`$filter=triggers+eq$triggers"}
            if ($userStates){$body += "&`$filter=userStates+eq$userStates"}
            if ($vulnerabilityStates){$body += "&`$filter=vulnerabilityStates+eq$vulnerabilityStates"}

            $body = $body -replace(" ",",")
            Write-Verbose "URI Body: $body"

            #region ----------------------------API CALL----------------------------

            Write-Verbose "In the List"
            try {
                Write-Verbose "Trying List"
                $resource = "security/alerts/"
                $uri = "https://graph.microsoft.com/$Version/$($resource)$body"


                $response = Invoke-RestMethod -Uri $uri -Headers $GSAAuthHeader -Method Get

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