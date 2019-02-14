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
        [int]$top = "10",

        # Specifies the number of records, from the beginning of the result set, to skip.
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateRange(0, 5000)]
        [int]$skip = 0,

        # Returns the number of alerts to the user
        [Parameter(ParameterSetName='Count', Mandatory=$false)]
        [ValidateSet("true, false")]
        [string]$count = "false",

         ##### OData Query Params #####

        # Specifies the number of records, from the beginning of the result set, to skip.
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateSet("Low","Medium", "High")]
        [string]$severity = "none",

        # Limits the results by performing a free text search
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({$_.Length -ge 5})]
        [string]$title,

        # Limits the results by performing a free text search
        [Parameter(ParameterSetName='List', Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({$_.Length -ge 5})]
        [string]$status

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
                $resource = "security/alerts/$ID"
                $uri = "https://graph.microsoft.com/$Version/$($resource)"
                $response = Invoke-RestMethod -Uri $uri -Headers $GSAAuthHeader -Method Get
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
            $response
        }
    }
    End
    {
        # After all things have been processed in pipeline
         if ($PSCmdlet.ParameterSetName -eq 'List')
         {

            # List mode logic only needs to happen once, so it goes in the 'End' block for efficiency

            $body = ""

            if($Skip){$body += "`$skip=$Skip"}
            if($top){$body += "?`$top=$top&"}

            $filterSet = @{}

            # Simple filters
            if ($severity -ne "none"){$filter=$true; $filterSet += @{'severity'= $severity}}
            if ($title){$filter=$true;$filterSet += @{'title'= $title}}
            if ($status){$filter=$true;$filterSet += @{'status'= $status}}

            $seperateFilterSet = $filterSet.GetEnumerator() | ForEach-Object({ "$($_.Name)+eq+'$($_.Value)'" })

            $filterCount = $seperateFilterSet.count
            ForEach ($string in $seperateFilterSet){
                Write-Verbose "This is the $filterCount"
                if($filterCount -le 1){
                    $filterString += $string
                }
                else {
                    $filterCount = $filterCount - 1
                    $filterString += $string + '&'
                }
            }
            Write-Verbose "This is the $filterString"

            ForEach($string in $filterString){
                if($filter){$body += "`$filter=$string"}
            }

            Write-Host $body
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
         else
         {
            Write-Verbose "Not Fetch or List"
             # Get the matching items and handle errors
             try {
                Write-Verbose "Trying of nothing"
                $resource = "security/alerts"
                $uri = "https://graph.microsoft.com/$Version/$($resource)"
                $response = (Invoke-RestMethod -Uri $uri -Headers $GSAAuthHeader -Method Get).value
                Write-Verbose "End of nothing"
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
            $response
         }
    }
}