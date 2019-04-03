<#
.Synopsis
   Deletes a Threat Intelligence Indicator in Microsoft Graph Security.

.DESCRIPTION
   Deletes a TI Indicator in Microsoft Graph Security.

   There are multiple options:

   You can delete a single TI Indicator by id
   You can delete multiple TI indicators with mutliple ids
   You can delete all TI Indicators with external id(s)

.EXAMPLE
   Remote-GraphSecurityTiIndicator -id D0ED9BD3-AB24-3E05-A4D3-171280CA3CB9

    This deletes a single specified TI Indicator.

.EXAMPLE
   Remove-GraphSecurityTiIndicator -ids D0ED9BD3-AB24-3E05-A4D3-171280CA3CB9,13d5fa7c-7e48-4ad3-939b-f26fce009e31

    This deletes each TI Indicator with the matching GUIDs.

.EXAMPLE
   Remove-GraphSecurityTiIndicator -externalid IPv4:192.168.1.2,HASH:13d5fa7c-7e48-4ad3-939b-f26fce009e31

    This deletes each TI Indicator with the matching GUIDs.

.FUNCTIONALITY
   Remove-GraphSecurityTiIndicator is intended to function as a mechanism for deleting TI indicators using Microsoft Graph Security.
#>

function Remove-GraphSecurityTiIndicator {
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    Param
    (

        #Specifies the API Version
        [Parameter(ParameterSetName = 'Default', Mandatory = $false)]
        [Parameter(ParameterSetName = 'Multiple', Mandatory = $false)]
        [Parameter(ParameterSetName = 'External', Mandatory = $false)]
        [Parameter(Mandatory=$false)]
        [ValidateSet("v1","Beta")]
        [string]$Version = "Beta",
        
        # Specifies the alert id
        [Parameter(ParameterSetName = 'Default', Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [string]$id,

        # Delete Multiple
        [Parameter(ParameterSetName = 'Multiple', Mandatory = $true)]
        [ValidatePattern("[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*")]
        [string]$ids,

        # Delete External Id
        [Parameter(ParameterSetName = 'External', Mandatory = $true)]
        [string]$externalId

    )

    Begin
    {

        Try {$GraphSecurityNothing = Test-GraphSecurityAuthToken}
            Catch {Throw $_}

        #Temp - Stop if Version is 1.0
        if($Version -ne "Beta"){
            Write-Error "Beta is only supported right now"
            break
        }

    }

    Process
    {
        # Delete mode should happen once for each item from the pipeline, so it goes in the 'Process' block
        if ($PSCmdlet.ParameterSetName -eq 'Default') {
             Write-Verbose "In the delete"
            try {
                # Delete the item by its id
                $resource = "security/tiIndicators/$id"
                $uri = "https://graph.microsoft.com/$Version/$($resource)"
                $response = Invoke-RestMethod -Uri $uri -Headers $GraphSecurityAuthHeader -Method DELETE
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
        if ($PSCmdlet.ParameterSetName -eq 'Multiple' -or $PSCmdlet.ParameterSetName -eq 'External' -and $PSCmdlet.ParameterSetName -ne 'Default') {

            If ($PSCmdlet.ParameterSetName -eq 'Multiple'){

                $resource = "security/tiIndicators/deleteTiIndicators"
                
                $value = $ids.split(",")

            }

            if ($PSCmdlet.ParameterSetName -eq 'External'){
                
                $resource = "security/tiIndicators/deleteTiIndicatorsByExternalId"
                
                $value = $externalId.split(",")

            }

            $baseBody = @"
{
    "value": [
        ""
    ]
}
"@

            $objBody = ConvertFrom-Json $baseBody

            $objBody.Value = $Value
            
            $Body = ConvertTo-Json $objBody -Depth 5

            Write-Verbose "JSON Body to POST"

            Write-Verbose $Body
            
            #region ----------------------------API CALL----------------------------

            Write-Verbose "In the delete multiple"
            try {
                Write-Verbose "Trying delete multiple"
                #$resource = "security/tiIndicators/"
                $uri = "https://graph.microsoft.com/$Version/$($resource)$body"
                $response = Invoke-RestMethod -Uri $uri -Headers $GraphSecurityAuthHeader -Method POST
                Write-Verbose "Trying delete multiple $response"
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
            $response.value
        }

    }

}