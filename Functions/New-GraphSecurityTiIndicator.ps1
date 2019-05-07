<#
.Synopsis
   Creates a new Threat Intelligence Indicator in Microsoft Graph Security.

.DESCRIPTION
   Creates a new Threat Intelligence Indicator(s) in Microsoft Graph Security.

   Each indicator must contain at least one email, file, or network observable.

   For string collection properties supply the data in the format of "value1","Value2" or value1,value2

.EXAMPLE
   New-GraphSecurityTiIndicator -action block -description "File hash for cyrptominer.exe" -expirationDateTime 01/02/2020 -requiredProduct "Azure Sentinel" -threatType CyrptoMining -tlpLevel red -fileHashType SHA256 -fileHashValue 2D6BDFB341BE3A6234B24742377F93AA7C7CFB0D9FD64EFA9282C87852E57085

    This will create a new indicator to block based on file hash and expires 01/01/2020.

.EXAMPLE
   $Data = Import-Csv .\email.csv | Select Action,ActivityGroupNames,AdditionalInformation,Description,DiamondModel,ExpirationDateTime,ExternalIndicatorId,KillChain,KnownfalsePositives,MalwareNames,Tags,TargetProduct,ThreatType,tlpLevel,EmailEncoding,EmailLanguage,EmailRecipient,EmailSenderAddress,EmailSenderName,EmailSourceDomain,EmailSourceIpAddress,EmailSubject,EmailXMailer,@{Name="passiveOnly"; Expression={[boolean]$_.passiveOnly}},@{Name="isActive"; Expression={[boolean]$_.isActive}},@{Name="Confidence"; Expression={[int32]$_.Confidence}},@{Name="Severity"; Expression={[int32]$_.Severity}}
   $Data2 = $Data | ForEach-Object {$NonEmptyProperties = $_.psobject.Properties | Where-Object {$_.Value} | Select-Object -ExpandProperty Name; $_ | Select-Object -Property $NonEmptyProperties | ConvertTo-Json}
   $Data2 | New-GraphSecurityTiIndicator

    This will create a new indicator for each item in the CSV.  The CSV must have the required properties that match the API property names.  Since CSV import treats every item as a string, you must import to variable and cast the correct type.

.EXAMPLE
   $Data = Import-Csv .\file.csv | Select Action,ActivityGroupNames,AdditionalInformation,Description,DiamondModel,ExpirationDateTime,ExternalIndicatorId,KillChain,KnownfalsePositives,MalwareNames,Tags,TargetProduct,ThreatType,tlpLevel,@{Name="passiveOnly"; Expression={[boolean]$_.passiveOnly}},@{Name="isActive"; Expression={[boolean]$_.isActive}},@{Name="Confidence"; Expression={[int32]$_.Confidence}},@{Name="Severity"; Expression={[int32]$_.Severity}},FileCompileDateTime,FileCreatedDateTime,FileHashType,FileHashValue,FileMutexName,FileName,FilePacker,FilePath,FileType,@{Name="FileSize"; Expression={[int64]$_.FileSize}}
   $Data2 = $Data | ForEach-Object {$NonEmptyProperties = $_.psobject.Properties | Where-Object {$_.Value} | Select-Object -ExpandProperty Name; $_ | Select-Object -Property $NonEmptyProperties | ConvertTo-Json}
   $Data2 | New-GraphSecurityTiIndicator

    This will create a new indicator for each item in the CSV.  The CSV must have the required properties that match the API property names.  Since CSV import treats every item as a string, you must import to variable and cast the correct type.

    .FUNCTIONALITY
   New-GraphSecurityTiIndicator is intended to function as a mechanism for creating TI Indicators using Microsoft Graph Security.
#>
function New-GraphSecurityTiIndicator {
    param
    (
        #Specifies the API Version
        [Parameter(ParameterSetName = 'Email', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'File', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("v1.0", "Beta")]
        [string]$Version = "Beta",

        # Base Object
        # The action to apply if the indicator is matched from within the targetProduct security tool.
        [Parameter(ParameterSetName = 'Email', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'File', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'Network', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("unknown", "allow", "block", "alert")]
        [string]$action,

        # Name or alias of the activity group (attacker) this indicator is attributed to.
        [Parameter(ParameterSetName = 'Email', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'File', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$activityGroupNames,

        # A catchall area into which extra data from the indicator not covered by the other tiIndicator properties
        [Parameter(ParameterSetName = 'Email', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'File', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$additionalInformation,

        # An integer representing the confidence the data within the indicator accurately identifies malicious behavior. Acceptable values are 0 – 100 with 100 being the highest.
        [Parameter(ParameterSetName = 'Email', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'File', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateRange(0, 100)]
        [int]$confidence,

        # Brief description (100 characters or less) of the threat represented by the indicator.
        [Parameter(ParameterSetName = 'Email', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'File', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'Network', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$description,

        # he area of the Diamond Model in which this indicator exists.
        [Parameter(ParameterSetName = 'Email', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'File', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("unknown", "adversary", "capability", "infrastructure", "victim")]
        [string]$diamondModel,

        # DateTime string indicating when the Indicator expires.
        [Parameter(ParameterSetName = 'Email', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'File', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'Network', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$expirationDateTime,

        # An identification number that ties the indicator back to the indicator provider’s system (e.g. a foreign key).
        [Parameter(ParameterSetName = 'Email', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'File', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$externalId,

        # Used to deactivate indicators within system.
        [Parameter(ParameterSetName = 'Email', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'File', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateSet($true, $false)]
        [boolean]$isActive = $false,

        # A JSON array of strings that describes which point or points on the Kill Chain this indicator targets.
        [Parameter(ParameterSetName = 'Email', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'File', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$killChain,

        # Scenarios in which the indicator may cause false positives. This should be human-readable text.
        [Parameter(ParameterSetName = 'Email', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'File', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$knownFalsePositives,

        # The last time the indicator was seen.
        [Parameter(ParameterSetName = 'Email', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'File', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$lastReportedDateTime,

        # The malware family name associated with an indicator if it exists.
        [Parameter(ParameterSetName = 'Email', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'File', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$malwareFamilyNames,

        # Determines if the indicator should trigger an event that is visible to an end-user.
        [Parameter(ParameterSetName = 'Email', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'File', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        #[ValidateScript({$passiveOnly =  [System.Convert]::ToInt32($_)})]
        [ValidateSet($true, $false)]
        [boolean]$passiveOnly,

        # An integer representing the severity of the malicious behavior identified by the data within the indicator.
        [Parameter(ParameterSetName = 'Email', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'File', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateRange(0, 5)]
        [int]$severity,

        # A JSON array of strings that stores arbitrary tags/keywords.
        [Parameter(ParameterSetName = 'Email', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'File', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$tags,

        # Target product for the TI indicator
        [Parameter(ParameterSetName = 'Email', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'File', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'Network', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("Azure Sentinel")]
        [string]$targetProduct = "Azure Sentinel",

        # Each indicator must have a valid Indicator Threat Type.
        [Parameter(ParameterSetName = 'Email', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'File', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'Network', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("Botnet", "C2", "CryptoMining", "Darknet", "DDoS", "MaliciousUrl", "Malware", "Phishing", "Proxy", "PUA", "WatchList")]
        [string]$threatType,

        # Traffic Light Protocol value for the indicator.
        [Parameter(ParameterSetName = 'Email', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'File', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'Network', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("white", "green", "amber", "red")]
        [string]$tlpLevel,

        # Email observables
        # The type of text encoding used in the email.
        [Parameter(ParameterSetName = 'Email', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$emailEncoding,

        # The language of the email.
        [Parameter(ParameterSetName = 'Email', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$emailLanguage,

	    # Recipient email address.
        [Parameter(ParameterSetName = 'Email', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$emailRecipient,

        # Email address of the attacker|victim.
        [Parameter(ParameterSetName = 'Email', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$emailSenderAddress,

        # Displayed name of the attacker|victim.
        [Parameter(ParameterSetName = 'Email', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$emailSenderName,
	    
        # Domain used in the email.
        [Parameter(ParameterSetName = 'Email', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$emailSourceDomain,

	    # Source IP address of email.
        [Parameter(ParameterSetName = 'Email', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$emailSourceIpAddress,

        # Subject line of email.
        [Parameter(ParameterSetName = 'Email', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$emailSubject,
        
        # X-Mailer value used in the email.
        [Parameter(ParameterSetName = 'Email', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$emailXMailer,

        # File Observables
        # DateTime when the file was compiled.
        [Parameter(ParameterSetName = 'File', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$fileCompileDateTime,

        #DateTime when the file was created.
        [Parameter(ParameterSetName = 'File', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$fileCreatedDateTime,

        # The type of hash stored in fileHashValue
        [Parameter(ParameterSetName = 'File', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateSet("unknown", "sha1", "sha256", "md5", "authenticodeHash256", "lsHash", "ctph")]
        [string]$fileHashType,
        
        # The file hash value.
        [Parameter(ParameterSetName = 'File', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$fileHashValue,

        # Mutex name used in file-based detections
        [Parameter(ParameterSetName = 'File', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$fileMutexName,

        # Name of the file if the indicator is file-based
        [Parameter(ParameterSetName = 'File', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$fileName,

        # The packer used to build the file in question.
        [Parameter(ParameterSetName = 'File', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$filePacker, 

        # Path of file indicating compromise. May be a Windows or *nix style path
        [Parameter(ParameterSetName = 'File', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$filePath,

        # Size of the file in bytes
        [Parameter(ParameterSetName = 'File', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [int64]$fileSize,

        # Text description of the type of file.
        [Parameter(ParameterSetName = 'File', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$fileType,

        # Network Observables
        # Domain name associated with this indicator.
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$domainName,

        # CIDR Block notation representation of the network referenced
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$networkCidrBlock,

        # The destination autonomous system identifier of the network referenced 
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [Int32]$networkDestinationAsn,

        # CIDR Block notation representation of the destination network
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$networkDestinationCidrBlock,

        # IPv4 IP address destination.
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$networkDestinationIPv4,

        # IPv6 IP address destination.
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$networkDestinationIPv6,

        # TCP port destination. 
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [Int32]$networkDestinationPort,

        # IPv4 IP address.
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$networkIPv4,

        # IPv6 IP address.
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$networkIPv6,

        # TCP port
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [int32]$networkPort,

        # Decimal representation of the protocol field in the IPv4 header.
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [int32]$networkProtocol, 

        # The source autonomous system identifier of the network referenced
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [Int32]$networkSourceAsn,

        # CIDR Block notation representation of the source network
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$networkSourceCidrBlock,

        # IPv4 IP Address source.
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$networkSourceIPv4,

        # IPv6 IP Address source.
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$networkSourceIPv6,

        # TCP port source.
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [Int32]$networkSourcePort,

        #Uniform Resource Locator. This URL must comply with RFC 1738.
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$url,

        # User-Agent string from a web request that could indicate compromise.
        [Parameter(ParameterSetName = 'Network', Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNull()]
        [string]$userAgent

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
        
        $baseBody = @"
{

}
"@
        $objBody = ConvertFrom-Json $baseBody

        #Base Properties
        if($action){$objBody | Add-Member -Type NoteProperty -Name 'action' -Value "$action"}
        if($activityGroupNames){$objBody | Add-Member -Type NoteProperty -Name 'activityGroupNames' -Value @($activityGroupNames)}
        if($additionalInformation){$objBody | Add-Member -Type NoteProperty -Name 'additionalInformation' -Value "$additionalInformation"}
        if($confidence){$objBody | Add-Member -Type NoteProperty -Name 'confidence' $confidence}
        if($description){$objBody | Add-Member -Type NoteProperty -Name 'description' -Value "$description"}
        if($diamondModel){$objBody | Add-Member -Type NoteProperty -Name 'diamondModel' -Value "$diamondModel"}
        if($expirationDateTime){
            $expirationDateTime = (Get-Date -Date $expirationDateTime -UFormat '+%Y-%m-%dT%H:%M:%SZ')
            $daysCheck =    New-TimeSpan $expirationDateTime ((Get-Date).AddDays(30))
            if($daysCheck.Days -gt 30){
                Write-Error "You can not enter more than 30 days in the future"
                break
            }
            $objBody | Add-Member -Type NoteProperty -Name 'expirationDateTime' -Value "$expirationDateTime"
        }
        if($externalId){$objBody | Add-Member -Type NoteProperty -Name 'externalId' -Value "$externalId"}
        if($isActive){$objBody | Add-Member -Type NoteProperty -Name 'isActive' $isActive}
        if($killChain){$objBody | Add-Member -Type NoteProperty -Name 'killChain' -Value @($killChain)}
        if($knownFalsePositives){$objBody | Add-Member -Type NoteProperty -Name 'knownFalsePositives' -Value "$knownFalsePositives"}
        if($lastReportedDateTime){
            $lastReportedDateTime = (Get-Date -Date $lastReportedDateTime -UFormat '+%Y-%m-%dT%H:%M:%SZ')
            $objBody | Add-Member -Type NoteProperty -Name 'lastReportedDateTime' -Value "$lastReportedDateTime"
        }
        if($malwareFamilyNames){$objBody | Add-Member -Type NoteProperty -Name 'malwareFamilyNames' -Value @($malwareFamilyNames)}
        if($passiveOnly){$objBody | Add-Member -Type NoteProperty -Name 'passiveOnly' $passiveOnly}
        if($severity){$objBody | Add-Member -Type NoteProperty -Name 'severity' $severity}
        if($tags){$objBody | Add-Member -Type NoteProperty -Name 'tags' -Value @($tags)}
        if($targetProduct){$objBody | Add-Member -Type NoteProperty -Name 'targetProduct' -Value "$targetProduct"}
        if($threatType){$objBody | Add-Member -Type NoteProperty -Name 'threatType' -Value "$threatType"}
        if($tlpLevel){$objBody | Add-Member -Type NoteProperty -Name 'tlpLevel' -Value "$tlpLevel"}

        if($PSCmdlet.ParameterSetName -eq "Email") {
            # Email observables
            Write-Verbose "Email Observables"
            if($emailEncoding){$objBody | add-Member -Type NoteProperty -name 'emailEncoding' -Value "$emailEncoding"}
            if($emailLanguage){$objBody | Add-Member -Type NoteProperty -Name 'emailLanguage' -Value "$emailLanguage"}
            if($emailRecipient){$objBody | Add-Member -Type NoteProperty -Name 'emailRecipient' -Value "$emailRecipient"}
            if($emailSenderAddress){$objBody | Add-Member -Type NoteProperty -Name 'emailSenderAddress' -Value "$emailSenderAddress"}
            if($emailSenderName){$objBody | Add-Member -Type NoteProperty -Name 'emailSenderName' -Value "$emailSenderName"}
            if($emailSourceDomain){$objBody | Add-Member -Type NoteProperty -Name 'emailSourceDomain' -Value "$emailSourceDomain"}
            if($emailSourceIpAddress){$objBody | Add-Member -Type NoteProperty -Name 'emailSourceIpAddress' -Value "$emailSourceIpAddress"}
            if($emailSubject){$objBody | Add-Member -Type NoteProperty -Name 'emailSubject' -Value "$emailSubject"}
            if($emailXMailer){$objBody | Add-Member -Type NoteProperty -Name 'emailXMailer' -Value "$emailXMailer"}
        }

        if($PSCmdlet.ParameterSetName -eq "File") {
            # File Observables
            Write-Verbose "File Observables"
            if($fileCompileDateTime){
                $fileCompileDateTime = (Get-Date -Date $fileCompileDateTime -UFormat '+%Y-%m-%dT%H:%M:%SZ')
                $objBody | Add-Member -Type NoteProperty -Name 'fileCompileDateTime' -Value "$fileCompileDateTime"
            }
            if($fileCreatedDateTime){
                $fileCreatedDateTime = (Get-Date -Date $fileCreatedDateTime -UFormat '+%Y-%m-%dT%H:%M:%SZ')
                $objBody | Add-Member -Type NoteProperty -Name 'fileCreatedDateTime' -Value "$fileCreatedDateTime"
            }
            if($fileHashType -or $fileHashValue){
                if($fileHashType -and $fileHashValue){
                    if($fileHashType){$objBody | Add-Member -Type NoteProperty -Name 'fileHashType' -Value "$fileHashType"}
                    if($fileHashValue){$objBody | Add-Member -Type NoteProperty -Name 'fileHashValue' -Value "$fileHashValue"}
                }            
                Else{
                    Write-Error "fileHashType and fileHashValue are required together"
                    break
                }
            }
            if($fileMutexName){$objBody | Add-Member -Type NoteProperty -Name 'fileMutexName' -Value "$fileMutexName"}
            if($fileName){$objBody | Add-Member -Type NoteProperty -Name 'fileName' -Value "$fileName"}
            if($filePacker){$objBody | Add-Member -Type NoteProperty -Name 'filePacker' -Value "$filePacker"}
            if($filePath){$objBody | Add-Member -Type NoteProperty -Name 'filePath' -Value "$filePath"}
            if($fileSize){$objBody | Add-Member -Type NoteProperty -Name 'fileSize' $fileSize}
            if($fileType){$objBody | Add-Member -Type NoteProperty -Name 'fileType' -Value "$fileType"}
        }

        if($PSCmdlet.ParameterSetName -eq "Network") {
            # Network Observables
            Write-Verbose "Network Observables"
            if($domainName){$objBody | Add-Member -Type NoteProperty -Name 'domainName' -Value "$domainName"}
            if($networkCidrBlock){$objBody | Add-Member -Type NoteProperty -Name 'networkCidrBlock' -Value "$networkCidrBlock"}
            if($networkDestinationAsn){$objBody | Add-Member -Type NoteProperty -Name 'networkDestinationAsn' $networkDestinationAsn}
            if($networkDestinationCidrBlock){$objBody | Add-Member -Type NoteProperty -Name 'networkDestinationCidrBlock' -Value "$networkDestinationCidrBlock"}
            if($networkDestinationIPv4){$objBody | Add-Member -Type NoteProperty -Name 'networkDestinationIPv4' -Value "$networkDestinationIPv4"}
            if($networkDestinationIPv6){$objBody | Add-Member -Type NoteProperty -Name 'networkDestinationIPv6' -Value "$networkDestinationIPv6"}
            if($networkDestinationPort){$objBody | Add-Member -Type NoteProperty -Name 'networkDestinationPort' $networkDestinationPort}
            if($networkIPv4){$objBody | Add-Member -Type NoteProperty -Name 'networkIPv4' -Value "$networkIPv4"}
            if($networkIPv6){$objBody | Add-Member -Type NoteProperty -Name 'networkIPv6' -Value "$networkIPv6"}
            if($networkPort){$objBody | Add-Member -Type NoteProperty -Name 'networkPort' $networkPort}
            if($networkProtocol){$objBody | Add-Member -Type NoteProperty -Name 'networkProtocol' $networkProtocol}
            if($networkSourceAsn){$objBody | Add-Member -Type NoteProperty -Name 'networkSourceAsn' $networkSourceAsn}
            if($networkSourceCidrBlock){$objBody | Add-Member -Type NoteProperty -Name 'networkSourceCidrBlock' -Value "$networkSourceCidrBlock"}
            if($networkSourceIPv4){$objBody | Add-Member -Type NoteProperty -Name 'networkSourceIPv4' -Value "$networkSourceIPv4"}
            if($networkSourceIPv6){$objBody | Add-Member -Type NoteProperty -Name 'networkSourceIPv6' -Value "$networkSourceIPv6"}
            if($networkSourcePort){$objBody | Add-Member -Type NoteProperty -Name 'networkSourcePort' $networkSourcePort}
            if($url){$objBody | Add-Member -Type NoteProperty -Name 'url' -Value "$url"}
            if($userAgent){$objBody | Add-Member -Type NoteProperty -Name 'userAgent' -Value "$userAgent"}
        }
        $Body = ConvertTo-Json $objBody -Depth 5
        Write-Verbose $Body

        try {
            # Fetch the item by its id
            $resource = "security/tiIndicators"
            $uri = "https://graph.microsoft.com/$Version/$($resource)"
            $response = Invoke-RestMethod -Uri $uri -Headers $GraphSecurityAuthHeader -Method POST -Body $Body
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
    End {

        # Nothing to See Here

    }
}