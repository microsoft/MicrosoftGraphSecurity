---
external help file: MicrosoftGraphSecurity-help.xml
Module Name: MicrosoftGraphSecurity
online version:
schema: 2.0.0
---

# Get-GraphSecurityAlert

## SYNOPSIS
Gets alerts in Microsoft Graph Security.

## SYNTAX

### Default (Default)
```
Get-GraphSecurityAlert [-Version <String>] [<CommonParameters>]
```

### List
```
Get-GraphSecurityAlert [-Version <String>] [-top <Int32>] [-skip <Int32>] [-orderBy <String>]
 [-riskScore <String>] [-activityGroupName <String>] [-assignedTo <String>] [-azureSubscriptionId <String>]
 [-azureTenantId <String>] [-category <String>] [-comments <String[]>] [-confidence <String[]>]
 [-detectionIds <String[]>] [-feedback <String>] [-severity <String>] [-sourceMaterials <String[]>]
 [-status <String>] [-tags <String[]>] [-title <String>] [-provider <String>] [-vendor <String>]
 [-aadUserId <String>] [-accountName <String>] [-emailRole <String>] [-userPrincipalName <String>]
 [-eventDateTimeAfter <String>] [-eventDateTimeBefore <String>] [-createdDateTimeAfter <String>]
 [-createdDateTimeBefore <String>] [-closedDateTimeAfter <String>] [-closedDateTimeBefore <String>]
 [-lastModifiedDateTimeAfter <String>] [-lastModifiedDateTimeBefore <String>] [<CommonParameters>]
```

### Fetch
```
Get-GraphSecurityAlert [-Version <String>] [-Identity] <String> [<CommonParameters>]
```

### Count
```
Get-GraphSecurityAlert [-count <String>] [<CommonParameters>]
```

## DESCRIPTION
Gets alerts in Microsoft Graph Security.

Without parameters, Get-GraphSecurityAlert gets 100 alerts and associated properties.
You can specify a particular alert  to fetch a single alert's information or you can pull a list of activities based on the provided filters.

There are multiple parameter sets:

## EXAMPLES

### EXAMPLE 1
```
Get-GraphSecurityAlert
```

This will default grab the Top 100 alerts.

### EXAMPLE 2
```
Get-GraphSecurityAlert -id D0ED9BD3-AB24-3E05-A4D3-171280CA3CB9
```

This will get a single alert.

### EXAMPLE 3
```
Get-GraphSecurityAlert -provider MCAS -severity high
```

This will get all alerts from MCAS with high severity.

## PARAMETERS

### -Version
Specifies the API Version

```yaml
Type: String
Parameter Sets: Default, List, Fetch
Aliases:

Required: False
Position: Named
Default value: V1.0
Accept pipeline input: False
Accept wildcard characters: False
```

### -Identity
Fetches an activity object by its unique identifier.

```yaml
Type: String
Parameter Sets: Fetch
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -top
Specifies the maximum number of results to retrieve

```yaml
Type: Int32
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: 100
Accept pipeline input: False
Accept wildcard characters: False
```

### -skip
Specifies the number of records, from the beginning of the result set, to skip.

```yaml
Type: Int32
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: 0
Accept pipeline input: False
Accept wildcard characters: False
```

### -count
Returns the number of alerts to the user

```yaml
Type: String
Parameter Sets: Count
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -orderBy
Currently orderBy Ascending by default

```yaml
Type: String
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -riskScore
Provider generated/calculated risk score of the network connection.
Recommended value range of 0-1, which equates to a percentage.

```yaml
Type: String
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -activityGroupName
Name or alias of the activity group (attacker) this alert is attributed to.

```yaml
Type: String
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -assignedTo
Name of the analyst the alert is assigned to for triage, investigation, or remediation (supports update).

```yaml
Type: String
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -azureSubscriptionId
Azure subscription ID, present if this alert is related to an Azure resource.

```yaml
Type: String
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -azureTenantId
Azure Active Directory tenant ID.
Required.

```yaml
Type: String
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -category
Category of the alert (for example, credentialTheft, ransomware, etc.).

```yaml
Type: String
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -comments
Customer-provided comments on alert (for customer alert management) (supports update).

```yaml
Type: String[]
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -confidence
Confidence of the detection logic (percentage between 1-100).

```yaml
Type: String[]
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -detectionIds
Set of alerts related to this alert entity (each alert is pushed to the SIEM as a separate record).

```yaml
Type: String[]
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -feedback
Analyst feedback on the alert.

```yaml
Type: String
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -severity
Alert severity - set by vendor/provider.

```yaml
Type: String
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -sourceMaterials
Hyperlinks (URIs) to the source material related to the alert, for example, provider's user interface for alerts or log search, etc.

```yaml
Type: String[]
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -status
Alert lifecycle status (stage).

```yaml
Type: String
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -tags
User-definable labels that can be applied to an alert and can serve as filter conditions (for example "HVA", "SAW", etc.) (supports update).

```yaml
Type: String[]
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -title
Alert title.
Required.

```yaml
Type: String
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -provider
Specific provider (product/service - not vendor company); for example, WindowsDefenderATP.

```yaml
Type: String
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -vendor
Name of the alert vendor (for example, Microsoft, Dell, FireEye).
Required

```yaml
Type: String
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -aadUserId
AAD User object identifier (GUID) - represents the physical/multi-account user entity.

```yaml
Type: String
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -accountName
Account name of user account (without Active Directory domain or DNS domain) - (also called mailNickName).
Case-Sensitive

```yaml
Type: String
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -emailRole
For email-related alerts - user account's email 'role'.

```yaml
Type: String
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -userPrincipalName
User sign-in name - internet format: (user account name)@(user account DNS domain name).

```yaml
Type: String
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -eventDateTimeAfter
Date Time Params ######

```yaml
Type: String
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -eventDateTimeBefore
{{ Fill eventDateTimeBefore Description }}

```yaml
Type: String
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -createdDateTimeAfter
{{ Fill createdDateTimeAfter Description }}

```yaml
Type: String
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -createdDateTimeBefore
{{ Fill createdDateTimeBefore Description }}

```yaml
Type: String
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -closedDateTimeAfter
{{ Fill closedDateTimeAfter Description }}

```yaml
Type: String
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -closedDateTimeBefore
{{ Fill closedDateTimeBefore Description }}

```yaml
Type: String
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -lastModifiedDateTimeAfter
{{ Fill lastModifiedDateTimeAfter Description }}

```yaml
Type: String
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -lastModifiedDateTimeBefore
{{ Fill lastModifiedDateTimeBefore Description }}

```yaml
Type: String
Parameter Sets: List
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see about_CommonParameters (http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
