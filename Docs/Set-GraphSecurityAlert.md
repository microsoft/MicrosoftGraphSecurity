---
external help file: MicrosoftGraphSecurity-help.xml
Module Name: MicrosoftGraphSecurity
online version:
schema: 2.0.0
---

# Set-GraphSecurityAlert

## SYNOPSIS
Sets the status of alerts in Microsoft Graph Security.

## SYNTAX

```
Set-GraphSecurityAlert [[-id] <String>] [[-Version] <String>] [[-assignedTo] <String>] [-Closed] [-Open]
 [[-closedDateTime] <DateTime>] [[-comments] <String>] [[-feedback] <String>] [[-Status] <String>]
 [[-Tags] <String>] [<CommonParameters>]
```

## DESCRIPTION
Sets the status of alerts in Microsoft Graph Security.

There are multiple parameter:

assignedTo: Used for setting the name of the analyst the alert is assigned to for triage, investigation, or remediation.
closed: Used to close the alert \[default is no\]
closedDateTime: Time at which the alert was closed.
\[default is current date and time\]
comments: Analyst comments on the alert.
feedback: Analyst feedback on the alert.
Possible values are: unknown, truePositive, falsePositive, benignPositive.
status: Alert lifecycle status (stage).
Possible values are: unknown, newAlert, inProgress, resolved.
tags: User-definable labels that can be applied to an alert and can serve as filter conditions.

An alert identity is always required to be specified either explicity or implicitly from the pipeline.

## EXAMPLES

### EXAMPLE 1
```
Set-GraphSecurityAlert -Id D0ED9BD3-AB24-3E05-A4D3-171280CA3CB9 -Status resolved -Feedback truePositive
```

This marks a single specified alert as 'resolved' and as a 'truePositive'.

### EXAMPLE 2
```
Get-GraphSecurityAlert -Id D0ED9BD3-AB24-3E05-A4D3-171280CA3CB9 | Set-GraphSecurityAlert -Status inProgress -Assignedto joe@contoso.com
```

This will set the status of the specified alert as "inProgress" and who is working it "joe@contoso.com".

## PARAMETERS

### -id
Specifies the alert id

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -Version
Specifies the API Version

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: V1
Accept pipeline input: False
Accept wildcard characters: False
```

### -assignedTo
Sets the owner of the alert

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Closed
sets the alert to closed

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Open
sets the alert to open

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -closedDateTime
Sets the close time

```yaml
Type: DateTime
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -comments
Sets any comments

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -feedback
Sets the Feedback; 0,1,2,3

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 6
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Status
Sets the Feedback; 0,1,2,3

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 7
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Tags
Sets any tags

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 8
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
