---
external help file: MicrosoftGraphSecurity-help.xml
Module Name: MicrosoftGraphSecurity
online version:
schema: 2.0.0
---

# Get-GraphSecuritySecureScore

## SYNOPSIS
Gets secure scores in Microsoft Graph Security.

## SYNTAX

```
Get-GraphSecuritySecureScore [[-top] <String>] [[-Version] <String>] [<CommonParameters>]
```

## DESCRIPTION
Gets secure score in Microsoft Graph Security.

Without parameters, Get-GraphSecuritySecureScore gets 100 secure scores and associated properties.

## EXAMPLES

### EXAMPLE 1
```
Get-GraphSecuritySecureScore
```

This will default grab the Top 100 secure scores.

## PARAMETERS

### -top
Specifies the maximum number of results to retrieve

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: 100
Accept pipeline input: False
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
Default value: Beta
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see about_CommonParameters (http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS
