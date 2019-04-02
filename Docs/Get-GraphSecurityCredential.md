---
external help file: MicrosoftGraphSecurity-help.xml
Module Name: MicrosoftGraphSecurity
online version:
schema: 2.0.0
---

# Get-GraphSecurityCredential

## SYNOPSIS
Gets a username and AppID to be used by other Microsoft Graph Security module cmdlets.

## SYNTAX

```
Get-GraphSecurityCredential [[-Username] <String>] [-PassThru] [<CommonParameters>]
```

## DESCRIPTION
Get-GraphSecurityCredential imports a username and AppId to be used by other Microsoft Graph Security module cmdlets.

When using Get-GraphSecurityCredential you will be prompted to provide your Azure AD username (UPN) and AppId.

Get-GraphSecurityCredential takes the username and AppId and stores them in a special global session variable called $GraphSecurityCredential.

Get-GraphSecurityAuthToken references that special global variable to get an authentication token.

See the examples section for ways to automate setting your Microsoft Graph Security credentials for the session.

## EXAMPLES

### EXAMPLE 1
```
Get-GraphSecurityCredential
```

This prompts the user to enter both their username as well as their password.

 Username = username (Example: Nicholas@contoso.com)
 Password = AppId (Example: 64407e7c-8522-417f-a003-f69ad0b1a89b)

 C:\\\>$GraphSecurityCredential

 To verify your credentials are set in the current session, run the above command.

 UserName                                 Password
 --------                                 --------
 nicholas@contoso.com  System.Security.SecureString

### EXAMPLE 2
```
Get-GraphSecurityCredential -PassThru | Export-CliXml C:\Users\Nicholas\MyGraphSecurityCred.credential -Force
```

By specifying the -PassThru switch parameter, this will put the $GraphSecurityCredential into the pipeline which can be exported to a .credential file that will store the username and encrypted version of the AppId in a file.

We can use this newly created .credential file to automate setting our credentials in the session by adding an import command to our profile.

C:\\\>notepad $profile

The above command will open our PowerShell profile, which is a set of commands that will run when we start a new session.
By default it is empty.

$GraphSecurityCredential = Import-Clixml "C:\Users\Nicholas\MyGraphSecurityCred.credential"

By adding the above line to our profile and save, the next time we open a new PowerShell session, the credential file will automatically be imported into the $GraphSecurityCredential which allows us to use other cmdlets without running Get-GraphSecurityCredential at the start of the session.

## PARAMETERS

### -Username
Specifies the username

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PassThru
Specifies that the credential should be returned into the pipeline for further processing.

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see about_CommonParameters (http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

### System.Management.Automation.PSCredential
## NOTES

## RELATED LINKS
