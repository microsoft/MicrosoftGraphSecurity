<#
.Synopsis
   Gets a authenticaiton token to be used by other Microsoft Graph Security module cmdlets.
.DESCRIPTION
   Get-GraphSecurityAuthToken gets an authentication token to be used by other Microsoft Graph Security module cmdlets.

   When using Get-GraphSecurityAuthToken you will be prompted to provide your Azure AD username (UPN), password and AppId.

   Get-GraphSecurityAuthToken takes the token and stores them in a special global session variable called $GraphSecurityAuthToken.

   All Microsoft Graph Security Module cmdlets reference that special global variable to pass requests to your tenant.

.EXAMPLE
   Get-GraphSecurityAuthToken

    This prompts the user to enter both their username as well as their password, then prompts for AppId.

    Username = username (Example: Nicholas@contoso.com)
    Password = Password (Example: Sup3rS3cureP@ssw0rd!)
    Username = AppId
    Password = AppId (Example: 64407e7c-8522-417f-a003-f69ad0b1a89b)

    C:\>$GraphSecurityAuthToken

    To verify your auth token is set in the current session, run the above command.

    UserName                                 Password
    --------                                 --------
    nicholas@contoso.com  System.Security.SecureString

.FUNCTIONALITY
   Get-GraphSecurityAuthToken is intended to get an authentication token into a global session variable to allow other cmdlets to authenticate when passing requests.
#>

function Get-GraphSecurityAuthToken {

    [CmdletBinding()]

    Param
    (

        # Specifies the password.
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]$GraphSecurityCredential

    )

    Try {$Username = Select-GraphSecurityUsername}
        Catch {Throw $_}

    Try {$AppId = Select-GraphSecurityAppId}
        Catch {Throw $_}

    $user = New-Object "System.Net.Mail.MailAddress" -ArgumentList $Username

    $tenant = $user.Host

    Write-Verbose "Checking for AzureAD module..."

    $AadModule = Get-Module -Name "AzureAD" -ListAvailable

    if ($AadModule -eq $null) {

        Write-Verbose "AzureAD PowerShell module not found, looking for AzureADPreview"

        $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable

    }

    if ($AadModule -eq $null) {

        Install-GraphSecurityAADModule

        $AadModule = Get-Module -Name "AzureAD" -ListAvailable

    }

    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version

    if($AadModule.count -gt 1){

        $Latest_Version = ($AadModule | select version | Sort-Object)[-1]

        $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }

            # Checking if there are multiple versions of the same module found

            if($AadModule.count -gt 1){

            $aadModule = $AadModule | Select-Object -Unique

        }

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"

        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

    else {

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"

        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

    [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null

    [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null

    $redirectUri = "urn:ietf:wg:oauth:2.0:oob"

    $resourceAppIdURI = "https://graph.microsoft.com"

    $authority = "https://login.microsoftonline.com/$Tenant"

    try {

        $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

        # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
        # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

        $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"

        $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($Username, "OptionalDisplayableId")

        $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$AppId,$redirectUri,$platformParameters,$userId).Result

        if($authResult.AccessToken){

        # Creating header for Authorization token

        $Global:GraphSecurityauthHeader = @{
            'Content-Type'='application/json'
            'Authorization'="Bearer " + $authResult.AccessToken
            'ExpiresOn'=$authResult.ExpiresOn
            'Prefer'='return=representation'
            }

        }

        else {


        Write-Warning "Authorization Access Token is null, please re-run authentication..."

        break

        }

    }

    catch {

    Write-Verbose $_.Exception.Message
    Write-Verbose $_.Exception.ItemName

    break

    }

}