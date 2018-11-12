<#
.Synopsis
   Gets a authenticaiton token to be used by other Graph Security API module cmdlets.
.DESCRIPTION
   Get-GSAAuthToken gets an authentication token to be used by other Graph Security API module cmdlets.

   When using Get-GSAAuthToken you will be prompted to provide your Azure AD username (UPN), password and AppId.

   Get-GSAAuthToken takes the token and stores them in a special global session variable called $GSAAuthToken.

   All Graph Security API Module cmdlets reference that special global variable to pass requests to your tenant.

.EXAMPLE
   Get-GSAAuthToken

    This prompts the user to enter both their username as well as their password, then prompts for AppId.

    Username = username (Example: Nicholas@contoso.com)
    Password = Password (Example: Sup3rS3cureP@ssw0rd!)
    Username = AppId
    Password = AppId (Example: 64407e7c-8522-417f-a003-f69ad0b1a89b)

    C:\>$GSAAuthToken

    To verify your auth token is set in the current session, run the above command.

    UserName                                 Password
    --------                                 --------
    nicholas@contoso.com  System.Security.SecureString

.FUNCTIONALITY
   Get-GSAAuthToken is intended to get an authentication token into a global session variable to allow other cmdlets to authenticate when passing requests.
#>

function Get-GSAAuthToken {
    [CmdletBinding()]
    
    Param
    (
        # Specifies the password.
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]$GSACredential

    )
    
    Try {$Username = Select-GSAUsername}
        Catch {Throw $_}

    Try {$AppId = Select-GSAAppId}
        Catch {Throw $_}

    $user = New-Object "System.Net.Mail.MailAddress" -ArgumentList $Username

    $tenant = $user.Host

    Write-Host "Checking for AzureAD module..."

    $AadModule = Get-Module -Name "AzureAD" -ListAvailable

    if ($AadModule -eq $null) {

        Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"

        $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable

    }

    if ($AadModule -eq $null) {
        Install-GSAAADModule
        $AadModule = Get-Module -Name "AzureAD" -ListAvailable
    }

    # Getting path to ActiveDirectory Assemblies
    # If the module count is greater than 1 find the latest version

    if($AadModule.count -gt 1){

        $Latest_Version = ($AadModule | select version | Sort-Object)[-1]

        $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }

            # Checking if there are multiple versions of the same module found

            if($AadModule.count -gt 1){

            $aadModule = $AadModule | select -Unique

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

        $Global:GSAauthHeader = @{
            'Content-Type'='application/json'
            'Authorization'="Bearer " + $authResult.AccessToken
            'ExpiresOn'=$authResult.ExpiresOn
            }

        }

        else {

        Write-Host
        Write-Warning "Authorization Access Token is null, please re-run authentication..."
        Write-Host
        break

        }

    }

    catch {

    write-host $_.Exception.Message -f Red
    write-host $_.Exception.ItemName -f Red
    write-host
    break

    }

}