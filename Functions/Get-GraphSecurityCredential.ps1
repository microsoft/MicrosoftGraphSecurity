<#
.Synopsis
   Gets a username and AppID to be used by other Microsoft Graph Security module cmdlets.
.DESCRIPTION
   Get-GraphSecurityCredential imports a username and AppId to be used by other Microsoft Graph Security module cmdlets.

   When using Get-GraphSecurityCredential you will be prompted to provide your Azure AD username (UPN) and AppId.

   Get-GraphSecurityCredential takes the username and AppId and stores them in a special global session variable called $GraphSecurityCredential.

   Get-GraphSecurityAuthToken references that special global variable to get an authentication token.

   See the examples section for ways to automate setting your Microsoft Graph Security credentials for the session.

.EXAMPLE
   Get-GraphSecurityCredential

    This prompts the user to enter both their username as well as their password.

    Username = username (Example: Nicholas@contoso.com)
    Password = AppId (Example: 64407e7c-8522-417f-a003-f69ad0b1a89b)

    C:\>$GraphSecurityCredential

    To verify your credentials are set in the current session, run the above command.

    UserName                                 Password
    --------                                 --------
    nicholas@contoso.com  System.Security.SecureString

.EXAMPLE
    Get-GraphSecurityCredential -PassThru | Export-CliXml C:\Users\Nicholas\MyGraphSecurityCred.credential -Force

    By specifying the -PassThru switch parameter, this will put the $GraphSecurityCredential into the pipeline which can be exported to a .credential file that will store the username and encrypted version of the AppId in a file.

    We can use this newly created .credential file to automate setting our credentials in the session by adding an import command to our profile.

    C:\>notepad $profile

    The above command will open our PowerShell profile, which is a set of commands that will run when we start a new session. By default it is empty.

    $GraphSecurityCredential = Import-Clixml "C:\Users\Nicholas\MyGraphSecurityCred.credential"

    By adding the above line to our profile and save, the next time we open a new PowerShell session, the credential file will automatically be imported into the $GraphSecurityCredential which allows us to use other cmdlets without running Get-GraphSecurityCredential at the start of the session.

.FUNCTIONALITY
   Get-GraphSecurityCredential is intended to import the username and password into a global session variable to allow Get-GraphSecurityAuthToken to request an authentication token.
#>

function Get-GraphSecurityCredential {

    [CmdletBinding()]

    [OutputType([System.Management.Automation.PSCredential])]

    Param
    (

        # Specifies the username
        [Parameter(Mandatory=$false)]
        [string]$Username,

        # Specifies that the credential should be returned into the pipeline for further processing.
        [Parameter(Mandatory=$false)]
        [switch]$PassThru

    )
    Process
    {

        # If username is specified, prompt for password token and get it all into a global variable
        If ($Username) {
            [System.Management.Automation.PSCredential]$Global:GraphSecurityCredential = Get-Credential -UserName $Username -Message "Enter your AppId in the password box"
        }

        # Else, prompt for both the username and password and get it all into a global variable
        Else {
            [System.Management.Automation.PSCredential]$Global:GraphSecurityCredential = Get-Credential -Message "Enter your username and AppId"
        }

        # If -PassThru is specified, write the credential object to the pipeline (the global variable will also be exported to the calling session with Export-ModuleMember)
        If ($PassThru) {
            $GraphSecurityCredential
        }

    }

}
