<#
.Synopsis
   Internal function to install the AAD Module for Microsoft Graph Security.

.DESCRIPTION
   Installs the AAD Module for Microsoft Graph Security.

.EXAMPLE
   Install-GraphSecurityAADModule

.FUNCTIONALITY
   Install-GraphSecurityAADModule is intended as an internal function to install the AAD Module.
#>

function Install-GraphSecurityAADModule {

    [CmdletBinding()]

    #Check for Admin Privleges
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())

    if (-not ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {

        #No Admin, install to current user
        Write-Warning -Message "Can not install AAD Module.  You are not running as Administrator"

        Write-Warning -Message "Installing AAD Module to Current User Scope"

        Install-Module AzureAD -Scope CurrentUser -Force
    }

    Else {

        #Admin, install to all users
        Install-Module AzureAD -Force


    }
}
