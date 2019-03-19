function Install-GraphSecurityAADModule
{
    [CmdletBinding()]

    #Check for Admin Privleges
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if(-not ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))){
        Write-Warning -Message "Can not install AAD Module.  You are not running as Administrator"
        Write-Warning -Message "Installing AAD Module to Current User Scope"
        Install-Module AzureAD -Scope CurrentUser -Force
    }
    Else{
        Install-Module AzureAD -Force

    }
 }
