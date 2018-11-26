#----------------------------Include functions---------------------------
# KUDOS to the chocolatey project for the basis of this code

# get the path of where the module is saved (if module is at c:\myscripts\module.psm1, then c:\myscripts\)
$mypath = (Split-Path -Parent -Path $MyInvocation.MyCommand.Definition)

#find all the ps1 files in the Functions subfolder
Resolve-Path -Path $mypath\Functions\*.ps1 | ForEach-Object -Process {
    . $_.ProviderPath
}

#----------------------------Exports---------------------------
# Cmdlets to export (must be exported as functions, not cmdlets) - This array format can be copied directly to the manifest as the 'FunctionsToExport' value
$ExportedCommands = @('Get-GSAAlert','Get-GSAAlerts', 'Get-GSASecureScores', 'Get-GSACredential','Get-GSAAuthToken','Set-GSAAlert')
$ExportedCommands | ForEach-Object {Export-ModuleMember -Function $_}

# Vars to export (must be exported here, even if also included in the module manifest in 'VariablesToExport'
Export-ModuleMember -Variable GSACredential
Export-ModuleMember -Variable GSAauthToken

# Aliases to export
Export-ModuleMember -Alias *
