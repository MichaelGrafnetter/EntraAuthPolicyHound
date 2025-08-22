<#
.SYNOPSIS
    Retrieves Entra ID settings related to Temporary Access Passes (TAPs)
    and Passkeys (FIDO2) using Microsoft Graph API and exports them
    in the BloodHound OpenGraph format.

.DESCRIPTION
    When executed with service principal identity, the following Microsoft Graph API application permissions are required:
    - Policy.Read.AuthenticationMethod
    - Application.Read.All
    Less granular permissions are also available.
#>

#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Authentication

# Import the BloodHound OpenGraph data model
using module '.\BloodHound.OpenGraph.Model.psm1'

# Show errors for uninitialized variables, etc.
Set-StrictMode -Version Latest

# Data source identifier for BloodHound OpenGraph
[string] $openGraphSourceKind = 'EntraTapPasskey'

# Authenticate
Write-Verbose -Message 'Connecting to Microsoft Graph...' -Verbose
Connect-MgGraph `
    -Scopes 'Policy.Read.AuthenticationMethod', 'Application.Read.All' `
    -ContextScope Process `
    -Environment Global `
    -NoWelcome

# Get info about the current tenant
Write-Verbose -Message 'Fetching Tenant ID...' -Verbose
[Microsoft.Graph.PowerShell.Authentication.AuthContext] $context = Get-MgContext
[guid] $tenantId = $context.TenantId
[AZTenant] $tenantNode = [AZTenant]::new($tenantId)

# Initialize BloodHound OpenGraph
[BloodHoundOpenGraph] $openGraph = [BloodHoundOpenGraph]::new($openGraphSourceKind)
[AZAuthenticationPolicy] $authenticationPolicy = [AZAuthenticationPolicy]::new($tenantId)
$openGraph.AddNode($authenticationPolicy)

# Get TAP settings
Write-Verbose -Message 'Retrieving TAP policy...' -Verbose
[pscustomobject] $tapPolicy = Invoke-MgGraphRequest `
    -Method GET `
    -Uri '/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/temporaryAccessPass' `
    -OutputType Json | ConvertFrom-Json

# Add the TAP policy to the BloodHound OpenGraph
$authenticationPolicy.SetTapEnabled($tapPolicy.state -eq 'enabled')

# Traverse the list of groups the TAP policy applies to
if ($null -ne $tapPolicy.includeTargets) {
    foreach ($includeTarget in $tapPolicy.includeTargets) {
        if ($includeTarget.id -eq 'all_users') {
            # The TAP policy applies to all users
            $authenticationPolicy.SetTapIncludesAllUsers($true)
        } else {
            # The TAP policy applies to a specific group
            [AZGroup] $group = [AZGroup]::new($includeTarget.id, $tenantId)
            [Edge] $edge = [AZTapInclude]::new($authenticationPolicy, $group)
            $openGraph.AddEdge($edge)
        }
    }
}

# Traverse the list of groups the TAP policy excludes
if ($null -ne $tapPolicy.excludeTargets) {
    foreach ($excludeTarget in $tapPolicy.excludeTargets) {
        [AZGroup] $group = [AZGroup]::new($excludeTarget.id, $tenantId)
        [Edge] $edge = [AZTapExclude]::new($authenticationPolicy, $group)
        $openGraph.AddEdge($edge)
    }
}

# Get Passkey settings
Write-Verbose -Message 'Retrieving Passkey (FIDO2) policy...' -Verbose
[pscustomobject] $passkeyPolicy = Invoke-MgGraphRequest `
    -Method GET `
    -Uri '/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/fido2' `
    -OutputType Json | ConvertFrom-Json

# Add the Passkey policy to the BloodHound OpenGraph
$authenticationPolicy.SetPasskeyEnabled($passkeyPolicy.state -eq 'enabled')

# Traverse the list of groups the Passkey policy applies to
if ($null -ne $passkeyPolicy.includeTargets) {
    foreach ($includeTarget in $passkeyPolicy.includeTargets) {
        if ($includeTarget.id -eq 'all_users') {
            # The Passkey policy applies to all users
            $authenticationPolicy.SetPasskeyIncludesAllUsers($true)
        } else {
            # The Passkey policy applies to a specific group
            [AZGroup] $group = [AZGroup]::new($includeTarget.id, $tenantId)
            [Edge] $edge = [AZPasskeyInclude]::new($authenticationPolicy, $group)
            $openGraph.AddEdge($edge)
        }
    }
}

# Traverse the list of groups the Passkey policy excludes
if ($null -ne $passkeyPolicy.excludeTargets) {
    foreach ($excludeTarget in $passkeyPolicy.excludeTargets) {
        [AZGroup] $group = [AZGroup]::new($excludeTarget.id, $tenantId)
        [Edge] $edge = [AZPasskeyExclude]::new($authenticationPolicy, $group)
        $openGraph.AddEdge($edge)
    }
}

# Fetch Microsoft Graph application permissions

# UserAuthenticationMethod.ReadWrite.All application permission ID:
[guid] $manageUserAuthenticationMethodsPermissionId = '50483e42-d915-4231-9639-7fdb7fd190e5'

# UserAuthMethod-Passkey.ReadWrite.All application permission ID:
[guid] $manageUserPasskeysPermissionId = '0400e371-7db1-4338-a269-96069eb65227'

# Policy.ReadWrite.AuthenticationMethod application permission ID:
[guid] $manageAuthenticationPolicyPermissionId = '29c18626-4985-4dcd-85c0-193eef327366'

# Hardcoded App ID of the Microsoft Graph application
# Note: As an alternative, the Microsoft Graph App ID could be fetched dynamically
Write-Verbose -Message 'Retrieving Microsoft Graph service principal...' -Verbose
[guid] $microsoftGraphAppId = '00000003-0000-0000-c000-000000000000'
[guid] $microsoftGraphServicePrincipalId = (Get-MgServicePrincipal -Filter "appId eq '$microsoftGraphAppId'" -Property Id).Id

# Fetch all service principal identifiers
Write-Verbose -Message 'Retrieving all service principals...' -Verbose
[guid[]] $servicePrincipals = Get-MgServicePrincipal -All -Property Id | Select-Object -ExpandProperty Id
[string] $activity = 'Processing service principal permissions...'

for ($i = 0; $i -lt $servicePrincipals.Count; $i++) {
    # This loop can take a while in large tenants, so we provide some progress feedback
    Write-Progress -Activity $activity -PercentComplete (($i / $servicePrincipals.Count) * 100)

    # Prepare the service principal graph node for possible edges
    [AZServicePrincipal] $servicePrincipalNode = [AZServicePrincipal]::new($servicePrincipals[$i], $tenantId)

    # Fetch all Microsoft Graph permission grants for the service principal
    [guid[]] $applicationPermissions =
        Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $servicePrincipals[$i] -All -Filter "resourceId eq $microsoftGraphServicePrincipalId" -Property AppRoleId |
        Select-Object -ExpandProperty AppRoleId

    # Check if the app has any permissions related to TAPs or Passkeys
    foreach ($permission in $applicationPermissions) {
        if ($permission -eq $manageUserAuthenticationMethodsPermissionId) {
            # The app has the UserAuthenticationMethod.ReadWrite.All permission
            $openGraph.AddEdge([AZMGUserAuthenticationMethod_ReadWrite_All]::new($servicePrincipalNode, $tenantNode))
        } elseif ($permission -eq $manageUserPasskeysPermissionId) {
            # The app has the UserAuthMethod-Passkey.ReadWrite.All permission
            $openGraph.AddEdge([AZMGUserAuthenticationMethod_Passkey_ReadWrite_All]::new($servicePrincipalNode, $tenantNode))
        } elseif ($permission -eq $manageAuthenticationPolicyPermissionId) {
            # The app has the Policy.ReadWrite.AuthenticationMethod permission
            $openGraph.AddEdge([AZMGPolicy_ReadWrite_AuthenticationMethod]::new($servicePrincipalNode, $tenantNode))
        }
    }
}

# Disconnect from Microsoft Graph
Write-Progress -Activity $activity -Completed
Write-Verbose -Message 'Disconnecting from Microsoft Graph...' -Verbose
Disconnect-MgGraph | Out-Null

# Display and save the BloodHound OpenGraph output
Write-Verbose -Message 'Exporting BloodHound OpenGraph data...' -Verbose
[string] $fileName = 'AuthenticationPolicyData_{0:yyyy-MM-dd_HH-mm}.json' -f (Get-Date)
[string] $filePath = Join-Path -Path $PSScriptRoot -ChildPath $fileName
$openGraph.ToJson($filePath, $false)
$openGraph.ToJson($false)

Write-Verbose -Message 'Done. You can now ingest the data to BloodHound manually or via the API.' -Verbose
