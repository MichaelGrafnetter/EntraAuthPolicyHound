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

.NOTES
    Version: 1.2
    Author: Michael Grafnetter

#>

#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Authentication, Microsoft.Graph.Applications

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
Write-Verbose -Message 'Fetching tenant ID and name...' -Verbose
[Microsoft.Graph.PowerShell.Models.MicrosoftGraphOrganization] $organization = Get-MgOrganization -Property Id,VerifiedDomains
[guid] $tenantId = $organization.Id
[string] $tenantPrimaryDomain =
    $organization.VerifiedDomains |
    Where-Object IsDefault -eq $true |
    Select-Object -ExpandProperty Name

# Initialize BloodHound OpenGraph
[BloodHoundOpenGraph] $openGraph = [BloodHoundOpenGraph]::new($openGraphSourceKind)
[AZAuthenticationPolicy] $authenticationPolicy = [AZAuthenticationPolicy]::new($tenantId, $tenantPrimaryDomain)
$openGraph.AddNode($authenticationPolicy)
[AZTenant] $tenantNode = [AZTenant]::new($tenantId)

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

# Fetch all service principal identifiers and application permissions
Write-Verbose -Message 'Retrieving service principal permissions...' -Verbose
[Microsoft.Graph.PowerShell.Models.MicrosoftGraphServicePrincipal[]] $servicePrincipals = Get-MgServicePrincipal -All -Property Id,AppId -ExpandProperty AppRoleAssignments

# Hardcoded App ID of the Microsoft Graph application
# Note: As an alternative, the Microsoft Graph App ID could be fetched dynamically
[guid] $microsoftGraphAppId = '00000003-0000-0000-c000-000000000000'
[guid] $microsoftGraphServicePrincipalId =
    $servicePrincipals |
    Where-Object AppId -eq $microsoftGraphAppId |
    Select-Object -ExpandProperty Id

foreach ($servicePrincipal in $servicePrincipals) {
    # Prepare the service principal graph node for possible edges
    [AZServicePrincipal] $servicePrincipalNode = [AZServicePrincipal]::new($servicePrincipal.Id, $tenantId)

    foreach ($permission in $servicePrincipal.AppRoleAssignments) {
        if ($permission.ResourceId -ne $microsoftGraphServicePrincipalId) {
            # The permission is not assigned for the Microsoft Graph application
            continue
        }

        # Check if the app has any permissions related to TAPs or Passkeys
        if ($permission.AppRoleId -eq $manageUserAuthenticationMethodsPermissionId) {
            # The app has the UserAuthenticationMethod.ReadWrite.All permission
            $openGraph.AddEdge([AZMGUserAuthenticationMethod_ReadWrite_All]::new($servicePrincipalNode, $tenantNode))
        } elseif ($permission.AppRoleId -eq $manageUserPasskeysPermissionId) {
            # The app has the UserAuthMethod-Passkey.ReadWrite.All permission
            $openGraph.AddEdge([AZMGUserAuthenticationMethod_Passkey_ReadWrite_All]::new($servicePrincipalNode, $tenantNode))
        } elseif ($permission.AppRoleId -eq $manageAuthenticationPolicyPermissionId) {
            # The app has the Policy.ReadWrite.AuthenticationMethod permission
            $openGraph.AddEdge([AZMGPolicy_ReadWrite_AuthenticationMethod]::new($servicePrincipalNode, $tenantNode))

            # In addition to the AZServicePrincipal->AZTenant edge, we also create a AZServicePrincipal->AZAuthenticationPolicy edge.
            [Edge] $edge = [AZChangeAuthenticationPolicy]::new($servicePrincipalNode, $authenticationPolicy)
            $edge.SetDescription('The application is assigned the Policy.ReadWrite.AuthenticationMethod permission.')
            $openGraph.AddEdge($edge)
        }
    }
}

# Create a single AZChangeAuthenticationPolicy edge from the "Authentication Policy Administrator" role to the AZAuthenticationPolicy node.
[guid] $authenticationPolicyAdminRoleTemplateId = '0526716b-113d-4c15-b2c8-68e3c22b9f80'
[AZRole] $authenticationPolicyAdminRole = [AZRole]::new($authenticationPolicyAdminRoleTemplateId, $tenantId)
[Edge] $authenticationPolicyAdminEdge = [AZChangeAuthenticationPolicy]::new($authenticationPolicyAdminRole, $authenticationPolicy)
$authenticationPolicyAdminEdge.SetDescription('Members of the "Authentication Policy Administrator" role can manage authentication method policies, including TAP and Passkey settings.')
$openGraph.AddEdge($authenticationPolicyAdminEdge)

# Create a single AZChangeAuthenticationPolicy edge from the "Global Administrator" role to the AZAuthenticationPolicy node.
# This is here just for completeness, as Global Admins can do everything.
[guid] $globalAdminRoleTemplateId = '62e90394-69f5-4237-9190-012177145e10'
[AZRole] $globalAdminRole = [AZRole]::new($globalAdminRoleTemplateId, $tenantId)
[Edge] $globalAdminEdge = [AZChangeAuthenticationPolicy]::new($globalAdminRole, $authenticationPolicy)
$globalAdminEdge.SetDescription('Members of the "Global Administrator" role can manage authentication method policies, including TAP and Passkey settings.')
$openGraph.AddEdge($globalAdminEdge)

# Disconnect from Microsoft Graph
Write-Verbose -Message 'Disconnecting from Microsoft Graph...' -Verbose
Disconnect-MgGraph | Out-Null

# Display and save the BloodHound OpenGraph output
Write-Verbose -Message 'Exporting BloodHound OpenGraph data...' -Verbose
[string] $fileName = 'AuthenticationPolicyData_{0:yyyy-MM-dd_HH-mm}.json' -f (Get-Date)
[string] $filePath = Join-Path -Path $PSScriptRoot -ChildPath $fileName
$openGraph.ToJson($filePath, $false)
$openGraph.ToJson($false)

Write-Verbose -Message 'Done. You can now ingest the data to BloodHound manually or via the API.' -Verbose
