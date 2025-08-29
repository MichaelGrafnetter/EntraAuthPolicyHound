<#
.SYNOPSIS
    Retrieves Entra ID settings related to Temporary Access Passes (TAPs)
    and Passkeys (FIDO2) using Microsoft Graph API and exports them
    in the BloodHound OpenGraph format.

.DESCRIPTION
    When executed with service principal identity, the following Microsoft Graph API application permissions are required:
    - Policy.Read.AuthenticationMethod
    - Application.Read.All
    - GroupMember.Read.All
    - User.ReadBasic.All
    Less granular permissions are also available.

.NOTES
    Version: 2.0
    Author: Michael Grafnetter

#>

#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Identity.SignIns, Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Groups

# Import the BloodHound OpenGraph data model
using module '.\BloodHound.OpenGraph.Model.psm1'

# Show errors for uninitialized variables, etc.
Set-StrictMode -Version Latest

# Data source identifier for BloodHound OpenGraph
[string] $openGraphSourceKind = 'EntraTapPasskey'

# Authenticate
Write-Verbose -Message 'Connecting to Microsoft Graph...' -Verbose
Connect-MgGraph `
    -Scopes 'Policy.Read.AuthenticationMethod', 'Application.Read.All', 'GroupMember.Read.All', 'User.ReadBasic.All' `
    -ContextScope Process `
    -Environment Global `
    -NoWelcome -TenantId lab.dsinternals.com

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

[System.Collections.Generic.List[guid]] $tapIncludedGroups = @()

# Traverse the list of groups the TAP policy applies to
if ($null -ne $tapPolicy.includeTargets) {
    foreach ($includeTarget in $tapPolicy.includeTargets) {
        if ($includeTarget.id -eq 'all_users') {
            # The TAP policy applies to all users
            $authenticationPolicy.SetTapIncludesAllUsers($true)
        } else { # The TAP policy applies to a specific group
            # Create the corresponding AZGroup->AZAuthenticationPolicy edge
            [AZGroup] $group = [AZGroup]::new($includeTarget.id, $tenantId)
            [Edge] $edge = [AZTapInclude]::new($authenticationPolicy, $group)
            $openGraph.AddEdge($edge)
            
            # Cache the group ID for later use
            $tapIncludedGroups.Add($includeTarget.id)
        }
    }
}

[System.Collections.Generic.List[guid]] $tapExcludedGroups = @()

# Traverse the list of groups the TAP policy excludes
if ($null -ne $tapPolicy.excludeTargets) {
    foreach ($excludeTarget in $tapPolicy.excludeTargets) {
        # Create the corresponding AZGroup->AZAuthenticationPolicy edge
        [AZGroup] $group = [AZGroup]::new($excludeTarget.id, $tenantId)
        [Edge] $edge = [AZTapExclude]::new($authenticationPolicy, $group)
        $openGraph.AddEdge($edge)

        # Cache the group ID for later use
        $tapExcludedGroups.Add($excludeTarget.id)
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

[System.Collections.Generic.List[guid]] $passkeyIncludedGroups = @()

# Traverse the list of groups the Passkey policy applies to
if ($null -ne $passkeyPolicy.includeTargets) {
    foreach ($includeTarget in $passkeyPolicy.includeTargets) {
        if ($includeTarget.id -eq 'all_users') {
            # The Passkey policy applies to all users
            $authenticationPolicy.SetPasskeyIncludesAllUsers($true)
        } else { # The Passkey policy applies to a specific group
            # Create the corresponding AZGroup->AZAuthenticationPolicy edge
            [AZGroup] $group = [AZGroup]::new($includeTarget.id, $tenantId)
            [Edge] $edge = [AZPasskeyInclude]::new($authenticationPolicy, $group)
            $openGraph.AddEdge($edge)

            # Cache the group ID for later use
            $passkeyIncludedGroups.Add($includeTarget.id)
        }
    }
}

[System.Collections.Generic.List[guid]] $passkeyExcludedGroups = @()

# Traverse the list of groups the Passkey policy excludes
if ($null -ne $passkeyPolicy.excludeTargets) {
    foreach ($excludeTarget in $passkeyPolicy.excludeTargets) {
        # Create the corresponding AZGroup->AZAuthenticationPolicy edge
        [AZGroup] $group = [AZGroup]::new($excludeTarget.id, $tenantId)
        [Edge] $edge = [AZPasskeyExclude]::new($authenticationPolicy, $group)
        $openGraph.AddEdge($edge)

        # Cache the group ID for later use
        $passkeyExcludedGroups.Add($excludeTarget.id)
    }
}

# Determine the list of TAP-enabled users
Write-Verbose -Message 'Retrieving all users...' -Verbose
[guid[]] $allUsers = Get-MgUser -All -Property Id | Select-Object -ExpandProperty Id

[System.Collections.Generic.HashSet[guid]] $tapIncludedUsers = @()
[System.Collections.Generic.HashSet[guid]] $tapExcludedUsers = @()

if ($authenticationPolicy.IsTapEnabled()) {
    if ($authenticationPolicy.TapIncludesAllUsers()) {
        $tapIncludedUsers.UnionWith($allUsers)
    } else {
        # Resolve nested group memberships for TAP included groups
        foreach ($groupId in $tapIncludedGroups) {
            Write-Verbose -Message "Retrieving transitive group membership of TAP included group $groupId..." -Verbose
            [guid[]] $groupMembers = Get-MgGroupTransitiveMemberAsUser -GroupId $groupId -Property Id -All | Select-Object -ExpandProperty Id
            $tapIncludedUsers.UnionWith($groupMembers)
        }
    }

    # Resolve nested group memberships for TAP excluded groups
    foreach ($groupId in $tapExcludedGroups) {
        Write-Verbose -Message "Retrieving transitive group membership of TAP excluded group $groupId..." -Verbose
        [guid[]] $groupMembers = Get-MgGroupTransitiveMemberAsUser -GroupId $groupId -Property Id -All | Select-Object -ExpandProperty Id
        $tapExcludedUsers.UnionWith($groupMembers)
    }
}

# Determine the list of Passkey-enabled users
[System.Collections.Generic.HashSet[guid]] $passkeyIncludedUsers = @()
[System.Collections.Generic.HashSet[guid]] $passkeyExcludedUsers = @()

if ($authenticationPolicy.IsPasskeyEnabled()) {
    if ($authenticationPolicy.PasskeyIncludesAllUsers()) {
        $passkeyIncludedUsers.UnionWith($allUsers)
    } else {
        # Resolve nested group memberships for Passkey included groups
        foreach ($groupId in $passkeyIncludedGroups) {
            Write-Verbose -Message "Retrieving transitive group membership of Passkey included group $groupId..." -Verbose
            [guid[]] $groupMembers = Get-MgGroupTransitiveMemberAsUser -GroupId $groupId -Property Id -All | Select-Object -ExpandProperty Id
            $passkeyIncludedUsers.UnionWith($groupMembers)
        }
    }

    # Resolve nested group memberships for Passkey excluded groups
    foreach ($groupId in $passkeyExcludedGroups) {
        Write-Verbose -Message "Retrieving transitive group membership of Passkey excluded group $groupId..." -Verbose
        [guid[]] $groupMembers = Get-MgGroupTransitiveMemberAsUser -GroupId $groupId -Property Id -All | Select-Object -ExpandProperty Id
        $passkeyExcludedUsers.UnionWith($groupMembers)
    }
}

# Calculate group membership intersections
$tapIncludedUsers.ExceptWith($tapExcludedUsers)
$passkeyIncludedUsers.ExceptWith($passkeyExcludedUsers)

# Augment the AZUser nodes with TAP and Passkey properties
[System.Collections.Generic.List[AZUser]] $allUserNodes = @()

foreach ($userId in $allUsers) {
    [AZUser] $user = [AZUser]::new($userId, $tenantId)
    $user.SetTapEnabled($tapIncludedUsers.Contains($userId))
    $user.SetPasskeyEnabled($passkeyIncludedUsers.Contains($userId))

    $allUserNodes.Add($user)
    $openGraph.AddNode($user)
}

# Pre-create filtered user lists for later use
[AZUser[]] $tapIncludedUserNodes = $allUserNodes | Where-Object { $PSItem.IsTapEnabled() }
[AZUser[]] $passkeyIncludedUserNodes = $allUserNodes | Where-Object { $PSItem.IsPasskeyEnabled() }

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
            # The permission is not associated with the Microsoft Graph application
            continue
        }

        # Check if the app has any permissions related to TAPs or Passkeys
        if ($permission.AppRoleId -eq $manageUserAuthenticationMethodsPermissionId) {
            # The app has the UserAuthenticationMethod.ReadWrite.All permission
            $openGraph.AddEdge([AZMGUserAuthenticationMethod_ReadWrite_All]::new($servicePrincipalNode, $tenantNode))

            # Create AZCreateTAP edges for this app (AZServicePrincipal->AZUser)
            foreach ($user in $tapIncludedUserNodes) {
                $openGraph.AddEdge([AZCreateTAP]::new($servicePrincipalNode, $user))
            }

            # Create AZRegisterPasskey edges for this app (AZServicePrincipal->AZUser)
            foreach ($user in $passkeyIncludedUserNodes) {
                $openGraph.AddEdge([AZRegisterPasskey]::new($servicePrincipalNode, $user))
            }
        } elseif ($permission.AppRoleId -eq $manageUserPasskeysPermissionId) {
            # The app has the UserAuthMethod-Passkey.ReadWrite.All permission
            $openGraph.AddEdge([AZMGUserAuthenticationMethod_Passkey_ReadWrite_All]::new($servicePrincipalNode, $tenantNode))

            # Create AZRegisterPasskey edges for this app (AZServicePrincipal->AZUser)
            foreach ($user in $passkeyIncludedUserNodes) {
                $openGraph.AddEdge([AZRegisterPasskey]::new($servicePrincipalNode, $user))
            }
        } elseif ($permission.AppRoleId -eq $manageAuthenticationPolicyPermissionId) {
            # The app has the Policy.ReadWrite.AuthenticationMethod permission
            $openGraph.AddEdge([AZMGPolicy_ReadWrite_AuthenticationMethod]::new($servicePrincipalNode, $tenantNode))

            # In addition to the AZServicePrincipal->AZTenant edge, we also create a AZServicePrincipal->AZAuthenticationPolicy edge.
            [Edge] $edge = [AZChangeAuthenticationPolicy]::new($servicePrincipalNode, $authenticationPolicy)
            $openGraph.AddEdge($edge)
        }
    }
}

# Create a single AZChangeAuthenticationPolicy edge from the "Authentication Policy Administrator" role to the AZAuthenticationPolicy node.
[guid] $authenticationPolicyAdminRoleTemplateId = '0526716b-113d-4c15-b2c8-68e3c22b9f80'
[AZRole] $authenticationPolicyAdminRole = [AZRole]::new($authenticationPolicyAdminRoleTemplateId, $tenantId)
[Edge] $authenticationPolicyAdminEdge = [AZChangeAuthenticationPolicy]::new($authenticationPolicyAdminRole, $authenticationPolicy)
$openGraph.AddEdge($authenticationPolicyAdminEdge)

# Create a single AZChangeAuthenticationPolicy edge from the "Global Administrator" role to the AZAuthenticationPolicy node.
# This is here just for completeness, as Global Admins can do everything.
[guid] $globalAdminRoleTemplateId = '62e90394-69f5-4237-9190-012177145e10'
[AZRole] $globalAdminRole = [AZRole]::new($globalAdminRoleTemplateId, $tenantId)
[Edge] $globalAdminEdge = [AZChangeAuthenticationPolicy]::new($globalAdminRole, $authenticationPolicy)
$openGraph.AddEdge($globalAdminEdge)

# The "Privileged Authentication Administrator" can set authentication method information for any user (admin or non-admin).
[guid] $privilegedAuthAdminRoleTemplateId = '7be44c8a-adaf-4e2a-84d6-ab2649e08a13'
[AZRole] $privilegedAuthAdminRole = [AZRole]::new($privilegedAuthAdminRoleTemplateId, $tenantId)

# Create AZCreateTAP edges for the Global Admins and Privileged Authentication Administrators roles
foreach ($user in $tapIncludedUserNodes) {
    $openGraph.AddEdge([AZCreateTAP]::new($globalAdminRole, $user))
    $openGraph.AddEdge([AZCreateTAP]::new($privilegedAuthAdminRole, $user))
}

# Create AZRegisterPasskey edges for the Global Admins and Privileged Authentication Administrators roles
foreach ($user in $passkeyIncludedUserNodes) {
    $openGraph.AddEdge([AZRegisterPasskey]::new($globalAdminRole, $user))
    $openGraph.AddEdge([AZRegisterPasskey]::new($privilegedAuthAdminRole, $user))
}

# Disconnect from Microsoft Graph
Write-Verbose -Message 'Disconnecting from Microsoft Graph...' -Verbose
Disconnect-MgGraph | Out-Null

# Save the BloodHound OpenGraph output

[string] $fileName = 'AuthenticationPolicyData_{0:yyyy-MM-dd_HH-mm}.json' -f (Get-Date)
[string] $filePath = Join-Path -Path $PSScriptRoot -ChildPath $fileName
Write-Verbose -Message "Exporting BloodHound OpenGraph data to file $fileName..." -Verbose
$openGraph.ToJson($filePath, $false)

Write-Verbose -Message 'Done. You can now ingest the data to BloodHound manually or via the API.' -Verbose
