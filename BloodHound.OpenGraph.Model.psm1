<#
.SYNOPSIS
    BloodHound OpenGraph Data Model
.DESCRIPTION
    Importing the classes to the current scope: using module '.\BloodHound.OpenGraph.Model.psm1'
#>
#requires -Version 5

#region Generic OpenGraph Data Model

# Main class that represents the entire OpenGraph document structure
# See https://github.com/SpecterOps/BloodHound/tree/main/cmd/api/src/services/upload/jsonschema
class BloodHoundOpenGraph
{
    [Metadata] $metadata;
    [Graph] $graph;

    BloodHoundOpenGraph([string] $sourceKind)
    {
        $this.metadata = [Metadata]::new($sourceKind)
        $this.graph = [Graph]::new()
    }

    [void] AddNode([Node] $node)
    {
        $this.graph.nodes.Add($node)
    }

    [void] AddEdge([Node] $start, [Node] $end, [string] $kind)
    {
        $edge = [Edge]::new($start, $end, $kind)
        $this.graph.AddEdge($edge)
    }

    [void] AddEdge([Edge] $edge)
    {
        $this.graph.AddEdge($edge)
    }

    [string] ToJson([bool] $compress = $false)
    {
        return ConvertTo-Json -InputObject $this -Depth 10 -Compress:$compress
    }

    [void] ToJson([string] $filePath, [bool] $compress = $false)
    {
        [string] $json = $this.ToJson($compress)
        Set-Content -Path $filePath -Value $json -Encoding UTF8
    }
}

class Metadata
{
    [string] $source_kind;

    Metadata([string] $sourceKind)
    {
        $this.source_kind = $sourceKind
    }
}

class Graph
{
    [System.Collections.Generic.List[Node]] $nodes;
    [System.Collections.Generic.List[Edge]] $edges;

    Graph()
    {
        $this.nodes = [System.Collections.Generic.List[Node]]::new()
        $this.edges = [System.Collections.Generic.List[Edge]]::new()
    }

    [void] AddNode([Node] $node)
    {
        $this.nodes.Add($node)
    }

    [void] AddEdge([Edge] $edge)
    {
        $this.edges.Add($edge)
    }

    [void] AddEdge([Node] $start, [Node] $end, [string] $kind)
    {
        $edge = [Edge]::new($start, $end, $kind)
        $this.edges.Add($edge)
    }
}

# Base class for all OpenGraph nodes
class Node
{
    [string] $id;
    [hashtable] $properties;
    [string[]] $kinds;

    Node([string] $id, [string[]] $kinds = @())
    {
        $this.id = $id
        $this.properties = @{}
        $this.kinds = $kinds
    }

    [void] SetName([string] $name)
    {
        $this.properties['name'] = $name
    }

    [void] SetDisplayName([string] $displayName)
    {
        $this.properties['displayname'] = $displayName
    }

    [EdgeNode] ToEdgeNode([MatchBy] $matchBy = [MatchBy]::id)
    {
        [string] $kind = $null
        if ($this.kinds.Count -gt 0) {
            $kind = $this.kinds[0]
        }

        if ($matchBy -eq [MatchBy]::id) {
            if ([string]::IsNullOrEmpty($this.id)) {
                throw 'Node ID is not set.'
            }

            return [EdgeNode]::new($this.id, $matchBy, $kind)
        } elseif ($matchBy -eq [MatchBy]::name) {
            if (-not $this.properties.ContainsKey('name')) {
                throw 'Node name is not set.'
            }

            return $this.ToEdgeNodeInternal($matchBy)
        } else {
            throw "Unsupported MatchBy value: $matchBy"
        }
    }
}

# Base class for all OpenGraph edges
class Edge
{
    [string] $kind;
    [EdgeNode] $start;
    [EdgeNode] $end;
    [hashtable] $properties;

    Edge([Node] $start, [Node] $end, [string] $kind)
    {
        $this.start = $start.ToEdgeNode([MatchBy]::id)
        $this.end = $end.ToEdgeNode([MatchBy]::id)
        $this.kind = $kind
        $this.properties = @{}
    }

    [void] SetDisplayName([string] $displayName)
    {
        $this.properties['displayname'] = $displayName
    }

    [void] SetDescription([string] $description)
    {
        $this.properties['description'] = $description
    }
}

# Represents the start and end vertices of an edge
class EdgeNode
{
    [string] $value
    [string] $match_by
    [string] $kind

    EdgeNode([string] $value, [MatchBy] $match_by = [MatchBy]::id, [string] $kind = $null)
    {
        $this.value = $value
        $this.match_by = $match_by
        $this.kind = $kind
    }

    [MatchBy] GetMatchBy()
    {
        return $this.match_by
    }

    SetMatchBy([MatchBy] $matchBy)
    {
        # The value is intentionally stored as a string, as the ConvertTo-Json
        # cmdlet in PowerShell Desktop does not support enum serialization as strings.
        $this.match_by = $matchBy
    }
}

enum MatchBy
{
    id
    name
}

#endregion Generic OpenGraph Data Model
#region Azure Built-in Data Model

# Base class for all Azure-specific edges
class AZEdge : Edge
{
    AZEdge([AZBase] $start, [AZBase] $end, [string] $kind) : base($start, $end, $kind)
    {
        $this.SetTenantId($start.GetTenantId())
    }

    [guid] GetTenantId()
    {
        return [guid] $this.properties['tenantid']
    }
    
    [void] SetTenantId([guid] $tenantId)
    {
        $this.properties['tenantid'] = $tenantId
    }
}

# Base class for all Azure-specific nodes
class AZBase : Node
{
    # Note: The objectId is a string to accommodate special IDs like "AZAuthenticationPolicy@{tenantId}"
    AZBase([string] $objectId, [guid] $tenantId, [string] $kind) : base($objectId, @($kind, 'AZBase'))
    {
        $this.SetTenantId($tenantId)
    }

    [guid] GetTenantId()
    {
        return [guid] $this.properties['tenantid']
    }

    [void] SetTenantId([guid] $tenantId)
    {
        $this.properties['tenantid'] = $tenantId
    }
}

# Entra ID group
class AZGroup : AZBase
{
    AZGroup([guid] $groupId, [guid] $tenantId) : base($groupId, $tenantId, 'AZGroup')
    {
    }
}

# Entra ID role
class AZRole : AZBase
{
    # Role IDs are scoped to the tenant, so we combine the role template ID and tenant ID to create a unique node ID
    AZRole([guid] $templateId, [guid] $tenantId) : base("$templateId@$tenantId", $tenantId, 'AZRole')
    {
    }
}

# Entra ID service principal
class AZServicePrincipal : AZBase
{
    AZServicePrincipal([guid] $servicePrincipalId, [guid] $tenantId) : base($servicePrincipalId, $tenantId, 'AZServicePrincipal')
    {
    }
}

# Entra ID tenant
class AZTenant : AZBase
{
    AZTenant([guid] $tenantId) : base($tenantId, $tenantId, 'AZTenant')
    {
    }
}

#endregion Azure Built-in Data Model
#region Custom Extensions

# Entra ID Authentication Method Policy
class AZAuthenticationPolicy : AZBase
{
    AZAuthenticationPolicy([guid] $tenantId, [string] $tenantName) : base("AZAuthenticationPolicy@$tenantId", $tenantId, 'AZAuthenticationPolicy')
    {
        $this.SetDisplayName('Entra ID Authentication Method Policy')
        $this.SetName("AZAuthenticationPolicy@$tenantName")

        # Default policy settings
        $this.SetTapEnabled($false)
        $this.SetPasskeyEnabled($false)
        $this.SetTapIncludesAllUsers($true)
        $this.SetPasskeyIncludesAllUsers($true)
    }

    [void] SetTapEnabled([bool] $enabled)
    {
        $this.properties['tapEnabled'] = $enabled
    }

    [void] SetPasskeyEnabled([bool] $enabled)
    {
        $this.properties['passkeyEnabled'] = $enabled
    }

    [void] SetTapIncludesAllUsers([bool] $includesAllUsers)
    {
        $this.properties['tapIncludesAllUsers'] = $includesAllUsers
    }

    [void] SetPasskeyIncludesAllUsers([bool] $includesAllUsers)
    {
        $this.properties['passkeyIncludesAllUsers'] = $includesAllUsers
    }
}

class AZTapInclude : AZEdge
{
    # Note: The direction of this edge is from the group to the policy.
    AZTapInclude([AZAuthenticationPolicy] $policy, [AZGroup] $includeTarget) : base($includeTarget, $policy, 'AZTapInclude')
    {
        $this.SetDisplayName('Temporary Access Pass Included')
    }
}

class AZTapExclude : AZEdge
{
    # Note: The direction of this edge is from the group to the policy.
    AZTapExclude([AZAuthenticationPolicy] $policy, [AZGroup] $excludeTarget) : base($excludeTarget, $policy, 'AZTapExclude')
    {
        $this.SetDisplayName('Temporary Access Pass Excluded')
    }
}

class AZPasskeyInclude : AZEdge
{
    AZPasskeyInclude([AZAuthenticationPolicy] $policy, [AZGroup] $includeTarget) : base($includeTarget, $policy, 'AZPasskeyInclude')
    {
        $this.SetDisplayName('Passkey Included')
    }
}

class AZPasskeyExclude : AZEdge
{
    # Note: The direction of this edge is from the group to the policy.
    AZPasskeyExclude([AZAuthenticationPolicy] $policy, [AZGroup] $excludeTarget) : base($excludeTarget, $policy, 'AZPasskeyExclude')
    {
        $this.SetDisplayName('Passkey Excluded')
    }
}

class AZChangeAuthenticationPolicy : AZEdge
{
    AZChangeAuthenticationPolicy([AZBase] $entity, [AZAuthenticationPolicy] $authenticationPolicy) : base($entity, $authenticationPolicy, 'AZChangeAuthenticationPolicy')
    {
        $this.SetDisplayName('Can change Authentication Method Policy')
    }
}

class AZMGPolicy_ReadWrite_AuthenticationMethod : AZEdge
{
    # Note Or should the end node be the AZAuthenticationPolicy instead of AZTenant?
    AZMGPolicy_ReadWrite_AuthenticationMethod([AZServicePrincipal] $servicePrincipal, [AZTenant] $tenant) : base($servicePrincipal, $tenant, 'AZMGPolicy_ReadWrite_AuthenticationMethod')
    {
        $this.SetDisplayName('Microsoft Graph Policy.ReadWrite.AuthenticationMethod Application Permission')
    }
}

class AZMGUserAuthenticationMethod_ReadWrite_All : AZEdge
{
    AZMGUserAuthenticationMethod_ReadWrite_All([AZServicePrincipal] $servicePrincipal, [AZTenant] $tenant) : base($servicePrincipal, $tenant, 'AZMGUserAuthenticationMethod_ReadWrite_All')
    {
        $this.SetDisplayName('Microsoft Graph UserAuthenticationMethod.ReadWrite.All Application Permission')
    }
}

class AZMGUserAuthenticationMethod_Passkey_ReadWrite_All : AZEdge
{
    AZMGUserAuthenticationMethod_Passkey_ReadWrite_All([AZServicePrincipal] $servicePrincipal, [AZTenant] $tenant) : base($servicePrincipal, $tenant, 'AZMGUserAuthenticationMethod_Passkey_ReadWrite_All')
    {
        $this.SetDisplayName('Microsoft Graph UserAuthenticationMethod-Passkey.ReadWrite.All Application Permission')
    }
}

#endregion Custom Extensions
