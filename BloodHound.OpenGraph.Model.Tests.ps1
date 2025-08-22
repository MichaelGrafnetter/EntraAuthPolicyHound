<#
.SYNOPSIS
    BloodHound OpenGraph Data Model Tests
.DESCRIPTION
    Pester tests for the classes in the BloodHound OpenGraph Data Model
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }

# Import the BloodHound OpenGraph data model
using module '.\BloodHound.OpenGraph.Model.psm1'

# Show errors for uninitialized variables, etc.
Set-StrictMode -Version Latest

Describe 'BloodHound OpenGraph Data Model' {
    Context 'Basics' {
        It 'requires the tenant ID to be set' {
            { [AZAuthenticationPolicy]::new() } | Should -Throw
        }

        It 'supports OpenGraph metadata' {
            [string] $sourceKind = 'Test'
            [BloodHoundOpenGraph] $openGraph = [BloodHoundOpenGraph]::new($sourceKind)
            $openGraph.metadata.source_kind | Should -Be $sourceKind
        }

        It 'supports adding nodes' {
            [BloodHoundOpenGraph] $openGraph = [BloodHoundOpenGraph]::new('Test')
            [guid] $tenantId = [guid]::NewGuid()
            [AZAuthenticationPolicy] $authenticationPolicy = [AZAuthenticationPolicy]::new($tenantId)
            $openGraph.AddNode($authenticationPolicy)
            $openGraph.graph.nodes.Count | Should -Be 1
            $openGraph.graph.nodes[0].id | Should -Be "AZAuthenticationPolicy@$tenantId"
        }

        It 'supports adding edges' {
            [BloodHoundOpenGraph] $openGraph = [BloodHoundOpenGraph]::new('Test')
            [guid] $tenantId = [guid]::NewGuid()

            [AZAuthenticationPolicy] $authenticationPolicy = [AZAuthenticationPolicy]::new($tenantId)
            $openGraph.AddNode($authenticationPolicy)

            [AZGroup] $group = [AZGroup]::new([guid]::NewGuid(), $tenantId)
            $openGraph.AddNode($group)
            
            $openGraph.AddEdge([AZTapInclude]::new($authenticationPolicy, $group))
            
            $openGraph.graph.edges.Count | Should -Be 1
            $openGraph.graph.edges[0].start.value | Should -Be $group.id
            $openGraph.graph.edges[0].end.value | Should -Be "AZAuthenticationPolicy@$tenantId"
            $openGraph.graph.edges[0].kind | Should -Be 'AZTapInclude'
        }
    }
    Context 'JSON Export' {
        It 'empty graph can be exported' {
            [BloodHoundOpenGraph] $openGraph = [BloodHoundOpenGraph]::new('Test')
            $openGraph.ToJson($true) | Should -Be '{"metadata":{"source_kind":"Test"},"graph":{"nodes":[],"edges":[]}}'
        }
    }
}
