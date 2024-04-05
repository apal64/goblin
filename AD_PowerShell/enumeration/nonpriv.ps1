##forest info
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()

##domain
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

##forest trusts
$ForestRootDomain = ‘contso.domain.org’
([System.DirectoryServices.ActiveDirectory.Forest]::GetForest((New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext(‘Forest’, $ForestRootDomain)))).GetAllTrustRelationships()

## domain trusts
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()

## get global catalogs
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().GlobalCatalogs

## SPN scanning get all eneterprise services :)
get-adcomputer -filter {ServicePrincipalName -like “*TERMSRV*”} -Properties OperatingSystem,OperatingSystemVersion,OperatingSystemServicePack,
PasswordLastSet,LastLogonDate,ServicePrincipalName,TrustedForDelegation,TrustedtoAuthForDelegation

## get ad service accounts:
function Find-PSServiceAccounts
{

<#
.SYNOPSIS
This function discovers all user accounts configured with a ServicePrincipalName in the Active Directory domain or forest.

Find-PSServiceAccounts
Author: Sean Metcalf, Twitter: @PyroTek3
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
Last Updated: 1/16/2015
Version: 1.1

.DESCRIPTION
This function discovers all user accounts configured with a ServicePrincipalName in the Active Directory domain or forest.

Currently, the script performs the following actions:
* Forest Mode: Queries a Global Catalog in the Active Directory root domain for all user accounts configured with a ServicePrincipalName in the forest by querying the Global Catalog for SPN info.
* Domain Mode: Queries a DC in the current Active Directory domain for all user accounts configured with a ServicePrincipalName in the forest by querying the DCfor SPN info.
* Identifies the ServicePrincipalNames associated with the account and reports on the SPN types and server names.
* Provides password last set date & last logon date for service accounts

REQUIRES: Active Directory user authentication. Standard user access is fine - admin access is not necessary.

.EXAMPLE
Find-PSServiceAccounts
Perform current AD domain user account SPN discovery via AD and returns the results in a custom PowerShell object.

.EXAMPLE
Find-PSServiceAccounts -Forest
Perform current AD forest user account SPN discovery via AD and returns the results in a custom PowerShell object.

.EXAMPLE
Find-PSServiceAccounts -Domain "ad.domain.com"
Perform user account SPN discovery for the Active Directory domain "ad.domain.com" via AD and returns the results in a custom PowerShell object.

.EXAMPLE
Find-PSServiceAccounts -Domain "ad.domain.com" -DumpSPNs
Perform user account SPN discovery for the Active Directory domain "ad.domain.com" via AD and returns the list of discovered SPN FQDNs (de-duplicated).


.NOTES
This function discovers all user accounts configured with a ServicePrincipalName in the Active Directory domain or forest.

.LINK
Blog: http://www.ADSecurity.org
Github repo: https://github.com/PyroTek3/PowerShell-AD-Recon
#>

Param
(
    [ValidateSet("Domain", "Forest")]
    [string]$Scope = "Domain",
    
    [string]$DomainName,
    
    [switch]$DumpSPNs,
    [switch]$GetTGS
    
)

Write-Verbose "Get current Active Directory domain... "


IF ($Scope -eq "Domain")
    {
        IF (!($DomainName))
            { 
                $ADDomainInfo = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                $ADDomainName = $ADDomainInfo.Name
            }
        $ADDomainDN = "DC=" + $ADDomainName -Replace("\.",',DC=')
        $ADDomainLDAPDN = 'LDAP://' + $ADDomainDN
        Write-Output "Discovering service account SPNs in the AD Domain $ADDomainName "
    }

IF ( ($Scope -eq "Forest") -AND (!($DomainName)) )
    {
        $ADForestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        $ADForestInfoRootDomain = $ADForestInfo.RootDomain
        $ADForestInfoRootDomainDN = "DC=" + $ADForestInfoRootDomain -Replace("\.",',DC=')
        $ADDomainLDAPDN = 'GC://' + $ADForestInfoRootDomainDN
        Write-Output "Discovering service account SPNs in the AD Forest $ADForestInfoRootDomain "
    }

$root = [ADSI]$ADDomainLDAPDN
$ADSearcher = new-Object System.DirectoryServices.DirectorySearcher($root,"(&(objectcategory=user)(serviceprincipalname=*))")
$ADSearcher.PageSize = 5000
$AllServiceAccounts = $ADSearcher.FindAll()
# $AllServiceAccountsCount = $AllServiceAccounts.Count
# Write-Output "Processing $AllServiceAccountsCount service accounts (user accounts) with SPNs discovered in AD ($ADDomainLDAPDN) `r "

$AllServiceAccountsReport = $Null
$AllServiceAccountsSPNs = @()
ForEach ($AllServiceAccountsItem in $AllServiceAccounts)
    {
       $AllServiceAccountsItemSPNTypes = @()
       $AllServiceAccountsItemSPNServerNames = @()
       $AllServiceAccountsItemSPNs = @()
       
        ForEach ($AllServiceAccountsItemSPN in $AllServiceAccountsItem.properties.serviceprincipalname)
            {
                $AllServiceAccountsItemDomainName = $NULL
                [array]$AllServiceAccountsItemmDNArray = $AllServiceAccountsItem.Path -Split(",DC=")
                [int]$DomainNameFECount = 0
                ForEach ($AllServiceAccountsItemmDNArrayItem in $AllServiceAccountsItemmDNArray)
                    {
                        IF ($DomainNameFECount -gt 0)
                        { [string]$AllServiceAccountsItemDomainName += $AllServiceAccountsItemmDNArrayItem + "." }
                        $DomainNameFECount++
                    }
                $AllServiceAccountsItemDomainName = $AllServiceAccountsItemDomainName.Substring(0,$AllServiceAccountsItemDomainName.Length-1)

                $AllServiceAccountsItemSPNArray1 = $AllServiceAccountsItemSPN -Split("/")
                $AllServiceAccountsItemSPNArray2 = $AllServiceAccountsItemSPNArray1 -Split(":")
                
                [string]$AllServiceAccountsItemSPNType = $AllServiceAccountsItemSPNArray1[0]
                [string]$AllServiceAccountsItemSPNServer = $AllServiceAccountsItemSPNArray2[1]
                IF ($AllServiceAccountsItemSPNServer -notlike "*$AllServiceAccountsItemDomainName*" )
                    { 
                        $AllServiceAccountsItemSPNServerName = $AllServiceAccountsItemSPNServer 
                        $AllServiceAccountsItemSPNServerFQDN = $NULL 
                    }
                 ELSE
                    {
                        $AllServiceAccountsItemSPNServerName = $AllServiceAccountsItemSPNServer -Replace(("."+ $AllServiceAccountsItemDomainName),"")
                        $AllServiceAccountsItemSPNServerFQDN = $AllServiceAccountsItemSPNServer
                        [array]$AllServiceAccountsSPNs += $AllServiceAccountsItemSPN
                    }
                    
                #[string]$AllMSSQLSPNsItemServerInstancePort = $ADSISQLServersItemSPNArray2[2]

                [array]$AllServiceAccountsItemSPNTypes += $AllServiceAccountsItemSPNType
                [array]$AllServiceAccountsItemSPNServerNames += $AllServiceAccountsItemSPNServerFQDN
                [array]$AllServiceAccountsItemSPNs += $AllServiceAccountsItemSPN
                
            }
        
        [array]$AllServiceAccountsItemSPNTypes = $AllServiceAccountsItemSPNTypes | sort-object | get-unique
        [array]$AllServiceAccountsItemSPNServerNames = $AllServiceAccountsItemSPNServerNames | sort-object  | get-unique
        [array]$AllServiceAccountsItemSPNs = $AllServiceAccountsItemSPNs | sort-object  | get-unique
                
        $AllServiceAccountsItemDN = $Null
        [array]$AllServiceAccountsItemDNArray = ($AllServiceAccountsItem.Properties.distinguishedname) -Split(",DC=")
        [int]$DomainNameFECount = 0
        ForEach ($AllServiceAccountsItemDNArrayItem in $AllServiceAccountsItemDNArray)
            {
                IF ($DomainNameFECount -gt 0)
                { [string]$AllServiceAccountsItemDN += $AllServiceAccountsItemDNArrayItem + "." }
                $DomainNameFECount++
            }
        $AllServiceAccountsItemDN = $AllServiceAccountsItemDN.Substring(0,$AllServiceAccountsItemDN.Length-1)
        
        [string]$ServiceAccountsItemSAMAccountName = $AllServiceAccountsItem.properties.samaccountname
        [string]$ServiceAccountsItemdescription = $AllServiceAccountsItem.properties.description
        [string]$ServiceAccountsItempwdlastset = $AllServiceAccountsItem.properties.pwdlastset
        [string]$ServiceAccountsItemPasswordLastSetDate = [datetime]::FromFileTimeUTC($ServiceAccountsItempwdlastset)
        [string]$ServiceAccountsItemlastlogon = $AllServiceAccountsItem.properties.lastlogon
        [string]$ServiceAccountsItemLastLogonDate = [datetime]::FromFileTimeUTC($ServiceAccountsItemlastlogon)
        
        $ServiceAccountsReport = New-Object PSObject -Property @{            
            Domain                = $AllServiceAccountsItemDomainName                
            UserID                = $ServiceAccountsItemSAMAccountName              
            Description           = $ServiceAccountsItemdescription            
            PasswordLastSet       = $ServiceAccountsItemPasswordLastSetDate            
            LastLogon             = $ServiceAccountsItemLastLogonDate  
            SPNServers            = $AllServiceAccountsItemSPNServerNames
            SPNTypes              = $AllServiceAccountsItemSPNTypes
            ServicePrincipalNames = $AllServiceAccountsItemSPNs
        } 
    
        [array]$AllServiceAccountsReport += $ServiceAccountsReport
    }

$AllServiceAccountsReport = $AllServiceAccountsReport | Select-Object Domain,UserID,PasswordLastSet,LastLogon,Description,SPNServers,SPNTypes,ServicePrincipalNames

If ($DumpSPNs -eq $True)
    {
        [array]$AllServiceAccountsSPNs = $AllServiceAccountsSPNs | sort-object | Get-Unique
        return $AllServiceAccountsSPNs
        
        IF ($GetTGS)
            {
                ForEach ($AllServiceAccountsSPNsItem in $AllServiceAccountsSPNs)
                    {
                        Add-Type -AssemblyName System.IdentityModel
                        New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "$AllServiceAccountsSPNsItem"
                    }
            }
    }

ELSE
    { return $AllServiceAccountsReport }

}


## discover computers w/o network scanning
get-adcomputer -filter {PrimaryGroupID -eq “515”} -Properties OperatingSystem,OperatingSystemVersion,OperatingSystemServicePack,Passwo
t,LastLogonDate,ServicePrincipalName,TrustedForDelegation,TrustedtoAuthForDelegation

## identify admin accounts
get-aduser -filter {AdminCount -eq 1} -Properties Name,AdminCount,ServicePrincipalName,PasswordLastSet,LastLogonDate,MemberOf


## find admin groups
 get-adgroup -filter {GroupCategory -eq ‘Security’ -AND Name -like “*admin*”}

## identify partner organizations
get-adobject -filter {ObjectClass -eq “Contact”} -Prop *

## password policies
Get-ADDefaultDomainPasswordPolicy

## finely grained password policies
Get-ADFineGrainedPasswordPolicy -Filter *

## identify managed service accounts and group managed service accounts
Get-ADServiceAccount -Filter * -Properties *

## powerview - groups w/ local admin rights on work/servers
 Get-NetGPOGroup

 get-netOU -guid “E9CABE0F-3A3F-40B1-B4C1-1FA89AC1F212”
LDAP://OU=Servers,DC=lab,DC=adsecurity,DC=org

 get-netOU -guid “45556105-EFE6-43D8-A92C-AACB1D3D4DE5”
LDAP://OU=Workstations,DC=lab,DC=adsecurity,DC=org

###Next, we identify the computers in these OUs

get-adcomputer -filter * -SearchBase “OU=Servers,DC=lab,DC=adsecurity,DC=org”

get-adcomputer -filter * -SearchBase “OU=Workstations,DC=lab,DC=adsecurity,DC=org”


# Get Active Directory Forest Information
$ADForestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$ADForestInfo.Name
$ADForestInfo.Sites
$ADForestInfo.Domains
$ADForestInfo.GlobalCatalogs
$ADForestInfo.ApplicationPartitions
$ADForestInfo.ForestMode
$ADForestInfo.RootDomain
$ADForestInfo.Schema
$ADForestInfo.SchemaRoleOwner
$ADForestInfo.NamingRoleOwner
# OR
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Name
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Domains
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().GlobalCatalogs
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().ApplicationPartitions
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().ForestMode
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().RootDomain
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Schema
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().SchemaRoleOwner
[System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().NamingRoleOwner
###
# Get Active Directory Domain Information
  # Target the current (local) computer’s domain:
  $ADDomainInfo = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
  # Target the current user’s domain:
  $ADDomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$ADDomainInfo.Forest
$ADDomainInfo.DomainControllers
$ADDomainInfo.Children
$ADDomainInfo.DomainMode
$ADDomainInfo.Parent
$ADDomainInfo.PdcRoleOwner
$ADDomainInfo.RidRoleOwner
$ADDomainInfo.DomainControllers
# OR
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Forest
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Children
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainMode
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Parent
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().RidRoleOwner
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers
# Note: Use [System.DirectoryServices.ActiveDirectory.Domain]::GetCOMPUTERDomain().Attribute for the local computer’s domain info.
# Example: [System.DirectoryServices.ActiveDirectory.Domain]::GetCOMPUTERDomain().Forest
###
# Get the local computer’s site information:
$LocalSiteInfo = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()
$LocalSiteInfo.Name
$LocalSiteInfo.Domains
$LocalSiteInfo.Subnets
$LocalSiteInfo.Servers
$LocalSiteInfo.AdjacentSites
$LocalSiteInfo.SiteLinks
$LocalSiteInfo.InterSiteTopologyGenerator
$LocalSiteInfo.Options
$LocalSiteInfo.Location
$LocalSiteInfo.BridgeheadServers
$LocalSiteInfo.PreferredSmtpBridgeheadServers
$LocalSiteInfo.PreferredRpcBridgeheadServers
$LocalSiteInfo.IntraSiteReplicationSchedule
# OR
[System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Name
[System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Domains
[System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Subnets
[System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Servers
[System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().AdjacentSites
[System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().SiteLinks
[System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().InterSiteTopologyGenerator
[System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Options
[System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().Location
[System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().BridgeheadServers
[System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().PreferredSmtpBridgeheadServers
[System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().PreferredRpcBridgeheadServers
[System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().IntraSiteReplicationSchedule
