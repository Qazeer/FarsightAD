#requires -Module ActiveDirectory

function Set-ObjectDenyRightForEveryone {
    Param(
        [Parameter(Mandatory=$True)][String]$Object,
        [Parameter(Mandatory=$True)][String]$Right,
        [Parameter(Mandatory=$False)][String]$AttributeGuid = "00000000-0000-0000-0000-000000000000",
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$False)][String]$ADDriveName = "ADHunting"
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("New-PSDrive:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("New-PSDrive:Credential", $Credential)
    }

    New-PSDrive -PSProvider ActiveDirectory -Name "$ADDriveName" -Root "//RootDSE/" | Out-Null

    $ObjectDN = $(Get-ADObject -LDAPFilter "(Name=$Object)").DistinguishedName

    $acl = Get-ACL "${ADDriveName}:$ObjectDN"
    
    $identity = [System.Security.Principal.IdentityReference] $(New-Object System.Security.Principal.SecurityIdentifier "S-1-1-0")
    $adRights = [System.DirectoryServices.ActiveDirectoryRights] "$Right"
    $type = [System.Security.AccessControl.AccessControlType] "Deny"
    $objectGuid = New-Object Guid $AttributeGuid
    $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "None"

    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $identity, $adRights, $type, $objectGuid, $inheritanceType
    $acl.AddAccessRule($ace)

    Set-Acl -AclObject $acl "${ADDriveName}:$ObjectDN"

    Remove-PSDrive -Name "$ADDriveName"
}