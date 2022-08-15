#requires -Module ActiveDirectory

# Requires the updated ActiveDirectory module compatible with PowerShell 7.
# Add-WindowsCapability -Online -Name Rsat.ServerManager.Tools~~~~0.0.1.0

Param(
    [Parameter(Mandatory=$False)][String]$Server = $null,
    [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
    [Parameter(Mandatory=$False)][String]$ADDriveName = "ADHunting"
)

Add-Type -AssemblyName System.Security
$ProgressPreference = 'SilentlyContinue'

########################################################
#
#
# Const for properties retrieval using Get-AD* cmdlets.
#
#
########################################################

$Script:OBJECT_MINIMAL_PROPERTIES_SET    = @(
                                   "Name",
                                   "ObjectGUID",
                                   "DistinguishedName", 
                                   "ObjectClass"
                                   )

$Script:ACCOUNT_MINIMAL_PROPERTIES_SET   = $OBJECT_MINIMAL_PROPERTIES_SET + 
                                  @(
                                    "Enabled",
                                    "SamAccountName",
                                    "objectSid",
                                    "Description",
                                    "whenCreated",
                                    "pwdLastSet",
                                    "lastLogon",
                                    "lastLogonTimestamp",
                                    "logonCount"
                                    )

$Script:ACCOUNT_EXTENDED_PROPERTIES_SET   = $ACCOUNT_MINIMAL_PROPERTIES_SET +
                                   @(
                                    "userAccountControl",
                                    "UserPrincipalName",
                                    "ServicePrincipalName",
                                    "ScriptPath"
                                   )

$Script:ACCOUNT_ALL_PROPERTIES_SET        = $ACCOUNT_EXTENDED_PROPERTIES_SET +
                                   @(
                                   "userCertificate"
                                   "mS-DS-CreatorSID"
                                   "primaryGroupID"
                                   "SIDHistory"
                                   "mail"
                                   "mailNickName"
                                   "altSecurityIdentities"
                                   "msDS-AllowedToDelegateTo"
                                   "msDS-AllowedToActOnBehalfOfOtherIdentity"
                                   )

# For retriving user constructed attributes with Get-ADUser.
$Script:USER_SPECIFIC_PROPERTIES_SET      = $ACCOUNT_EXTENDED_PROPERTIES_SET +
                                   @(
                                   "Enabled",
                                   "Certificates",
                                   "PasswordNeverExpires",
                                   "PasswordNotRequired",
                                   "AccountNotDelegated",
                                   "DoesNotRequirePreAuth",
                                   "SmartcardLogonRequired"
                                   )

# For retriving computer constructed attributes with Get-ADComputer.
$Script:COMPUTER_SPECIFIC_PROPERTIES_SET  = $ACCOUNT_EXTENDED_PROPERTIES_SET +
                                   @(
                                   "Enabled",
                                   "Certificates",
                                   "PasswordNeverExpires",
                                   "PasswordNotRequired",
                                   "AccountNotDelegated",
                                   "DoesNotRequirePreAuth",
                                   "dNSHostName",
                                   "OperatingSystem",
                                   "OperatingSystemVersion"
                                   )

# Certificate EKU OIDs.
$Script:CERT_EKU_CLIENT_AUTH_OID = @(
    "2.5.29.37.0"
    "1.3.6.1.5.5.7.3.2"
    "1.3.6.1.5.2.3.4"
    "1.3.6.1.4.1.311.20.2.2"
)

########################################################
#
#
# Helper functions.
#
#
########################################################

function Convert-UnixTimeToISO8601 {
<#
.SYNOPSIS

Convert a Unix timestamp to a ISO 8601 date in the format yyyy-MM-dd HH:mm:ss.fff.

.PARAMETER UnixTime

Specifies the UnixTime attribute as a Int64.

.OUTPUTS

[string]

#>

    Param(
        [Parameter(Mandatory=$True)][Int64]$UnixTime
    )

    return [datetime]::FromFileTime($unixTime).ToString('yyyy-MM-dd HH:mm:ss.fff')
}

Function Get-ClassRelatedClasses {
<#
.SYNOPSIS

Get the (eventual) classes related to the specified class (subClassOf, auxiliaryClass, and systemAuxiliaryClass).

.PARAMETER ClassName

Specifies the ObjectClass attribute as a string.

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.OUTPUTS

[System.Collections.ArrayList]

#>

    Param(
        [Parameter(Mandatory=$True)][string]$ClassName,
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)
    $PSDefaultParameterValues.Add("Get-Class*:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
        $PSDefaultParameterValues.Add("Get-Class*:Credential", $Credential)
    }
   
    $Classes = New-Object System.Collections.ArrayList
    $null = $Classes.Add($ClassName)
    
    $ObjectSchema = Get-ADObject -SearchBase "$((Get-ADRootDSE).SchemaNamingContext)" -LDAPFilter "(lDAPDisplayName=$ClassName)" -properties subClassOf, auxiliaryClass, systemAuxiliaryClass
    $AdditionalClasses = @($ObjectSchema.subClassOf) + @($ObjectSchema.auxiliaryClass) + @($ObjectSchema.systemAuxiliaryClass)
    $AdditionalClasses | Foreach-Object {
        If ($_ -and !($_ -in $Classes)) {
            Get-ClassRelatedClasses $_ | Where-Object { $_ -notin $Classes } | ForEach-Object {
                $null = $Classes.Add($_)
            }
        }
    }
    return $Classes
}

function Get-ClassSupportedAttributes {
<#
.SYNOPSIS

Get the attributes supported by a class through a Schema lookup (of all the related classes).

.PARAMETER ClassName

Specifies the ClassName attribute as a string.

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.OUTPUTS

[System.Collections.ArrayList]

#>

    Param(
        [Parameter(Mandatory=$True)][string]$ClassName,
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)
    $PSDefaultParameterValues.Add("Get-Class*:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
        $PSDefaultParameterValues.Add("Get-Class*:Credential", $Credential)
    }

    $ATTRIBUTE_TYPES = 'MayContain','MustContain','systemMayContain','systemMustContain'
    
    $AllClasses = Get-ClassRelatedClasses -ClassName $ClassName
    $SchemaNamingContext = (Get-ADRootDSE).SchemaNamingContext

    $AllAttributes = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $AllClasses | ForEach-Object {
        $ClassInfo = Get-ADObject -SearchBase "$SchemaNamingContext" -LDAPFilter "(lDAPDisplayName=$_)" -Properties $ATTRIBUTE_TYPES
        ForEach ($attribute in $ATTRIBUTE_TYPES) {
            $null = $AllAttributes.AddRange(@($ClassInfo.$attribute))
            # $AllAttributes += $ClassInfo.$attribute
        }
    }
    
    return $AllAttributes
}

function Get-GPOFromGPLink {
<#
.SYNOPSIS

Extract the GPOs' DistinguishedName and link status from a gPLink attribute.

.DESCRIPTION

Extract the GPOs' DistinguishedName and link status from a gPLink attribute using a regex match.

gPLink attribute format exemple (string): 
[LDAP://cn={E6913ADB-5E9D-43E0-8550-AC21456C8795},cn=policies,cn=system,DC=forest1,DC=loc;0][LDAP://CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System,DC=forest1,DC=loc;0]

.PARAMETER gPLinkAttribute

Specifies the gPLink attribute as a string.

.OUTPUTS

[System.Collections.ArrayList]

#>

    Param(
        [Parameter(Mandatory=$True)][String]$gPLinkAttribute
    )

    If (!$gPLinkAttribute) {
        return $null
    }
    
    [System.Collections.ArrayList] $GPOs = New-Object System.Collections.ArrayList
    
    [regex]::Matches($gPLinkAttribute, "://(.*?;\d)") | ForEach-Object { 
        $match = $_.groups[1].value.Split(';')
        $null = $GPOs.Add([PSCustomObject]@{
            DistinguishedName = $match[0]
            IsLinkEnabled = $match[1] % 2 -eq 0
            IsLinkEnforced = $match[1] -ge 2
        })
    }
    
    return ,$GPOs
}

function Get-AllOUsFromDistinguishedName {
<#
.SYNOPSIS

Extract all the OUs' DistinguishedNames from an object DistinguishedName, ordered by proximity with the object.

.PARAMETER DistinguishedNames

Specifies the DistinguishedNames attribute as a string.

.OUTPUTS

[System.Collections.ArrayList]

#>

    Param(
        [Parameter(Mandatory=$True)][String]$DistinguishedName
    )

    $Output = New-Object System.Collections.ArrayList

    while ($DistinguishedName.IndexOf('OU=') -ge 0) {
        $DistinguishedName = $DistinguishedName.Substring($DistinguishedName.IndexOf('OU='))
        $null = $Output.Add($DistinguishedName)
        # Skip "OU=" to go the next eventual OU.
        $DistinguishedName = $DistinguishedName.Substring(3)
    }

    return ,$Output
}

function Get-X509CertificateStringFromUserCertificate {
<#
.SYNOPSIS

Return a formated string constructed from an object's usercertificate attribute.

.PARAMETER usercertificate

Specifies the Certificates attribute.

.OUTPUTS

[string]

#>

    Param(
        [Parameter(Mandatory=$True)] $usercertificate
    )
    
    $CertificatesString = ""
    
    for ($i = 0; $i -lt $usercertificate.Count; $i++) {
        # Requires PowerShell >= v5.
        # New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($usercertificate[$i]) bugs in PowerShell v7+.
        # And "X509Certificates immutable on this platform" in PowerShell v7+ so no usage of the Import method is possible. 
        $X509Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]] $usercertificate[$i])
        $EnhancedKeyUsageListString = If ($X509Certificate.EnhancedKeyUsageList) { [string]::join("-", $X509Certificate.EnhancedKeyUsageList) } Else { "None" }
        $X509CertificateAsString = [string]::Format("SerialNumber={0}|Subject={1}|NotBefore={2}|NotAfter={3}|EnhancedKeyUsageList={4}", $X509Certificate.SerialNumber, $X509Certificate.Subject, $X509Certificate.NotBefore, $X509Certificate.NotAfter, $EnhancedKeyUsageListString)
        $CertificatesString += "$X509CertificateAsString;"
    }

    return $CertificatesString
}

########################################################
#
#
# ACL / ACE helper functions.
#
#
########################################################

function Add-PrivilegeLevelType {
    # Try catch as Add-Type may fail in a new PowerShell session with "An item with the same key has already been added" errors.
    # https://github.com/PowerShell/CompletionPredictor/issues/14

    If (-not ([System.Management.Automation.PSTypeName]'PrivilegeLevel').Type) {
        try {
            $PRIVILEGE_LEVEL_STRING =
@"
            public enum PrivilegeLevel : uint {
                Everyone = 0,
                NonPrivileged = 1,
                Privileged = 2,
            }
"@
            Add-Type -TypeDefinition $PRIVILEGE_LEVEL_STRING
        }
        catch {}
    }
}

$Script:ACE_GUID_MAPPING = @{
    "00000000-0000-0000-0000-000000000000" = "All"
    "bf9679a8-0de6-11d0-a285-00aa003049e2" = "Script-Path property"
    "e48d0154-bcf8-11d1-8702-00c04fb96050" = "Public-Information property"
    "f3a64788-5306-11d1-a9c5-0000f80367c1" = "servicePrincipalName property"
    "00fbf30c-91fe-11d1-aebc-0000f80367c1" = "Alt-Security-Identities property"
    "5b47d60f-6090-40b2-9f37-2a4de88f3063" = "msDS-KeyCredentialLink property"
    "bf9679c0-0de6-11d0-a285-00aa003049e2" = "Member property"
    "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79" = "msDS-AllowedToActOnBehalfOfOtherIdentity property"
    "564e9325-d057-c143-9e3b-4f9e5ef46f93" = "ms-DS-principal-name property"
    "00299570-246d-11d0-a768-00aa006e0529" = "User-Force-Change-Password right"
    "e362ed86-b728-0842-b27d-2dea7a9df218" = "ms-DS-ManagedPassword property"
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Get-Changes right"
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Get-Changes-All right"
    "9923a32a-3607-11d2-b9be-0000f87a36b2" = "DS-Install-Replica right"
    "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Manage-Topology right"
    "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Synchronize right"
    "e2a36dc9-ae17-47c3-b58b-be34c55ba633" = "Create-Inbound-Forest-Trust right"
    "f30e3bbe-9ff0-11d1-b603-0000f80367c1" = "gPLink property"
    "f30e3bc1-9ff0-11d1-b603-0000f80367c1" = "gPCFileSysPath property"
    "bf967a86-0de6-11d0-a285-00aa003049e2" = "Computer object"
    "bf967a9c-0de6-11d0-a285-00aa003049e2" = "Group property object"
    "f30e3bc2-9ff0-11d1-b603-0000f80367c1" = "GroupPolicyObject object"
    "7b8b558a-93a5-4af7-adca-c017e67f1057" = "msDS-GroupManagedServiceAccount object"
    "ce206244-5827-4a86-ba1c-1c0c386c1b64" = "msDS-ManagedServiceAccount object"
    "bf967aa5-0de6-11d0-a285-00aa003049e2" = "Organizational Unit object"
    "bf967aba-0de6-11d0-a285-00aa003049e2" = "User object"
    "bf967a80-0de6-11d0-a285-00aa003049e2" = "attributeSchema object"
    "bf967a83-0de6-11d0-a285-00aa003049e2" = "classSchema object"
    "1c332fe0-0c2a-4f32-afca-23c5e45a9e77" = "ms-DFSR-ReplicationGroup object"
    "18976af6-3b9e-11d2-90cc-00c04fd91ab1" = "pKIExtendedKeyUsage property"
    "d15ef7d8-f226-46db-ae79-b34e560bd12c" = "msPKI-Enrollment-Flag property"
    "dbd90548-aa37-4202-9966-8c537ba5ce32" = "msPKI-Certificate-Application-Policy property"
    "bf967932-0de6-11d0-a285-00aa003049e2" = "cACertificate"
}

function Is-DangerousADACE {
<#
.SYNOPSIS

Determine if a given ACE is dangerous, based on the ACE access rights and impacted attributes. 

Required Dependencies: ActiveDirectory module and Get-ADHuntingAllPrivilegedSIDs.

.DESCRIPTION

Return True if a given ACE is dangerous, False otherwise.

An ACE is judged to be dangerous if (all) the following conditions are meet:
  - The ACE grant access (i.e AccessControlType == "Allow").
  - The ACE apply to the object (i.e not InheritOnly).
  - The ACE is not granted to a privileged principal (enumerated using Get-ADHuntingAllPrivilegedSIDs)
  - The ACE access right is one of the following right:
    - GenericAll, WriteDacl, or WriteOwner
    - GenericWrite or WriteProperty on all properties
    - GenericWrite or WriteProperty on one of the following attributes:
      - Script-Path (bf9679a8-0de6-11d0-a285-00aa003049e2)
      - Public-Information (e48d0154-bcf8-11d1-8702-00c04fb96050)
      - servicePrincipalName (f3a64788-5306-11d1-a9c5-0000f80367c1)
      - Alt-Security-Identities (00fbf30c-91fe-11d1-aebc-0000f80367c1)
      - msDS-KeyCredentialLink (5b47d60f-6090-40b2-9f37-2a4de88f3063)
      - Member (bf9679c0-0de6-11d0-a285-00aa003049e2)
      - msDS-AllowedToActOnBehalfOfOtherIdentity (3f78c3e5-f79a-46bd-a0b8-9d18116ddc79)
      - ms-DS-principal-name (564e9325-d057-c143-9e3b-4f9e5ef46f93)
      - msPKI-Certificate-Application-Policy (dbd90548-aa37-4202-9966-8c537ba5ce32)
      - pKIExtendedKeyUsage property (18976af6-3b9e-11d2-90cc-00c04fd91ab1), by precaution as msPKI-Certificate-Application-Policy seems to prevail
      - msPKI-Enrollment-Flag (d15ef7d8-f226-46db-ae79-b34e560bd12c)
      - cACertificate (bf967932-0de6-11d0-a285-00aa003049e2)
    - AllExtendedRight or one of the following extended right:
      - User-Force-Change-Password right (right's GUID: 00299570-246d-11d0-a768-00aa006e0529)
      - DS-Replication-Get-Changes (rights' GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)
      - DS-Replication-Get-Changes-All (rights' GUID: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)
      - DS-Install-Replica (right's GUID: 9923a32a-3607-11d2-b9be-0000f87a36b2)
      - DS-Replication-Manage-Topology (right's GUID: 1131f6ac-9c07-11d1-f79f-00c04fc2dcd2)
      - DS-Replication-Synchronize (right's GUID: 1131f6ab-9c07-11d1-f79f-00c04fc2dcd2)
      - Create-Inbound-Forest-Trust (right's GUID: e2a36dc9-ae17-47c3-b58b-be34c55ba633)
    - Self on all or the Member attribue (bf9679c0-0de6-11d0-a285-00aa003049e2) => right to self add one-self to a group.

For more information: https://notes.qazeer.io/active-directory/exploitation-acl_exploiting

.PARAMETER ACE

Specifies the ACE to evaluate.

.PARAMETER ACE

Specifies the object type on which the GPO was applied.

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER PrivilegedSIDs

Specifies the list of privileged SIDs in the domain. If not specified, the list is determined using Get-ADHuntingAllPrivilegedSIDs.
Used for optimization purposes for subsequent calls to the function.

.PARAMETER AttributedToSID

Specifies the principal (identified by its SID) the ACE is granted to.
If not specified, the SID is determined directly using the ACE.
Used for optimization purposes for subsequent calls to the function.

.OUTPUTS

[System.ValueType.Boolean]

#>

    Param(
        [Parameter(Mandatory=$True)][System.DirectoryServices.ActiveDirectoryAccessRule]$ACE,
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$False)]$PrivilegedSIDs = $null,
        [Parameter(Mandatory=$False)][string]$AttributedToSID,
        [Parameter(Mandatory=$True)][string]$ObjectClass
    )

    If (!$PrivilegedSIDs) {    
        If (!$Server) {
            $Server = (Get-ADDomain).PDCEmulator
        }
        $PrivilegedSIDs = If ($Credential) { Get-ADHuntingAllPrivilegedSIDs -Server $Server -Credential $Credential } Else { Get-ADHuntingAllPrivilegedSIDs -Server $Server }
    }

    If (!$AttributedToSID) {
        try { $AttributedToSID = $ACE.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
        catch { $AttributedToSID = $ACE.IdentityReference.Value }
    }

    # Deny access rights.
    If ($ACE.AccessControlType -ne "Allow") {
        return $False
    }

    # Inherit only access rights with no impact on current object.
    If ($ACE.PropagationFlags -eq "InheritOnly") {
        return $False
    }

    If ($PrivilegedSIDs.Contains($AttributedToSID) -or $AttributedToSID.EndsWith('-519')) {
    #If ($AttributedToSID -in $PrivilegedSIDs -or $AttributedToSID.EndsWith('-519')) {
        return $False
    }
    
    $AccessRights = $ACE.ActiveDirectoryRights.ToString()
    
    # Take over rights.
    If ($AccessRights -match 'GenericAll|WriteDacl|WriteOwner|268435456') {
    # If ($ACE.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner' -or $ACE.ActiveDirectoryRights -eq 268435456) {
        return $True
    }
   
    # Right to write any property of the object.
    # Right to write a property that would allow potential takeover of the object.
    # Script-Path bf9679a8-0de6-11d0-a285-00aa003049e2
    # Public-Information e48d0154-bcf8-11d1-8702-00c04fb96050
    # servicePrincipalName f3a64788-5306-11d1-a9c5-0000f80367c1
    # Alt-Security-Identities 00fbf30c-91fe-11d1-aebc-0000f80367c1
    # msDS-KeyCredentialLink 5b47d60f-6090-40b2-9f37-2a4de88f3063
    # Member bf9679c0-0de6-11d0-a285-00aa003049e2
    # msDS-AllowedToActOnBehalfOfOtherIdentity 3f78c3e5-f79a-46bd-a0b8-9d18116ddc79
    # ms-DS-principal-name 564e9325-d057-c143-9e3b-4f9e5ef46f93
    # gPLink (for Organizational Units) f30e3bbe-9ff0-11d1-b603-0000f80367c1
    # gPCFileSysPath (for group policy object) f30e3bc1-9ff0-11d1-b603-0000f80367c1
    # pKIExtendedKeyUsage 18976af6-3b9e-11d2-90cc-00c04fd91ab1
    # msPKI-Enrollment-Flag d15ef7d8-f226-46db-ae79-b34e560bd12c
    # msPKI-Certificate-Application-Policy dbd90548-aa37-4202-9966-8c537ba5ce32
    # cACertificate bf967932-0de6-11d0-a285-00aa003049e2
    # For more information: https://notes.qazeer.io/active-directory/exploitation-acl_exploiting
    If ($AccessRights -match 'GenericWrite|WriteProperty|1073741824' -and $ACE.ObjectType -match '00000000-0000-0000-0000-000000000000|bf9679a8-0de6-11d0-a285-00aa003049e2|e48d0154-bcf8-11d1-8702-00c04fb96050|f3a64788-5306-11d1-a9c5-0000f80367c1|00fbf30c-91fe-11d1-aebc-0000f80367c1|5b47d60f-6090-40b2-9f37-2a4de88f3063|bf9679c0-0de6-11d0-a285-00aa003049e2|3f78c3e5-f79a-46bd-a0b8-9d18116ddc79|564e9325-d057-c143-9e3b-4f9e5ef46f93|f30e3bbe-9ff0-11d1-b603-0000f80367c1|f30e3bc1-9ff0-11d1-b603-0000f80367c1|18976af6-3b9e-11d2-90cc-00c04fd91ab1|d15ef7d8-f226-46db-ae79-b34e560bd12c|dbd90548-aa37-4202-9966-8c537ba5ce32|bf967932-0de6-11d0-a285-00aa003049e2') {
        return $True
    }

    # All extended rights (0-[...]-0)
    # User-Force-Change-Password right (right's GUID: 00299570-246d-11d0-a768-00aa006e0529)
    # Replication rights to conduct a DcSync attack:
    # - DS-Replication-Get-Changes (rights' GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)
    # - DS-Replication-Get-Changes-All (rights' GUID: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)
    # Minimal rights to conduct a DCShadow attack:
    # - DS-Install-Replica (right's GUID: 9923a32a-3607-11d2-b9be-0000f87a36b2)
    # - DS-Replication-Manage-Topology (right's GUID: 1131f6ac-9c07-11d1-f79f-00c04fc2dcd2)
    # - DS-Replication-Synchronize (right's GUID: 1131f6ab-9c07-11d1-f79f-00c04fc2dcd2)
    # Right to create a forest trust Create-Inbound-Forest-Trust (right's GUID: e2a36dc9-ae17-47c3-b58b-be34c55ba633)
    # Rights to generate resultant set of policy (RSOP) planning / logging: b7b1b3dd-ab09-4242-9e30-9980e5d322f7 / b7b1b3de-ab09-4242-9e30-9980e5d322f7
    # Other potentially dangerous extended rights:
    # - Change-Domain-MasterChange-Domain-Master (right's GUID: 014bf69c-7b3b-11d1-85f6-08002be74fab)
    # - Change-Infrastructure-Master (right's GUID: cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd)
    # - Change-PDC (right's GUID: bae50096-4752-11d1-9052-00c04fc2d4cf)
    # - Change-Rid-Master (right's GUID: d58d5f36-0a98-11d1-adbb-00c04fd8d5cd)
    # - Change-Schema-Master (right's GUID: e12b56b6-0a95-11d1-adbb-00c04fd8d5cd)
    # - Reanimate-Tombstones (right's GUID: 45ec5156-db7e-47bb-b53f-dbeb2d03c40f)
    If ($AccessRights -match 'ExtendedRight' -and $ACE.ObjectType -match '00000000-0000-0000-0000-000000000000|00299570-246d-11d0-a768-00aa006e0529|1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|9923a32a-3607-11d2-b9be-0000f87a36b2|1131f6ac-9c07-11d1-f79f-00c04fc2dcd2|1131f6ab-9c07-11d1-f79f-00c04fc2dcd2|e2a36dc9-ae17-47c3-b58b-be34c55ba633|b7b1b3de-ab09-4242-9e30-9980e5d322f7|b7b1b3dd-ab09-4242-9e30-9980e5d322f7|014bf69c-7b3b-11d1-85f6-08002be74fab|cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd|bae50096-4752-11d1-9052-00c04fc2d4cf|d58d5f36-0a98-11d1-adbb-00c04fd8d5cd|e12b56b6-0a95-11d1-adbb-00c04fd8d5cd') {
        # Filter false positive on Enterprise Read-only Domain Controllers, that have DS-Replication-Get-Changes right (1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)
        if ($ACE.ObjectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' -and $AttributedToSID.EndsWith('498')) {
            return $False
        }
        
        return $True
    }

    # Validated writes
    # All validated writes: 00000000-0000-0000-0000-000000000000
    # Right to add one-self to a group: bf9679c0-0de6-11d0-a285-00aa003049e2
    # Validated write to service principal name: f3a64788-5306-11d1-a9c5-0000f80367c1
    If (($AccessRights -match 'Self') -and ($ACE.ObjectType -match '00000000-0000-0000-0000-000000000000|bf9679c0-0de6-11d0-a285-00aa003049e2|f3a64788-5306-11d1-a9c5-0000f80367c1')) {
        return $True
    }

    # Rights on containers (such as Organizational Units, Schema container, DFSR-GlobalSettings, etc.)
    # Delete / delete subtree: Delete / DeleteTree
    # Create / delete child items:
    #   - CreateChild: Rights to create child objects (+ optionnal object GUID)
    #   - DeleteChild: Rights to delete child objects (+ optionnal object GUID)
    # All objects: 00000000-0000-0000-0000-000000000000
    # Computer: bf967a86-0de6-11d0-a285-00aa003049e2
    # Group: bf967a9c-0de6-11d0-a285-00aa003049e2
    # Group policy object: f30e3bc2-9ff0-11d1-b603-0000f80367c1
    # msDS-GroupManagedServiceAccount: 7b8b558a-93a5-4af7-adca-c017e67f1057
    # msDS-ManagedServiceAccount: ce206244-5827-4a86-ba1c-1c0c386c1b64
    # Organizational Unit: bf967aa5-0de6-11d0-a285-00aa003049e2
    # User: bf967aba-0de6-11d0-a285-00aa003049e2
    # attributeSchema (an attribute object in the schema): bf967a80-0de6-11d0-a285-00aa003049e2
    # classSchema (a class object in the schema): bf967a83-0de6-11d0-a285-00aa003049e2
    # ms-DFSR-ReplicationGroup: 1c332fe0-0c2a-4f32-afca-23c5e45a9e77
    If (($ObjectClass -match 'domainDNS|msDFSR-ReplicationGroup|organizationalUnit|groupPolicyContainer') -and ($AccessRights -match 'Delete|DeleteTree|CreateChild|DeleteChild') -and ($ACE.ObjectType -match '00000000-0000-0000-0000-000000000000|bf967a86-0de6-11d0-a285-00aa003049e2|bf967a9c-0de6-11d0-a285-00aa003049e2|f30e3bc2-9ff0-11d1-b603-0000f80367c1|7b8b558a-93a5-4af7-adca-c017e67f1057|ce206244-5827-4a86-ba1c-1c0c386c1b64|bf967aa5-0de6-11d0-a285-00aa003049e2|bf967aba-0de6-11d0-a285-00aa003049e2|bf967a80-0de6-11d0-a285-00aa003049e2|bf967a83-0de6-11d0-a285-00aa003049e2|1c332fe0-0c2a-4f32-afca-23c5e45a9e77')) {
        return $True
    }

    # Specific rights for gMSA accounts.
    # Read / write on the msDS-ManagedPassword attribute (e362ed86-b728-0842-b27d-2dea7a9df218)
    If ($AccessRights -match 'ReadProperty|WriteProperty|1073741824' -and $ACE.ObjectType -match 'e362ed86-b728-0842-b27d-2dea7a9df218') {
        return $True
    }
    
    # Return False by default (if no matching dangerous rights found).
    return $False
}

function Is-DangerousFileACE {
<#
.SYNOPSIS

Determine if a given file ACE is dangerous.

Required Dependencies: ActiveDirectory module and Get-ADHuntingAllPrivilegedSIDs.

.DESCRIPTION

Return True if a given ACE is dangerous, False otherwise.

An ACE is judged to be dangerous if (all) the following conditions are meet:
  - The ACE grant access (i.e AccessControlType == "Allow").
  - The ACE is not granted to a privileged principal (enumerated using Get-ADHuntingAllPrivilegedSIDs)
  - The ACE access right is one of the following right:
    - GenericAll, WriteDacl, or WriteOwner
    - GenericWrite or WriteProperty on one of the following attributes:

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER PrivilegedSIDs

Specifies the list of privileged SIDs in the domain. If not specified, the list is determined using Get-ADHuntingAllPrivilegedSIDs.
Used for optimization purposes for subsequent calls to the function.

.PARAMETER ACE

Specifies the ACE to evaluate.

.PARAMETER AttributedToSID

Specifies the principal (identified by its SID) the ACE is granted to.
If not specified, the SID is determined directly using the ACE.
Used for optimization purposes for subsequent calls to the function.
    
.OUTPUTS

[System.ValueType.Boolean]

#>
    
    Param(
        [Parameter(Mandatory=$True)][System.Security.AccessControl.FileSystemAccessRule]$ACE,
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$False)]$PrivilegedSIDs = $null,
        [Parameter(Mandatory=$False)][string]$AttributedToSID
    )

    If (!$PrivilegedSIDs) {    
        If (!$Server) {
            $Server = (Get-ADDomain).PDCEmulator
        }
        $PrivilegedSIDs = If ($Credential) { Get-ADHuntingAllPrivilegedSIDs -Server $Server -Credential $Credential } Else { Get-ADHuntingAllPrivilegedSIDs -Server $Server }
    }

    If (!$AttributedToSID) {
        try { $AttributedToSID = $ACE.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
        catch { $AttributedToSID = $ACE.IdentityReference.Value }
    }

    # Deny access rights.
    If ($ACE.AccessControlType -ne "Allow") {
        return $False
    }
    
    # Inherit only access rights with no impact on current object.
    If ($ACE.PropagationFlags -eq "InheritOnly") {
        return $False
    }
    If ($PrivilegedSIDs.Contains($AttributedToSID) -or $AttributedToSID.EndsWith('-519')) {
        return $False
    }
    
    # Sensitive Windows filesystem rights (https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemrights)
    If ($ACE.FileSystemRights -match 'FullControl|ChangePermissions|TakeOwnership|Modify|Write|WriteAttributes|WriteExtendedAttributes|WriteData|AppendData|CreateFiles|Delete|DeleteSubdirectoriesAndFiles') {
        return $True
    }
    # Some Generic FileSystem rights may not be parsed, requiring additionnal checks.
    # https://blog.cjwdev.co.uk/2011/06/28/permissions-not-included-in-net-accessrule-filesystemrights-enum/
    # https://www.powershellgallery.com/packages/GPOZaurr/0.0.59/Content/GPOZaurr.psm1
    # GENERIC_WRITE = 0x40000000
    # GENERIC_ALL = 0x10000000
    If (($ACE.FileSystemRights -eq 0x40000000) -or ($ACE.FileSystemRights -eq 0x10000000)) {
        return $True
    }
    
    return $False
}

# TODO doc
function Get-ADHuntingFileParsedACL {
    Param(
        [Parameter(Mandatory=$True)][String]$FilePath,
        [Parameter(Mandatory=$False)][Boolean]$IncludeFileInOutput = $True,
        [Parameter(Mandatory=$False)]$PrivilegedSIDs = $null,
        [Parameter(Mandatory=$False)]$UnprivilegedSIDs = $null,
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
    }

    If (!$PrivilegedSIDs) {
        $PrivilegedSIDs = Get-ADHuntingAllPrivilegedSIDs
    }

    If (!$UnprivilegedSIDs) {
        $UnprivilegedSIDs = Get-ADHuntingUnprivilegedSIDs
    }

    $FileACL = Get-Acl $FilePath
    If (!$FileACL) { return $null }

    $OutputObject = [PSCustomObject]@{
        FileOwnerSID = $null
        DangerousFileOwner = $null
        DangerousFilesOwnerAsString = ""
        FileSenstiveRightGrantedTo = $null
        FilesSenstiveRightsAsString = ""
    }

    # Checks on GPO file owner.
    $OutputObject.FileOwnerSID = $FileACL.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    If (!$PrivilegedSIDs.Contains($OutputObject.FileOwnerSID)) {
        If ($IncludeFileInOutput) { $OutputObject.DangerousFilesOwnerAsString = "File=$($FilePath) | " }
        $OutputObject.DangerousFilesOwnerAsString += "Owner=$($FileACL.Owner) | OwnerSID=$($OutputObject.FileOwnerSID);"

        If ($UnprivilegedSIDs.Contains($OutputObject.FileOwnerSID)) { $OutputObject.DangerousFileOwner = [PrivilegeLevel]::Everyone }
        Else { $OutputObject.DangerousFileOwner = [PrivilegeLevel]::NonPrivileged }   
    }

    # Checks on GPO file access rights.
    foreach ($FileACE in $FileACL.Access) {
        # Attempt to retrieve SID from ACE IdentityReference if automatically translated to principal name.
        try { $FileACEAttributedToSID = $FileACE.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
        catch { $FileACEAttributedToSID = $FileACE.IdentityReference }

        # Skip non dangerous access rights (i.e rights granted to privileged principals or that do not allow modification of the file).
        If (!(Is-DangerousFileACE -ACE $FileACE -AttributedToSID $FileACEAttributedToSID -PrivilegedSIDs $PrivilegedSIDs)) { continue }
        
        If ($IncludeFileInOutput) { $OutputObject.FilesSenstiveRightsAsString += "File=$($FilePath) | " }
        $OutputObject.FilesSenstiveRightsAsString += "GrantedTo=$($FileACE.IdentityReference) | GrantedToSID=$FileACEAttributedToSID | AccessType=$($FileACE.AccessControlType) | FileSystemRights=$($FileACE.FileSystemRights) | IsInherited=$($FileACE.IsInherited) | PropagationFlags=$($FileACE.PropagationFlags);"
        
        # Check if Everyone is owner (only if no previous senstive access rights granted to every was found for performance reason).
        If ($OutputObject.FileSenstiveRightGrantedTo -ne [PrivilegeLevel]::Everyone) {
            If ($UnprivilegedSIDs.Contains($FileACEAttributedToSID)) { $OutputObject.FileSenstiveRightGrantedTo = [PrivilegeLevel]::Everyone }
            Else { $OutputObject.FileSenstiveRightGrantedTo = [PrivilegeLevel]::NonPrivileged }
        }
    }

    return $OutputObject
}

function Is-EnrollmentADACE {
<#
.SYNOPSIS

Determine if a given ACE allows direct or indirect certificate enrollment.

.DESCRIPTION

Return True if a given ACE allows direct or indirect certificate enrollment, False otherwise.

An ACE allows direct or indirect certificate enrollment if (all) the following conditions are meet:
  - The ACE grant access (i.e AccessControlType == "Allow").
  - The ACE apply to the object (i.e not InheritOnly).
  - The ACE access right is one of the following right:
    - GenericAll, WriteDacl, or WriteOwner
    - GenericWrite or WriteProperty on all properties
    - GenericWrite or WriteProperty on one of the following attributes:
      - msPKI-Certificate-Application-Policy (dbd90548-aa37-4202-9966-8c537ba5ce32)
      - pKIExtendedKeyUsage property (18976af6-3b9e-11d2-90cc-00c04fd91ab1), by precaution as msPKI-Certificate-Application-Policy seems to prevail.
    - AllExtendedRight or one of the following extended right:
      - Certificate-Enrollment right (right's GUID: 0e10c968-78fb-11d2-90d4-00c04f79dc55)
      - Certificate-AutoEnrollment right (right's GUID: a05b8cc2-17bc-4802-a710-e7c15ab866a2)

For more information: https://notes.qazeer.io/active-directory/exploitation-acl_exploiting

.PARAMETER ACE

Specifies the ACE to evaluate.

.OUTPUTS

[System.ValueType.Boolean]

#>

    Param(
        [Parameter(Mandatory=$True)][System.DirectoryServices.ActiveDirectoryAccessRule]$ACE
    )

    # Deny access rights.
    If ($ACE.AccessControlType -ne "Allow") {
        return $False
    }

    # Inherit only access rights with no impact on current object.
    If ($ACE.PropagationFlags -eq "InheritOnly") {
        return $False
    }

    $AccessRights = $ACE.ActiveDirectoryRights.ToString()

    # Take over rights.
    If ($AccessRights -match 'GenericAll|WriteDacl|WriteOwner|268435456') {
        return $True
    }

    # Right to write any property of the object or properties related to certificate enrollment.
    If ($AccessRights -match 'GenericWrite|WriteProperty|1073741824' -and $ACE.ObjectType -match '00000000-0000-0000-0000-000000000000|dbd90548-aa37-4202-9966-8c537ba5ce32|18976af6-3b9e-11d2-90cc-00c04fd91ab1') {
        return $True
    }
    
    # All extended rights (0-[...]-0)
    # Certificate-Enrollment 0e10c968-78fb-11d2-90d4-00c04f79dc55
    # Certificate-AutoEnrollment a05b8cc2-17bc-4802-a710-e7c15ab866a2
    If ($AccessRights -match 'ExtendedRight' -and $ACE.ObjectType -match '00000000-0000-0000-0000-000000000000|0e10c968-78fb-11d2-90d4-00c04f79dc55|a05b8cc2-17bc-4802-a710-e7c15ab866a2') {
        return $True
    }
    
    # Return False by default (if no matching dangerous rights found).
    return $False
}

########################################################
#
#
# Hidden objects and attributes hunting.
#
#
########################################################

$Script:sourceDrsr = 
@"
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace drsrdotnet
{
    public class drsr
    {
        public const int MAX_ATTRIBUTES_TO_REPLICATE = <TEMPLATE_MAX_ATTRIBUTES_TO_REPLICATE>;
        // public const int MAX_ATTRIBUTES_TO_REPLICATE = 38;

        #region pinvoke

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingFromStringBindingW",
        CallingConvention = CallingConvention.StdCall,
        CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern Int32 RpcBindingFromStringBinding(String bindingString, out IntPtr lpBinding);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
           CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern IntPtr NdrClientCall2x64(IntPtr pMIDL_STUB_DESC, IntPtr formatString, __arglist);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
           CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern IntPtr NdrClientCall2x64_DrsBind(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr hBinding, Guid NtdsDsaObjectGuid, DRS_EXTENSIONS_INT extensions_in, ref IntPtr pDrsExtensionsExt, ref IntPtr hDrs);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
        CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern IntPtr NdrClientCall2x64_DrsUnbind(IntPtr pMIDL_STUB_DESC, IntPtr formatString, ref IntPtr hDrs);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
        CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern IntPtr NdrClientCall2x64_DrsDomainControllerInfo(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr hDrs, UInt32 dcInVersion, DRS_MSG_DCINFOREQ_V1 dcInfoReq, ref UInt32 dcOutVersion, ref DRS_MSG_DCINFOREPLY_V2 dcInfoRep);

        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
        CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern IntPtr NdrClientCall2x64_GetNCChanges(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr hDrs, UInt32 dwInVersion, DRS_MSG_GETCHGREQ_V8 pmsgIn, out UInt32 dwOutVersion, out DRS_MSG_GETCHGREPLY_V6 pmsgOut);


        [DllImport("Rpcrt4.dll", EntryPoint = "NdrClientCall2", CallingConvention = CallingConvention.Cdecl,
            CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern IntPtr NdrClientCall2x86(IntPtr pMIDL_STUB_DESC, IntPtr formatString, IntPtr args);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingFree", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern Int32 RpcBindingFree(ref IntPtr lpString);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LoadLibrary(string lib);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void FreeLibrary(IntPtr module);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr module, string proc);

        //#region RpcStringBindingCompose

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcStringBindingComposeW", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern Int32 RpcStringBindingCompose(
            String ObjUuid, String ProtSeq, String NetworkAddr, String Endpoint, String Options,
            out IntPtr lpBindingString
            );

        [StructLayout(LayoutKind.Sequential)]
        private struct RPC_SECURITY_QOS
        {
            public Int32 Version;
            public Int32 Capabilities;
            public Int32 IdentityTracking;
            public Int32 ImpersonationType;
        };

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetAuthInfoExW", CallingConvention = CallingConvention.StdCall,
            CharSet = CharSet.Unicode, SetLastError = false)]
        private static extern Int32 RpcBindingSetAuthInfoEx(IntPtr lpBinding, string ServerPrincName,
                                           UInt32 AuthnLevel, UInt32 AuthnSvc, IntPtr identity, UInt32 AuthzSvc, ref RPC_SECURITY_QOS SecurityQOS);

        [DllImport("Rpcrt4.dll", EntryPoint = "RpcBindingSetOption", CallingConvention = CallingConvention.StdCall, SetLastError = false)]
        private static extern Int32 RpcBindingSetOption(IntPtr Binding, UInt32 Option, IntPtr OptionValue);

        [DllImport("Rpcrt4.dll", EntryPoint = "I_RpcBindingInqSecurityContext", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern Int32 I_RpcBindingInqSecurityContext(IntPtr Binding, out IntPtr SecurityContextHandle);


        [StructLayout(LayoutKind.Sequential)]
        private struct SecPkgContext_SessionKey
        {
            public UInt32 SessionKeyLength;
            public IntPtr SessionKey;
        }

        [DllImport("secur32.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        private static extern int QueryContextAttributes(IntPtr hContext,
                                                        uint ulAttribute,
                                                        ref SecPkgContext_SessionKey pContextAttributes);

        [StructLayout(LayoutKind.Sequential)]
        private struct CRYPTO_BUFFER
        {
            public UInt32 Length;
            public UInt32 MaximumLength;
            public IntPtr Buffer;
        }

        [DllImport("advapi32.Dll", CharSet = CharSet.Auto, SetLastError = false, EntryPoint = "SystemFunction032")]
        private static extern int SystemFunction032(ref CRYPTO_BUFFER data, ref CRYPTO_BUFFER key);

        private static byte[] RtlEncryptDecryptRC4(byte[] input, byte[] key)
        {
            CRYPTO_BUFFER inputBuffer = new CRYPTO_BUFFER();
            inputBuffer.Length = inputBuffer.MaximumLength = (UInt32)input.Length;
            inputBuffer.Buffer = Marshal.AllocHGlobal(input.Length);
            Marshal.Copy(input, 0, inputBuffer.Buffer, input.Length);
            CRYPTO_BUFFER keyBuffer = new CRYPTO_BUFFER();
            keyBuffer.Length = keyBuffer.MaximumLength = (UInt32)key.Length;
            keyBuffer.Buffer = Marshal.AllocHGlobal(key.Length);
            Marshal.Copy(key, 0, keyBuffer.Buffer, key.Length);
            int ret = SystemFunction032(ref inputBuffer, ref keyBuffer);
            byte[] output = new byte[inputBuffer.Length];
            Marshal.Copy(inputBuffer.Buffer, output, 0, output.Length);
            Marshal.FreeHGlobal(inputBuffer.Buffer);
            Marshal.FreeHGlobal(keyBuffer.Buffer);
            return output;
        }

        [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "SystemFunction027")]
        private static extern int RtlDecryptDES2blocks1DWORD(byte[] data, ref UInt32 key, IntPtr output);


        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr GetSidSubAuthority(IntPtr sid, UInt32 subAuthorityIndex);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr GetSidSubAuthorityCount(IntPtr psid);
        #endregion

        #region low level operations for ASN conversion
        private static bool EqualMemory(IntPtr ptr1, IntPtr ptr2, int length)
        {
            for (int i = 0; i < length; i++)
            {
                if (Marshal.ReadByte(ptr1, i) != Marshal.ReadByte(ptr2, i))
                {
                    return false;
                }
            }
            return true;
        }

        private static bool CopyMemory(IntPtr src, IntPtr dest, int length)
        {
            try
            {
                byte[] tmpbyte = new byte[length];
                Marshal.Copy(src, tmpbyte, 0, length);
                Marshal.Copy(tmpbyte, 0, dest, length);
            }
            catch (Exception)
            {
                return false;
            }
            return true;
        }

        private static IntPtr GetMsasn1()
        {

            return LoadLibrary("msasn1.dll");

        }

        public enum ASN1encodingrule_e
        {
            ASN1_BER_RULE_BER = 0x0100,
            ASN1_BER_RULE_CER = 0x0200,
            ASN1_BER_RULE_DER = 0x0400,
            ASN1_BER_RULE = ASN1_BER_RULE_BER | ASN1_BER_RULE_CER | ASN1_BER_RULE_DER,
        }

        public enum ASN1Flags : long
        {
            ASN1FLAGS_NONE = 0x00000000L, /* no flags */
            ASN1FLAGS_NOASSERT = 0x00001000L, /* no asertion */
        }

        public enum ASN1error_e
        {
            ASN1_SUCCESS = 0,            /* success */

            // Teles specific error codes
            ASN1_ERR_INTERNAL = (-1001),      /* internal error */
            ASN1_ERR_EOD = (-1002),      /* unexpected end of data */
            ASN1_ERR_CORRUPT = (-1003),      /* corrupted data */
            ASN1_ERR_LARGE = (-1004),      /* value too large */
            ASN1_ERR_CONSTRAINT = (-1005),      /* constraint violated */
            ASN1_ERR_MEMORY = (-1006),      /* out of memory */
            ASN1_ERR_OVERFLOW = (-1007),      /* buffer overflow */
            ASN1_ERR_BADPDU = (-1008),      /* function not supported for this pdu*/
            ASN1_ERR_BADARGS = (-1009),      /* bad arguments to function call */
            ASN1_ERR_BADREAL = (-1010),      /* bad real value */
            ASN1_ERR_BADTAG = (-1011),      /* bad tag value met */
            ASN1_ERR_CHOICE = (-1012),      /* bad choice value */
            ASN1_ERR_RULE = (-1013),      /* bad encoding rule */
            ASN1_ERR_UTF8 = (-1014),      /* bad unicode (utf8) */

            // New error codes
            ASN1_ERR_PDU_TYPE = (-1051),      /* bad pdu type */
            ASN1_ERR_NYI = (-1052),      /* not yet implemented */

            // Teles specific warning codes
            ASN1_WRN_EXTENDED = 1001,         /* skipped unknown extension(s) */
            ASN1_WRN_NOEOD = 1002,         /* end of data expected */
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ASN1BerFunArr_t
        {
            IntPtr apfnEncoder;//ASN1BerEncFun_t
            IntPtr apfnDecoder;//ASN1BerDecFun_t
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ASN1module_t
        {
            uint nModuleName;
            ASN1encodingrule_e eRule;
            uint dwFlags;
            uint cPDUs;

            //__field_xcount(cPDUs)
            IntPtr apfnFreeMemory;//ASN1FreeFun_t

            //__field_xcount(cPDUs)
            IntPtr acbStructSize;//uint

            ASN1BerFunArr_t BER;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ASN1encoding_s
        {
            public uint magic;  /* magic for this structure */
            public uint version;/* version number of this library */
            public IntPtr module; /* module this encoding_t depends to */
            //__field_bcount(size)
            IntPtr buf;    /* buffer to encode into */
            uint size;   /* current size of buffer */
            uint len;    /* len of encoded data in buffer */
            ASN1error_e err;    /* error code for last encoding */
            uint bit;
            IntPtr pos;
            uint cbExtraHeader;
            ASN1encodingrule_e eRule;
            uint dwFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ASN1decoding_s
        {
            uint magic;  /* magic for this structure */
            uint version;/* version number of this library */
            IntPtr module; /* module this decoding_t depends to */
            //__field_bcount(size)
            IntPtr buf;    /* buffer to decode from */
            uint size;   /* size of buffer */
            uint len;    /* len of decoded data in buffer */
            ASN1error_e err;    /* error code for last decoding */
            uint bit;
            IntPtr pos;
            ASN1encodingrule_e eRule;
            uint dwFlags;
        }

        static IntPtr hASN1Module = IntPtr.Zero;
        static ASN1encoding_s ASN1enc;
        static ASN1decoding_s ASN1dec;

        static IntPtr[] kull_m_asn1_encdecfreefntab = { IntPtr.Zero };
        static int[] kull_m_asn1_sizetab = { 0 };

        [System.Security.SuppressUnmanagedCodeSecurity]
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate IntPtr ASN1_CreateModuleDelegate(uint nVersion, uint eRule, uint dwFlags, uint cPDU, IntPtr[] apfnEncoder, IntPtr[] apfnDecoder, IntPtr[] apfnFreeMemory, int[] acbStructSize, uint nModuleName);

        private static IntPtr ASN1_CreateModule(uint nVersion, uint eRule, uint dwFlags, uint cPDU, IntPtr[] apfnEncoder, IntPtr[] apfnDecoder, IntPtr[] apfnFreeMemory, int[] acbStructSize, uint nModuleName)
        {
            IntPtr proc = GetProcAddress(GetMsasn1(), "ASN1_CreateModule");
            ASN1_CreateModuleDelegate ASN1_CreateModuleFunc = (ASN1_CreateModuleDelegate)Marshal.GetDelegateForFunctionPointer(proc, typeof(ASN1_CreateModuleDelegate));
            return ASN1_CreateModuleFunc(nVersion, eRule, dwFlags, cPDU, apfnEncoder, apfnDecoder, apfnFreeMemory, acbStructSize, nModuleName);
        }

        [System.Security.SuppressUnmanagedCodeSecurity]
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate ASN1error_e ASN1_CreateDecoderDelegate(IntPtr pModule, out IntPtr ppDecoderInfo, IntPtr pbBuf, uint cbBufSize, IntPtr pParent);

        private static ASN1error_e ASN1_CreateDecoder(IntPtr pModule, out IntPtr ppDecoderInfo, IntPtr pbBuf, uint cbBufSize, IntPtr pParent)
        {
            IntPtr proc = GetProcAddress(GetMsasn1(), "ASN1_CreateDecoder");
            ASN1_CreateDecoderDelegate ASN1_CreateDecoderFunc = (ASN1_CreateDecoderDelegate)Marshal.GetDelegateForFunctionPointer(proc, typeof(ASN1_CreateDecoderDelegate));
            return ASN1_CreateDecoderFunc(pModule, out ppDecoderInfo, pbBuf, cbBufSize, pParent);
        }

        [System.Security.SuppressUnmanagedCodeSecurity]
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate void ASN1_CloseModuleDelegate(IntPtr pModule);

        private static void ASN1_CloseModule(IntPtr pModule)
        {
            IntPtr proc = GetProcAddress(GetMsasn1(), "ASN1_CloseModule");
            ASN1_CloseModuleDelegate ASN1_CloseModuleFunc = (ASN1_CloseModuleDelegate)Marshal.GetDelegateForFunctionPointer(proc, typeof(ASN1_CloseModuleDelegate));
            ASN1_CloseModuleFunc(pModule);
        }

        private static bool Asn1_init()
        {
            bool status;
            ASN1error_e ret;

            hASN1Module = ASN1_CreateModule((((1) << 16) | (0)), 1024, 4096, 1, kull_m_asn1_encdecfreefntab, kull_m_asn1_encdecfreefntab, kull_m_asn1_encdecfreefntab, kull_m_asn1_sizetab, (uint)1769433451);
            if (hASN1Module != IntPtr.Zero)
            {
                IntPtr s = IntPtr.Zero;

                IntPtr mt = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(ASN1encoding_s)));
                Marshal.StructureToPtr(ASN1enc, mt, false);
                ret = ASN1_CreateDecoder(hASN1Module, out mt, IntPtr.Zero, 0, s);
                ASN1enc = (ASN1encoding_s)Marshal.PtrToStructure(mt, typeof(ASN1encoding_s));

                if (ret < 0)
                {
                    Console.WriteLine("ASN1_CreateEncoder: {0}", ret);
                    ASN1enc = new ASN1encoding_s();
                }
                else
                {
                    IntPtr d = new IntPtr();
                    IntPtr mt2 = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(ASN1decoding_s)));
                    Marshal.StructureToPtr(ASN1dec, mt2, false);
                    ret = ASN1_CreateDecoder(hASN1Module, out mt2, IntPtr.Zero, 0, d);
                    ASN1dec = (ASN1decoding_s)Marshal.PtrToStructure(mt2, typeof(ASN1decoding_s));
                    if (ret < 0)
                    {
                        Console.WriteLine("ASN1_CreateDecoder: {0}", ret);
                        ASN1dec = new ASN1decoding_s();
                    }
                }
            }
            else
                Console.WriteLine("ASN1_CreateModule");

            status = (hASN1Module != IntPtr.Zero) && !ASN1enc.Equals(default(ASN1encoding_s)) && !ASN1dec.Equals(default(ASN1decoding_s));
            if (!status)
                Asn1_term();

            return status;
        }

        public static void Asn1_term()
        {
            if (hASN1Module != IntPtr.Zero)
            {
                ASN1_CloseModule(hASN1Module);
            }
        }

        #endregion

        #region rpc initialization
        private Int32 RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH = 0x1;

        private UInt32 RPC_C_AUTHN_LEVEL_PKT_PRIVACY = 6;

        private UInt32 RPC_C_AUTHN_GSS_NEGOTIATE = 9;
        private UInt32 RPC_C_AUTHN_WINNT = 10;

        private UInt32 RPC_C_OPT_SECURITY_CALLBACK = 10;
        private UInt32 RPC_C_OPT_CALL_TIMEOUT = 12;

        private byte[] MIDL_ProcFormatString;
        private byte[] MIDL_TypeFormatString;
        private GCHandle procString;
        private GCHandle formatString;
        private GCHandle stub;
        private GCHandle faultoffsets;
        private GCHandle clientinterface;

        private UInt32 RPCTimeOut = 1000;

        [StructLayout(LayoutKind.Sequential)]
        private struct COMM_FAULT_OFFSETS
        {
            public short CommOffset;
            public short FaultOffset;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct GENERIC_BINDING_ROUTINE_PAIR
        {
            public IntPtr Bind;
            public IntPtr Unbind;
        }


        [StructLayout(LayoutKind.Sequential)]
        private struct RPC_VERSION
        {
            public ushort MajorVersion;
            public ushort MinorVersion;

            public RPC_VERSION(ushort InterfaceVersionMajor, ushort InterfaceVersionMinor)
            {
                MajorVersion = InterfaceVersionMajor;
                MinorVersion = InterfaceVersionMinor;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct RPC_SYNTAX_IDENTIFIER
        {
            public Guid SyntaxGUID;
            public RPC_VERSION SyntaxVersion;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SEC_WINNT_AUTH_IDENTITY_W
        {
            public string User;
            public int UserLength;
            public string Domain;
            public int DomainLength;
            public string Password;
            public int PasswordLength;
            public int Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct RPC_CLIENT_INTERFACE
        {
            public uint Length;
            public RPC_SYNTAX_IDENTIFIER InterfaceId;
            public RPC_SYNTAX_IDENTIFIER TransferSyntax;
            public IntPtr /*PRPC_DISPATCH_TABLE*/ DispatchTable;
            public uint RpcProtseqEndpointCount;
            public IntPtr /*PRPC_PROTSEQ_ENDPOINT*/ RpcProtseqEndpoint;
            public IntPtr Reserved;
            public IntPtr InterpreterInfo;
            public uint Flags;

            public static readonly Guid IID_SYNTAX = new Guid(0x8A885D04u, 0x1CEB, 0x11C9, 0x9F, 0xE8, 0x08, 0x00, 0x2B,
                                                              0x10,
                                                              0x48, 0x60);

            public RPC_CLIENT_INTERFACE(Guid iid, ushort InterfaceVersionMajor, ushort InterfaceVersionMinor)
            {
                Length = (uint)Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE));
                RPC_VERSION rpcVersion = new RPC_VERSION(InterfaceVersionMajor, InterfaceVersionMinor);
                InterfaceId = new RPC_SYNTAX_IDENTIFIER();
                InterfaceId.SyntaxGUID = iid;
                InterfaceId.SyntaxVersion = rpcVersion;
                rpcVersion = new RPC_VERSION(2, 0);
                TransferSyntax = new RPC_SYNTAX_IDENTIFIER();
                TransferSyntax.SyntaxGUID = IID_SYNTAX;
                TransferSyntax.SyntaxVersion = rpcVersion;
                DispatchTable = IntPtr.Zero;
                RpcProtseqEndpointCount = 0u;
                RpcProtseqEndpoint = IntPtr.Zero;
                Reserved = IntPtr.Zero;
                InterpreterInfo = IntPtr.Zero;
                Flags = 0u;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIDL_STUB_DESC
        {
            public IntPtr /*RPC_CLIENT_INTERFACE*/ RpcInterfaceInformation;
            public IntPtr pfnAllocate;
            public IntPtr pfnFree;
            public IntPtr pAutoBindHandle;
            public IntPtr /*NDR_RUNDOWN*/ apfnNdrRundownRoutines;
            public IntPtr /*GENERIC_BINDING_ROUTINE_PAIR*/ aGenericBindingRoutinePairs;
            public IntPtr /*EXPR_EVAL*/ apfnExprEval;
            public IntPtr /*XMIT_ROUTINE_QUINTUPLE*/ aXmitQuintuple;
            public IntPtr pFormatTypes;
            public int fCheckBounds;
            /* Ndr library version. */
            public uint Version;
            public IntPtr /*MALLOC_FREE_STRUCT*/ pMallocFreeStruct;
            public int MIDLVersion;
            public IntPtr CommFaultOffsets;
            // New fields for version 3.0+
            public IntPtr /*USER_MARSHAL_ROUTINE_QUADRUPLE*/ aUserMarshalQuadruple;
            // Notify routines - added for NT5, MIDL 5.0
            public IntPtr /*NDR_NOTIFY_ROUTINE*/ NotifyRoutineTable;
            public IntPtr mFlags;
            // International support routines - added for 64bit post NT5
            public IntPtr /*NDR_CS_ROUTINES*/ CsRoutineTables;
            public IntPtr ProxyServerInfo;
            public IntPtr /*NDR_EXPR_DESC*/ pExprInfo;
            // Fields up to now present in win2000 release.

            public MIDL_STUB_DESC(IntPtr pFormatTypesPtr, IntPtr RpcInterfaceInformationPtr,
                                    IntPtr pfnAllocatePtr, IntPtr pfnFreePtr, IntPtr aGenericBindingRoutinePairsPtr)
            {
                pFormatTypes = pFormatTypesPtr;
                RpcInterfaceInformation = RpcInterfaceInformationPtr;
                CommFaultOffsets = IntPtr.Zero;
                pfnAllocate = pfnAllocatePtr;
                pfnFree = pfnFreePtr;
                pAutoBindHandle = IntPtr.Zero;
                apfnNdrRundownRoutines = IntPtr.Zero;
                aGenericBindingRoutinePairs = aGenericBindingRoutinePairsPtr;
                apfnExprEval = IntPtr.Zero;
                aXmitQuintuple = IntPtr.Zero;
                fCheckBounds = 1;
                Version = 0x50002u;
                pMallocFreeStruct = IntPtr.Zero;
                MIDLVersion = 0x8000253;
                aUserMarshalQuadruple = IntPtr.Zero;
                NotifyRoutineTable = IntPtr.Zero;
                mFlags = new IntPtr(0x00000001);
                CsRoutineTables = IntPtr.Zero;
                ProxyServerInfo = IntPtr.Zero;
                pExprInfo = IntPtr.Zero;
            }
        }

        private void InitializeStub(Guid interfaceID, byte[] MIDL_ProcFormatString, byte[] MIDL_TypeFormatString, ushort MajorVerson, ushort MinorVersion)
        {
            this.MIDL_ProcFormatString = MIDL_ProcFormatString;
            this.MIDL_TypeFormatString = MIDL_TypeFormatString;
            procString = GCHandle.Alloc(this.MIDL_ProcFormatString, GCHandleType.Pinned);

            RPC_CLIENT_INTERFACE clientinterfaceObject = new RPC_CLIENT_INTERFACE(interfaceID, MajorVerson, MinorVersion);

            COMM_FAULT_OFFSETS commFaultOffset = new COMM_FAULT_OFFSETS();
            commFaultOffset.CommOffset = -1;
            commFaultOffset.FaultOffset = -1;
            faultoffsets = GCHandle.Alloc(commFaultOffset, GCHandleType.Pinned);
            clientinterface = GCHandle.Alloc(clientinterfaceObject, GCHandleType.Pinned);
            formatString = GCHandle.Alloc(MIDL_TypeFormatString, GCHandleType.Pinned);

            _allocmemory = AllocateMemory;
            _freememory = FreeMemory;
            IntPtr pAllocMemory = Marshal.GetFunctionPointerForDelegate(_allocmemory);
            IntPtr pFreeMemory = Marshal.GetFunctionPointerForDelegate(_freememory);

            MIDL_STUB_DESC stubObject = new MIDL_STUB_DESC(formatString.AddrOfPinnedObject(),
                                                            clientinterface.AddrOfPinnedObject(),
                                                            pAllocMemory /*Marshal.GetFunctionPointerForDelegate((allocmemory)AllocateMemory)*/,
                                                            pFreeMemory /*Marshal.GetFunctionPointerForDelegate((freememory)FreeMemory)*/,
                                                            IntPtr.Zero);

            stub = GCHandle.Alloc(stubObject, GCHandleType.Pinned);
        }

        private void freeStub()
        {
            if (procString != null)
                procString.Free();

            if (faultoffsets != null)
                faultoffsets.Free();

            if (clientinterface != null)
                clientinterface.Free();

            if (formatString != null)
                formatString.Free();

            if (stub != null)
                stub.Free();
        }

        private static List<IntPtr> TrackedMemoryAllocations;

        static allocmemory _allocmemory;
        private delegate IntPtr allocmemory(int size);
        private static IntPtr AllocateMemory(int size)
        {
            IntPtr memory = Marshal.AllocHGlobal(size);
            if (TrackedMemoryAllocations != null)
            {
                TrackedMemoryAllocations.Add(memory);
            }
            return memory;
        }

        static freememory _freememory;
        private delegate void freememory(IntPtr memory);
        private static void FreeMemory(IntPtr memory)
        {
            Marshal.FreeHGlobal(memory);
            if (TrackedMemoryAllocations != null && TrackedMemoryAllocations.Contains(memory))
            {
                TrackedMemoryAllocations.Remove(memory);
            }
        }

        private static void EnableMemoryTracking()
        {
            TrackedMemoryAllocations = new List<IntPtr>();
        }

        private static void FreeTrackedMemoryAndRemoveTracking()
        {
            if (TrackedMemoryAllocations == null)
                return;

            List<IntPtr> list = TrackedMemoryAllocations;
            TrackedMemoryAllocations = null;
            foreach (IntPtr memory in list)
            {
                Marshal.FreeHGlobal(memory);
            }
        }

        private IntPtr Bind(string server, string authdomain = null, string authuser = null, string authpassword = null, bool forceLMAuth = false)
        {
            IntPtr bindingstring = IntPtr.Zero;
            IntPtr binding = IntPtr.Zero;
            Int32 status;

            UInt32 rpcAuth = RPC_C_AUTHN_GSS_NEGOTIATE;
            if (forceLMAuth)
                rpcAuth = RPC_C_AUTHN_WINNT;

            status = RpcStringBindingCompose(null, "ncacn_ip_tcp", server, null, null, out bindingstring);
            if (status != 0)
            {
                throw new Win32Exception((int)status, "Unable to bind to the domain. RpcStringBindingCompose failed with error code: " + (int)status);
            }

            status = RpcBindingFromStringBinding(Marshal.PtrToStringUni(bindingstring), out binding);
            if (status != 0)
            {
                throw new Win32Exception((int)status, "Unable to bind to the domain. RpcBindingFromStringBinding failed with error code: " + (int)status);
            }
            RpcBindingFree(ref bindingstring);

            RPC_SECURITY_QOS qos = new RPC_SECURITY_QOS();
            qos.Version = 1;
            qos.Capabilities = RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH;
            GCHandle qoshandle = GCHandle.Alloc(qos, GCHandleType.Pinned);

            IntPtr psecAuth = IntPtr.Zero;
            if (authuser != null && authuser != "")
            {
                SEC_WINNT_AUTH_IDENTITY_W secAuth = new SEC_WINNT_AUTH_IDENTITY_W();
                secAuth.User = authuser;
                secAuth.Domain = authdomain;
                secAuth.Password = authpassword;
                secAuth.UserLength = authuser.Length;
                secAuth.DomainLength = authdomain.Length;
                secAuth.PasswordLength = authpassword.Length;
                secAuth.Flags = 2;

                psecAuth = Marshal.AllocHGlobal(Marshal.SizeOf(secAuth));
                Marshal.StructureToPtr(secAuth, psecAuth, false);
            }

            status = RpcBindingSetAuthInfoEx(binding, "ldap/" + server, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, rpcAuth, psecAuth, 0, ref qos);
            qoshandle.Free();
            if (status != 0)
            {
                Unbind(binding);
                throw new Win32Exception((int)status, "Unable to bind to the domain. RpcBindingSetAuthInfoEx failed with error code: " + (int)status);
            }

            securityCallbackDelegate = SecurityCallback;
            status = RpcBindingSetOption(binding, RPC_C_OPT_SECURITY_CALLBACK, Marshal.GetFunctionPointerForDelegate(securityCallbackDelegate));
            if (status != 0)
            {
                Unbind(binding);
                throw new Win32Exception((int)status, "Unable to bind to the domain. RpcBindingSetOption failed with error code: " + (int)status);
            }

            status = RpcBindingSetOption(binding, RPC_C_OPT_CALL_TIMEOUT, new IntPtr(RPCTimeOut));
            if (status != 0)
            {
                Unbind(binding);
                throw new Win32Exception((int)status, "Unable to bind to the domain. RpcBindingSetOption failed with error code: " + (int)status);
            }

            return binding;
        }

        private static void Unbind(IntPtr hBinding)
        {
            RpcBindingFree(ref hBinding);
        }

        private byte[] SessionKey;

        SecurityCallbackDelegate securityCallbackDelegate;
        private delegate void SecurityCallbackDelegate(IntPtr context);
        private void SecurityCallback(IntPtr context)
        {
            IntPtr SecurityContextHandle;
            SecPkgContext_SessionKey sessionKey = new SecPkgContext_SessionKey();

            int res = I_RpcBindingInqSecurityContext(context, out SecurityContextHandle);
            if (res == 0)
            {
                res = QueryContextAttributes(SecurityContextHandle, 9, ref sessionKey);
                if (res == 0)
                {
                    SessionKey = new byte[sessionKey.SessionKeyLength];
                    Marshal.Copy(sessionKey.SessionKey, SessionKey, 0, (int)sessionKey.SessionKeyLength);
                }
            }
        }

        private IntPtr GetProcStringHandle(int offset)
        {
            return Marshal.UnsafeAddrOfPinnedArrayElement(MIDL_ProcFormatString, offset);
        }

        private IntPtr GetStubHandle()
        {
            return stub.AddrOfPinnedObject();
        }

        private IntPtr CallNdrClientCall2x86(int offset, params IntPtr[] args)
        {

            GCHandle stackhandle = GCHandle.Alloc(args, GCHandleType.Pinned);
            IntPtr result;
            try
            {
                result = NdrClientCall2x86(GetStubHandle(), GetProcStringHandle(offset), stackhandle.AddrOfPinnedObject());
            }
            finally
            {
                stackhandle.Free();
            }
            return result;
        }
        #endregion

        #region MIDL strings

        private static byte[] MIDL_ProcFormatStringx64 = new byte[] {
                0x00,0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x30,0x00,0x32,0x00,0x00,0x00,0x44,0x00,0x40,0x00,0x47,0x05,0x0a,0x47,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,
                0x0a,0x00,0x08,0x00,0x02,0x00,0x0b,0x00,0x10,0x00,0x18,0x00,0x13,0x20,0x18,0x00,0x3a,0x00,0x10,0x01,0x20,0x00,0x42,0x00,0x70,0x00,0x28,0x00,0x08,0x00,
                0x00,0x48,0x00,0x00,0x00,0x00,0x01,0x00,0x10,0x00,0x30,0xe0,0x00,0x00,0x00,0x00,0x38,0x00,0x40,0x00,0x44,0x02,0x0a,0x41,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x18,0x01,0x00,0x00,0x4a,0x00,0x70,0x00,0x08,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x40,0x00,0x0a,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x03,0x00,0x30,0x00,0x30,0x40,0x00,0x00,0x00,0x00,
                0x2c,0x00,0x24,0x00,0x47,0x06,0x0a,0x47,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x4e,0x00,0x48,0x00,0x08,0x00,0x08,0x00,0x0b,0x01,
                0x10,0x00,0x56,0x00,0x50,0x21,0x18,0x00,0x08,0x00,0x13,0x01,0x20,0x00,0xb6,0x02,0x70,0x00,0x28,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x04,0x00,
                0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x05,0x00,
                0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x06,0x00,
                0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x07,0x00,
                0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x08,0x00,
                0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x09,0x00,
                0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0a,0x00,
                0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0b,0x00,
                0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0c,0x00,
                0x30,0x00,0x30,0x40,0x00,0x00,0x00,0x00,0x2c,0x00,0x24,0x00,0x47,0x06,0x0a,0x47,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x4e,0x00,
                0x48,0x00,0x08,0x00,0x08,0x00,0x0b,0x01,0x10,0x00,0xe0,0x05,0x50,0x21,0x18,0x00,0x08,0x00,0x13,0x21,0x20,0x00,0x42,0x06,0x70,0x00,0x28,0x00,0x08,0x00,
                0x00,0x48,0x00,0x00,0x00,0x00,0x0d,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x48,0x00,0x00,0x00,0x00,0x0e,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x48,0x00,0x00,0x00,0x00,0x0f,0x00,0x08,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x0a,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x48,0x00,0x00,0x00,0x00,0x10,0x00,0x30,0x00,0x30,0x40,0x00,0x00,0x00,0x00,0x2c,0x00,0x24,0x00,0x47,0x06,0x0a,0x47,0x01,0x00,0x01,0x00,0x00,0x00,
                0x00,0x00,0x08,0x00,0x00,0x00,0x4e,0x00,0x48,0x00,0x08,0x00,0x08,0x00,0x0b,0x01,0x10,0x00,0xc4,0x06,0x50,0x21,0x18,0x00,0x08,0x00,0x13,0x41,0x20,0x00,
                0xf8,0x06,0x70,0x00,0x28,0x00,0x08,0x00,0x00
            };

        private static byte[] MIDL_TypeFormatStringx64 = new byte[] {
                0x00,0x00,0x12,0x00,0x08,0x00,0x1d,0x00,0x08,0x00,0x01,0x5b,0x15,0x03,0x10,0x00,0x08,0x06,0x06,0x4c,0x00,0xf1,0xff,0x5b,0x12,0x00,0x18,0x00,0x1b,0x00,
                0x01,0x00,0x09,0x00,0xfc,0xff,0x11,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x10,0x27,0x00,0x00,0x01,0x5b,0x17,0x03,0x04,0x00,0xe6,0xff,0x08,0x5b,0x11,0x14,
                0xdc,0xff,0x11,0x04,0x02,0x00,0x30,0xa0,0x00,0x00,0x11,0x04,0x02,0x00,0x30,0xe1,0x00,0x00,0x30,0x41,0x00,0x00,0x11,0x00,0x02,0x00,0x2b,0x09,0x29,0x00,
                0x08,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0xa8,0x00,0x05,0x00,0x04,0x00,0x00,0x00,0x66,0x01,0x05,0x00,0x00,0x00,
                0x7c,0x01,0x07,0x00,0x00,0x00,0x9e,0x01,0x08,0x00,0x00,0x00,0xbc,0x01,0x0a,0x00,0x00,0x00,0xec,0x01,0xff,0xff,0x15,0x07,0x18,0x00,0x0b,0x0b,0x0b,0x5b,
                0x1b,0x00,0x01,0x00,0x19,0x00,0x00,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x10,0x27,0x00,0x00,0x01,0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,0x06,0x00,
                0x08,0x40,0x36,0x5b,0x12,0x20,0xdc,0xff,0x1a,0x03,0x18,0x00,0x00,0x00,0x00,0x00,0x08,0x40,0x4c,0x00,0xe4,0xff,0x5c,0x5b,0x21,0x03,0x00,0x00,0x19,0x00,
                0x00,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x4c,0x00,0xca,0xff,0x5c,0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,0x06,0x00,0x08,0x40,0x36,0x5b,0x12,0x20,0xc8,0xff,0x1d,0x00,0x1c,0x00,0x02,0x5b,0x15,0x00,
                0x1c,0x00,0x4c,0x00,0xf4,0xff,0x5c,0x5b,0x1b,0x01,0x02,0x00,0x09,0x57,0xfc,0xff,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0xa0,0x00,0x05,0x5b,
                0x17,0x03,0x38,0x00,0xe6,0xff,0x08,0x08,0x4c,0x00,0xd6,0xfe,0x4c,0x00,0xd2,0xff,0x08,0x5b,0x15,0x07,0x18,0x00,0x4c,0x00,0xc8,0xfe,0x0b,0x5b,0x1b,0x07,
                0x18,0x00,0x09,0x00,0xf8,0xff,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x4c,0x00,0xe0,0xff,0x5c,0x5b,0x17,0x07,0x10,0x00,0xe2,0xff,
                0x08,0x08,0x08,0x08,0x5c,0x5b,0x1b,0x03,0x04,0x00,0x09,0x00,0xfc,0xff,0x11,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x08,0x5b,0x17,0x03,
                0x0c,0x00,0xe6,0xff,0x08,0x08,0x08,0x5b,0x1a,0x07,0x70,0x00,0x00,0x00,0x1a,0x00,0x4c,0x00,0x74,0xfe,0x4c,0x00,0x70,0xfe,0x36,0x4c,0x00,0xed,0xfe,0x36,
                0x36,0x4c,0x00,0x4f,0xff,0x08,0x08,0x08,0x08,0x5b,0x11,0x00,0x7c,0xff,0x12,0x00,0xae,0xff,0x12,0x00,0xcc,0xff,0x1b,0x00,0x01,0x00,0x09,0x00,0xfc,0xff,
                0x11,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x02,0x5b,0x17,0x03,0x04,0x00,0xe6,0xff,0x08,0x5b,0x1a,0x07,0x88,0x00,0x00,0x00,0x0c,0x00,
                0x4c,0x00,0x2a,0xfe,0x36,0x4c,0x00,0xa7,0xff,0x5b,0x11,0x00,0xe4,0xff,0x15,0x07,0x08,0x00,0x0b,0x5b,0x1a,0x07,0x60,0x00,0x00,0x00,0x1a,0x00,0x4c,0x00,
                0x0e,0xfe,0x4c,0x00,0x0a,0xfe,0x36,0x4c,0x00,0x87,0xfe,0x36,0x08,0x08,0x08,0x08,0x4c,0x00,0xde,0xff,0x5c,0x5b,0x11,0x00,0x16,0xff,0x12,0x00,0x48,0xff,
                0x1a,0x07,0xa8,0x00,0x00,0x00,0x12,0x00,0x4c,0x00,0xe6,0xfd,0x36,0x4c,0x00,0x63,0xff,0x36,0x36,0x4c,0x00,0xc5,0xfe,0x5b,0x11,0x00,0x9a,0xff,0x12,0x00,
                0x4a,0xff,0x12,0x00,0x46,0xff,0x1a,0x07,0x80,0x00,0x00,0x00,0x20,0x00,0x4c,0x00,0xc2,0xfd,0x4c,0x00,0xbe,0xfd,0x36,0x4c,0x00,0x3b,0xfe,0x36,0x08,0x08,
                0x08,0x08,0x4c,0x00,0x92,0xff,0x36,0x36,0x4c,0x00,0x94,0xfe,0x5c,0x5b,0x11,0x00,0xc4,0xfe,0x12,0x00,0xf6,0xfe,0x12,0x00,0x14,0xff,0x12,0x00,0x10,0xff,
                0x1a,0x07,0x88,0x00,0x00,0x00,0x22,0x00,0x4c,0x00,0x8c,0xfd,0x4c,0x00,0x88,0xfd,0x36,0x4c,0x00,0x05,0xfe,0x36,0x08,0x08,0x08,0x08,0x4c,0x00,0x5c,0xff,
                0x36,0x36,0x4c,0x00,0x5e,0xfe,0x08,0x40,0x5c,0x5b,0x11,0x00,0x8c,0xfe,0x12,0x00,0xbe,0xfe,0x12,0x00,0xdc,0xfe,0x12,0x00,0xd8,0xfe,0x11,0x0c,0x08,0x5c,
                0x11,0x00,0x02,0x00,0x2b,0x09,0x29,0x54,0x18,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0xa8,0x00,0x05,0x00,0x01,0x00,
                0x00,0x00,0x40,0x01,0x02,0x00,0x00,0x00,0x92,0x01,0x06,0x00,0x00,0x00,0x1e,0x02,0x07,0x00,0x00,0x00,0x54,0x02,0x09,0x00,0x00,0x00,0xb6,0x02,0xff,0xff,
                0x1b,0x00,0x01,0x00,0x19,0x00,0x00,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x90,0x01,0x02,0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,0x06,0x00,
                0x08,0x40,0x36,0x5b,0x12,0x20,0xdc,0xff,0x21,0x03,0x00,0x00,0x19,0x00,0x00,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xa0,0x00,0xff,0xff,
                0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4c,0x00,0xca,0xff,0x5c,0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,0x06,0x00,0x08,0x40,
                0x36,0x5b,0x12,0x20,0xc8,0xff,0x1a,0x03,0x18,0x00,0x00,0x00,0x00,0x00,0x08,0x40,0x4c,0x00,0xe4,0xff,0x5c,0x5b,0x21,0x03,0x00,0x00,0x19,0x00,0x00,0x00,
                0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4c,0x00,
                0xca,0xff,0x5c,0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,0x06,0x00,0x08,0x40,0x36,0x5b,0x12,0x20,0xc8,0xff,0x1a,0x03,0x20,0x00,0x00,0x00,0x0a,0x00,0x36,0x08,
                0x40,0x4c,0x00,0xe3,0xff,0x5b,0x12,0x00,0x82,0xfd,0xb1,0x07,0x28,0x00,0x00,0x00,0x00,0x00,0x08,0x40,0x0b,0x4c,0x00,0x53,0xfc,0x0b,0x5c,0x5b,0x21,0x07,
                0x00,0x00,0x09,0x00,0xf8,0xff,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x4c,0x00,0xc8,0xff,0x5c,0x5b,0x1a,0x07,0x08,0x00,0xd2,0xff,0x00,0x00,0x08,0x40,0x5c,0x5b,0x1a,0x03,0x40,0x00,0x00,0x00,0x0c,0x00,
                0x36,0x4c,0x00,0x99,0xff,0x08,0x40,0x36,0x36,0x5b,0x12,0x00,0xec,0xff,0x12,0x00,0x00,0xfc,0x12,0x00,0xd8,0xff,0x1a,0x07,0x90,0x00,0x00,0x00,0x20,0x00,
                0x4c,0x00,0xf0,0xfb,0x4c,0x00,0xec,0xfb,0x36,0x4c,0x00,0x69,0xfc,0x4c,0x00,0x65,0xfc,0x36,0x4c,0x00,0xc8,0xfc,0x08,0x08,0x08,0x40,0x36,0x08,0x40,0x5b,
                0x12,0x00,0xf2,0xfc,0x12,0x00,0x24,0xfd,0x12,0x00,0xb2,0xff,0x1b,0x00,0x01,0x00,0x19,0x00,0x04,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x01,0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,0x06,0x00,0x08,0x08,0x36,0x5b,0x12,0x20,0xdc,0xff,0x1a,0x03,0x10,0x00,0x00,0x00,0x00,0x00,0x4c,0x00,
                0xe6,0xff,0x5c,0x5b,0x15,0x07,0x20,0x00,0x4c,0x00,0x8e,0xfb,0x0b,0x0b,0x5c,0x5b,0x1b,0x07,0x20,0x00,0x09,0x00,0xf8,0xff,0x11,0x00,0x01,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x10,0x00,0x4c,0x00,0xde,0xff,0x5c,0x5b,0x17,0x07,0x10,0x00,0xe2,0xff,0x08,0x08,0x08,0x08,0x5c,0x5b,0xb1,0x07,0x30,0x00,0x00,0x00,
                0x00,0x00,0x0b,0x4c,0x00,0xf7,0xfe,0x5b,0x1a,0x07,0x58,0x00,0x00,0x00,0x10,0x00,0x36,0x08,0x40,0x4c,0x00,0x3f,0xfe,0x08,0x40,0x4c,0x00,0xdf,0xff,0x5b,
                0x12,0x00,0x5c,0xfc,0x21,0x07,0x00,0x00,0x19,0x00,0x94,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0xff,0xff,0xff,0xff,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4c,0x00,0xc0,0xff,0x5c,0x5b,0x1a,0x07,0xa8,0x00,0x00,0x00,0x26,0x00,0x4c,0x00,0x06,0xfb,0x4c,0x00,
                0x02,0xfb,0x36,0x4c,0x00,0x7f,0xfb,0x4c,0x00,0x7b,0xfb,0x36,0x4c,0x00,0xde,0xfb,0x08,0x08,0x08,0x40,0x36,0x08,0x08,0x08,0x08,0x36,0x08,0x40,0x5c,0x5b,
                0x12,0x00,0x02,0xfc,0x12,0x00,0x70,0xff,0x12,0x00,0xc2,0xfe,0x12,0x20,0x9c,0xff,0x1a,0x03,0x18,0x00,0x00,0x00,0x00,0x00,0x08,0x0d,0x4c,0x00,0x16,0xff,
                0x5c,0x5b,0xb1,0x07,0x48,0x00,0x00,0x00,0x00,0x00,0x0b,0x4c,0x00,0x59,0xfe,0x08,0x08,0x08,0x40,0x0b,0x5c,0x5b,0x1a,0x07,0x70,0x00,0x00,0x00,0x10,0x00,
                0x36,0x08,0x40,0x4c,0x00,0x9b,0xfd,0x08,0x40,0x4c,0x00,0xd9,0xff,0x5b,0x12,0x00,0xb8,0xfb,0x21,0x07,0x00,0x00,0x19,0x00,0x94,0x00,0x11,0x00,0x01,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4c,0x00,0xc0,0xff,0x5c,0x5b,
                0x1a,0x07,0xa8,0x00,0x00,0x00,0x26,0x00,0x4c,0x00,0x62,0xfa,0x4c,0x00,0x5e,0xfa,0x36,0x4c,0x00,0xdb,0xfa,0x4c,0x00,0xd7,0xfa,0x36,0x4c,0x00,0x3a,0xfb,
                0x08,0x08,0x08,0x40,0x36,0x08,0x08,0x08,0x08,0x36,0x08,0x40,0x5c,0x5b,0x12,0x00,0x5e,0xfb,0x12,0x00,0xcc,0xfe,0x12,0x00,0x1e,0xfe,0x12,0x20,0x9c,0xff,
                0x11,0x00,0x02,0x00,0x2b,0x09,0x29,0x00,0x08,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x20,0x00,0x01,0x00,0x01,0x00,
                0x00,0x00,0x2e,0x00,0xff,0xff,0x21,0x03,0x00,0x00,0x19,0x00,0x14,0x00,0x11,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x10,0x27,0x00,0x00,0xff,0xff,0xff,0xff,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x12,0x08,0x25,0x5c,0x5c,0x5b,0x1a,0x03,0x20,0x00,0x00,0x00,0x0a,0x00,0x08,0x08,0x08,0x08,
                0x08,0x08,0x36,0x5b,0x12,0x20,0xc4,0xff,0x11,0x04,0x02,0x00,0x2b,0x09,0x29,0x54,0x18,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x02,0x00,0x08,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x54,0x00,0xff,0xff,0x1a,0x03,0x18,0x00,0x00,0x00,0x08,0x00,0x08,0x40,0x36,0x36,0x5c,0x5b,0x12,0x08,
                0x25,0x5c,0x12,0x08,0x25,0x5c,0x21,0x03,0x00,0x00,0x19,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4c,0x00,0xc4,0xff,0x5c,0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,0x06,0x00,0x08,0x40,0x36,0x5b,
                0x12,0x20,0xc8,0xff,0x1a,0x03,0x08,0x00,0x00,0x00,0x04,0x00,0x36,0x5b,0x12,0x00,0xe4,0xff,0x11,0x00,0x02,0x00,0x2b,0x09,0x29,0x00,0x08,0x00,0x01,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x10,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x04,0x00,0xff,0xff,0x1a,0x03,0x10,0x00,0x00,0x00,
                0x06,0x00,0x36,0x08,0x40,0x5b,0x12,0x08,0x25,0x5c,0x11,0x04,0x02,0x00,0x2b,0x09,0x29,0x54,0x18,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x02,0x00,0x10,0x00,0x04,0x00,0x01,0x00,0x00,0x00,0x64,0x00,0x02,0x00,0x00,0x00,0xd8,0x00,0x03,0x00,0x00,0x00,0x4c,0x01,0xff,0xff,0xff,0xff,
                0x94,0x01,0xff,0xff,0x1a,0x03,0x30,0x00,0x00,0x00,0x0a,0x00,0x36,0x36,0x36,0x36,0x36,0x08,0x08,0x5b,0x12,0x08,0x25,0x5c,0x12,0x08,0x25,0x5c,0x12,0x08,
                0x25,0x5c,0x12,0x08,0x25,0x5c,0x12,0x08,0x25,0x5c,0x21,0x03,0x00,0x00,0x19,0x00,0x00,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x10,0x27,0x00,0x00,
                0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4c,0x00,0xb6,0xff,0x5c,0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,0x06,0x00,
                0x08,0x40,0x36,0x5b,0x12,0x20,0xc8,0xff,0x1a,0x03,0x88,0x00,0x00,0x00,0x1e,0x00,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x08,0x08,0x08,0x4c,0x00,0x70,0xf8,
                0x4c,0x00,0x6c,0xf8,0x4c,0x00,0x68,0xf8,0x4c,0x00,0x64,0xf8,0x40,0x5b,0x12,0x08,0x25,0x5c,0x12,0x08,0x25,0x5c,0x12,0x08,0x25,0x5c,0x12,0x08,0x25,0x5c,
                0x12,0x08,0x25,0x5c,0x12,0x08,0x25,0x5c,0x12,0x08,0x25,0x5c,0x21,0x03,0x00,0x00,0x19,0x00,0x00,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x10,0x27,
                0x00,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4c,0x00,0x9a,0xff,0x5c,0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,
                0x06,0x00,0x08,0x40,0x36,0x5b,0x12,0x20,0xc8,0xff,0x1a,0x03,0x88,0x00,0x00,0x00,0x1e,0x00,0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x08,0x08,0x08,0x08,0x4c,
                0x00,0xf5,0xf7,0x4c,0x00,0xf1,0xf7,0x4c,0x00,0xed,0xf7,0x4c,0x00,0xe9,0xf7,0x5b,0x12,0x08,0x25,0x5c,0x12,0x08,0x25,0x5c,0x12,0x08,0x25,0x5c,0x12,0x08,
                0x25,0x5c,0x12,0x08,0x25,0x5c,0x12,0x08,0x25,0x5c,0x12,0x08,0x25,0x5c,0x21,0x03,0x00,0x00,0x19,0x00,0x00,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,
                0x10,0x27,0x00,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4c,0x00,0x9a,0xff,0x5c,0x5b,0x1a,0x03,0x10,0x00,
                0x00,0x00,0x06,0x00,0x08,0x40,0x36,0x5b,0x12,0x20,0xc8,0xff,0x1a,0x03,0x20,0x00,0x00,0x00,0x0a,0x00,0x08,0x08,0x08,0x08,0x08,0x08,0x36,0x5b,0x12,0x08,
                0x25,0x5c,0x21,0x03,0x00,0x00,0x19,0x00,0x00,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x10,0x27,0x00,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4c,0x00,0xc6,0xff,0x5c,0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,0x06,0x00,0x08,0x40,0x36,0x5b,0x12,0x20,0xc8,0xff,
                0x00
            };

        private static byte[] MIDL_ProcFormatStringx86 = new byte[] {
                0x00,0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x00,0x32,0x00,0x00,0x00,0x44,0x00,0x40,0x00,0x47,0x05,0x08,0x47,0x01,0x00,0x01,0x00,0x00,0x00,0x0a,0x00,
                0x04,0x00,0x02,0x00,0x0b,0x00,0x08,0x00,0x18,0x00,0x13,0x20,0x0c,0x00,0x3a,0x00,0x10,0x01,0x10,0x00,0x42,0x00,0x70,0x00,0x14,0x00,0x08,0x00,0x00,0x48,
                0x00,0x00,0x00,0x00,0x01,0x00,0x08,0x00,0x30,0xe0,0x00,0x00,0x00,0x00,0x38,0x00,0x40,0x00,0x44,0x02,0x08,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x01,
                0x00,0x00,0x4a,0x00,0x70,0x00,0x04,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x02,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,
                0x08,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x03,0x00,0x18,0x00,0x30,0x40,0x00,0x00,0x00,0x00,0x2c,0x00,0x24,0x00,0x47,0x06,
                0x08,0x47,0x01,0x00,0x01,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x4e,0x00,0x48,0x00,0x04,0x00,0x08,0x00,0x0b,0x01,0x08,0x00,0x56,0x00,0x50,0x21,0x0c,0x00,
                0x08,0x00,0x13,0x01,0x10,0x00,0xbe,0x02,0x70,0x00,0x14,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x04,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x40,0x00,0x08,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x05,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x40,0x00,0x08,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x06,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,
                0x08,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x07,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x41,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x08,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x41,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x09,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x41,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0a,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x41,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x48,0x00,0x00,0x00,0x00,0x0b,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,
                0x00,0x00,0x00,0x00,0x0c,0x00,0x18,0x00,0x30,0x40,0x00,0x00,0x00,0x00,0x2c,0x00,0x24,0x00,0x47,0x06,0x08,0x47,0x01,0x00,0x01,0x00,0x00,0x00,0x08,0x00,
                0x00,0x00,0x4e,0x00,0x48,0x00,0x04,0x00,0x08,0x00,0x0b,0x01,0x08,0x00,0xde,0x05,0x50,0x21,0x0c,0x00,0x08,0x00,0x13,0x21,0x10,0x00,0x46,0x06,0x70,0x00,
                0x14,0x00,0x08,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0d,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x41,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x00,0x0e,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x41,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x48,0x00,0x00,0x00,0x00,0x0f,0x00,0x04,0x00,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x08,0x41,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,
                0x00,0x00,0x00,0x00,0x10,0x00,0x18,0x00,0x30,0x40,0x00,0x00,0x00,0x00,0x2c,0x00,0x24,0x00,0x47,0x06,0x08,0x47,0x01,0x00,0x01,0x00,0x00,0x00,0x08,0x00,
                0x00,0x00,0x4e,0x00,0x48,0x00,0x04,0x00,0x08,0x00,0x0b,0x01,0x08,0x00,0xe6,0x06,0x50,0x21,0x0c,0x00,0x08,0x00,0x13,0x21,0x10,0x00,0x1e,0x07,0x70,0x00,
                0x14,0x00,0x08,0x00,0x00
            };

        private static byte[] MIDL_TypeFormatStringx86 = new byte[] {
                0x00,0x00,0x12,0x00,0x08,0x00,0x1d,0x00,0x08,0x00,0x01,0x5b,0x15,0x03,0x10,0x00,0x08,0x06,0x06,0x4c,0x00,0xf1,0xff,0x5b,0x12,0x00,0x18,0x00,0x1b,0x00,
                0x01,0x00,0x09,0x00,0xfc,0xff,0x11,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x10,0x27,0x00,0x00,0x01,0x5b,0x17,0x03,0x04,0x00,0xe6,0xff,0x08,0x5b,0x11,0x14,
                0xdc,0xff,0x11,0x04,0x02,0x00,0x30,0xa0,0x00,0x00,0x11,0x04,0x02,0x00,0x30,0xe1,0x00,0x00,0x30,0x41,0x00,0x00,0x11,0x00,0x02,0x00,0x2b,0x09,0x29,0x00,
                0x04,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x88,0x00,0x05,0x00,0x04,0x00,0x00,0x00,0x64,0x01,0x05,0x00,0x00,0x00,
                0x7c,0x01,0x07,0x00,0x00,0x00,0xa0,0x01,0x08,0x00,0x00,0x00,0xc0,0x01,0x0a,0x00,0x00,0x00,0xf2,0x01,0xff,0xff,0x15,0x07,0x18,0x00,0x0b,0x0b,0x0b,0x5b,
                0x1b,0x00,0x01,0x00,0x19,0x00,0x04,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x10,0x27,0x00,0x00,0x01,0x5b,0x16,0x03,0x0c,0x00,0x4b,0x5c,0x46,0x5c,
                0x08,0x00,0x08,0x00,0x12,0x20,0xdc,0xff,0x5b,0x08,0x08,0x08,0x5c,0x5b,0x1b,0x03,0x0c,0x00,0x19,0x00,0x00,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x10,0x00,0x4b,0x5c,0x48,0x49,0x0c,0x00,0x00,0x00,0x01,0x00,0x08,0x00,0x08,0x00,0x12,0x20,0xb0,0xff,0x5b,0x4c,0x00,0xc1,0xff,0x5b,0x16,0x03,
                0x08,0x00,0x4b,0x5c,0x46,0x5c,0x04,0x00,0x04,0x00,0x12,0x20,0xc6,0xff,0x5b,0x08,0x08,0x5b,0x1d,0x00,0x1c,0x00,0x02,0x5b,0x15,0x00,0x1c,0x00,0x4c,0x00,
                0xf4,0xff,0x5c,0x5b,0x1b,0x01,0x02,0x00,0x09,0x57,0xfc,0xff,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0xa0,0x00,0x05,0x5b,0x17,0x03,0x38,0x00,
                0xe6,0xff,0x08,0x08,0x4c,0x00,0xda,0xfe,0x4c,0x00,0xd2,0xff,0x08,0x5b,0x15,0x07,0x18,0x00,0x4c,0x00,0xcc,0xfe,0x0b,0x5b,0x1b,0x07,0x18,0x00,0x09,0x00,
                0xf8,0xff,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x4c,0x00,0xe0,0xff,0x5c,0x5b,0x17,0x07,0x10,0x00,0xe2,0xff,0x08,0x08,0x08,0x08,
                0x5c,0x5b,0x1b,0x03,0x04,0x00,0x09,0x00,0xfc,0xff,0x11,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x08,0x5b,0x17,0x03,0x0c,0x00,0xe6,0xff,
                0x08,0x08,0x08,0x5b,0xb1,0x07,0x60,0x00,0x00,0x00,0x1c,0x00,0x4c,0x00,0x78,0xfe,0x4c,0x00,0x74,0xfe,0x36,0x40,0x4c,0x00,0xf0,0xfe,0x36,0x36,0x4c,0x00,
                0x4a,0xff,0x08,0x08,0x08,0x08,0x5c,0x5b,0x11,0x00,0x7a,0xff,0x12,0x00,0xac,0xff,0x12,0x00,0xca,0xff,0x1b,0x00,0x01,0x00,0x09,0x00,0xfc,0xff,0x11,0x00,
                0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x02,0x5b,0x17,0x03,0x04,0x00,0xe6,0xff,0x08,0x5b,0xb1,0x07,0x78,0x00,0x00,0x00,0x0e,0x00,0x4c,0x00,
                0x2c,0xfe,0x36,0x40,0x4c,0x00,0xa4,0xff,0x5c,0x5b,0x11,0x00,0xe2,0xff,0x15,0x07,0x08,0x00,0x0b,0x5b,0xb1,0x07,0x60,0x00,0x00,0x00,0x1c,0x00,0x4c,0x00,
                0x0e,0xfe,0x4c,0x00,0x0a,0xfe,0x36,0x40,0x4c,0x00,0x86,0xfe,0x36,0x08,0x08,0x08,0x08,0x40,0x4c,0x00,0xdc,0xff,0x5c,0x5b,0x11,0x00,0x10,0xff,0x12,0x00,
                0x42,0xff,0xb1,0x07,0x88,0x00,0x00,0x00,0x14,0x00,0x4c,0x00,0xe4,0xfd,0x36,0x40,0x4c,0x00,0x5c,0xff,0x36,0x36,0x4c,0x00,0xba,0xfe,0x5c,0x5b,0x11,0x00,
                0x94,0xff,0x12,0x00,0x42,0xff,0x12,0x00,0x3e,0xff,0xb1,0x07,0x70,0x00,0x00,0x00,0x22,0x00,0x4c,0x00,0xbe,0xfd,0x4c,0x00,0xba,0xfd,0x36,0x40,0x4c,0x00,
                0x36,0xfe,0x36,0x08,0x08,0x08,0x08,0x40,0x4c,0x00,0x8c,0xff,0x36,0x36,0x4c,0x00,0x86,0xfe,0x5c,0x5b,0x11,0x00,0xba,0xfe,0x12,0x00,0xec,0xfe,0x12,0x00,
                0x0a,0xff,0x12,0x00,0x06,0xff,0x1a,0x07,0x78,0x00,0x00,0x00,0x24,0x00,0x4c,0x00,0x86,0xfd,0x4c,0x00,0x82,0xfd,0x36,0x40,0x4c,0x00,0xfe,0xfd,0x36,0x08,
                0x08,0x08,0x08,0x40,0x4c,0x00,0x54,0xff,0x36,0x36,0x4c,0x00,0x4e,0xfe,0x08,0x40,0x5c,0x5b,0x11,0x00,0x80,0xfe,0x12,0x00,0xb2,0xfe,0x12,0x00,0xd0,0xfe,
                0x12,0x00,0xcc,0xfe,0x11,0x0c,0x08,0x5c,0x11,0x00,0x02,0x00,0x2b,0x09,0x29,0x54,0x0c,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x02,0x00,0x90,0x00,0x05,0x00,0x01,0x00,0x00,0x00,0x3e,0x01,0x02,0x00,0x00,0x00,0x80,0x01,0x06,0x00,0x00,0x00,0x14,0x02,0x07,0x00,0x00,0x00,0x4a,0x02,
                0x09,0x00,0x00,0x00,0xac,0x02,0xff,0xff,0x1b,0x00,0x01,0x00,0x19,0x00,0x00,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x90,0x01,0x02,0x5b,
                0x16,0x03,0x08,0x00,0x4b,0x5c,0x46,0x5c,0x04,0x00,0x04,0x00,0x12,0x20,0xdc,0xff,0x5b,0x08,0x08,0x5b,0x1b,0x03,0x08,0x00,0x19,0x00,0x04,0x00,0x11,0x00,
                0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xa0,0x00,0x4b,0x5c,0x48,0x49,0x08,0x00,0x00,0x00,0x01,0x00,0x04,0x00,0x04,0x00,0x12,0x20,0xb2,0xff,0x5b,0x4c,
                0x00,0xc3,0xff,0x5b,0x16,0x03,0x0c,0x00,0x4b,0x5c,0x46,0x5c,0x08,0x00,0x08,0x00,0x12,0x20,0xc6,0xff,0x5b,0x08,0x08,0x08,0x5c,0x5b,0x1b,0x03,0x0c,0x00,
                0x19,0x00,0x0c,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0x4b,0x5c,0x48,0x49,0x0c,0x00,0x00,0x00,0x01,0x00,0x08,0x00,0x08,0x00,
                0x12,0x20,0x9a,0xff,0x5b,0x4c,0x00,0xc1,0xff,0x5b,0xb1,0x07,0x28,0x00,0x00,0x00,0x00,0x00,0x08,0x40,0x0b,0x4c,0x00,0x71,0xfc,0x0b,0x5c,0x5b,0x21,0x07,
                0x00,0x00,0x09,0x00,0xf8,0xff,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x4c,0x00,0xc8,0xff,0x5c,0x5b,0x1a,0x07,0x08,0x00,0xd2,0xff,0x00,0x00,0x08,0x40,0x5c,0x5b,0x16,0x03,0x20,0x00,0x4b,0x5c,0x46,0x5c,
                0x00,0x00,0x00,0x00,0x12,0x00,0xf2,0xff,0x46,0x5c,0x04,0x00,0x04,0x00,0x12,0x00,0x3a,0xfd,0x46,0x5c,0x10,0x00,0x10,0x00,0x12,0x20,0x6a,0xff,0x46,0x5c,
                0x18,0x00,0x18,0x00,0x12,0x00,0x0a,0xfc,0x46,0x5c,0x1c,0x00,0x1c,0x00,0x12,0x00,0xbe,0xff,0x5b,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x5b,0xb1,0x07,
                0x78,0x00,0x00,0x00,0x20,0x00,0x4c,0x00,0xea,0xfb,0x4c,0x00,0xe6,0xfb,0x36,0x40,0x4c,0x00,0x62,0xfc,0x4c,0x00,0x5e,0xfc,0x36,0x4c,0x00,0xb9,0xfc,0x08,
                0x08,0x08,0x36,0x08,0x5c,0x5b,0x12,0x00,0xe8,0xfc,0x12,0x00,0x1a,0xfd,0x12,0x00,0x8e,0xff,0x1b,0x00,0x01,0x00,0x19,0x00,0x04,0x00,0x01,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x5b,0x16,0x03,0x0c,0x00,0x4b,0x5c,0x46,0x5c,0x08,0x00,0x08,0x00,0x12,0x20,0xdc,0xff,0x5b,0x08,0x08,0x08,
                0x5c,0x5b,0x15,0x07,0x20,0x00,0x4c,0x00,0x90,0xfb,0x0b,0x0b,0x5c,0x5b,0x1b,0x07,0x20,0x00,0x09,0x00,0xf8,0xff,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x10,0x00,0x4c,0x00,0xde,0xff,0x5c,0x5b,0x17,0x07,0x10,0x00,0xe2,0xff,0x08,0x08,0x08,0x08,0x5c,0x5b,0xb1,0x07,0x30,0x00,0x00,0x00,0x00,0x00,
                0x0b,0x4c,0x00,0xdb,0xfe,0x5b,0xb1,0x07,0x48,0x00,0x00,0x00,0x10,0x00,0x36,0x08,0x4c,0x00,0x4a,0xfe,0x08,0x40,0x4c,0x00,0xe0,0xff,0x5c,0x5b,0x12,0x00,
                0x5a,0xfc,0x21,0x07,0x00,0x00,0x19,0x00,0x80,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4c,0x00,0xc0,0xff,0x5c,0x5b,0x1a,0x07,0x90,0x00,0x00,0x00,0x26,0x00,0x4c,0x00,0x08,0xfb,0x4c,0x00,0x04,0xfb,
                0x36,0x40,0x4c,0x00,0x80,0xfb,0x4c,0x00,0x7c,0xfb,0x36,0x4c,0x00,0xd7,0xfb,0x08,0x08,0x08,0x36,0x08,0x08,0x08,0x08,0x36,0x08,0x40,0x5c,0x5b,0x12,0x00,
                0x00,0xfc,0x12,0x00,0x70,0xff,0x12,0x00,0xa6,0xfe,0x12,0x20,0x9c,0xff,0x1a,0x03,0x14,0x00,0x00,0x00,0x00,0x00,0x08,0x0d,0x4c,0x00,0x1e,0xff,0x5c,0x5b,
                0xb1,0x07,0x48,0x00,0x00,0x00,0x00,0x00,0x0b,0x4c,0x00,0x3d,0xfe,0x08,0x08,0x08,0x40,0x0b,0x5c,0x5b,0xb1,0x07,0x60,0x00,0x00,0x00,0x10,0x00,0x36,0x08,
                0x4c,0x00,0xa6,0xfd,0x08,0x40,0x4c,0x00,0xda,0xff,0x5c,0x5b,0x12,0x00,0xb6,0xfb,0x21,0x07,0x00,0x00,0x19,0x00,0x80,0x00,0x11,0x00,0x01,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x10,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4c,0x00,0xc0,0xff,0x5c,0x5b,0x1a,0x07,
                0x90,0x00,0x00,0x00,0x26,0x00,0x4c,0x00,0x64,0xfa,0x4c,0x00,0x60,0xfa,0x36,0x40,0x4c,0x00,0xdc,0xfa,0x4c,0x00,0xd8,0xfa,0x36,0x4c,0x00,0x33,0xfb,0x08,
                0x08,0x08,0x36,0x08,0x08,0x08,0x08,0x36,0x08,0x40,0x5c,0x5b,0x12,0x00,0x5c,0xfb,0x12,0x00,0xcc,0xfe,0x12,0x00,0x02,0xfe,0x12,0x20,0x9c,0xff,0x11,0x00,
                0x02,0x00,0x2b,0x09,0x29,0x00,0x04,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x1c,0x00,0x01,0x00,0x01,0x00,0x00,0x00,
                0x2e,0x00,0xff,0xff,0x1b,0x03,0x04,0x00,0x19,0x00,0x14,0x00,0x11,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x10,0x27,0x00,0x00,0x4b,0x5c,0x48,0x49,0x04,0x00,
                0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x12,0x08,0x25,0x5c,0x5b,0x08,0x5c,0x5b,0x16,0x03,0x1c,0x00,0x4b,0x5c,0x46,0x5c,0x18,0x00,0x18,0x00,0x12,0x20,
                0xc8,0xff,0x5b,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x5c,0x5b,0x11,0x04,0x02,0x00,0x2b,0x09,0x29,0x54,0x0c,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x02,0x00,0x04,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x6c,0x00,0xff,0xff,0x16,0x03,0x0c,0x00,0x4b,0x5c,0x46,0x5c,0x04,0x00,0x04,0x00,
                0x12,0x08,0x25,0x5c,0x46,0x5c,0x08,0x00,0x08,0x00,0x12,0x08,0x25,0x5c,0x5b,0x08,0x08,0x08,0x5c,0x5b,0x1b,0x03,0x0c,0x00,0x19,0x00,0x00,0x00,0x01,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4b,0x5c,0x48,0x49,0x0c,0x00,0x00,0x00,0x02,0x00,0x04,0x00,0x04,0x00,0x12,0x08,0x25,0x5c,0x08,0x00,
                0x08,0x00,0x12,0x08,0x25,0x5c,0x5b,0x4c,0x00,0xaf,0xff,0x5b,0x16,0x03,0x08,0x00,0x4b,0x5c,0x46,0x5c,0x04,0x00,0x04,0x00,0x12,0x20,0xbe,0xff,0x5b,0x08,
                0x08,0x5b,0x16,0x03,0x04,0x00,0x4b,0x5c,0x46,0x5c,0x00,0x00,0x00,0x00,0x12,0x00,0xde,0xff,0x5b,0x08,0x5c,0x5b,0x11,0x00,0x02,0x00,0x2b,0x09,0x29,0x00,
                0x04,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x04,0x00,0xff,0xff,0x16,0x03,
                0x08,0x00,0x4b,0x5c,0x46,0x5c,0x00,0x00,0x00,0x00,0x12,0x08,0x25,0x5c,0x5b,0x08,0x08,0x5b,0x11,0x04,0x02,0x00,0x2b,0x09,0x29,0x54,0x0c,0x00,0x01,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x04,0x00,0x01,0x00,0x00,0x00,0xa4,0x00,0x02,0x00,0x00,0x00,0x76,0x01,0x03,0x00,
                0x00,0x00,0x4a,0x02,0xff,0xff,0xff,0xff,0x9e,0x02,0xff,0xff,0x16,0x03,0x1c,0x00,0x4b,0x5c,0x46,0x5c,0x00,0x00,0x00,0x00,0x12,0x08,0x25,0x5c,0x46,0x5c,
                0x04,0x00,0x04,0x00,0x12,0x08,0x25,0x5c,0x46,0x5c,0x08,0x00,0x08,0x00,0x12,0x08,0x25,0x5c,0x46,0x5c,0x0c,0x00,0x0c,0x00,0x12,0x08,0x25,0x5c,0x46,0x5c,
                0x10,0x00,0x10,0x00,0x12,0x08,0x25,0x5c,0x5b,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x5c,0x5b,0x1b,0x03,0x1c,0x00,0x19,0x00,0x00,0x00,0x11,0x00,0x01,0x00,
                0x00,0x00,0x00,0x00,0x10,0x27,0x00,0x00,0x4b,0x5c,0x48,0x49,0x1c,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x00,0x00,0x12,0x08,0x25,0x5c,0x04,0x00,0x04,0x00,
                0x12,0x08,0x25,0x5c,0x08,0x00,0x08,0x00,0x12,0x08,0x25,0x5c,0x0c,0x00,0x0c,0x00,0x12,0x08,0x25,0x5c,0x10,0x00,0x10,0x00,0x12,0x08,0x25,0x5c,0x5b,0x4c,
                0x00,0x75,0xff,0x5b,0x16,0x03,0x08,0x00,0x4b,0x5c,0x46,0x5c,0x04,0x00,0x04,0x00,0x12,0x20,0xa6,0xff,0x5b,0x08,0x08,0x5b,0x16,0x03,0x68,0x00,0x4b,0x5c,
                0x46,0x5c,0x00,0x00,0x00,0x00,0x12,0x08,0x25,0x5c,0x46,0x5c,0x04,0x00,0x04,0x00,0x12,0x08,0x25,0x5c,0x46,0x5c,0x08,0x00,0x08,0x00,0x12,0x08,0x25,0x5c,
                0x46,0x5c,0x0c,0x00,0x0c,0x00,0x12,0x08,0x25,0x5c,0x46,0x5c,0x10,0x00,0x10,0x00,0x12,0x08,0x25,0x5c,0x46,0x5c,0x14,0x00,0x14,0x00,0x12,0x08,0x25,0x5c,
                0x46,0x5c,0x18,0x00,0x18,0x00,0x12,0x08,0x25,0x5c,0x5b,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x4c,0x00,0xc1,0xf7,0x4c,0x00,0xbd,0xf7,0x4c,
                0x00,0xb9,0xf7,0x4c,0x00,0xb5,0xf7,0x5b,0x1b,0x03,0x68,0x00,0x19,0x00,0x00,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x10,0x27,0x00,0x00,0x4b,0x5c,
                0x48,0x49,0x68,0x00,0x00,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x12,0x08,0x25,0x5c,0x04,0x00,0x04,0x00,0x12,0x08,0x25,0x5c,0x08,0x00,0x08,0x00,0x12,0x08,
                0x25,0x5c,0x0c,0x00,0x0c,0x00,0x12,0x08,0x25,0x5c,0x10,0x00,0x10,0x00,0x12,0x08,0x25,0x5c,0x14,0x00,0x14,0x00,0x12,0x08,0x25,0x5c,0x18,0x00,0x18,0x00,
                0x12,0x08,0x25,0x5c,0x5b,0x4c,0x00,0x3f,0xff,0x5b,0x16,0x03,0x08,0x00,0x4b,0x5c,0x46,0x5c,0x04,0x00,0x04,0x00,0x12,0x20,0x96,0xff,0x5b,0x08,0x08,0x5b,
                0x16,0x03,0x6c,0x00,0x4b,0x5c,0x46,0x5c,0x00,0x00,0x00,0x00,0x12,0x08,0x25,0x5c,0x46,0x5c,0x04,0x00,0x04,0x00,0x12,0x08,0x25,0x5c,0x46,0x5c,0x08,0x00,
                0x08,0x00,0x12,0x08,0x25,0x5c,0x46,0x5c,0x0c,0x00,0x0c,0x00,0x12,0x08,0x25,0x5c,0x46,0x5c,0x10,0x00,0x10,0x00,0x12,0x08,0x25,0x5c,0x46,0x5c,0x14,0x00,
                0x14,0x00,0x12,0x08,0x25,0x5c,0x46,0x5c,0x18,0x00,0x18,0x00,0x12,0x08,0x25,0x5c,0x5b,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x4c,0x00,
                0xe8,0xf6,0x4c,0x00,0xe4,0xf6,0x4c,0x00,0xe0,0xf6,0x4c,0x00,0xdc,0xf6,0x5c,0x5b,0x1b,0x03,0x6c,0x00,0x19,0x00,0x00,0x00,0x11,0x00,0x01,0x00,0x00,0x00,
                0x00,0x00,0x10,0x27,0x00,0x00,0x4b,0x5c,0x48,0x49,0x6c,0x00,0x00,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x12,0x08,0x25,0x5c,0x04,0x00,0x04,0x00,0x12,0x08,
                0x25,0x5c,0x08,0x00,0x08,0x00,0x12,0x08,0x25,0x5c,0x0c,0x00,0x0c,0x00,0x12,0x08,0x25,0x5c,0x10,0x00,0x10,0x00,0x12,0x08,0x25,0x5c,0x14,0x00,0x14,0x00,
                0x12,0x08,0x25,0x5c,0x18,0x00,0x18,0x00,0x12,0x08,0x25,0x5c,0x5b,0x4c,0x00,0x3d,0xff,0x5b,0x16,0x03,0x08,0x00,0x4b,0x5c,0x46,0x5c,0x04,0x00,0x04,0x00,
                0x12,0x20,0x96,0xff,0x5b,0x08,0x08,0x5b,0x16,0x03,0x1c,0x00,0x4b,0x5c,0x46,0x5c,0x18,0x00,0x18,0x00,0x12,0x08,0x25,0x5c,0x5b,0x08,0x08,0x08,0x08,0x08,
                0x08,0x08,0x5c,0x5b,0x1b,0x03,0x1c,0x00,0x19,0x00,0x00,0x00,0x11,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x10,0x27,0x00,0x00,0x4b,0x5c,0x48,0x49,0x1c,0x00,
                0x00,0x00,0x01,0x00,0x18,0x00,0x18,0x00,0x12,0x08,0x25,0x5c,0x5b,0x4c,0x00,0xbd,0xff,0x5b,0x16,0x03,0x08,0x00,0x4b,0x5c,0x46,0x5c,0x04,0x00,0x04,0x00,
                0x12,0x20,0xc6,0xff,0x5b,0x08,0x08,0x5b,0x00
            };
        #endregion

        #region RPC structures
        [StructLayout(LayoutKind.Sequential)]
        private struct DRS_EXTENSIONS_INT
        {
            public UInt32 cb;
            public UInt32 dwFlags;
            public Guid SiteObjGuid;
            public UInt32 Pid;
            public UInt32 dwReplEpoch;
            public UInt32 dwFlagsExt;
            public Guid ConfigObjGUID;
            public UInt32 dwExtCaps;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DRS_MSG_DCINFOREQ_V1
        {
            public IntPtr Domain;
            public UInt32 InfoLevel;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DRS_MSG_DCINFOREPLY_V2
        {
            public UInt32 cItems;
            public IntPtr rItems;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct DS_DOMAIN_CONTROLLER_INFO_2W
        {
            public IntPtr NetbiosName;
            public IntPtr DnsHostName;
            public IntPtr SiteName;
            public IntPtr SiteObjectName;
            public IntPtr ComputerObjectName;
            public IntPtr ServerObjectName;
            public IntPtr NtdsDsaObjectName;
            public UInt32 fIsPdc;
            public UInt32 fDsEnabled;
            public UInt32 fIsGc;
            public Guid SiteObjectGuid;
            public Guid ComputerObjectGuid;
            public Guid ServerObjectGuid;
            public Guid NtdsDsaObjectGuid;
        }


        [StructLayout(LayoutKind.Sequential)]
        private struct USN_VECTOR
        {
            public ulong usnHighObjUpdate;
            public ulong usnReserved;
            public ulong usnHighPropUpdate;
        }

        // Replication flags
        UInt32 DRS_INIT_SYNC = 0x00000020;
        UInt32 DRS_WRIT_REP = 0x00000010;
        UInt32 DRS_NEVER_SYNCED = 0x00200000;
        UInt32 DRS_FULL_SYNC_NOW = 0x00008000;
        UInt32 DRS_SYNC_URGENT = 0x00080000;
        UInt32 DRS_GET_NC_SIZE = 0x00001000;

        [StructLayout(LayoutKind.Sequential)]
        public struct PARTIAL_ATTR_VECTOR_V1_EXT
        {
            public uint dwVersion;
            public uint dwReserved1;
            public uint cAttrs;
            // Number of elements in ATTRIBUTES_TO_EXPORT_OIDS.
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = MAX_ATTRIBUTES_TO_REPLICATE)]
            public uint[] rgPartialAttr;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PrefixTableEntry
        {
            public uint ndx;
            public OID_t prefix;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OID_t
        {
            public uint length;
            public IntPtr elements;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SCHEMA_PREFIX_TABLE
        {
            public UInt32 PrefixCount;
            public IntPtr pPrefixEntry;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct OssEncodedOID
        {
            public ushort length;
            public IntPtr value;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DSNAME
        {
            public UInt32 structLen;
            public UInt32 SidLen;
            public Guid Guid;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 28)]
            public byte[] Sid;
            public UInt32 NameLen;
            public IntPtr StringName;
        };

        [StructLayout(LayoutKind.Sequential)]
        private struct DRS_MSG_GETCHGREQ_V8
        {
            public Guid uuidDsaObjDest;
            public Guid uuidInvocIdSrc;
            public IntPtr pNC;
            public USN_VECTOR usnvecFrom;
            public IntPtr pUpToDateVecDest;
            public UInt32 ulFlags;
            public UInt32 cMaxObjects;
            public UInt32 cMaxBytes;
            public UInt32 ulExtendedOp;
            public ulong liFsmoInfo;
            public IntPtr pPartialAttrSet;
            public IntPtr pPartialAttrSetEx;
            public SCHEMA_PREFIX_TABLE PrefixTableDest;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DRS_MSG_GETCHGREPLY_V6
        {
            public Guid uuidDsaObjSrc;
            public Guid uuidInvocIdSrc;
            public IntPtr pNC;
            public USN_VECTOR usnvecFrom;
            public USN_VECTOR usnvecTo;
            public IntPtr pUpToDateVecSrc;
            public SCHEMA_PREFIX_TABLE PrefixTableSrc;
            public UInt32 ulExtendedRet;
            public UInt32 cNumObjects;
            public UInt32 cNumBytes;
            public IntPtr pObjects;
            public UInt32 fMoreData;
            public UInt32 cNumNcSizeObjects;
            public UInt32 cNumNcSizeValues;
            public UInt32 cNumValues;
            public IntPtr rgValues;
            public UInt32 dwDRSError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DRS_MSG_CRACKREQ_V1
        {
            public UInt32 CodePage;
            public UInt32 LocaleId;
            public UInt32 dwFlags;
            public UInt32 formatOffered;
            public UInt32 formatDesired;
            public UInt32 cNames;
            public IntPtr rpNames;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DS_NAME_RESULT_ITEMW
        {
            public UInt32 status;
            public IntPtr pDomain;
            public IntPtr pName;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DS_NAME_RESULTW
        {
            public UInt32 cItems;
            public IntPtr rItems;
        }


        [StructLayout(LayoutKind.Sequential)]
        private struct ATTRVAL
        {
            public UInt32 valLen;
            public IntPtr pVal;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ATTRVALBLOCK
        {
            public UInt32 valCount;
            public IntPtr pAVal;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ATTR
        {
            public UInt32 attrTyp;
            public ATTRVALBLOCK AttrVal;
        }


        [StructLayout(LayoutKind.Sequential)]
        private struct ATTRBLOCK
        {
            public UInt32 attrCount;
            public IntPtr pAttr;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct ENTINF
        {
            public IntPtr pName;
            public UInt32 ulFlags;
            public ATTRBLOCK AttrBlock;
        };
        [StructLayout(LayoutKind.Sequential)]
        private struct REPLENTINFLIST
        {
            public IntPtr pNextEntInf;
            public ENTINF Entinf;
            public UInt32 fIsNCPrefix;
            public IntPtr pParentGuid;
            public IntPtr pMetaDataExt;
        }
        #endregion

        #region drsr class and public interfaces

        public drsr()
        {
            Guid interfaceId = new Guid("e3514235-4b06-11d1-ab04-00c04fc2dcd2");
            if (IntPtr.Size == 8)
            {
                InitializeStub(interfaceId, MIDL_ProcFormatStringx64, MIDL_TypeFormatStringx64, 4, 0);
            }
            else
            {
                InitializeStub(interfaceId, MIDL_ProcFormatStringx86, MIDL_TypeFormatStringx86, 4, 0);
            }
        }

        ~drsr()
        {
            FreeTrackedMemoryAndRemoveTracking();
            freeStub();
            Uninitialize();
        }

        private DRS_EXTENSIONS_INT extensions;
        public IntPtr hBind;

        public void Initialize(string server, string authdomain = null, string authuser = null, string authpassword = null, bool forceLMAuth = false)
        {
            UInt32 result;
            extensions = new DRS_EXTENSIONS_INT();
            IntPtr hDrs = IntPtr.Zero;

            try
            {
                hBind = Bind(server, authdomain, authuser, authpassword, forceLMAuth);
                if (hBind == IntPtr.Zero)
                    throw new Exception("Unable to connect to the server " + server);

                DRS_EXTENSIONS_INT extensions_int = new DRS_EXTENSIONS_INT();
                extensions_int.cb = (UInt32)(Marshal.SizeOf(typeof(DRS_EXTENSIONS_INT)) - Marshal.SizeOf(typeof(UInt32)));
                extensions_int.dwFlags = 0x04000000 | 0x00008000;

                result = DrsBind(hBind, new Guid("e24d201a-4fd6-11d1-a3da-0000f875ae0d"), extensions_int, out extensions, out hDrs);
                if (result != 0)
                    throw new Win32Exception((int)result, "Unable to bind to Drs with generic Guid");
            }

            catch (Exception)
            {
                if (hBind != IntPtr.Zero)
                    Unbind(hBind);
                hBind = IntPtr.Zero;
                throw;
            }
        }

        public void Uninitialize()
        {
            FreeTrackedMemoryAndRemoveTracking();
            if (hBind != IntPtr.Zero)
                Unbind(hBind);
        }

        public Dictionary<Guid, Dictionary<string, object>> GetAllData(string ntDSAGuidString, string targetGuidString, Dictionary<string, string> attributesToReplicateOIDs)
        {
            UInt32 result;
            Dictionary<Guid, Dictionary<int, object>> allReplicationData;
            Dictionary<Guid, Dictionary<string, object>> allDecodedReplicationData;
            IntPtr hDrs = IntPtr.Zero;
            DRS_EXTENSIONS_INT extensions_out;
            Guid ntDSAGuid = new Guid(ntDSAGuidString);
            Guid targetGuid = new Guid(targetGuidString);
            Dictionary<string, uint> attributesToReplicateATTID = new Dictionary<string, uint>();

            if (hBind == IntPtr.Zero)
                throw new Exception("The class has not been initialized");

            try
            {
                result = DrsBind(hBind, ntDSAGuid, extensions, out extensions_out, out hDrs);
                if (result != 0)
                {
                    throw new Win32Exception((int)result, "Unable to bind to the DC with the NTDSA guid " + ntDSAGuid);
                }
            }
            catch (Exception e)
            {
                Uninitialize();
                throw new Exception("Unable to bind to Drs with DrsBind:" + e.Message + "\n\n DrsBind stack trace:" + e.StackTrace);
            }

            try { Asn1_init(); }
            catch (Exception e)
            {
                Uninitialize();
                throw new Exception("Unable to initialize ASN with Asn1_init: " + e.Message + "\n\nAsn1_init stack trace:" + e.StackTrace);
            }

            try
            {
                result = GetNCChanges(hDrs, ntDSAGuid, targetGuid, out allReplicationData, attributesToReplicateOIDs, ref attributesToReplicateATTID);
                if (result != 0)
                    throw new Win32Exception((int)result, "Unable to get the replication changes for " + targetGuidString);
            }
            catch (Exception e)
            {
                DrsUnbind(ref hDrs);
                Uninitialize();
                throw new Exception("Unable to get replication data with GetNCChanges: " + e.Message + "\n\nGetNCChanges stack trace:" + e.StackTrace);
            }

            try
            {
                DecodeReplicationFields(allReplicationData, out allDecodedReplicationData, attributesToReplicateATTID);
            }
            catch (Exception e)
            {
                DrsUnbind(ref hDrs);
                Asn1_term();
                Uninitialize();
                throw new Exception("Unable to decode replication data with DecodeReplicationFields: " + e.Message + "\n\nDecodeReplicationFields stack trace:" + e.StackTrace);
            }

            DrsUnbind(ref hDrs);
            Asn1_term();

            return allDecodedReplicationData;
        }
        #endregion

        #region drsr rpc functions and decoding functions

        private UInt32 DrsBind(IntPtr hBinding, Guid NtdsDsaObjectGuid, DRS_EXTENSIONS_INT extensions_in, out DRS_EXTENSIONS_INT extensions_out, out IntPtr hDrs)
        {
            IntPtr result = IntPtr.Zero;
            IntPtr pDrsExtensionsExt = new IntPtr();
            hDrs = new IntPtr();
            EnableMemoryTracking();

            try
            {
                if (IntPtr.Size == 8)
                {
                    // result = NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(0), __arglist(hBinding, NtdsDsaObjectGuid, extensions_in, out pDrsExtensionsExt, out hDrs));
                    result = NdrClientCall2x64_DrsBind(GetStubHandle(), GetProcStringHandle(0), hBinding, NtdsDsaObjectGuid, extensions_in, ref pDrsExtensionsExt, ref hDrs);
                }
                else
                {
                    GCHandle handle1 = GCHandle.Alloc(NtdsDsaObjectGuid, GCHandleType.Pinned);
                    IntPtr tempValuePointer1 = handle1.AddrOfPinnedObject();
                    GCHandle handle2 = GCHandle.Alloc(extensions_in, GCHandleType.Pinned);
                    IntPtr tempValuePointer2 = handle2.AddrOfPinnedObject();
                    IntPtr tempValue3 = IntPtr.Zero;
                    GCHandle handle3 = GCHandle.Alloc(tempValue3, GCHandleType.Pinned);
                    IntPtr tempValuePointer3 = handle3.AddrOfPinnedObject();
                    IntPtr tempValue4 = IntPtr.Zero;
                    GCHandle handle4 = GCHandle.Alloc(tempValue4, GCHandleType.Pinned);
                    IntPtr tempValuePointer4 = handle4.AddrOfPinnedObject();
                    try
                    {
                        result = CallNdrClientCall2x86(0, hBinding, tempValuePointer1, tempValuePointer2, tempValuePointer3, tempValuePointer4);
                        pDrsExtensionsExt = Marshal.ReadIntPtr(tempValuePointer3);
                        hDrs = Marshal.ReadIntPtr(tempValuePointer4);
                    }
                    finally
                    {
                        if (handle1 != null)
                            handle1.Free();

                        if (handle2 != null)
                            handle2.Free();

                        if (handle3 != null)
                            handle3.Free();

                        if (handle4 != null)
                            handle4.Free();
                    }
                }

                if ((UInt32)result != 0)
                {
                    throw new Win32Exception((int)result, "Error while calling DrsBind with NdrClientCall2x64-x86: " + (UInt32)result);
                }

                extensions_out = extensions_in;
                DRS_EXTENSIONS_INT extensions_out_temp = (DRS_EXTENSIONS_INT)Marshal.PtrToStructure(pDrsExtensionsExt, typeof(DRS_EXTENSIONS_INT));
                if (extensions_out_temp.cb > Marshal.OffsetOf(typeof(DRS_EXTENSIONS_INT), "SiteObjGuid").ToInt32())
                {
                    extensions_out.SiteObjGuid = extensions_out_temp.SiteObjGuid;
                    if (extensions_out_temp.cb > Marshal.OffsetOf(typeof(DRS_EXTENSIONS_INT), "dwReplEpoch").ToInt32())
                    {
                        extensions_out.dwReplEpoch = extensions_out_temp.dwReplEpoch;
                        if (extensions_out_temp.cb > Marshal.OffsetOf(typeof(DRS_EXTENSIONS_INT), "dwFlagsExt").ToInt32())
                        {
                            extensions_out.dwFlagsExt = extensions_out_temp.dwFlagsExt & 4;
                            if (extensions_out_temp.cb > Marshal.OffsetOf(typeof(DRS_EXTENSIONS_INT), "ConfigObjGUID").ToInt32())
                            {
                                extensions_out.ConfigObjGUID = extensions_out_temp.ConfigObjGUID;
                            }
                        }
                    }
                }
            }
            catch (SEHException)
            {
                FreeTrackedMemoryAndRemoveTracking();
                extensions_out = new DRS_EXTENSIONS_INT();
                UInt32 ex = (UInt32)Marshal.GetExceptionPointers();
                return ex;
            }
            finally
            {
                FreeTrackedMemoryAndRemoveTracking();
            }
            return (UInt32)result.ToInt64();
        }

        private UInt32 DrsUnbind(ref IntPtr hDrs)
        {
            IntPtr result = IntPtr.Zero;
            try
            {
                if (IntPtr.Size == 8)
                {
                    // result = NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(60), __arglist(ref hDrs));
                    result = NdrClientCall2x64_DrsUnbind(GetStubHandle(), GetProcStringHandle(60), ref hDrs);
                }
                else
                {
                    GCHandle handle1 = GCHandle.Alloc(hDrs, GCHandleType.Pinned);
                    IntPtr tempValuePointer1 = handle1.AddrOfPinnedObject();
                    try
                    {
                        result = CallNdrClientCall2x86(58, tempValuePointer1);
                        hDrs = Marshal.ReadIntPtr(tempValuePointer1);
                    }
                    finally
                    {
                        if (handle1 != null)
                            handle1.Free();
                    }
                }
            }
            catch (SEHException)
            {
                int ex = (int)Marshal.GetExceptionPointers();
                return (UInt32)ex;
            }
            finally
            {
            }
            return (UInt32)result.ToInt64();
        }

        private UInt32 DrsDomainControllerInfo(IntPtr hDrs, string domain, string serverName, out Guid NtdsDsaObjectGuid)
        {
            IntPtr result = IntPtr.Zero;
            DRS_MSG_DCINFOREQ_V1 dcInfoReq = new DRS_MSG_DCINFOREQ_V1();
            dcInfoReq.InfoLevel = 2;
            dcInfoReq.Domain = Marshal.StringToHGlobalUni(domain);
            UInt32 dcOutVersion = 0;
            UInt32 dcInVersion = 1;
            DRS_MSG_DCINFOREPLY_V2 dcInfoRep = new DRS_MSG_DCINFOREPLY_V2();
            EnableMemoryTracking();
            try
            {
                if (IntPtr.Size == 8)
                {
                    // result = NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(600), __arglist(hDrs, dcInVersion, dcInfoReq, out dcOutVersion, ref dcInfoRep));
                    result = NdrClientCall2x64_DrsDomainControllerInfo(GetStubHandle(), GetProcStringHandle(600), hDrs, dcInVersion, dcInfoReq, ref dcOutVersion, ref dcInfoRep);
                }
                else
                {
                    GCHandle handle1 = GCHandle.Alloc(dcInfoReq, GCHandleType.Pinned);
                    IntPtr tempValuePointer1 = handle1.AddrOfPinnedObject();
                    IntPtr tempValue2 = IntPtr.Zero;
                    GCHandle handle2 = GCHandle.Alloc(tempValue2, GCHandleType.Pinned);
                    IntPtr tempValuePointer2 = handle2.AddrOfPinnedObject();
                    GCHandle handle3 = GCHandle.Alloc(dcInfoRep, GCHandleType.Pinned);
                    IntPtr tempValuePointer3 = handle3.AddrOfPinnedObject();
                    try
                    {
                        result = CallNdrClientCall2x86(568, hDrs, new IntPtr(dcInVersion), tempValuePointer1, tempValuePointer2, tempValuePointer3);
                        dcOutVersion = (UInt32)Marshal.ReadInt32(tempValuePointer2);
                        dcInfoRep = (DRS_MSG_DCINFOREPLY_V2)Marshal.PtrToStructure(tempValuePointer3, typeof(DRS_MSG_DCINFOREPLY_V2));
                    }
                    finally
                    {
                        if (handle1 != null)
                            handle1.Free();
                        if (handle2 != null)
                            handle2.Free();
                        if (handle3 != null)
                            handle3.Free();
                    }
                }
                NtdsDsaObjectGuid = GetDsaGuid(dcInfoRep, serverName);
            }
            catch (SEHException)
            {
                NtdsDsaObjectGuid = Guid.Empty;
                int ex = (int)Marshal.GetExceptionPointers();
                return (UInt32)ex;
            }
            finally
            {
                Marshal.FreeHGlobal(dcInfoReq.Domain);
                FreeTrackedMemoryAndRemoveTracking();
            }
            return (UInt32)result.ToInt64();
        }

        private Guid GetDsaGuid(DRS_MSG_DCINFOREPLY_V2 dcInfoRep, string server)
        {
            Guid OutGuid = Guid.Empty;
            int size = Marshal.SizeOf(typeof(DS_DOMAIN_CONTROLLER_INFO_2W));
            for (uint i = 0; i < dcInfoRep.cItems; i++)
            {
                DS_DOMAIN_CONTROLLER_INFO_2W info = (DS_DOMAIN_CONTROLLER_INFO_2W)Marshal.PtrToStructure(new IntPtr(dcInfoRep.rItems.ToInt64() + i * size), typeof(DS_DOMAIN_CONTROLLER_INFO_2W));
                string infoDomain = Marshal.PtrToStringUni(info.DnsHostName);
                string infoNetbios = Marshal.PtrToStringUni(info.NetbiosName);
                if (server.StartsWith(infoDomain, StringComparison.InvariantCultureIgnoreCase) || server.StartsWith(infoNetbios, StringComparison.InvariantCultureIgnoreCase))
                {
                    OutGuid = info.NtdsDsaObjectGuid;
                }
            }
            return OutGuid;
        }

        private static void DrsrMakeAttid(ref SCHEMA_PREFIX_TABLE prefixTable, string szOid, ref uint att)
        {
            uint lastValue;
            uint ndx = 0;
            string lastValueString;
            OssEncodedOID oidPrefix;

            try
            {
                lastValueString = szOid.Substring(szOid.LastIndexOf(".") + 1);
                lastValue = UInt32.Parse(lastValueString);

                att = (ushort)(lastValue % 0x4000);
                if (att >= 0x4000)
                    att += 0x8000;

                if (DotVal2Eoid(szOid, out oidPrefix))
                {
                    oidPrefix.length -= (ushort)((lastValue < 0x80) ? 1 : 2);

                    if (DrsrMakeAttidAddPrefixToTable(ref prefixTable, ref oidPrefix, ref ndx))
                        att = (uint)(att | ndx << 16);

                    FreeEnc(oidPrefix.value);
                }
                else
                {
                    throw new Exception("DotVal2Eoid failed");
                }
            }
            catch (Exception e)
            {
                throw new Exception("DrsrMakeAttid failed with: " + e.Message);
            }
        }

        private static void FreeEnc(IntPtr pBuf)
        {
            if (!ASN1enc.Equals(default(ASN1encoding_s)) && pBuf != IntPtr.Zero)
                ASN1_FreeEncoded(ref ASN1enc, pBuf);
        }

        [System.Security.SuppressUnmanagedCodeSecurity]
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate bool ASN1BERDotVal2EoidDelegate(IntPtr pEncoderInfo, string dotOID, IntPtr encodedOID);

        public static bool ASN1BERDotVal2Eoid(IntPtr pEncoderInfo, string dotOID, IntPtr encodedOID)
        {
            IntPtr proc = GetProcAddress(GetMsasn1(), "ASN1BERDotVal2Eoid");
            ASN1BERDotVal2EoidDelegate ASN1BERDotVal2Eoid = (ASN1BERDotVal2EoidDelegate)Marshal.GetDelegateForFunctionPointer(proc, typeof(ASN1BERDotVal2EoidDelegate));
            return ASN1BERDotVal2Eoid(pEncoderInfo, dotOID, encodedOID);
        }

        [System.Security.SuppressUnmanagedCodeSecurity]
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate void ASN1_FreeEncodedDelegate(ref ASN1encoding_s pEncoderInfo, IntPtr pBuf);

        public static void ASN1_FreeEncoded(ref ASN1encoding_s pEncoderInfo, IntPtr pBuf)
        {
            IntPtr proc = GetProcAddress(GetMsasn1(), "ASN1_FreeEncoded");
            ASN1_FreeEncodedDelegate ASN1_FreeEncodedFunc = (ASN1_FreeEncodedDelegate)Marshal.GetDelegateForFunctionPointer(proc, typeof(ASN1_FreeEncodedDelegate));
            ASN1_FreeEncodedFunc(ref pEncoderInfo, pBuf);
        }

        private static bool DotVal2Eoid(string dotOID, out OssEncodedOID encodedOID)
        {
            bool status = false;
            encodedOID = new OssEncodedOID();

            if (!ASN1enc.Equals(default(ASN1encoding_s)) && !string.IsNullOrEmpty(dotOID))
            {
                encodedOID.length = 0;
                encodedOID.value = IntPtr.Zero;

                IntPtr mt = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(ASN1encoding_s)));
                Marshal.StructureToPtr(ASN1enc, mt, false);

                IntPtr ot = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(OssEncodedOID)));
                Marshal.StructureToPtr(encodedOID, ot, false);

                status = ASN1BERDotVal2Eoid(mt, dotOID, ot);

                encodedOID = (OssEncodedOID)Marshal.PtrToStructure(ot, typeof(OssEncodedOID));
            }
            return status;
        }

        private static bool DrsrMakeAttidAddPrefixToTable(ref SCHEMA_PREFIX_TABLE prefixTable, ref OssEncodedOID oidPrefix, ref uint ndx)
        {
            bool status = false;
            int size = Marshal.SizeOf(typeof(PrefixTableEntry));

            IntPtr entries;
            entries = Marshal.AllocHGlobal((int)(Marshal.SizeOf(typeof(PrefixTableEntry)) * (prefixTable.PrefixCount + 1)));
                        
            // Their are already some elements in the prefixTable.
            if (prefixTable.pPrefixEntry != IntPtr.Zero)
            {
                for (int i = 0; i < prefixTable.PrefixCount; i++)
                {
                    PrefixTableEntry entry = (PrefixTableEntry)Marshal.PtrToStructure(IntPtr.Add(prefixTable.pPrefixEntry, i * size), typeof(PrefixTableEntry));

                    // Only add element if not already present.
                    if (entry.prefix.length == oidPrefix.length)
                    {
                        if (EqualMemory(entry.prefix.elements, oidPrefix.value, oidPrefix.length))
                        {
                            ndx = entry.ndx;
                            status = true;
                            break;
                        }
                    }
                    Marshal.StructureToPtr(entry, IntPtr.Add(entries, i * size), false);
                }
            }

            if (!status)
            {
                ndx = prefixTable.PrefixCount;

                PrefixTableEntry newentry = new PrefixTableEntry();
                newentry.ndx = ndx;
                newentry.prefix.length = oidPrefix.length;

                newentry.prefix.elements = Marshal.AllocHGlobal(oidPrefix.length);

                if (CopyMemory(oidPrefix.value, newentry.prefix.elements, oidPrefix.length))
                {
                    Marshal.StructureToPtr(newentry, IntPtr.Add(entries, (int)ndx * size), false);
                    prefixTable.pPrefixEntry = entries;
                    prefixTable.PrefixCount = prefixTable.PrefixCount + 1;
                    status = true;
                }
            }
            return status;
        }

        // Source: https://github.com/vletoux/ADSecrets/blob/master/ConvertAtttributeToAttID.cs
        private uint ConvertOidToAttId(string attributeOid)
        {
            uint attId = 0;

            int pos = attributeOid.LastIndexOf('.');
            string prefix = attributeOid.Substring(0, pos);
            string lastDigit = attributeOid.Substring(pos + 1);

            switch (prefix)
            {
                case "2.5.4":
                    attId = 0;
                    break;
                case "2.5.6":
                    attId = 1;
                    break;
                case "1.2.840.113556.1.2":
                    attId = 2;
                    break;
                case "1.2.840.113556.1.3":
                    attId = 3;
                    break;
                case "2.16.840.1.101.2.2.1":
                    attId = 4;
                    break;
                case "2.16.840.1.101.2.2.3":
                    attId = 5;
                    break;
                case "2.16.840.1.101.2.1.5":
                    attId = 6;
                    break;
                case "2.16.840.1.101.2.1.4":
                    attId = 7;
                    break;
                case "2.5.5":
                    attId = 8;
                    break;
                case "1.2.840.113556.1.4":
                    attId = 9;
                    break;
                case "1.2.840.113556.1.5":
                    attId = 10;
                    break;
                case "1.2.840.113556.1.4.260":
                    attId = 11;
                    break;
                case "1.2.840.113556.1.5.56":
                    attId = 12;
                    break;
                case "1.2.840.113556.1.4.262":
                    attId = 13;
                    break;
                case "1.2.840.113556.1.5.57":
                    attId = 14;
                    break;
                case "1.2.840.113556.1.4.263":
                    attId = 15;
                    break;
                case "1.2.840.113556.1.5.58":
                    attId = 16;
                    break;
                case "1.2.840.113556.1.5.73":
                    attId = 17;
                    break;
                case "1.2.840.113556.1.4.305":
                    attId = 18;
                    break;
                case "0.9.2342.19200300.100":
                    attId = 19;
                    break;
                case "2.16.840.1.113730.3":
                    attId = 20;
                    break;
                case "0.9.2342.19200300.100.1":
                    attId = 21;
                    break;
                case "2.16.840.1.113730.3.1":
                    attId = 22;
                    break;
                case "1.2.840.113556.1.5.7000":
                    attId = 23;
                    break;
                case "2.5.21":
                    attId = 24;
                    break;
                case "2.5.18":
                    attId = 25;
                    break;
                case "2.5.20":
                    attId = 26;
                    break;
                case "1.3.6.1.4.1.1466.101.119":
                    attId = 27;
                    break;
                case "2.16.840.1.113730.3.2":
                    attId = 28;
                    break;
                case "1.3.6.1.4.1.250.1":
                    attId = 29;
                    break;
                case "1.2.840.113549.1.9":
                    attId = 30;
                    break;
                case "0.9.2342.19200300.100.4":
                    attId = 31;
                    break;
                case "1.2.840.113556.1.6.23":
                    attId = 32;
                    break;
                case "1.2.840.113556.1.6.18.1":
                    attId = 33;
                    break;
                case "1.2.840.113556.1.6.18.2":
                    attId = 34;
                    break;
                case "1.2.840.113556.1.6.13.3":
                    attId = 35;
                    break;
                case "1.2.840.113556.1.6.13.4":
                    attId = 36;
                    break;
                case "1.3.6.1.1.1.1":
                    attId = 37;
                    break;
                case "1.3.6.1.1.1.2":
                    attId = 38;
                    break;

                default:
                    return 0xFFFFFFFF;
            }

            attId = (attId * 0x10000) + Convert.ToUInt32(lastDigit);
            return attId;
        }

        private UInt32 GetNCChanges(IntPtr hDrs, Guid ntDSAGuid, Guid targetGuid, out Dictionary<Guid, Dictionary<int, object>> allReplicationData, Dictionary<string, string> attributesToReplicateOIDs, ref Dictionary<string, uint> attributesATTID)
        {
            IntPtr result = IntPtr.Zero;
            allReplicationData = new Dictionary<Guid, Dictionary<int, object>>();
            UInt32 dwInVersion = 8;
            UInt32 dwOutVersion = 0;
            DRS_MSG_GETCHGREQ_V8 pmsgIn = new DRS_MSG_GETCHGREQ_V8();
            DRS_MSG_GETCHGREPLY_V6 pmsgOut = new DRS_MSG_GETCHGREPLY_V6();

            EnableMemoryTracking();

            try
            {
                DSNAME dsName = new DSNAME();
                dsName.Guid = targetGuid;
                IntPtr unmanageddsName = AllocateMemory(Marshal.SizeOf(typeof(DSNAME)));
                Marshal.StructureToPtr(dsName, unmanageddsName, true);
                pmsgIn.pNC = unmanageddsName;

                pmsgIn.ulFlags = DRS_INIT_SYNC | DRS_WRIT_REP | DRS_NEVER_SYNCED | DRS_FULL_SYNC_NOW | DRS_SYNC_URGENT | DRS_GET_NC_SIZE;
                pmsgIn.cMaxObjects = 100;         // Default is 100 anyway, risk to crash the DC if rep data > DC available RAM.
                pmsgIn.cMaxBytes = 0x00a00000;    // 10M
                pmsgIn.ulExtendedOp = 0;          // 0 == multiple objects, 6 single object.
                pmsgIn.uuidDsaObjDest = ntDSAGuid;
                pmsgIn.usnvecFrom.usnHighObjUpdate = 0;

                
                pmsgIn.PrefixTableDest = new SCHEMA_PREFIX_TABLE();
                PARTIAL_ATTR_VECTOR_V1_EXT partAttSet = new PARTIAL_ATTR_VECTOR_V1_EXT();
                partAttSet.cAttrs = (uint) attributesToReplicateOIDs.Count;
                partAttSet.rgPartialAttr = new uint[MAX_ATTRIBUTES_TO_REPLICATE];
                partAttSet.dwVersion = 1;
                partAttSet.dwReserved1 = 0;
                
                int i = 0;
                foreach (KeyValuePair<string, string> attribute in attributesToReplicateOIDs)
                {
                    DrsrMakeAttid(ref pmsgIn.PrefixTableDest, attribute.Value, ref partAttSet.rgPartialAttr[i]);
                    attributesATTID.Add(attribute.Key, ConvertOidToAttId(attribute.Value));
                    i = i + 1;
                }
                
                pmsgIn.pPartialAttrSet = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(PARTIAL_ATTR_VECTOR_V1_EXT)));
                Marshal.StructureToPtr(partAttSet, pmsgIn.pPartialAttrSet, false);
                
                // Cycle: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/eb6876c5-6997-4541-8165-3844e46b464d
                do
                {
                    pmsgOut = new DRS_MSG_GETCHGREPLY_V6();

                    if (IntPtr.Size == 8)
                    {
                        //result = NdrClientCall2x64(GetStubHandle(), GetProcStringHandle(134), __arglist(hDrs, dwInVersion, pmsgIn, out dwOutVersion, ref pmsgOut));
                        var stubhere = GetStubHandle();
                        var procstringhandle = GetProcStringHandle(134);
                        result = NdrClientCall2x64_GetNCChanges(stubhere, procstringhandle, hDrs, dwInVersion, pmsgIn, out dwOutVersion, out pmsgOut);
                    }

                    else
                    {
                        GCHandle handle1 = GCHandle.Alloc(pmsgIn, GCHandleType.Pinned);
                        IntPtr tempValuePointer1 = handle1.AddrOfPinnedObject();
                        GCHandle handle2 = GCHandle.Alloc(dwOutVersion, GCHandleType.Pinned);
                        IntPtr tempValuePointer2 = handle2.AddrOfPinnedObject();
                        GCHandle handle3 = GCHandle.Alloc(pmsgOut, GCHandleType.Pinned);
                        IntPtr tempValuePointer3 = handle3.AddrOfPinnedObject();
                        try
                        {
                            result = CallNdrClientCall2x86(128, hDrs, new IntPtr(dwInVersion), tempValuePointer1, tempValuePointer2, tempValuePointer3);
                            dwOutVersion = (UInt32)Marshal.ReadInt32(tempValuePointer2);
                            pmsgOut = (DRS_MSG_GETCHGREPLY_V6)Marshal.PtrToStructure(tempValuePointer3, typeof(DRS_MSG_GETCHGREPLY_V6));
                        }
                        finally
                        {
                            if (handle1 != null)
                                handle1.Free();
                            if (handle2 != null)
                                handle2.Free();
                            if (handle3 != null)
                                handle3.Free();
                        }
                    }

                    if ((UInt32)result != 0)
                    {
                        throw new Win32Exception((int)result, "Error while calling GetNCChanges: " + (UInt32)result);
                    }

                    MarshalReplicationData(pmsgOut, ref allReplicationData);

                    pmsgIn.uuidInvocIdSrc = pmsgOut.uuidInvocIdSrc;
                    pmsgIn.usnvecFrom = pmsgOut.usnvecTo;
                } while (pmsgOut.fMoreData == 1);
            }

            catch (Exception e)
            {
                FreeTrackedMemoryAndRemoveTracking();
                int ex = (int)Marshal.GetExceptionPointers();
                throw new Win32Exception((int)ex, "Error in GetNCChanges:" + e.Message + "\n\nStack trace: " + e.StackTrace);
            }
            finally
            {
                FreeTrackedMemoryAndRemoveTracking();
            }

            return (UInt32)result.ToInt64();
        }

        private void MarshalReplicationData(DRS_MSG_GETCHGREPLY_V6 pmsgOut, ref Dictionary<Guid, Dictionary<int, object>> allReplicationData)
        {

            IntPtr pObjects = pmsgOut.pObjects;
            uint numObjects = pmsgOut.cNumObjects;

            REPLENTINFLIST Replentinflist = (REPLENTINFLIST)Marshal.PtrToStructure(pObjects, typeof(REPLENTINFLIST));

            uint numObjectsDone = 0;
            while (numObjectsDone < numObjects)
            {
                try
                {
                    Dictionary<int, object> replicationData = new Dictionary<int, object>();
                    ENTINF eltEntinf = (ENTINF)Replentinflist.Entinf;
                    DSNAME eltDsName = (DSNAME)Marshal.PtrToStructure(eltEntinf.pName, typeof(DSNAME));

                    if (Replentinflist.pNextEntInf != IntPtr.Zero)
                        Replentinflist = (REPLENTINFLIST)Marshal.PtrToStructure(Replentinflist.pNextEntInf, typeof(REPLENTINFLIST));

                    int size = Marshal.SizeOf(typeof(ATTR));
                    for (uint i = 0; i < eltEntinf.AttrBlock.attrCount; i++)
                    {
                        ATTR attr = (ATTR)Marshal.PtrToStructure(new IntPtr(eltEntinf.AttrBlock.pAttr.ToInt64() + i * size), typeof(ATTR));

                        int sizeval = Marshal.SizeOf(typeof(ATTRVAL));
                        List<byte[]> values = new List<byte[]>();

                        for (uint j = 0; j < attr.AttrVal.valCount; j++)
                        {
                            ATTRVAL attrval = (ATTRVAL)Marshal.PtrToStructure(new IntPtr(attr.AttrVal.pAVal.ToInt64() + j * sizeval), typeof(ATTRVAL));

                            byte[] data = new byte[attrval.valLen];
                            Marshal.Copy(attrval.pVal, data, 0, (int)attrval.valLen);

                            if ((int)attrval.valLen <= 0 || data == null || data.Length <= 0)
                            {
                                continue;
                            }

                            values.Add(data);

                        }

                        if (values.Count == 1)
                        {
                            replicationData[(int)attr.attrTyp] = values[0];
                        }
                        else if (values.Count > 1)
                        {
                            replicationData[(int)attr.attrTyp] = values;
                        }
                    }

                    allReplicationData[eltDsName.Guid] = replicationData;

                    numObjectsDone = numObjectsDone + 1;
                }

                catch
                {
                    Console.WriteLine("Failed to parse replication data for object in MarshalReplicationData");
                    continue;
                }
            }
        }

        UInt32[] dwCrc32Table = new UInt32[]
        {
                0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
                0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
                0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
                0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
                0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE,
                0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
                0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,
                0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
                0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
                0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
                0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940,
                0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
                0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,
                0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
                0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
                0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,

                0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A,
                0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
                0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818,
                0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
                0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
                0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
                0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C,
                0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
                0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,
                0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
                0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
                0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
                0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086,
                0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
                0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4,
                0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,

                0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
                0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
                0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
                0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
                0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE,
                0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
                0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
                0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
                0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252,
                0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
                0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60,
                0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
                0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
                0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
                0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04,
                0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,

                0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,
                0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
                0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
                0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
                0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E,
                0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
                0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C,
                0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
                0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
                0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
                0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0,
                0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
                0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6,
                0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
                0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
                0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D,
        };

        UInt32 CalcCrc32(byte[] data)
        {
            UInt32 dwCRC = 0xFFFFFFFF;
            for (int i = 0; i < data.Length; i++)
            {
                dwCRC = (dwCRC >> 8) ^ dwCrc32Table[(data[i]) ^ (dwCRC & 0x000000FF)];
            }
            dwCRC = ~dwCRC;
            return dwCRC;
        }


        private void DecodeReplicationFields(Dictionary<Guid, Dictionary<int, object>> allReplicationData, out Dictionary<Guid, Dictionary<string, object>> allDecodedReplicationData, Dictionary<string, uint> attributesToReplicateATTID)
        {
            allDecodedReplicationData = new Dictionary<Guid, Dictionary<string, object>>();

            foreach (KeyValuePair<Guid, Dictionary<int, object>> ObjectAllReplicationData in allReplicationData)
            {
                Dictionary<string, object> decodedReplicationData = new Dictionary<string, object>();

                foreach (KeyValuePair<string, uint> attributeATTID in attributesToReplicateATTID)
                {
                    Dictionary<int, object> encodedReplicationData = ObjectAllReplicationData.Value;

                    if (encodedReplicationData.ContainsKey((int)attributeATTID.Value))
                    {
                        byte[] encodedData = encodedReplicationData[(int)attributeATTID.Value] as byte[];
                        if (encodedData != null)
                        {
                            DecodeData(encodedData, attributeATTID.Key, attributeATTID.Value, decodedReplicationData);
                        }
                        else
                        {
                            List<byte[]> encodedDataList = encodedReplicationData[(int)attributeATTID.Value] as List<byte[]>;
                            foreach (byte[] encodedDataItem in encodedDataList)
                            {
                                DecodeData(encodedDataItem, attributeATTID.Key, attributeATTID.Value, decodedReplicationData);
                            }
                        }
                    }
                }

                allDecodedReplicationData[ObjectAllReplicationData.Key] = decodedReplicationData;
            }
        }

        private void DecodeData(byte[] encodedData, string attributeName, uint attributeATTID, Dictionary<string, object> decodedReplicationData)
        {
            string key = attributeName;
            if (decodedReplicationData.ContainsKey(key))
            {
                uint i = 1;
                while (decodedReplicationData.ContainsKey(key + i.ToString()))
                {
                    i = i + 1;
                }
                key = key + i.ToString();
            }

            switch (attributeName)
            {
                case "whenCreated":
                case "whenChanged":
                    //    var test = BitConverter.ToInt64(encodedData, 0);    
                    //string stringdate = UnicodeEncoding.Default.GetString(encodedData);
                    //    DateTime d = DateTime.ParseExact(stringdate, "yyyyMMddHHmmss.f'Z'", CultureInfo.InvariantCulture);
                    //    decodedReplicationData.Add(key, d);
                    decodedReplicationData.Add(key, encodedData.ToString());
                    break;

                case "lastLogon":
                case "pwdLastSet":
                case "accountExpires":
                case "AccountLockoutTime":
                    Int64 intdate = BitConverter.ToInt64(encodedData, 0);
                    DateTime datetime;
                    if (intdate == Int64.MaxValue)
                    {
                        datetime = DateTime.MaxValue;
                    }
                    else
                    {
                        datetime = DateTime.FromFileTime(intdate);
                    }
                    decodedReplicationData.Add(key, datetime);
                    break;

                case "Name":
                case "DistinguishedName":
                case "sAMAccountName":
                case "UserPrincipalName":
                case "ServicePrincipalName":
                case "DisplayName":
                case "msDS-AllowedToDelegateTo":
                    decodedReplicationData.Add(key, UnicodeEncoding.Unicode.GetString(encodedData));
                    break;

                case "LogonWorkstations":
                    break;

                case "adminCount":
                case "primaryGroupID":
                case "userAccountControl":
                case "OperatingSystemVersion":
                    decodedReplicationData.Add(key, BitConverter.ToInt32(encodedData, 0));
                    break;

                case "sAMAccountType":
                    decodedReplicationData.Add(key, BitConverter.ToInt32(encodedData, 0));
                    break;

                case "objectSid":
                case "SIDHistory":
                    decodedReplicationData.Add(key, new SecurityIdentifier(encodedData, 0));
                    break;

                case "logonHours":
                default:
                    decodedReplicationData.Add(key, encodedData.ToString());
                    break;
            }
        }
        #endregion
    }
}
"@

function Get-ADHuntingReplicationDataWithDRS {
<#
.SYNOPSIS

Retrieves through the Directory Replication Service (DRS) Remote Protocol the specified attributes replication data for all objects.

Requires the drsr C# class from the drsrdotnet namespace (stored as a string in $sourceDrsr) and replication privileges at the domain level.

C# code originally and adapted from:
  - MakeMeEnterpriseAdmin by @vletoux (https://github.com/vletoux/MakeMeEnterpriseAdmin)
  - Mimikatz by @gentilkiwi and @vletoux (https://github.com/gentilkiwi/mimikatz)
  - SharpKatz by @b4rtik (https://github.com/b4rtik/SharpKatz)

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER AttributesToReplicate

Specifies the attributes to replicate as an array of attributes' ldap display name.

.OUTPUTS

[Dictionary<Guid, Dictionary<string, object>>]

#>

    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$False)][System.Array]$AttributesToReplicate = $null
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)

    $authdomain = ""
    $authuser = ""
    $authpassword = ""

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)

        If (!$authuser) {
            $NetworkCredentialObj = $Credential.GetNetworkCredential()
        
            $authdomain = $NetworkCredentialObj.Domain
            $authuser = $NetworkCredentialObj.UserName
            $authpassword = $NetworkCredentialObj.Password
        }
    }

    $ADDomain = Get-ADDomain
    $ADSchemaNamingContext = $(Get-ADRootDSE).SchemaNamingContext

    # Use the Server specifed in argument only if its not an IPv4.
    If ($Server -and !($Server -As [System.Net.IPAddress] -As [bool])) {
        $ntDSAGuidString = (Get-ADObject -LDAPFilter "(DnsHostname=$Server)").ObjectGUID
    }
    Else {
        $ntDSAGuidString = (Get-ADObject -LDAPFilter "(DnsHostname=$($ADDomain.PDCEmulator))").ObjectGUID
    }

    # Construct Attributes OID mapping from the Schema.
    $AttributesToReplicateOIDs = New-Object System.Collections.Generic.Dictionary"[String,String]"

    If (!$AttributesToReplicate) {
        $AttributesToReplicate = @(
            "DisplayName"
            "DistinguishedName"
            "Enabled"
            "Name"
            "ObjectCategory"
             #"ObjectClass"
            "ObjectGUID"
            "OperatingSystem"
            "OperatingSystemVersion"
            "SIDHistory"
            "ScriptPath"
            "ServicePrincipalName"
            "UserPrincipalName"
            "accountExpires"
            "adminCount"
            "altSecurityIdentities"
            "badPasswordTime"
            "badPwdCount"
            "createTimeStamp"
            "dNSHostName"
            "isDeleted"
            "mS-DS-CreatorSID"
            "mail"
            "mailNickName"
            "memberOf"
            "modifyTimeStamp"
            "msDS-AllowedToActOnBehalfOfOtherIdentity"
            "msDS-AllowedToDelegateTo"
            "nTSecurityDescriptor"
            "objectSid"
            "primaryGroupID"
            "pwdLastSet"
            "sAMAccountName"
            "userAccountControl"
            "userCertificate"
            "whenChanged"
            "whenCreated"
        )
    }

    foreach ($Attribute in $AttributesToReplicate) {
        $AttributeOID = $(Get-ADObject -SearchBase "$ADSchemaNamingContext" -LDAPFilter "(&(objectclass=attributeSchema)(lDAPDisplayName=$Attribute))" -Properties attributeID).attributeID
        If ($AttributeOID) { $AttributesToReplicateOIDs[$Attribute] = $AttributeOID }
    }

    If ($AttributesToReplicateOIDs -eq 0) {
        Write-Host -ForegroundColor DarkYellow "[Get-ADHuntingReplicationDataWithDRS][-] No attributes OIDs could be retrieved for replication"
        return
    }

    $sourceDrsr = $sourceDrsr.replace("<TEMPLATE_MAX_ATTRIBUTES_TO_REPLICATE>", $AttributesToReplicateOIDs.Count)

    If (-not ("drsrdotnet.drsr" -as [type])) {
        Add-Type -TypeDefinition $sourceDrsr
    }

    $drsr = New-Object drsrdotnet.drsr

    If ($authdomain -and $authuser -and $authpassword) {
        $drsr.Initialize($Server, $authdomain, $authuser, $authpassword)
    }
    ElseIf ($Credential) {
        Write-Host "PowerShell credentials are specified but cleartext username or password couldn't be retrieved for RPC authentication"
        Write-Host "Specifiy cleartext credentials with the -AuthDomain, -AuthUserName, and -AuthPassword options"
        return
    }
    Else {
        $drsr.Initialize($Server)
    }

    try {
        $ObjectsReplicationMetadata = $drsr.GetAllData($ntDSAGuidString, $ADDomain.ObjectGUID, $AttributesToReplicateOIDs)
    }
    catch {
        Write-Host -ForegroundColor DarkYellow "[$MyInvocation.MyCommand]][-] Error occured while trying to retrieve objects replication metadata"
        Write-Host -ForegroundColor DarkYellow "[$MyInvocation.MyCommand][-] Exception: $_"
    }

    $drsr.Uninitialize()

    return $ObjectsReplicationMetadata
}

function Export-ADHuntingHiddenObjectsWithDRSRepData {
<#
.SYNOPSIS

Export to a CSV / JSON file the objects' attributes that are accessible through replication (with the Directory Replication Service (DRS) protocol) but not by direct query.
Access control are not taken into account for replication operations, which allows to identify access control blocking access to specific objects attribute(s).

Only a limited set of sensitive attributes are assessed.

.DESCRIPTION

Retrieve replication data on a partial set of sensitive attributes for all objects.

Implemented using code from MakeMeEnterpriseAdmin (by @vletoux), mimikatz (by @gentilkiwi & @vletoux), and SharpKatz (by @b4rtik).

Compare the attribute replication data with the data accessible through direct queries to identify non-accessible attributes.

Access control are not taken into account for replication operations, which allows to identify access control blocking access to specific objects attribute(s).

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER OutputFolder

Specifies the CSV / JSON output file location (where the data will be exported to).

.PARAMETER OutputType

Specifies the format for the exported data (CSV or JSON). Defaults to CSV.

.OUTPUTS

CSV / JSON file written to disk.

#>

    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$False)][String]$OutputFolder = $null,
        [Parameter(Mandatory=$False)]
            [ValidateSet("JSON","CSV")]
            [string]$OutputType = "CSV"
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
    }

    $DomainName = (Get-ADDomain).DNSRoot
    
    $OutputFolder = If (!$OutputFolder) { "." } Else { $OutputFolder }
    $OutputPath = "$OutputFolder\${DomainName}_Hidden_object_enumerated_through_DRS_$(Get-Date -f yyyy-MM-dd-HHmmss).$($OutputType.ToLower())"
    
    $CurrentFunctionName = $MyInvocation.MyCommand

    Write-Host "[$($MyInvocation.MyCommand)][*] Enumerating hidden users using replication data retrieved through DRS..."

    $RootDSR = Get-ADRootDSE
    $namingContexts = $RootDSR.namingContexts
    $ADSchemaNamingContext = $RootDSR.SchemaNamingContext

    $AttributesToReplicate = @(
        "DisplayName"
        "DistinguishedName"
        "Enabled"
        "Name"
        "ObjectCategory"
        # Map to ATTID 0, with all the classes associated with the object being returned.
        # "ObjectClass"
        "ObjectGUID"
        "OperatingSystem"
        "OperatingSystemVersion"
        "SIDHistory"
        "ScriptPath"
        "ServicePrincipalName"
        "UserPrincipalName"
        "accountExpires"
        "adminCount"
        "altSecurityIdentities"
        "badPasswordTime"
        "badPwdCount"
        "createTimeStamp"
        "dNSHostName"
        "isDeleted"
        "mS-DS-CreatorSID"
        "mail"
        "mailNickName"
        "memberOf"
        "modifyTimeStamp"
        "msDS-AllowedToActOnBehalfOfOtherIdentity"
        "msDS-AllowedToDelegateTo"
        "nTSecurityDescriptor"
        "objectSid"
        "primaryGroupID"
        "pwdLastSet"
        "sAMAccountName"
        "userAccountControl"
        "userCertificate"
        "whenChanged"
        "whenCreated"
    )
    
    $AttributesToReplicateInSchema = New-Object System.Collections.ArrayList
    foreach ($Attribute in $AttributesToReplicate) {
        If ($(Get-ADObject -SearchBase "$ADSchemaNamingContext" -LDAPFilter "(&(objectclass=attributeSchema)(lDAPDisplayName=$Attribute))" -Properties attributeID)) {
            $null = $AttributesToReplicateInSchema.Add($Attribute)
        }
    }

    Write-Host "[$CurrentFunctionName][*] Starting enumeration of replication data through DRS..."
    $ObjectsRepDataDict = Get-ADHuntingReplicationDataWithDRS -AttributesToReplicate $AttributesToReplicateInSchema
    If ($ObjectsRepDataDict.Count -ne 0 ) {
        Write-Host "[$CurrentFunctionName][*] Enumeration of replication data done, $($ObjectsRepDataDict.Count) objects found"
    }
    Else {
        Write-Host -ForegroundColor DarkYellow "[$CurrentFunctionName][-] No replication data retrieved, the cmdlet must be executed with replication privileges"
        return
    }

    Write-Host "[$CurrentFunctionName][*] Starting enumeration of accessible objects and attributes through LDAP access..."
    $ObjectsAccessibleDataDict = New-Object 'System.Collections.Generic.Dictionary[[string],[object]]'
    $i = 0
    while ($i -lt $namingContexts.Count) {
        Get-ADObject -IncludeDeletedObjects -SearchBase $namingContexts[$i] -Filter * -Properties $AttributesToReplicateInSchema | Foreach-Object {
            $null = $ObjectsAccessibleDataDict.TryAdd($_.ObjectGuid, $_)
        }
        $i = $i + 1
    }
    Write-Host "[$CurrentFunctionName][*] Enumeration of accessible objects and their attributes done"
    
    $Output = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))

    $ObjectFullyHiddenCount = [ref] 0
    $ObjectWithHiddenAttributeCount = [ref] 0
    
    Write-Host "[$CurrentFunctionName][*] Starting validation of replicated attributes versus actual attributes..."

    $ObjectsRepDataDict.GetEnumerator() | ForEach-Object -Parallel {
        $Output = $using:Output
        $PSDefaultParameterValues = $using:PSDefaultParameterValues
        $DomainName = $using:DomainName
        $namingContexts = $using:namingContexts
        $ObjectsAccessibleDataDict = $using:ObjectsAccessibleDataDict
        $ObjectFullyHiddenCount = $using:ObjectFullyHiddenCount
        $ObjectWithHiddenAttributeCount = $using:ObjectWithHiddenAttributeCount
        $CurrentFunctionName = $using:CurrentFunctionName

        $ObjectGuid = $_.Key.ToString()
        $ObjectAttributesMetaData = $_.Value

        try {
            $ADObject = If ($ObjectsAccessibleDataDict.ContainsKey($ObjectGuid)) { $ObjectsAccessibleDataDict[$ObjectGuid] } Else { $null }

            If (!$ADObject) { $null = [Threading.Interlocked]::Increment($ObjectFullyHiddenCount) }
            
            $HiddenAttributeFound = $False

            foreach ($Attribute in $ObjectAttributesMetaData.GetEnumerator()) {
                $AttributeType = $Attribute.Key
                $AttributeValue = $Attribute.Value
                
                # Object for which replication metadata was available but the object was not (!ADObject)
                # Or the current object's attribute was retrievable through DRS but not by direct queries.
                If (!$ADObject -or ($null -eq $ADObject[$AttributeType].Value -and $null -eq $ADObject[$AttributeType -replace '\d+$',''].Value)) {

                    # For some reason, the nTSecurityDescriptor on the "Deleted Objects" container are not accessible through LDAP / but are through DRS.
                    If ($ObjectAttributesMetaData["Name"] -eq "Deleted Objects" -and $AttributeType -eq "nTSecurityDescriptor") { continue }

                    $HiddenAttributeFound = $True

                    $null = $Output.Add([PSCustomObject]@{
                        Domain = $DomainName
                        Name = $ObjectAttributesMetaData["Name"]
                        ObjectGUID = $ObjectGuid
                        IsFullyHidden = if (!$ADObject) { $True } Else { $False }
                        HiddenAttributeType = $AttributeType
                        HiddenAttributeValue = If ($AttributeValue.GetType() -eq [System.Security.Principal.SecurityIdentifier]) { $AttributeValue.Value } Else { $AttributeValue }
                    })
                }
            }

            If ($ADObject -and $HiddenAttributeFound) { $null = [Threading.Interlocked]::Increment($ObjectWithHiddenAttributeCount) }
        }

        catch {
            Write-Host -ForegroundColor DarkYellow "[$CurrentFunctionName][-] Error while processing object $ObjectGuid"
            Write-Host -ForegroundColor DarkYellow "[$CurrentFunctionName][-] Exception: $_"
            continue
        }
    }

    If ($Output.Count -gt 0) {
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($ObjectFullyHiddenCount.Value) fully hidden objects (i.e object found through DRS but not by LDAP queries)"
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($ObjectWithHiddenAttributeCount.Value) accessible objects with one or more hidden attributes (i.e attribute found through DRS but not by LDAP queries)"
        Write-Host "[$($MyInvocation.MyCommand)][*] Total of hidden attributes: $($Output.Count)"
        If ($OutputType -eq "CSV") {
            $Output | Export-Csv -NoTypeInformation -Encoding UTF8 -Append -Path $OutputPath
        }
        ElseIf ($OutputType -eq "JSON") {
            $Output | ConvertTo-Json -depth 100 | Out-File $OutputPath
        }
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] Hidden objects and attributes detected through DRS written to '$OutputPath'"
    }
    Else {
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] No hidden objects or attributes found!"
    }
}

########################################################
#
#
# Privileged objects enumeration functions.
#
#
########################################################

function Get-ADHuntingBuiltinPrivilegedGroupSIDs {
<#
.SYNOPSIS

Return the SIDs of the privileged groups in the domain.

Required Dependencies: ActiveDirectory module.

.DESCRIPTION

Return the SID of the following groups:
  - Domain Admins (SID: S-1-5-<DOMAIN>-512)
  - Schema Admin (SID: S-1-5-<DOMAIN>-518)
  - Cert Publishers (SID: S-1-5-<DOMAIN>-517)
  - Group Policy Creator Owners (SID: S-1-5-<DOMAIN>-520)
  - Administrators (SID: S-1-5-32-544)
  - Account Operators (SID: S-1-5-32-548)
  - Backup Operators (SID: S-1-5-32-551)
  - Print Operators (SID: S-1-5-32-550)
  - Server Operators (SID: S-1-5-32-549)
  - Cryptographic Operators (SID: S-1-5-32-569)
  - Remote Desktop Users (SID: S-1-5-32-555)
  - Distributed COM Users (SID: S-1-5-32-562)
  - Network Configuration Operators (SID: S-1-5-32-556)
  - Incoming Forest Trust Builder (SID: S-1-5-32-557)
  - DnsAdmins (SID: non-default)
  - Enterprise Admins (SID: S-1-5-<FOREST>-519)

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.OUTPUTS

[System.Collections.ArrayList]

.EXAMPLE

Get-ADHuntingBuiltinPrivilegedGroupSIDs
S-1-5-21-898253280-1155539434-3291038768-512
S-1-5-21-898253280-1155539434-3291038768-518
S-1-5-21-898253280-1155539434-3291038768-517
S-1-5-21-898253280-1155539434-3291038768-520
S-1-5-32-544
S-1-5-32-548
S-1-5-32-551
S-1-5-32-550
S-1-5-32-549
S-1-5-32-569
S-1-5-32-555
S-1-5-32-562
S-1-5-32-556
S-1-5-32-557
S-1-5-21-898253280-1155539434-3291038768-1102
S-1-5-21-898253280-1155539434-3291038768-519

#>

    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
    }

    $Domain = Get-ADDomain
    $DomainSID = $Domain.DomainSID

    # Retrieve the forest root domain SID base. 
    try {
        If ($null -eq $Domain.ParentDomain) {
            $ForestSID = $DomainSID  
        }
        Else {
            $RootDomainName = $(Get-ADForest).RootDomain
            $ForestSID = $(Get-ADObject -LDAPFilter "(&(ObjectClass=trustedDomain)(Name=$RootDomainName)" -Properties securityIdentifier).securityIdentifier
        }
    }
    catch {
        Write-Host -ForegroundColor DarkYellow "[$($MyInvocation.MyCommand)][-] Couldn't determine the forest's root domain SID"
        Write-Host -ForegroundColor DarkYellow "[$($MyInvocation.MyCommand)][-] Exception: $_"
    }

    
    [System.Collections.ArrayList] $PrivilegedGroupSIDs = @(
        # Domain Admins (SID: S-1-5-<DOMAIN>-512)
        (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AccountDomainAdminsSid, $DomainSID)).Value,
        # Schema Admin (SID: S-1-5-<DOMAIN>-518)
        (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AccountSchemaAdminsSid, $DomainSID)).Value,
        # Cert Publishers (SID: S-1-5-<DOMAIN>-517)
        (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AccountCertAdminsSid, $DomainSID)).Value,
        # Group Policy Creator Owners (SID: S-1-5-<DOMAIN>-520)
        (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AccountPolicyAdminsSid, $DomainSID)).Value,
        # Administrators (SID: S-1-5-32-544)
        (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $DomainSID)).Value,
        # Account Operators (SID: S-1-5-32-548)
        (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::BuiltinAccountOperatorsSid, $DomainSID)).Value,
        # Backup Operators (SID: S-1-5-32-551)
        (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::BuiltinBackupOperatorsSid, $DomainSID)).Value,
        # Print Operators (SID: S-1-5-32-550)
        (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::BuiltinPrintOperatorsSid, $DomainSID)).Value,
        # Server Operators (SID: S-1-5-32-549)
        (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::BuiltinSystemOperatorsSid, $DomainSID)).Value,
        # Cryptographic Operators (SID: S-1-5-32-569)
        'S-1-5-32-569',
        # Remote Desktop Users (SID: S-1-5-32-555)
        (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::BuiltinRemoteDesktopUsersSid, $DomainSID)).Value,
        # Distributed COM Users (SID: S-1-5-32-562)
        'S-1-5-32-562',
        # Network Configuration Operators (SID: S-1-5-32-556)
        (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::BuiltinNetworkConfigurationOperatorsSid, $DomainSID)).Value,
        # Incoming Forest Trust Builder (SID: S-1-5-32-557)
        (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::BuiltinIncomingForestTrustBuildersSid, $DomainSID)).Value,
        # DnsAdmins (SID: non-default)
        (Get-ADGroup -Identity "DnsAdmins").SID.Value
    )

    # Enterprise Admins (SID: S-1-5-<FOREST>-519)
    If ($ForestSID) {
        [void] $PrivilegedGroupSIDs.Add((New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AccountEnterpriseAdminsSid, $ForestSID)).Value)
    }

    return $PrivilegedGroupSIDs
}

function Get-ADHuntingAllPrivilegedSIDs {
<#
.SYNOPSIS

Return the SIDs of all the privileged principals in the domain. 

Required Dependencies: ActiveDirectory module and Get-ADHuntingBuiltinPrivilegedGroupSIDs.

.DESCRIPTION

Return the SID of the principals members of the following groups (all members recursively including eventual intermediate nested groups):
  - krbtgt (SID S-1-5-<DOMAIN>-502)
  - Built-in Administrator (SID S-1-5-32-544)
  - Domain Admins (SID: S-1-5-<DOMAIN>-512)
  - Schema Admin (SID: S-1-5-<DOMAIN>-518)
  - Cert Publishers (SID: S-1-5-<DOMAIN>-517)
  - Group Policy Creator Owners (SID: S-1-5-<DOMAIN>-520)
  - Administrators (SID: S-1-5-32-544)
  - Account Operators (SID: S-1-5-32-548)
  - Backup Operators (SID: S-1-5-32-551)
  - Print Operators (SID: S-1-5-32-550)
  - Server Operators (SID: S-1-5-32-549)
  - Cryptographic Operators (SID: S-1-5-32-569)
  - Remote Desktop Users (SID: S-1-5-32-555)
  - Distributed COM Users (SID: S-1-5-32-562)
  - Network Configuration Operators (SID: S-1-5-32-556)
  - Incoming Forest Trust Builder (SID: S-1-5-32-557)
  - DnsAdmins (SID: non-default)
  - Enterprise Admins (SID: S-1-5-<FOREST>-519)
  - Domain Controllers group (RID 516).
  - CREATOR OWNER (SID S-1-3-0).
  - "NT AUTHORITY\SELF" (SID S-1-5-10).
  - "NT AUTHORITY\SYSTEM" (SID S-1-5-18).
  - Enterprise Read-only Domain Controllers.
  - ENTERPRISE DOMAIN CONTROLLERS (SID S-1-5-9).

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.OUTPUTS

[System.Collections.ArrayList]

.EXAMPLE

Get-ADHuntingBuiltinPrivilegedGroupSIDs
S-1-5-21-898253280-1155539434-3291038768-512
S-1-5-21-898253280-1155539434-3291038768-518
S-1-5-21-898253280-1155539434-3291038768-517
S-1-5-21-898253280-1155539434-3291038768-520
S-1-5-32-544
S-1-5-32-548
S-1-5-32-551
S-1-5-32-550
S-1-5-32-549
S-1-5-32-569
S-1-5-32-555
S-1-5-32-562
S-1-5-32-556
S-1-5-32-557
S-1-5-21-898253280-1155539434-3291038768-1102
S-1-5-21-898253280-1155539434-3291038768-519
S-1-5-21-898253280-1155539434-3291038768-516
S-1-3-0
S-1-5-10
S-1-5-21-898253280-1155539434-3291038768-502
S-1-5-18
S-1-5-32-544
S-1-5-9

#>

    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
    }

    $Domain = Get-ADDomain
    $DomainSID = $Domain.DomainSID

    # Retrieve the forest root domain SID base. 
    try {
        If ($null -eq $Domain.ParentDomain) {
            $ForestSID = $DomainSID  
        }
        Else {
            $RootDomainName = $(Get-ADForest).RootDomain
            $ForestSID = $(Get-ADObject -LDAPFilter "(&(ObjectClass=trustedDomain)(Name=$RootDomainName)" -Properties securityIdentifier).securityIdentifier
        }
    }
    catch {
        Write-Host -ForegroundColor DarkYellow "[$($MyInvocation.MyCommand)][-] Couldn't determine the forest's root domain SID"
        Write-Host -ForegroundColor DarkYellow "[$($MyInvocation.MyCommand)][-] Exception: $_"
    }

    [System.Collections.ArrayList] $PrivilegedSIDsInit = Get-ADHuntingBuiltinPrivilegedGroupSIDs
    # Domain Controllers group (RID 516).
    [void] $PrivilegedSIDsInit.Add((New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AccountControllersSid, $DomainSID)).Value)
    # CREATOR OWNER (SID S-1-3-0).
    [void] $PrivilegedSIDsInit.Add((New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::CreatorOwnerSid, $DomainSID)).Value)
    # "NT AUTHORITY\SELF" (SID S-1-5-10).
    [void] $PrivilegedSIDsInit.Add((New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::SelfSid, $DomainSID)).Value)
    # krbtgt (SID S-1-5-<DOMAIN>-502)
    [void] $PrivilegedSIDsInit.Add((New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AccountKrbtgtSid, $DomainSID)).Value)
    # "NT AUTHORITY\SYSTEM" (SID S-1-5-18).
    [void] $PrivilegedSIDsInit.Add((New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $DomainSID)).Value)
    # Built-in Administrator (SID S-1-5-32-544)
    [void] $PrivilegedSIDsInit.Add((New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $DomainSID)).Value)
    # Enterprise Read-only Domain Controllers SID.
    # $PrivilegedSIDsInit = $PrivilegedSIDsInit + (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::, $DomainSID)).Value

    # ENTERPRISE DOMAIN CONTROLLERS (SID S-1-5-9).
    If ($ForestSID) {
        [void] $PrivilegedSIDsInit.Add((New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::EnterpriseControllersSid, $DomainSID)).Value)
    }

    # Set used to keep track of already enumerated objects (to avoid infinite recursion).
    $PrivilegedSIDsOutput = New-Object System.Collections.Generic.HashSet[string]
    
    # Enumerate the members of the privileged groups. Retrieving all members recursively (including intermediate nested groups).
    $PrivilegedSIDsQueue = New-Object System.Collections.Queue
    foreach ($SID in $PrivilegedSIDsInit) {
        $PrivilegedSIDsQueue.Enqueue($SID)
    }

    While ($PrivilegedSIDsQueue.Count -ne 0) {
        $SID = $PrivilegedSIDsQueue.Dequeue()

        If ($PrivilegedSIDsOutput.Contains($SID)) {
            continue
        }
        
        $null = $PrivilegedSIDsOutput.Add($SID)

        try {
            If ((Get-ADObject -LDAPFilter "(objectsid=$SID)" -Properties ObjectClass).ObjectClass -eq "group") {
                Get-ADGroupMember -Identity $SID | Where-Object { !$PrivilegedSIDsOutput.Contains($_.SID) } | ForEach-Object { 
                    $PrivilegedSIDsQueue.Enqueue($_.SID.Value)
                }
            }
        }

        catch {
            # Skip error related to Enterprise Admins SID.
            If ($SID.EndsWith("-519")) { continue }
            Write-Host -ForegroundColor DarkYellow "[$($MyInvocation.MyCommand)][-] Group $SID not found in the targeted domain"
            Write-Host -ForegroundColor DarkYellow "[$($MyInvocation.MyCommand)][-] Exception: $_"
        }
    }

    return [array] $PrivilegedSIDsOutput
}

function Get-ADHuntingUnprivilegedSIDs {
<#
.SYNOPSIS

Return the SIDs of the unprivileged principals in the domain.

Required Dependencies: ActiveDirectory module.

.DESCRIPTION

Return the SID of the following principals:
  -  World group, "that includes all users" (SID S-1-1-0).
  -  Anonymous Logon (SID S-1-5-7).
  -  Authenticated Users group (SID S-1-5-11).
  -  Guest principal, used as "an user account that can logon interactively for people who do not have individual accounts" (SID S-1-5-21-<DOMAIN>-515).
  -  Users built-in group (SID S-1-5-32-545).
  -  Guest built-in group (SID S-1-5-32-546).
  -  Domain Users global group (SID S-1-5-21-<DOMAIN>-513).
  -  Domain Guests global group (SID S-1-5-21-<DOMAIN>-514).
  -  Domain Computers global group (SID S-1-5-21-<DOMAIN>-515).

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.OUTPUTS

[System.Collections.ArrayList]

.EXAMPLE

Get-ADHuntingBuiltinPrivilegedGroupSIDs
S-1-1-0
S-1-5-7
S-1-5-11
S-1-5-21-898253280-1155539434-3291038768-501
S-1-5-32-545
S-1-5-32-546
S-1-5-21-898253280-1155539434-3291038768-513
S-1-5-21-898253280-1155539434-3291038768-514
S-1-5-21-898253280-1155539434-3291038768-515

#>

    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
    }

    $DomainSID = (Get-ADDomain).DomainSID

    [System.Collections.ArrayList] $UnprivilegedSIDs = @(
        # World group, "that includes all users" (SID S-1-1-0).
        (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::WorldSid, $DomainSID)).Value
        # Anonymous Logon (SID S-1-5-7).
        (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AnonymousSid, $DomainSID)).Value,
        # Authenticated Users group (SID S-1-5-11).
        (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AuthenticatedUserSid, $DomainSID)).Value,
        # Guest principal, used as "an user account that can logon interactively for people who do not have individual accounts" (SID S-1-5-21-<DOMAIN>-515).
        (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AccountGuestSid, $DomainSID)).Value,
        # Users built-in group (SID S-1-5-32-545).
        (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::BuiltinUsersSid, $DomainSID)).Value,
        # Guest built-in group (SID S-1-5-32-546).
        (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::BuiltinGuestsSid, $DomainSID)).Value,
        # Domain Users global group (SID S-1-5-21-<DOMAIN>-513).
        (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AccountDomainUsersSid, $DomainSID)).Value,
        # Domain Guests global group (SID S-1-5-21-<DOMAIN>-514).
        (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AccountDomainGuestsSid, $DomainSID)).Value,
        # Domain Computers global group (SID S-1-5-21-<DOMAIN>-515).
        (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AccountComputersSid, $DomainSID)).Value
    )

    return $UnprivilegedSIDs
}

function Get-ADHuntingPrivilegedContainersAndGPOs {
<#
.SYNOPSIS

Return the OU, Sites, or Domain that contain privileged objects (first return value)
and the GPOs linked on the aforementioned containers (second return value).

Required Dependencies: ActiveDirectory module.

.DESCRIPTION

Return the following privileged containers as the first return value (HashMap):
  - OUs where privileged accounts reside.
  - The Domain Root object.
  - Site of privileged computers.

The GPO linked on the aforementioned containers are returned as the second return value (HashMap), with their application status.
The GPO "IsApplied" is marked to $false if the GPO link is disabled.
The GPO "IsApplied" is marked to $false if an OU that is blocking inheritance was previously found and the GPO is not enforced.
The GPO "IsApplied" is marked to $true in all the other cases.

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER AllPrivilegedAccounts

Specifies the privileged accounts in the domain.

.OUTPUTS

([System.Object.Hashtable], [System.Object.Hashtable])

#>

    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$True)][System.Collections.ArrayList] $AllPrivilegedAccounts
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
    }

    $PrivilegedGPOs = @{}
    $AlreadyProcessedContainers = @{}
    
    foreach ($Object in $AllPrivilegedAccounts) {
        # Process the Object OU, starting from the OU closer to the object.
        $ObjectResidencyContainers = Get-AllOUsFromDistinguishedName -DistinguishedName $Object.DistinguishedName

        # Add the Domain Root object.
        $null = $ObjectResidencyContainers.Add([regex]::Match($Object.DistinguishedName, "DC=.*$").Captures.Value)

        # For computer objects, add the Site of residency.
        If ($Object.objectClass -eq "computer") {
            $ObjectServerReferenceBL = $(Get-ADObject $Object.DistinguishedName -Properties serverReferenceBL).serverReferenceBL.Value
            $ObjectSite = [regex]::Match($ObjectServerReferenceBL, "[^,]*,CN=Sites,CN=Configuration.*$").Captures.Value

            If ($null -ne $ObjectSiteDN) {
                $null = $ObjectResidencyContainers.Add($ObjectSite)
            }
        }

        $FoundOUThatBlockInheritance = $False
        
        foreach ($ObjectResidencyContainer in $ObjectResidencyContainers) {
            # Skip already processed containers.
            If ($AlreadyProcessedContainers.Contains($ObjectResidencyContainer)) {
                If (($AlreadyProcessedContainers[$ObjectResidencyContainer].gPOptions -band 1) -eq 1) { $FoundOUThatBlockInheritance = $True }
                continue
            }
            
            $ContainerObject = Get-ADObject $ObjectResidencyContainer -Properties DistinguishedName, objectClass, gPLink, gPOptions
            $null = [void] $AlreadyProcessedContainers.Add($ContainerObject.DistinguishedName, $ContainerObject)
            
            If (($ContainerObject.gPOptions -band 1) -eq 1) { $FoundOUThatBlockInheritance = $True }

            # No GPO linked to the Container.
            If (!$ContainerObject.gPLink) { continue }
            
            # Add each GPO(s) linked on the Container.
            $ContainerObjectLinkedGPOs = Get-GPOFromGPLink -gPLinkAttribute "$($ContainerObject.gPLink)"

            foreach ($ContainerObjectLinkedGPO in $ContainerObjectLinkedGPOs) {
                $ContainerObjectLinkedGPOCustomObject = [PSCustomObject]@{
                    AppliedTo = $ObjectResidencyContainer
                    IsLinkEnabled = $ContainerObjectLinkedGPO.IsLinkEnabled
                    IsLinkEnforced = $ContainerObjectLinkedGPO.IsLinkEnforced
                    IsApplied = $ContainerObjectLinkedGPO.IsLinkEnabled -and (!$FoundOUThatBlockInheritance -or $ContainerObjectLinkedGPO.IsLinkEnforced)
                }

                If (!$PrivilegedGPOs.ContainsKey($ContainerObjectLinkedGPO.DistinguishedName)) {
                    [void] $PrivilegedGPOs.Add($ContainerObjectLinkedGPO.DistinguishedName, [System.Collections.ArrayList]@())
                    $null = $PrivilegedGPOs[$ContainerObjectLinkedGPO.DistinguishedName].Add($ContainerObjectLinkedGPOCustomObject)
                }
                Else {
                    $null = [void] $PrivilegedGPOs[$ContainerObjectLinkedGPO.DistinguishedName].Add($ContainerObjectLinkedGPOCustomObject)
                }
            }
        }
    }

    return $AlreadyProcessedContainers, $PrivilegedGPOs
}

function Get-ADHuntingAllPrivilegedObjects {
<#
.SYNOPSIS

Return all the privileged objects in the domain.

Required Dependencies: ActiveDirectory module.

.DESCRIPTION

Return the following privileged objects:
  - The Domain Root object.
  - The Domain Root object's linked GPO(s).
  - The Domain schema container.
  - The CN=MicrosoftDNS,CN=System container.
  - The msDFSR-GlobalSettings and msDFSR-ReplicationGroup containers.
  - The AdminSDHolder container.
  - Using Get-ADHuntingAllPrivilegedSIDs, the privileged groups and principals (even if protected by SDProp), processed recursively to include eventual intermediate nested groups.
  - The OUs any privileged users / computers reside (processed recursively until the root OU).
  - The GPO(s) linked to OU and Sites where a privileged user or computer account reside, independently of the link status and whether inheritance is blocked by a closer OU.
    The GPO object have three custom attributes: LinkStatus, EnforcementStatus, and IsApplied. IsApplied is set to true only if the link is enabled, the GPO is enforced, or the GPO is applied on OU where inheritance was not blocked.    
  - The Domain Controllers group and Domain Controller machine accounts.
  - The Domain Controllers OU and its linked GPO(s).
  - For each Domain Controller machine account, its site and site's linked GPO(s).
  - The "Dns Admins" group and its member(s).
  - DPAPI domain backup keys.
  - Key Distribution Service (KDS) root keys.

Multiple privileged objects are based on work from ANSSI: https://www.cert.ssi.gouv.fr/uploads/guide-ad.html

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER PrivilegedSIDs

Specifies the privileged SIDs in the domain. If not specified, the privileged SIDs are enumerated using Get-ADHuntingAllPrivilegedSIDs.
Used for optimization purposes for subsequent calls to AD Hunting functions.

.OUTPUTS

[System.Collections.ArrayList]

#>

    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$False)]$PrivilegedSIDs = $null
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
    }

    If (!$PrivilegedSIDs) {
        $PrivilegedSIDs = Get-ADHuntingAllPrivilegedSIDs
    }

    # TODO: optimize by switching to set.
    [System.Collections.ArrayList] $AllPrivilegedObjects = @()

    # Add Domain Root object.
    $RootDSE = Get-ADRootDSE
    [void] $AllPrivilegedObjects.Add($(Get-ADObject $RootDSE.rootDomainNamingContext -Properties $OBJECT_MINIMAL_PROPERTIES_SET))
    
    # Add Domain schema container.
    [void] $AllPrivilegedObjects.Add($(Get-ADObject -SearchBase $RootDSE.schemaNamingContext -LDAPFilter "(Name=Schema)" -Properties $OBJECT_MINIMAL_PROPERTIES_SET))
    
    # Add Domain CN=MicrosoftDNS,CN=System container.
    [void] $AllPrivilegedObjects.Add($(Get-ADObject "CN=MicrosoftDNS,CN=System,$($RootDSE.rootDomainNamingContext)" -Properties $OBJECT_MINIMAL_PROPERTIES_SET))

    # Add Domain msDFSR-GlobalSettings container.
    [void] $AllPrivilegedObjects.Add($(Get-ADObject -SearchBase "CN=System,$($RootDSE.rootDomainNamingContext)" -LDAPFilter "(objectClass=msDFSR-GlobalSettings)" -Properties $OBJECT_MINIMAL_PROPERTIES_SET))
    
    # Add Domain msDFSR-ReplicationGroup container(s).
    [void] $AllPrivilegedObjects.AddRange(@($(Get-ADObject -SearchBase "CN=System,$($RootDSE.rootDomainNamingContext)" -LDAPFilter "(objectClass=msDFSR-ReplicationGroup)" -Properties $OBJECT_MINIMAL_PROPERTIES_SET)))
    
    # Add AdminSDHolder container.
    [void] $AllPrivilegedObjects.Add($(Get-ADObject -LDAPFilter "(name=AdminSDHolder)" -Properties $OBJECT_MINIMAL_PROPERTIES_SET))
    
    # Add Domain Controllers group.
    $DCSID = (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AccountControllersSid, (Get-ADDomain).DomainSID)).Value
    [void] $AllPrivilegedObjects.Add($(Get-ADObject -LDAPFilter "(objectSid=$DCSID)" -Properties $OBJECT_MINIMAL_PROPERTIES_SET))
    
    # Add Domain Controllers OU.
    $DomainControllersOU = "OU=Domain Controllers,$($RootDSE.rootDomainNamingContext)"
    [void] $AllPrivilegedObjects.Add($(Get-ADObject "$DomainControllersOU" -Properties $OBJECT_MINIMAL_PROPERTIES_SET))
       
    # Add Domain Controllers machine accounts.
    [void] $AllPrivilegedObjects.AddRange(@($(Get-ADObject -LDAPFilter "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" -Properties $OBJECT_MINIMAL_PROPERTIES_SET)))

    # Add individual principals member of privileged groups (even if their ACL are in practice replicated from the AdminSDHolder container by SDProp).
    foreach ($PrivilegedSID in $PrivilegedSIDs) {
        $Object = $(Get-ADObject -LDAPFilter "(objectsid=$PrivilegedSID)" -Properties $OBJECT_MINIMAL_PROPERTIES_SET)
        If ($Object) { [void] $AllPrivilegedObjects.Add($Object) }
    }
    
    # Add DPAPI domain backup keys.
    [void] $AllPrivilegedObjects.AddRange(@($(Get-ADObject -LDAPFilter "(objectClass=secret)" -Properties $OBJECT_MINIMAL_PROPERTIES_SET)))
    
    # Add Key Distribution Service (KDS) root keys.
    [void] $AllPrivilegedObjects.AddRange(@($(Get-ADObject -SearchBase "$($RootDSE.configurationNamingContext)" -LDAPFilter "(objectClass=msKDS-ProvRootKey)" -Properties $OBJECT_MINIMAL_PROPERTIES_SET)))
    
    # Add privileged containers (where privileged objects live) and GPOs linked to those privileged containers (independently of GPO enforcement / inheritance blockage). 
    $PrivilegedContainers, $PrivilegedGPOs = Get-ADHuntingPrivilegedContainersAndGPOs -AllPrivilegedAccounts $($AllPrivilegedObjects | Where-Object { $_.objectClass -eq "user" -or $_.objectClass -eq "computer" })
    [void] $AllPrivilegedObjects.AddRange($PrivilegedContainers.Values)
    
    foreach ($PrivilegedGPODN in $PrivilegedGPOs.Keys) {
        [void] $AllPrivilegedObjects.Add($(Get-ADObject "$PrivilegedGPODN" -Properties $OBJECT_MINIMAL_PROPERTIES_SET))
    }

    $AllPrivilegedObjects | Select-Object -Unique
}

########################################################
#
#
# Priviliged principals accounts detail.
#
#
########################################################

function Export-ADHuntingPrincipalsPrivilegedAccounts {
<#
.SYNOPSIS

Export to a CSV / JSON file detailed information about members of privileged groups.

Required Dependencies: ActiveDirectory module and Get-ADHuntingBuiltinPrivilegedGroupSIDs.

.DESCRIPTION

Export to a CSV / JSON file detailed information about privileged accounts, i.e accounts thar are member of one or more privileged groups (that are enumerated using their SID retrieved with Get-ADHuntingBuiltinPrivilegedGroupSIDs).

The following groups members are enumerated:
  - Domain Admins (SID: S-1-5-<DOMAIN>-512)
  - Schema Admin (SID: S-1-5-<DOMAIN>-518)
  - Cert Publishers (SID: S-1-5-<DOMAIN>-517)
  - Group Policy Creator Owners (SID: S-1-5-<DOMAIN>-520)
  - Administrators (SID: S-1-5-32-544)
  - Account Operators (SID: S-1-5-32-548)
  - Backup Operators (SID: S-1-5-32-551)
  - Print Operators (SID: S-1-5-32-550)
  - Server Operators (SID: S-1-5-32-549)
  - Cryptographic Operators (SID: S-1-5-32-569)
  - Remote Desktop Users (SID: S-1-5-32-555)
  - Distributed COM Users (SID: S-1-5-32-562)
  - Network Configuration Operators (SID: S-1-5-32-556)
  - Incoming Forest Trust Builder (SID: S-1-5-32-557)
  - DnsAdmins (SID: non-default)
  - Enterprise Admins (SID: S-1-5-<FOREST>-519)

A number of attributes are retrieved, and if necessary parsed, for each account, including the account's scriptPath, userCertificate, userAccountControl, ...

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER OutputFolder

Specifies the CSV / JSON output file location (where the data will be exported to).

.PARAMETER OutputType

Specifies the format for the exported data (CSV or JSON). Defaults to CSV.

.OUTPUTS

CSV / JSON file written to disk.

#>

    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$False)][String]$OutputFolder = $null,
        [Parameter(Mandatory=$False)]
            [ValidateSet("JSON","CSV")]
            [string]$OutputType = "CSV"
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
    }

    $DomainName = (Get-ADDomain).DNSRoot
    $OutputFolder = If (!$OutputFolder) { "." } Else { $OutputFolder }
    $OutputPath = "$OutputFolder\${DomainName}_Principals_Privileged_Accounts_$(Get-Date -f yyyy-MM-dd-HHmmss).$($OutputType.ToLower())"

    Write-Host "[$($MyInvocation.MyCommand)][*] Enumerating privileged principals..."

    [System.Collections.ArrayList] $PrivilegedGroupSIDs = Get-ADHuntingBuiltinPrivilegedGroupSIDs

    # Enumerate all accounts in PrivilegedGroupSIDs and adding them to a set.
    $AccountsSIDSet = New-Object System.Collections.Generic.HashSet[String]

    foreach ($SID in $PrivilegedGroupSIDs) {
        try {
            Get-ADGroupMember -Recursive -Identity $SID | ForEach-Object { $null = $AccountsSIDSet.Add($_.SID) }
        }

        catch {
            # Skip error related to Enterprise Admins SID.
            If ($SID.EndsWith("-519")) { continue }
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingPrincipalsPrivilegedAccounts][-] Group $SID not found in the targeted domain"
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingPrincipalsPrivilegedAccounts][-] Exeception: $_"
         }
    }

    $Output = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $SpecificPropertiesSet = $ACCOUNT_EXTENDED_PROPERTIES_SET + @("userCertificate")
    # $funcDefConvertUnixTimeToISO8601 = ${function:Convert-UnixTimeToISO8601}.ToString()
    # $funcDefGetCertificatesStringFromCertificates = ${function:Get-X509CertificateStringFromUserCertificate}.ToString()

    # Parrallel this code snipet create transient issue DC-side.
    $AccountsSIDSet | ForEach-Object <#-Parallel#> {
        try {
            # $Output = $using:Output
            # $PSDefaultParameterValues = $using:PSDefaultParameterValues
            # $DomainName = $using:DomainName
            # $SpecificPropertiesSet = $using:SpecificPropertiesSet;
            # $USER_SPECIFIC_PROPERTIES_SET = $using:USER_SPECIFIC_PROPERTIES_SET;
            # $COMPUTER_SPECIFIC_PROPERTIES_SET = $using:COMPUTER_SPECIFIC_PROPERTIES_SET;
            # ${function:Convert-UnixTimeToISO8601} = $using:funcDefConvertUnixTimeToISO8601
            # ${function:Get-X509CertificateStringFromUserCertificate} = $using:funcDefGetCertificatesStringFromCertificates

            $Account = Get-ADObject -LDAPFilter "(objectsid=$_)" -Properties $SpecificPropertiesSet
                       
            $null = $Output.Add([PSCustomObject]@{
                Domain = $DomainName
                SamAccountName = $Account["SamAccountName"].Value
                DistinguishedName = $Account["DistinguishedName"].Value
                SID = $Account["objectSid"].Value.Value
                ObjectClass = $Account["ObjectClass"].Value
                Description = $Account["Description"].Value               
                Enabled = If (($Account["userAccountControl"].Value -band 2) -eq 2) { $False } Else { $True }
                WhenCreated = If ($Account["whenCreated"].Value) { $Account["whenCreated"].Value.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                pwdLastSet = If ($Account["pwdLastSet"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Account["pwdLastSet"].Value } Else { $null }
                lastLogon = If ($Account["lastLogon"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Account["lastLogon"].Value } Else { $null }
                lastLogonTimestamp = If ($Account["lastLogonTimestamp"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Account["lastLogonTimestamp"].Value } Else { $null }
                logonCount = $Account["logonCount"].Value
                UserPrincipalName = $Account["UserPrincipalName"].Value
                ServicePrincipalName = If ($Account["servicePrincipalName"].Value.Count -gt 0) { [string]::join(";", [array] $Account["servicePrincipalName"].Value) } Else { $null }
                ScriptPath = $Account["ScriptPath"].Value
                # $Account["userCertificate"].Value doesn't work.
                userCertificate = If ($Account.userCertificate) { Get-X509CertificateStringFromUserCertificate -usercertificate $Account.userCertificate } Else { $null }
                PasswordNeverExpires = If (($Account["userAccountControl"].Value -band 65536) -eq 65536) { $True } Else { $False }
                PasswordNotRequired = If (($Account["userAccountControl"].Value -band 32) -eq 32) { $True } Else { $False }
                AccountNotDelegated = If (($Account["userAccountControl"].Value -band 1048576) -eq 1048576) { $True } Else { $False }
                DoesNotRequirePreAuth = If (($Account["userAccountControl"].Value -band 4194304) -eq 4194304) { $True } Else { $False }
                SmartcardLogonRequired = If (($Account["userAccountControl"].Value -band 262144) -eq 262144) { $True } Else { $False }
            })
        }

        catch {
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingPrincipalsPrivilegedAccounts][-] Error while processing principal $Account"
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingPrincipalsPrivilegedAccounts][-] Exeception: $_"
        }
    }

    If ($Output.Count -gt 0) {
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($Output.Count) privileged principals"
        If ($OutputType -eq "CSV") {
            $Output | Export-Csv -NoTypeInformation -Encoding UTF8 -Append -Path $OutputPath
        }
        ElseIf ($OutputType -eq "JSON") {
            $Output | ConvertTo-Json -depth 100 | Out-File -Encoding UTF8 -Path $OutputPath
        }
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] Privileged principals information written to '$OutputPath'"
    }
    Else {
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] No privileged principals found"
    }
}

########################################################
#
#
# Once privileged users (admincount == 1) enumeration.
#
#
########################################################

function Export-ADHuntingPrincipalsOncePrivileged {
<#
.SYNOPSIS

Export to a CSV / JSON file the accounts that were once member of privileged groups.

Required Dependencies: ActiveDirectory module and Get-ADHuntingBuiltinPrivilegedGroupSIDs.

.DESCRIPTION

Export to a CSV / JSON file the accounts that have their admincount attribute set to 1 but are no longer member of a privileged group (i.e a group protected by the SDProp mechanism).

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER OutputFolder

Specifies the CSV / JSON output file location (where the data will be exported to).

.PARAMETER OutputType

Specifies the format for the exported data (CSV or JSON). Defaults to CSV.

.OUTPUTS

CSV / JSON file written to disk.

#>

    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$False)][String]$OutputFolder,
        [Parameter(Mandatory=$False)]
            [ValidateSet("JSON","CSV")]
            [string]$OutputType = "CSV"
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
    }

    $DomainName = (Get-ADDomain).DNSRoot
    $OutputFolder = If (!$OutputFolder) { "." } Else { $OutputFolder }
    $OutputPath = "$OutputFolder\${DomainName}_Principals_Once_Privileged_$(Get-Date -f yyyy-MM-dd-HHmmss).$($OutputType.ToLower())"

    Write-Host "[$($MyInvocation.MyCommand)][*] Enumerating once privileged users (principals with their admincount set to 1)..."

    $SpecificPropertiesSet = $ACCOUNT_EXTENDED_PROPERTIES_SET + @("userCertificate")
    # objectClass=user matches both computers and users accounts.
    $ADObjects = Get-ADObject -LDAPFilter "(&(objectClass=user)(admincount=1))" -Properties $SpecificPropertiesSet
    If ($ADObjects.Count -eq 0) {
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] No once-privileged principals found"
        return
    }

    $PrivilegedGroupSIDs = Get-ADHuntingBuiltinPrivilegedGroupSIDs
    $PrivilegedUsersSIDs = New-Object System.Collections.ArrayList
    foreach ($SID in $PrivilegedGroupSIDs) {
        try {
            [void] $PrivilegedUsersSIDs.AddRange(@((Get-ADGroupMember -Recursive -Identity $SID).SID.Value))
        }
        catch {
            # Skip error related to Enterprise Admins SID.
            If ($SID.EndsWith("-519")) { continue }
            Write-Host -ForegroundColor DarkYellow "[$($MyInvocation.MyCommand)][-] Group $SID not found in the targeted domain"
            Write-Host -ForegroundColor DarkYellow "[$($MyInvocation.MyCommand)][-] Exception: $_"
         }
    }
    $PrivilegedUsersSIDs = $PrivilegedUsersSIDs | Select-Object -Unique
    
    $funcDefConvertUnixTimeToISO8601 = ${function:Convert-UnixTimeToISO8601}.ToString()
    $funcDefGetCertificatesStringFromCertificates = ${function:Get-X509CertificateStringFromUserCertificate}.ToString()

    $Output = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))

    $ADObjects | Where-Object { $_.objectSid -notin $PrivilegedUsersSIDs -and $_.Name -ne 'krbtgt' } | ForEach-Object -Parallel {
        try {
            $Output = $using:Output
            $PSDefaultParameterValues = $using:PSDefaultParameterValues
            $DomainName = $using:DomainName
            $USER_SPECIFIC_PROPERTIES_SET = $using:USER_SPECIFIC_PROPERTIES_SET;
            $COMPUTER_SPECIFIC_PROPERTIES_SET = $using:COMPUTER_SPECIFIC_PROPERTIES_SET;
            ${function:Convert-UnixTimeToISO8601} = $using:funcDefConvertUnixTimeToISO8601
            ${function:Get-X509CertificateStringFromUserCertificate} = $using:funcDefGetCertificatesStringFromCertificates
            
            $Account = $_
            $AccountReplicationMetadata = Get-ADReplicationAttributeMetadata -IncludeDeletedObjects -ShowAllLinkedValues "$($Account.DistinguishedName)" -Properties admincount

            $null = $Output.Add([PSCustomObject]@{
                Domain = $DomainName
                SamAccountName = $Account["SamAccountName"].Value
                DistinguishedName = $Account["DistinguishedName"].Value
                SID = $Account["objectSid"].Value.Value
                WhenLastChangedAdminCount = If ($AccountReplicationMetadata.LastOriginatingChangeTime) { $AccountReplicationMetadata.LastOriginatingChangeTime.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                Description = $Account["Description"].Value
                Enabled = If (($Account["userAccountControl"].Value -band 2) -eq 2) { $False } Else { $True }
                WhenCreated = If ($Account["whenCreated"].Value) { $Account["whenCreated"].Value.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                pwdLastSet = If ($Account["pwdLastSet"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Account["pwdLastSet"].Value } Else { $null }
                lastLogon = If ($Account["lastLogon"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Account["lastLogon"].Value } Else { $null }
                lastLogonTimestamp = If ($Account["lastLogonTimestamp"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Account["lastLogonTimestamp"].Value } Else { $null }
                logonCount = $Account["logonCount"].Value
                UserPrincipalName = $Account["UserPrincipalName"].Value
                ServicePrincipalName = If ($Account["servicePrincipalName"].Value.Count -gt 0) { [string]::join(";", [array] $Account["servicePrincipalName"].Value) } Else { $null }
                # $Account["userCertificate"].Value doesn't work.
                userCertificate = If ($Account.userCertificate.Value) { Get-X509CertificateStringFromUserCertificate -usercertificate $Account.userCertificate } Else { $null }
                PasswordNeverExpires = If (($Account["userAccountControl"].Value -band 65536) -eq 65536) { $True } Else { $False }
                PasswordNotRequired = If (($Account["userAccountControl"].Value -band 32) -eq 32) { $True } Else { $False }
                AccountNotDelegated = If (($Account["userAccountControl"].Value -band 1048576) -eq 1048576) { $True } Else { $False }
                DoesNotRequirePreAuth = If (($Account["userAccountControl"].Value -band 4194304) -eq 4194304) { $True } Else { $False }
                ScriptPath = $Account["ScriptPath"].Value
                SmartcardLogonRequired = If (($Account["userAccountControl"].Value -band 262144) -eq 262144) { $True } Else { $False }
            })
        }

        catch {
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingPrincipalsOncePrivileged][-] Error while processing principal $Account"
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingPrincipalsOncePrivileged][-] Exeception: $_"
        }
    }
    
    If ($Output.Count -gt 0) {
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($Output.Count) once privileged principals"
        If ($OutputType -eq "CSV") {
            $Output | Export-Csv -NoTypeInformation -Encoding UTF8 -Append -Path $OutputPath
        }
        ElseIf ($OutputType -eq "JSON") {
            $Output | ConvertTo-Json -depth 100 | Out-File -Encoding UTF8 -Path $OutputPath
        }
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] Once privileged users information written to '$OutputPath'"
    }
    Else {
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][-] No once-privileged principals found, no information exported"
    }
}

########################################################
#
#
# Technical privileged accounts persistence.
#
#
########################################################

function Export-ADHuntingPrincipalsTechnicalPrivileged {
<#
.SYNOPSIS

Export to a CSV / JSON file the technical privileged accounts (SERVER_TRUST_ACCOUNT and INTERDOMAIN_TRUST_ACCOUNT).

Required Dependencies: ActiveDirectory module.

.DESCRIPTION

Export to a CSV / JSON file the following privileged technical accounts, identified using their userAccountControl attribute:
  - SERVER_TRUST_ACCOUNT - Domain Controller - (userAccountControl "8192" flag).
  - INTERDOMAIN_TRUST_ACCOUNT (userAccountControl "2048" flag).

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER OutputFolder

Specifies the CSV / JSON output file location (where the data will be exported to).

.PARAMETER OutputType

Specifies the format for the exported data (CSV or JSON). Defaults to CSV.

.OUTPUTS

CSV / JSON file written to disk.

#>

    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$False)][String]$OutputFolder,
        [Parameter(Mandatory=$False)]
            [ValidateSet("JSON","CSV")]
            [string]$OutputType = "CSV"
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
    }

    $DomainName = (Get-ADDomain).DNSRoot
    $OutputFolder = If (!$OutputFolder) { "." } Else { $OutputFolder }
    $OutputPath = "$OutputFolder\${DomainName}_Principals_Privileged_Technical_$(Get-Date -f yyyy-MM-dd-HHmmss).$($OutputType.ToLower())"

    Write-Host "[$($MyInvocation.MyCommand)][*] Enumerating technical privileged accounts..."

    # userAccountControl:1.2.840.113556.1.4.803:=8192 == SERVER_TRUST_ACCOUNT (Domain Controller)
    # userAccountControl:1.2.840.113556.1.4.803:=2048 == INTERDOMAIN_TRUST_ACCOUNT
    $ADObjects = Get-ADObject -LDAPFilter "(|(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=2048)))" -Properties $ACCOUNT_EXTENDED_PROPERTIES_SET
    If ($ADObjects.Count -eq 0) {
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] No technical privileged principals found"
        return
    }

    $funcDefConvertUnixTimeToISO8601 = ${function:Convert-UnixTimeToISO8601}.ToString()

    $Output = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
   
    $ADObjects | ForEach-Object -Parallel {
        try {
            $Output = $using:Output
            $PSDefaultParameterValues = $using:PSDefaultParameterValues
            ${function:Convert-UnixTimeToISO8601} = $using:funcDefConvertUnixTimeToISO8601

            $Account = $_

            $AccountType = ""
            If (($Account["userAccountControl"].Value -band 8192) -eq 8192) {
                $AccountType = "SERVER_TRUST_ACCOUNT"
            }
            ElseIf (($Account["userAccountControl"].Value -band 2048) -eq 2048) {
                $AccountType = "INTERDOMAIN_TRUST_ACCOUNT"
            }

            $null = $Output.Add([PSCustomObject]@{
                Domain = $DomainName
                SamAccountName = $Account["SamAccountName"].Value
                DistinguishedName = $Account["DistinguishedName"].Value
                SID = $Account["objectSid"].Value.Value
                ObjectClass = $Account["ObjectClass"].Value
                ObjectType = $AccountType
                Description = $Account["Description"].Value
                WhenCreated = If ($Account["whenCreated"].Value) { $Account["whenCreated"].Value.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                pwdLastSet = If ($Account["pwdLastSet"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Account["pwdLastSet"].Value } Else { $null }
                lastLogon = If ($Account["lastLogon"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Account["lastLogon"].Value } Else { $null }
                lastLogonTimestamp = If ($Account["lastLogonTimestamp"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Account["lastLogonTimestamp"].Value } Else { $null }
                logonCount = $Account["logonCount"].Value
                UserPrincipalName = $Account["UserPrincipalName"].Value
                ServicePrincipalName = If ($Account["servicePrincipalName"].Value.Count -gt 0) { [string]::join(";", [array] $Account["servicePrincipalName"].Value) } Else { $null }
            })
        }

        catch {
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingPrincipalsTechnicalPrivileged][-] Error while processing principal $Account"
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingPrincipalsTechnicalPrivileged][-] Exeception: $_"
        }
    }
    
    If ($Output.Count -gt 0) {
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($Output.Count) technical privileged principals"
        If ($OutputType -eq "CSV") {
            $Output | Export-Csv -NoTypeInformation -Encoding UTF8 -Append -Path $OutputPath
        }
        ElseIf ($OutputType -eq "JSON") {
            $Output | ConvertTo-Json -depth 100 | Out-File -Encoding UTF8 -Path $OutputPath
        }
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] Technical privileged accounts information written to '$OutputPath'"
    }
    Else {
        Write-Host -ForegroundColor DarkYellow "[$($MyInvocation.MyCommand)][-] Error while processing technical privileged principals, no information exported"
    }
}

function Export-ADHuntingPrincipalsPrivilegedGroupsMembership {
<#
.SYNOPSIS

Export to a CSV / JSON file privileged groups' current and past members, retrieved using replication metadata.

Required Dependencies: ActiveDirectory module and Get-ADHuntingBuiltinPrivilegedGroupSIDs.

.DESCRIPTION

Export to a CSV / JSON file the current and past members of all privileged groups.

The builtin privileged groups are first enumerated with Get-ADHuntingBuiltinPrivilegedGroupSIDs:
  - Domain Admins (SID: S-1-5-<DOMAIN>-512)
  - Schema Admin (SID: S-1-5-<DOMAIN>-518)
  - Cert Publishers (SID: S-1-5-<DOMAIN>-517)
  - Group Policy Creator Owners (SID: S-1-5-<DOMAIN>-520)
  - Administrators (SID: S-1-5-32-544)
  - Account Operators (SID: S-1-5-32-548)
  - Backup Operators (SID: S-1-5-32-551)
  - Print Operators (SID: S-1-5-32-550)
  - Server Operators (SID: S-1-5-32-549)
  - Cryptographic Operators (SID: S-1-5-32-569)
  - Remote Desktop Users (SID: S-1-5-32-555)
  - Distributed COM Users (SID: S-1-5-32-562)
  - Network Configuration Operators (SID: S-1-5-32-556)
  - Incoming Forest Trust Builder (SID: S-1-5-32-557)
  - DnsAdmins (SID: non-default)
  - Enterprise Admins (SID: S-1-5-<FOREST>-519)

Then current and past members are retrieved through AD replication metadata (using Get-ADReplicationAttributeMetadata).
Nested groups are processed recursively.

A number of information are retrieved from the replication metadata (first added, last added / deleted, current membership).

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER OutputFolder

Specifies the CSV / JSON output file location (where the data will be exported to).

.PARAMETER OutputType

Specifies the format for the exported data (CSV or JSON). Defaults to CSV.

.OUTPUTS

CSV / JSON file written to disk.

#>

    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$False)][String]$OutputFolder,
        [Parameter(Mandatory=$False)]
            [ValidateSet("JSON","CSV")]
            [string]$OutputType = "CSV"
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
    }

    $DomainName = (Get-ADDomain).DNSRoot
    $OutputFolder = If (!$OutputFolder) { "." } Else { $OutputFolder }
    $OutputPath = "$OutputFolder\${DomainName}_Principals_Privileged_Groups_Membership_$(Get-Date -f yyyy-MM-dd-HHmmss).$($OutputType.ToLower())"

    Write-Host "[$($MyInvocation.MyCommand)][*] Enumerating privileged groups members..."

    [System.Collections.ArrayList] $PrivilegedBuiltinGroupSIDs = Get-ADHuntingBuiltinPrivilegedGroupSIDs
    $PrivilegedGroupQueue = New-Object System.Collections.Queue
    
    foreach ($PrivilegedBuiltinGroupSID in $PrivilegedBuiltinGroupSIDs) {
        $ADGroup = Get-ADGroup -Identity $PrivilegedBuiltinGroupSID
        $PrivilegedGroupQueue.Enqueue([PSCustomObject]@{
            SID = $PrivilegedBuiltinGroupSID
            Name = $ADGroup.Name
            DistinguishedName = $ADGroup.DistinguishedName
            From = "Builtin"
        })
    }
    
    $OutputHashTable = @{}

    While ($PrivilegedGroupQueue.Count -ne 0) {
        try {
            $PrivilegedGroup = $PrivilegedGroupQueue.Dequeue()

            # Process group once. If a group has already been processed, update the "From" attribute (for group nested from two or more privileged groups).
            If ($OutputHashTable.ContainsKey($PrivilegedGroup.DistinguishedName)) {
                foreach ($OutputObjet in $OutputHashTable[$PrivilegedGroup.DistinguishedName]) {
                    If ($OutputObjet.GroupNestedFrom -notmatch $PrivilegedGroup.From) { $OutputObjet.GroupNestedFrom = [string]::join(";", @($OutputObjet.GroupNestedFrom, $PrivilegedGroup.From)) }
                }
                continue
            }

            $PrivilegedGroupInfo = Get-ADGroup -Properties member -Identity $PrivilegedGroup.SID
            $PrivilegedGroupCurrentMembersCount = If ($PrivilegedGroupInfo.member) { $PrivilegedGroupInfo.member.Count } Else { 0 }
            $GroupReplicationMetadataMembers = @(Get-ADReplicationAttributeMetadata -IncludeDeletedObjects -Properties member -ShowAllLinkedValues "$($PrivilegedGroupInfo.DistinguishedName)" | Where-Object { $null -ne $_.AttributeValue })
            
            foreach ($GroupReplicationMetadataMember in $GroupReplicationMetadataMembers) {
                
                # Skip member attribute that store a list members as each member is defined individually in a string version of the replicated member attribute.
                If ($GroupReplicationMetadataMember.AttributeValue.GetType() -cne [String]) { continue }
                
                $Object = Get-ADObject -LDAPFilter "(DistinguishedName=$($GroupReplicationMetadataMember.AttributeValue))" -Properties $ACCOUNT_EXTENDED_PROPERTIES_SET
                
                # Process group recursively.
                If ($Object.ObjectClass -eq "group") {
                    $PrivilegedGroupQueue.Enqueue([PSCustomObject]@{
                        SID = $Object.objectSid
                        Name = $Object.Name
                        DistinguishedName = $Object.DistinguishedName
                        From = $PrivilegedGroupInfo.Name
                    })
                }

                $OutputCustomObject = [PSCustomObject]@{
                    Domain = $DomainName
                    Group = $PrivilegedGroupInfo.Name
                    GroupSID = $PrivilegedGroupInfo.SID.Value
                    GroupDistinguishedName = $PrivilegedGroupInfo.DistinguishedName
                    GroupNestedFrom = $PrivilegedGroup.From
                    SamAccountName = $Object.SamAccountName
                    DistinguishedName = $Object.DistinguishedName
                    SID = $Object.objectSid.Value
                    ObjectClass = $Object.ObjectClass
                    CurrentMember = If ($GroupReplicationMetadataMember.Version % 2 -eq 1) { $True } Else { $False }
                    FirstAdded = If ($GroupReplicationMetadataMember.FirstOriginatingCreateTime) { $GroupReplicationMetadataMember.FirstOriginatingCreateTime.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                    LastChanged = If ($GroupReplicationMetadataMember.LastOriginatingChangeTime) { $GroupReplicationMetadataMember.LastOriginatingChangeTime.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                    LastDeleted = If ($GroupReplicationMetadataMember.LastOriginatingDeleteTime) { $GroupReplicationMetadataMember.LastOriginatingDeleteTime.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                    LastChangeFrom = $GroupReplicationMetadataMember.LastOriginatingChangeDirectoryServerIdentity
                    # Enabled = $ObjectDetailedInfo.Enabled
                    WhenCreated = If ($Object.whenCreated) { $Object.whenCreated.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                    pwdLastSet = If ($Object.pwdLastSet) { Convert-UnixTimeToISO8601 -UnixTime $Object.pwdLastSet } Else { $null }
                    lastLogon = If ($Object.lastLogon) { Convert-UnixTimeToISO8601 -UnixTime $Object.lastLogon } Else { $null }
                    lastLogonTimestamp = If ($Object.lastLogonTimestamp) { Convert-UnixTimeToISO8601 -UnixTime $Object.lastLogonTimestamp } Else { $null }
                    logonCount = $Object.logonCount
                }

                If (!$OutputHashTable.ContainsKey($PrivilegedGroup.DistinguishedName)) {
                    $OutputHashTable.Add($PrivilegedGroup.DistinguishedName, [System.Collections.ArrayList]@())
                    $null = $OutputHashTable[$PrivilegedGroup.DistinguishedName].Add($OutputCustomObject)
                }
                Else {
                    $null = $OutputHashTable[$PrivilegedGroup.DistinguishedName].Add($OutputCustomObject)
                }
            }

            If ($GroupReplicationMetadataMembers.Count -gt 0) {
                Write-Host "[Export-ADHuntingPrincipalsPrivilegedGroupsMembership][*] Group ""$($PrivilegedGroupInfo.DistinguishedName)"" has seen $($GroupReplicationMetadataMembers.Count) direct member(s) and currently has $PrivilegedGroupCurrentMembersCount members"
            }
            Else {
                Write-Host "[Export-ADHuntingPrincipalsPrivilegedGroupsMembership][*] Group ""$($PrivilegedGroupInfo.DistinguishedName)"" never had members (and thus currently has $PrivilegedGroupCurrentMembersCount member)"
            }
        }

        catch {
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingPrincipalsPrivilegedGroupsMembership][-] Error while processing group $($PrivilegedGroup.SID)"
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingPrincipalsPrivilegedGroupsMembership][-] Exception: $_"
         }
    }

    foreach ($Output in $OutputHashTable.Values) {
        If ($OutputType -eq "CSV") {
            $Output | Export-Csv -NoTypeInformation -Encoding UTF8 -Append -Path $OutputPath
        }
        ElseIf ($OutputType -eq "JSON") {
            $Output | ConvertTo-Json -depth 100 | Out-File -Append -Encoding UTF8 -Path $OutputPath
        }
    }
    
    Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] Privileged groups members information written to '$OutputPath'"
}

########################################################
#
#
# Machine accounts added with ms-DS-MachineAccountQuota
#
#
########################################################

function Export-ADHuntingPrincipalsAddedViaMachineAccountQuota {
<#
.SYNOPSIS

Export to a CSV / JSON file the computers that were added to the domain by non-privileged principals (using the ms-DS-MachineAccountQuota mechanism).

Required Dependencies: ActiveDirectory module.

.DESCRIPTION

Export to a CSV / JSON file the machine accounts that have a non-null mS-DS-CreatorSID attribute.

This attribute is set to the SID of the principal that added the computer in the domain if the computer was added by a principal that was not granted the "Create child" (for computers) access rights.

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER OutputFolder

Specifies the CSV / JSON output file location (where the data will be exported to).

.PARAMETER OutputType

Specifies the format for the exported data (CSV or JSON). Defaults to CSV.

.OUTPUTS

CSV / JSON file written to disk.

#>

    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$False)][String]$OutputFolder,
        [Parameter(Mandatory=$False)]
            [ValidateSet("JSON","CSV")]
            [string]$OutputType = "CSV"
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
    }

    $DomainName = (Get-ADDomain).DNSRoot
    $OutputFolder = If (!$OutputFolder) { "." } Else { $OutputFolder }
    $OutputPath = "$OutputFolder\${DomainName}_Principals_Added_Via_MachineAccountQuota_$(Get-Date -f yyyy-MM-dd-HHmmss).$($OutputType.ToLower())"

    Write-Host "[$($MyInvocation.MyCommand)][*] Enumerating computers added through ms-DS-MachineAccountQuota..."

    $SpecificPropertiesSet = $COMPUTER_SPECIFIC_PROPERTIES_SET + @("mS-DS-CreatorSID")
    $ADObjects = Get-ADComputer -LDAPFilter "(&(objectcategory=computer)(mS-DS-CreatorSID=*))" -Properties $SpecificPropertiesSet
    If ($ADObjects.Count -eq 0) {
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] No computers added through ms-DS-MachineAccountQuota found"
        return
    }

    $funcDefConvertUnixTimeToISO8601 = ${function:Convert-UnixTimeToISO8601}.ToString()

    $Output = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))

    # https://github.com/PowerShell/PowerShell/issues/12240
    $ADObjects | ForEach-Object -Parallel {
        try {
            $Output = $using:Output
            $PSDefaultParameterValues = $using:PSDefaultParameterValues
            $DomainName = $using:DomainName
            ${function:Convert-UnixTimeToISO8601} = $using:funcDefConvertUnixTimeToISO8601

            $Computer = $_

            $null = $Output.Add([PSCustomObject]@{
                Domain = $DomainName
                SamAccountName = $Computer["SamAccountName"].Value
                DistinguishedName = $Computer["DistinguishedName"].Value
                DNSHostName = $Computer["dNSHostName"].Value
                SID = $Computer["objectSid"].Value.Value
                "mS-DS-CreatorSID" = $Computer["mS-DS-CreatorSID"].Value.Value
                ObjectClass = $Computer["ObjectClass"].Value
                OperatingSystem = $Computer["OperatingSystem"].Value
                OperatingSystemVersion = $Computer["OperatingSystemVersion"].Value
                Description = $Computer["Description"].Value
                # Enabled = $Computer["Enabled
                WhenCreated = If ($Computer["whenCreated"].Value) { $Computer["whenCreated"].Value.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                pwdLastSet = If ($Computer["pwdLastSet"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Computer["pwdLastSet"].Value } Else { $null }
                lastLogon = If ($Computer["lastLogon"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Computer["lastLogon"].Value } Else { $null }
                lastLogonTimestamp = If ($Computer["lastLogonTimestamp"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Computer["lastLogonTimestamp"].Value } Else { $null }
                logonCount = $Computer["logonCount"].Value
                userAccountControl = $Computer["userAccountControl"].Value
            })
        }

        catch {
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingPrincipalsAddedViaMachineAccountQuota][-] Error while processing computer $Computer"
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingPrincipalsAddedViaMachineAccountQuota][-] Exception: $_"
         }
    }

    If ($Output.Count -gt 0) {
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($Output.Count) computers added through ms-DS-MachineAccountQuota"
        If ($OutputType -eq "CSV") {
            $Output | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutputPath
        }
        ElseIf ($OutputType -eq "JSON") {
            $Output | ConvertTo-Json -depth 100 | Out-File -Encoding UTF8 -Path $OutputPath
        }
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] Computers added through ms-DS-MachineAccountQuota written to '$OutputPath'"
    }
    Else {
        Write-Host -ForegroundColor DarkYellow "[$($MyInvocation.MyCommand)][-] Error while processing computers added through ms-DS-MachineAccountQuota, no information exported"
    }
}

########################################################
#
#
# PrimaryGroupID persistence.
#
#
########################################################

function Export-ADHuntingPrincipalsPrimaryGroupID {
<#
.SYNOPSIS

Export to a CSV / JSON file the accounts that have a non default primaryGroupID attribute, highlighting RID linked to privileged groups. 

Required Dependencies: ActiveDirectory module.

.DESCRIPTION

Export to a CSV / JSON file the accounts that have a non default primaryGroupID, i.e:
  - Domain Computers (except Domain Controller and Read-Only Domain Controllers) with a primaryGroupID != 515 (Domain Computers)
  - Domain users ((ObjectClass=user)(ObjectCategory=person)) with primaryGroupID != 513 (Domain Users), 514 (Guest)
  - Domain Controllers with a primaryGroupID != 516 (Domain Controllers)
  - Read-Only Domain Controllers with a primmmcaryGroupID != 521 (Read-Only Domain Controllers)

Identify RID of a privileged group (built-in or not).

Timestamp of last modification of the attribute are retrieved in replication data.

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER PrivilegedSIDs

Specifies the privileged SIDs in the domain. If not specified, the privileged SIDs are enumerated using Get-ADHuntingAllPrivilegedSIDs.
Used for optimization purposes for subsequent calls to AD Hunting functions.

.PARAMETER OutputFolder

Specifies the CSV / JSON output file location (where the data will be exported to).

.PARAMETER OutputType

Specifies the format for the exported data (CSV or JSON). Defaults to CSV.

.OUTPUTS

CSV / JSON file written to disk.

#>

    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$False)]$PrivilegedSIDs = $null,
        [Parameter(Mandatory=$False)][String]$OutputFolder,
        [Parameter(Mandatory=$False)]
            [ValidateSet("JSON","CSV")]
            [string]$OutputType = "CSV"
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
    }

    $DomainName = (Get-ADDomain).DNSRoot
    $OutputFolder = If (!$OutputFolder) { "." } Else { $OutputFolder }
    $OutputPath = "$OutputFolder\${DomainName}_Principals_PrimaryGroupIDs_$(Get-Date -f yyyy-MM-dd-HHmmss).$($OutputType.ToLower())"

    Write-Host "[$($MyInvocation.MyCommand)][*] Enumerating principals primaryGroupID..."

    # userAccountControl:1.2.840.113556.1.4.803:=8192 == Domain Controller.
    # userAccountControl:1.2.840.113556.1.4.803:=67108864 == RODC.
    # primaryGroupID=513 == Domain Users.
    # primaryGroupID=514 == Guest.
    # primaryGroupID=515 == Domain Computers.
    $SpecificPropertiesSet = $ACCOUNT_MINIMAL_PROPERTIES_SET + @("primaryGroupID")
    $ADObjects = Get-ADObject -LDAPFilter "(|(&(ObjectClass=computer)(!userAccountControl:1.2.840.113556.1.4.803:=8192)(!userAccountControl:1.2.840.113556.1.4.803:=67108864)(!primaryGroupID=515))(&(ObjectClass=user)(ObjectCategory=person)(!primaryGroupID=513)(!primaryGroupID=514))(&(ObjectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192)(!primaryGroupID=516))(&(ObjectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=67108864)(!primaryGroupID=521)))" -Properties $SpecificPropertiesSet
    If ($ADObjects.Count -eq 0) {
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] All principals have a primaryGroupID matching the default value"
        return
    }

    If (!$PrivilegedSIDs) {
        $PrivilegedSIDs = Get-ADHuntingAllPrivilegedSIDs
    }

    $PrivilegedRIDs = New-Object System.Collections.Generic.HashSet[string]
    foreach ($PrivilegedSID in $PrivilegedSIDs) {
        $null = $PrivilegedRIDs.Add($PrivilegedSID.ToString().Split('-')[-1])
    }
    
    $Output = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $PrivilegedPrimaryGroupIDCount = [ref] 0
    $funcDefConvertUnixTimeToISO8601 = ${function:Convert-UnixTimeToISO8601}.ToString()

    $ADObjects | ForEach-Object -Parallel {
        try {
            $Output = $using:Output
            $PSDefaultParameterValues = $using:PSDefaultParameterValues
            $PrivilegedRIDs = $using:PrivilegedRIDs
            $PrivilegedPrimaryGroupIDCount = $using:PrivilegedPrimaryGroupIDCount
            ${function:Convert-UnixTimeToISO8601} = $using:funcDefConvertUnixTimeToISO8601
            
            $Account = $_
            $AccountReplicationMetadata = Get-ADReplicationAttributeMetadata -IncludeDeletedObjects -ShowAllLinkedValues "$($Account.DistinguishedName)" -Properties primaryGroupID
        
            $IsPrivilegedPrimaryGroupID = $PrivilegedRIDs.Contains($Account["primaryGroupID"].Value)
            If ($IsPrivilegedPrimaryGroupID) {
                $null = [Threading.Interlocked]::Increment($PrivilegedPrimaryGroupIDCount)
            }
        
            $null = $Output.Add([PSCustomObject]@{
                Domain = $DomainName
                SamAccountName = $Account["SamAccountName"].Value
                DistinguishedName = $Account["DistinguishedName"].Value
                SID = $Account["objectSid"].Value.Value
                primaryGroupID = $Account["primaryGroupID"].Value
                IsPrivilegedPrimaryGroupID = $IsPrivilegedPrimaryGroupID
                WhenLastChangedPrimaryGroupID = If ($AccountReplicationMetadata.LastOriginatingChangeTime) { $AccountReplicationMetadata.LastOriginatingChangeTime.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                LastChangedPrimaryGroupIDFrom = If ($AccountReplicationMetadata.LastOriginatingChangeDirectoryServerIdentity) { $AccountReplicationMetadata.LastOriginatingChangeDirectoryServerIdentity } Else { $null }
                NbTimesChangedPrimaryGroupID = If ($AccountReplicationMetadata.Version) { $AccountReplicationMetadata.Version } Else { $null }
                ObjectClass = $Account["ObjectClass"].Value
                Description = $Account["Description"].Value
                # Enabled = $Account["Enabled"].Value
                WhenCreated = If ($Account["whenCreated"].Value) { $Account["whenCreated"].Value.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                pwdLastSet = If ($Account["pwdLastSet"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Account["pwdLastSet"].Value } Else { $null }
                lastLogon = If ($Account["lastLogon"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Account["lastLogon"].Value } Else { $null }
                lastLogonTimestamp = If ($Account["lastLogonTimestamp"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Account["lastLogonTimestamp"].Value } Else { $null }
                logonCount = $Account["logonCount"].Value
            })
        }

        catch {
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingPrincipalsPrimaryGroupID][-] Error while processing principal $Account"
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingPrincipalsPrimaryGroupID][-] Exception: $_"
        }
    }
    
    If ($Output.Count -gt 0) {
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($Output.Count) principals with non default primaryGroupID, including $($PrivilegedPrimaryGroupIDCount.Value) primaryGroupIDs matching privileged RIDs"
        If ($OutputType -eq "CSV") {
            $Output | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutputPath
        }
        ElseIf ($OutputType -eq "JSON") {
            $Output | ConvertTo-Json -depth 100 | Out-File -Encoding UTF8 -Path $OutputPath
        }
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] Suspicious principals' primaryGroupID information written to '$OutputPath'"
    }
    Else {
        Write-Host -ForegroundColor DarkYellow "[$($MyInvocation.MyCommand)][-] Error while processing principals with non default primaryGroupID, no information exported"
    }
}

########################################################
#
#
# SID History persistence.
#
#
########################################################

function Export-ADHuntingPrincipalsSIDHistory {
<#
.SYNOPSIS

Export to a CSV / JSON file the accounts that have a non-empty SID History attribute, with resolution of the associated domain and highlighting of privileged SIDs.

Required Dependencies: ActiveDirectory module and Get-ADHuntingAllPrivilegedSIDs.

.DESCRIPTION

Export to a CSV / JSON file the accounts that have a non-empty SID History attribute.

The domain associated with each SID is resolved using the "trustedDomain" objects in the domain.
If no trustedDomain object associated with the SID is found, the SID is identified as being from a domain no longer trusted.

The SID from the current domain, and wherever they are privileged, are highlighted. The list of privileged SIDs is retrieved with Get-ADHuntingBuiltinPrivilegedGroupSIDs.

Timestamp of last modification of the attribute are retrieved in replication data.

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER PrivilegedSIDs

Specifies the privileged SIDs in the domain. If not specified, the privileged SIDs are enumerated using Get-ADHuntingAllPrivilegedSIDs.
Used for optimization purposes for subsequent calls to AD Hunting functions.

.PARAMETER OutputFolder

Specifies the CSV / JSON output file location (where the data will be exported to).

.PARAMETER OutputType

Specifies the format for the exported data (CSV or JSON). Defaults to CSV.

.OUTPUTS

CSV / JSON file written to disk.

#>

    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$False)]$PrivilegedSIDs = $null,
        [Parameter(Mandatory=$False)][String]$OutputFolder,
        [Parameter(Mandatory=$False)]
            [ValidateSet("JSON","CSV")]
            [string]$OutputType = "CSV"
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
    }

    $DomainName = (Get-ADDomain).DNSRoot
    $OutputFolder = If (!$OutputFolder) { "." } Else { $OutputFolder }
    $OutputPath = "$OutputFolder\${DomainName}_Principals_SIDHistory_$(Get-Date -f yyyy-MM-dd-HHmmss).$($OutputType.ToLower())"

    Write-Host "[$($MyInvocation.MyCommand)][*] Enumerating principals SID history..."
    
    $SpecificPropertiesSet = $ACCOUNT_MINIMAL_PROPERTIES_SET + @("SIDHistory")
    $ADObjects = Get-ADObject -LDAPFilter "(SIDHistory=*)" -Properties $SpecificPropertiesSet
    If ($ADObjects.Count -eq 0) {
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] No principals with SID in history found"
        return
    }

    $DomainSID = (Get-ADDomain).DomainSID.Value
    $DomainsTable = @{$DomainSID = $DomainName}
    Get-ADObject -LDAPFilter "(ObjectClass=trustedDomain)" -Properties securityIdentifier | ForEach-Object {
        $DomainsTable[$_.securityIdentifier.ToString()] = $_.Name
    }

    If (!$PrivilegedSIDs) {
        $PrivilegedSIDs = Get-ADHuntingAllPrivilegedSIDs
    }
    $PrincipalsCount = [ref] 0
    $CurrentDomainCount = [ref] 0
    $CurrentDomainPrivilegedCount = [ref] 0
    
    $funcDefConvertUnixTimeToISO8601 = ${function:Convert-UnixTimeToISO8601}.ToString()

    $Output = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    
    $ADObjects | ForEach-Object -Parallel {
        try {
            $Output = $using:Output
            $PSDefaultParameterValues = $using:PSDefaultParameterValues
            $DomainName = $using:DomainName
            $DomainSID = $using:DomainSID
            $DomainsTable = $using:DomainsTable
            $PrivilegedSIDs = $using:PrivilegedSIDs
            $PrincipalsCount = $using:PrincipalsCount
            $CurrentDomainCount = $using:CurrentDomainCount
            $CurrentDomainPrivilegedCount = $using:CurrentDomainPrivilegedCount
            ${function:Convert-UnixTimeToISO8601} = $using:funcDefConvertUnixTimeToISO8601

            $Account = $_
            $null = [Threading.Interlocked]::Increment($PrincipalsCount)

            $AccountReplicationMetadata = Get-ADReplicationAttributeMetadata -IncludeDeletedObjects -ShowAllLinkedValues "$($Account.DistinguishedName)" -Properties SIDHistory
            $SIDHistoryReplicationMetadataHashTable = @{}
            foreach ($SIDHistoryReplicationMetadata in $AccountReplicationMetadata) {
                $SIDHistoryReplicationMetadataHashTable.Add($SIDHistoryReplicationMetadata.AttributeValue.Value, [PSCustomObject]@{LastOriginatingChangeTime = $SIDHistoryReplicationMetadata.LastOriginatingChangeTime; LastOriginatingChangeDirectoryServerIdentity = $SIDHistoryReplicationMetadata.LastOriginatingChangeDirectoryServerIdentity; Version = $SIDHistoryReplicationMetadata.Version })
            }       
        
            foreach ($SID in $Account["SIDHistory"]) {
                $SIDBase = $SID.ToString().SubString(0, $SID.ToString().LastIndexOf('-'))
                $IsCurrentDomain = If ($SID -match $DomainSID) { $True } Else { $False }
                $IsCurrentDomainPrivileged = If ($SID -in $PrivilegedSIDs) { $True } Else { $False }

                If ($IsCurrentDomain) { $null = [Threading.Interlocked]::Increment($CurrentDomainCount) }
                If ($IsCurrentDomainPrivileged) { $null = [Threading.Interlocked]::Increment($CurrentDomainPrivilegedCount) }

                $null = $Output.Add([PSCustomObject]@{
                    Domain = $DomainName
                    Name = $Account["Name"].Value
                    DistinguishedName = $Account["DistinguishedName"].Value
                    SID = $Account["objectSid"].Value.Value
                    SIDHistory = $SID.Value
                    SIDDomain = If ($DomainsTable.Contains($SIDBase)) { $DomainsTable[$SIDBase] } Else { 'No longer trusted' }
                    IsCurrentDomain = $IsCurrentDomain
                    IsCurrentDomainPrivileged = $IsCurrentDomainPrivileged
                    WhenLastChangedSIDHistory = If ($SIDHistoryReplicationMetadataHashTable.Contains($SID.Value) -and $SIDHistoryReplicationMetadataHashTable[$SID.Value].LastOriginatingChangeTime) { $SIDHistoryReplicationMetadataHashTable[$SID.Value].LastOriginatingChangeTime.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                    LastChangedSIDHistoryFrom = If ($SIDHistoryReplicationMetadataHashTable.Contains($SID.Value) -and $SIDHistoryReplicationMetadataHashTable[$SID.Value].LastOriginatingChangeDirectoryServerIdentity) { $SIDHistoryReplicationMetadataHashTable[$SID.Value].LastOriginatingChangeDirectoryServerIdentity } Else { $null }
                    NbTimesChangedSIDHistory = If ($SIDHistoryReplicationMetadataHashTable.Contains($SID.Value) -and $SIDHistoryReplicationMetadataHashTable[$SID.Value].Version) { $SIDHistoryReplicationMetadataHashTable[$SID.Value].Version } Else { $null }
                    WhenCreated = If ($Account["whenCreated"].Value) { $Account["whenCreated"].Value.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                    pwdLastSet = If ($Account["pwdLastSet"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Account["pwdLastSet"].Value } Else { $null }
                    lastLogon = If ($Account["lastLogon"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Account["lastLogon"].Value } Else { $null }
                    lastLogonTimestamp = If ($Account["lastLogonTimestamp"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Account["lastLogonTimestamp"].Value } Else { $null }
                })
            }
        }

        catch {
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingPrincipalsSIDHistory][-] Error while processing principal $Account"
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingPrincipalsSIDHistory][-] Exception: $_"
        }
    }

    If ($Output.Count -gt 0) {
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($PrincipalsCount.Value) principals with SID in their SIDhistory, for a total of $($Output.Count) SIDs"
        Write-Host "[$($MyInvocation.MyCommand)][*] $($CurrentDomainCount.Value) SID from the current domain including $($CurrentDomainPrivilegedCount.Value) privileged SID"
        If ($OutputType -eq "CSV") {
            $Output | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutputPath
        }
        ElseIf ($OutputType -eq "JSON") {
            $Output | ConvertTo-Json -depth 100 | Out-File -Encoding UTF8 -Path $OutputPath
        }
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] Principals SIDHistory information written to '$OutputPath'"
    }
    Else {
        Write-Host -ForegroundColor DarkYellow "[$($MyInvocation.MyCommand)][-] Error while processing principals with SID in their SIDhistory, no information exported"
    }
}

########################################################
#
#
# Shadow credentials msDS-KeyCredentialLink.
#
#
########################################################

<#
# Helper functions to parse Key Credentials is from the ADComputerKeys PowerShell module. (Copyright (c) Microsoft Corporation. All rights reserved.).
#>

function Add-KeyCredentialLinkTypes {
    # Try catch as Add-Type may fail in a new PowerShell session with "An item with the same key has already been added" errors.
    # https://github.com/PowerShell/CompletionPredictor/issues/14
    
    If (-not ([System.Management.Automation.PSTypeName]'KEY_OBJECT_ATTR_TYPE').Type) {
        try {
            $KEY_OBJECT_ATTR_TYPE_STRING =
@"
            public enum KEY_OBJECT_ATTR_TYPE : byte {
                KeyObjectValueIdMsDsKeyVersion = 0,
                KeyObjectValueIdMsDsKeyId = 1,
                KeyObjectValueIdMsDsKeyHash,
                KeyObjectValueIdMsDsKeyMaterial,
                KeyObjectValueIdMsDsKeyUsage,
                KeyObjectValueIdMsDsKeySource,
                KeyObjectValueIdMsDsDeviceId,
                KeyObjectValueIdMsDsCustomKeyInformation,
                KeyObjectValueIdMsDsKeyApproximateLastLogonTimeStamp,
                KeyObjectValueIdMsDsKeyCreationTime,
                KeyObjectValueIdMsDsKeyMax,
            }
"@
            Add-Type -TypeDefinition $KEY_OBJECT_ATTR_TYPE_STRING
        }
        catch {}
    }

    <#
    Sources:
        https://www.dsinternals.com/wp-content/uploads/eu-19-Grafnetter-Exploiting-Windows-Hello-for-Business.pdf
        https://www.powershellgallery.com/packages/S.DS.P/2.1.3/Content/Transforms%5CWindowsHelloKeyInfo.ps1
        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d4b9b239-dbe8-4475-b6f9-745612c64ed0
    #>
    If (-not ([System.Management.Automation.PSTypeName]'KEY_USAGE').Type) {
        try {
            $KEY_USAGE_STRING = 
@"
            public enum KEY_USAGE : byte {
                AdminKeyPINResetKey = 0, // Key is an admin (pin-reset key)
                NextGenCredentials = 1, // Key is an NGC key attached to a user object
                SessionTransportKey = 2, // Key is a transport key attached to a device object.
                BitlockerRecovery = 3, // Key is bitlocker recovery key
                FastIDentityOnlineKey = 7,
                FileEncryptionKey = 8,
                Other = 255, // Key usage not recognized by DRS
            }
"@
            Add-Type -TypeDefinition $KEY_USAGE_STRING
        }
        catch {}
    }

    If (-not ([System.Management.Automation.PSTypeName]'KEY_SOURCE').Type) {
        try {
            $KEY_SOURCE_STRING =
@"
            public enum KEY_SOURCE : byte {
                AD = 0,
                AAD = 1,
            }
"@
            Add-Type -TypeDefinition $KEY_SOURCE_STRING
        }
        catch {}
}
    

    If (-not ([System.Management.Automation.PSTypeName]'KEY_OBJECT_STORAGE_VERSION').Type) {
        try {
            $KEY_OBJECT_STORAGE_VERSION_STRING =
@"
            public enum KEY_OBJECT_STORAGE_VERSION : uint {
                Version0 = 0,
                Version1 = 0x100,
                Version2 = 0x200,
                VersionLatest = Version2,
            }
"@
            Add-Type -TypeDefinition $KEY_OBJECT_STORAGE_VERSION_STRING
        }
        catch {}
    }

    If (-not ([System.Management.Automation.PSTypeName]'DRKey').Type) {
        try {
            $DRKEY_STRING =
@"
            public class DRKey {
                public string Id;
                public string Source;
                public int Version;
                public string Usage;
                public System.Guid DeviceId;
                public byte[] Data;
                public System.DateTime Created;
                public System.DateTime ApproximateLastUse;
                public byte[] CustomInfo;
                public string ComputerDN;
                public string RawValue;
            }
"@
        Add-Type -ReferencedAssemblies "System.DirectoryServices" -TypeDefinition $DRKEY_STRING
        }
        catch { }
    }
}

function Get-ByteArrayFromHexString {
<#
.SYNOPSIS

Convert a hex string to a byte array.

.DESCRIPTION

Convert a hex string to byte array.

.PARAMETER HexString

The hex string to convert.

#>

    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory=$true,
            Position=0)]
            [String]$HexString
    )

    $i = 0
    $bytes = @()
    
    While ($i -lt $HexString.Length) {
        $chars = $HexString.SubString($i, 2)
        $b = [Convert]::ToByte($chars, 16)
        $bytes += $b
        $i = $i+2
    }

    Write-Output $bytes
}

function Get-KeyTimeFromBytes {
<#
.SYNOPSIS

Parse time from byte array. The time format is infered from the key source and version.

.DESCRIPTION

Parse time from byte array. The time format is infered from the key source and version.

.PARAMETER TimeData

Byte array containing the time information.

.PARAMETER KeySource

The time source (AD or AAD).

.PARAMETER KeyVersion

The NGC key version

#>

    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory=$true,
            Position=0)]
            [byte[]]$TimeData,

        [Parameter(
            Mandatory=$true,
            Position=1)]
            [KEY_SOURCE]$KeySource,

        [Parameter(
            Mandatory=$true,
            Position=2)]
            [int]$KeyVersion
    )

    $dateTime64 = [System.BitConverter]::ToInt64($TimeData, 0)
    $time = [DateTime]::MinValue

    If (($KeyVersion -le 1) -or ($KeySource -eq [KEY_SOURCE]::AAD)) {
        $time = [DateTime]::FromBinary($dateTime64)
    }
    
    ElseIf ($KeySource -eq [KEY_SOURCE]::AD) {
        $time = [DateTime]::FromFileTime($dateTime64)
    }
    
    Else {
        throw New-Object System.Exception -ArgumentList "Unexpected time format"
    }

    Write-Output $time
}

function Get-KeyFromRawValueBinary {
<#

.SYNOPSIS

Parse NGC key from binary value.

.DESCRIPTION

Parse NGC key from binary value.

.PARAMETER Reader

The binary value loaded into a binary reader object.

.PARAMETER Key

Reference to a DRKey object that will be set using the value from Reader

#>

    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory=$true)]
            [System.IO.BinaryReader]
            $Reader,

        [Parameter(
            Mandatory=$true)]
            [ref]$Key
    )

    $Key.Value = New-Object DRKey
    $key.Value.Usage = [String]::Empty
    $Key.Value.Data = @()
    $Key.Value.CustomInfo = @()
    $Key.Value.DeviceId = [Guid]::Empty
    $Key.Value.Id = [String]::Empty
    $Key.Value.Created = [DateTime]::MinValue
    $Key.Value.ApproximateLastUse = [DateTime]::MinValue
        
    $keySourceString = [String]::Empty
    $keySource = @(1)
    $lastReadKeyId = [KEY_OBJECT_ATTR_TYPE]::KeyObjectValueIdMsDsKeyVersion

    # First four bytes is the key version
    $KeyVersionBytes = 0
    $KeyVersionBytes = $Reader.ReadUInt32()
    
    Switch ($KeyVersionBytes) {
        0 {
            $Key.Value = $null
            throw New-Object System.Exception -ArgumentList "Key version not supported. Version: 0"
        }

        0x100 {
            $Key.Value.Version = 1
            break
        }

        0x200 {
            $Key.Value.Version = 2
            break
        }

        default {
            $Key.Value = $null
            throw New-Object System.Exception -ArgumentList "Unknown key version: $KeyVersionBytes"
        }
    }

    # Each set in this stream is in the form of:
    # { keyValueCount (2bytes), keyId (1byte), keyValue (keyValueCount bytes) }
    Do {
        # Read the keyValueCount
        $keyValueCount = $Reader.ReadUInt16()

        # Read the keyId
        $keyId = $Reader.ReadByte()

        If ($keyId -ge 10 -or $keyId -lt 0) {
            $Key.Value = $null
            throw New-Object System.Exception -ArgumentList "Unexpected KeyId: $keyId"
        }

        $readKeyId = [KEY_OBJECT_ATTR_TYPE]$keyId

        If ($lastReadKeyId -ge $readKeyId) {
            $Key.Value = $null
            throw New-Object System.Exception -ArgumentList "Unexpected keyId order: LastKeyRead = $lastReadKeyId, CurrentKey = $readKeyId"
        }

        # Read the actual keyValue.
        $keyValue = $Reader.ReadBytes($keyValueCount)

        Switch($readKeyId) {
            "KeyObjectValueIdMsDsKeyUsage" {
                If ($keyValueCount -eq 1) {
                    $usage = [KEY_USAGE]$keyValue[0]
                    $Key.Value.Usage = $usage.ToString()
                }
                Else { $Key.Value.Usage = [System.Text.Encoding.UTF8]::GetString($keyValue) }
                break
            }

            "KeyObjectValueIdMsDsKeyId" {
                $keyIdBytes = @()
                $keyIdBytes = $keyValue

                If ($Key.Value.Version -eq 1) { $Key.Value.Id = [System.BitConverter]::ToString($keyIdBytes).Replace("-", "") }
                Else { $Key.Value.Id = [System.Convert]::ToBase64String($keyIdBytes) }
                break
            }

            "KeyObjectValueIdMsDsKeyHash" {
                break
            }

            "KeyObjectValueIdMsDsKeyMaterial" {
                $Key.Value.Data = [byte[]]$keyValue
                break
            }

            "KeyObjectValueIdMsDsKeySource" {
                $keySource = $keyValue

                If ($Key.Value.Version -le 1) { $Key.Value.Source = "NA" }
                ElseIf ($keySource[0]-eq 0) { $Key.Value.Source = "AD" }
                ElseIf ($keySource[0]-eq 1) { $Key.Value.Source = "AzureAD" }
                Else { $Key.Value.Source = "Unknown" }
                break
            }

            "KeyObjectValueIdMsDsDeviceId" {
                $Key.Value.DeviceId = New-Object System.Guid (,$keyValue)
                break
            }

            "KeyObjectValueIdMsDsCustomKeyInformation" {
                $Key.Value.CustomInfo = $keyValue
                break
            }

            "KeyObjectValueIdMsDsKeyApproximateLastLogonTimeStamp" {
                $Key.Value.ApproximateLastUse = Get-KeyTimeFromBytes -TimeData $keyValue -KeySource $keySource[0] -KeyVersion $Key.Value.Version
                break
            }

            "KeyObjectValueIdMsDsKeyCreationTime" {
                $Key.Value.Created = Get-KeyTimeFromBytes -TimeData $keyValue -KeySource $keySource[0] -KeyVersion $Key.Value.Version
                break
            }

            default {
                break
            }
       }

    } While ($Reader.PeekChar() -ne -1)
}

function Get-KeyFromRawValue {
<#
.SYNOPSIS

Parse NGC key using the value stored in the msDS-KeyCredentialLink AD attribute.

.DESCRIPTION

Parse NGC key using the value stored in the msDS-KeyCredentialLink AD attribute.

.PARAMETER RawValue

The value stored in the msDS-KeyCredentialLink attribute in Active Directory.

#>

    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory=$true)]
            [System.String]$RawValue
    )

    $memStream = $null
    $binReader = $null

    try {
        $parsedLink = $RawValue.Split(':')

        If ($parsedLink.Length -ne 4) {
            Write-Output $null
            throw New-Object System.Exception -ArgumentList "Key raw value is not an expected DN binary value"
        }

        $valueCount = [Convert]::ToInt32($parsedLink[1])

        If ($parsedLink[2].Length -ne $valueCount) {
            Write-Output $null
            throw New-Object System.Exception -ArgumentList "Key raw value has unexpected count: ParsedCount = $($parsedLink[2].Length) ValueCount = $valueCount"
        }

        $keyBytes = Get-ByteArrayFromHexString -HexString $parsedLink[2]

        $memStream = New-Object System.IO.MemoryStream (,[byte[]]$keyBytes)
        $binReader = New-Object System.IO.BinaryReader $memStream

        $key = [DRKey]$null
        Get-KeyFromRawValueBinary -Reader $binReader -Key ([ref]$key)

        If ($null -eq $key) {
            # Error should have been thrown in Get-KeyFromRawValueBinary.
            Write-Output $null
            return
        }

        $key.ComputerDN = $parsedLink[3]
        $key.RawValue = $RawValue

        Write-Output $key
    }

    finally {
        If ($null -ne $binReader) {
            $binReader.Close()
            $binReader.Dispose()
        }

        If ($null -ne $memStream) {
            $memStream.Close()
            $memStream.Dispose()
        }
    }
}

function Export-ADHuntingPrincipalsShadowCredentials {
<#
.SYNOPSIS

Export to a CSV / JSON file parsed Key Credentials information (of accounts having a non-empty msDS-KeyCredentialLink attribute).

Required Dependencies: ActiveDirectory module.

.DESCRIPTION

Export to a CSV / JSON file parsed Key Credentials information (of accounts having a non-empty msDS-KeyCredentialLink attribute).

Enumerate and parse each Key Credentials, using code from the ADComputerKeys PowerShell module, to identify each key:
  - Source (AD / AAD)
  - Type (NextGenCredentials being used for user object)
  - Key created timestamps
  - Approximate last use timestamps

Helper functions to parse Key Credentials is from the ADComputerKeys PowerShell module.

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER PrivilegedSIDs

Specifies the privileged SIDs in the domain. If not specified, the privileged SIDs are enumerated using Get-ADHuntingAllPrivilegedSIDs.
Used for optimization purposes for subsequent calls to AD Hunting functions.

.PARAMETER OutputFolder

Specifies the CSV / JSON output file location (where the data will be exported to).

.PARAMETER OutputType

Specifies the format for the exported data (CSV or JSON). Defaults to CSV.

.OUTPUTS

CSV / JSON file written to disk.

#>
    
    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$False)]$PrivilegedSIDs = $null,
        [Parameter(Mandatory=$False)][String]$OutputFolder,
        [Parameter(Mandatory=$False)]
            [ValidateSet("JSON","CSV")]
            [string]$OutputType = "CSV"
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
    }

    $DomainName = (Get-ADDomain).DNSRoot
    $OutputFolder = If (!$OutputFolder) { "." } Else { $OutputFolder }
    $OutputPath = "$OutputFolder\${DomainName}_Principals_ShadowCredentials_$(Get-Date -f yyyy-MM-dd-HHmmss).$($OutputType.ToLower())"

    Write-Host "[$($MyInvocation.MyCommand)][*] Enumerating accounts having their msDS-keyCredentialLink attribute set and parsing key credential..."

    # Specific properties are not working as msDS-keyCredentialLink is not recognized as a valid property by Get-ADObject
    # $SpecificPropertiesSet = $ACCOUNT_MINIMAL_PROPERTIES_SET + @("msDS-keyCredentialLink")
    $ADObjects = Get-ADObject -LDAPFilter "(msDS-keyCredentialLink=*)" -Properties *
    If ($ADObjects.Count -eq 0) {
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] No principals with their msDS-keyCredentialLink attribute set found"
        return
    }

    If (!$PrivilegedSIDs) {
        $PrivilegedSIDs = Get-ADHuntingAllPrivilegedSIDs
    }

    $funcDefConvertUnixTimeToISO8601 = ${function:Convert-UnixTimeToISO8601}.ToString()
    $funcDefAddKeyCredentialLinkTypes = ${function:Add-KeyCredentialLinkTypes}.ToString()
    $funcDefGetByteArrayFromHexString = ${function:Get-ByteArrayFromHexString}.ToString()
    $funcDefGetKeyTimeFromBytes = ${function:Get-KeyTimeFromBytes}.ToString()
    $funcDefGetKeyFromRawValueBinary = ${function:Get-KeyFromRawValueBinary}.ToString()
    $funcDefGetKeyFromRawValue = ${function:Get-KeyFromRawValue}.ToString()
    
    $Output = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $PrincipalsCount = [ref] 0
    $KeyCredentialSourceAD = [ref] 0
    $KeyCredentialSourceAAD = [ref] 0
    $KeyCredentialSourceUnknown = [ref] 0
    
    $ADObjects | ForEach-Object <#-Parallel#> {
        try {
            # $Output = $using:Output
            # $PSDefaultParameterValues = $using:PSDefaultParameterValues
            # $DomainName = $using:DomainName
            # $PrivilegedSIDs = $using:PrivilegedSIDs
            # $PrincipalsCount = $using:PrincipalsCount
            # $KeyCredentialSourceAD = $using:KeyCredentialSourceAD
            # $KeyCredentialSourceAAD = $using:KeyCredentialSourceAAD
            # $KeyCredentialSourceUnknown = $using:KeyCredentialSourceUnknown
            # ${function:Convert-UnixTimeToISO8601} = $using:funcDefConvertUnixTimeToISO8601
            # ${function:Add-KeyCredentialLinkTypes} = $using:funcDefAddKeyCredentialLinkTypes
            # ${function:Get-ByteArrayFromHexString} = $using:funcDefGetByteArrayFromHexString
            # ${function:Get-KeyTimeFromBytes} = $using:funcDefGetKeyTimeFromBytes
            # ${function:Get-KeyFromRawValueBinary} = $using:funcDefGetKeyFromRawValueBinary
            # ${function:Get-KeyFromRawValue} = $using:funcDefGetKeyFromRawValue

            $Account = $_
            $null = [Threading.Interlocked]::Increment($PrincipalsCount)
            
            # $AccountReplicationMetadata = Get-ADReplicationAttributeMetadata -IncludeDeletedObjects -ShowAllLinkedValues "$($Account.DistinguishedName)" -Properties "msDS-keyCredentialLink"
            
            Add-KeyCredentialLinkTypes

            for ($i = 0; $i -lt $Account["msDS-keyCredentialLink"].Value.Count; $i++) {
            
                try {
                    $KeyParsed = Get-KeyFromRawValue -RawValue $Account["msDS-keyCredentialLink"][$i]
                }
                catch {
	        	    Write-Error "Error while parsing $($Account["Name"].Value) key credential at index $i :"
                    Write-Error $_.Exception.Message
                    Write-Error "Raw key: $($Account["msDS-keyCredentialLink"][$i])"
                    continue
                }

                Switch ($KeyParsed.Source) {
                    $([KEY_SOURCE]::AD) { $null = [Threading.Interlocked]::Increment($KeyCredentialSourceAD) }
                    $([KEY_SOURCE]::AAD) { $null = [Threading.Interlocked]::Increment($KeyCredentialSourceAAD) }
                    default { $null = [Threading.Interlocked]::Increment($KeyCredentialSourceUnknown) }
                }

                $null = $Output.Add([PSCustomObject]@{
                    Domain = $DomainName
                    SamAccountName = $Account["SamAccountName"].Value
                    DistinguishedName = $Account["DistinguishedName"].Value
                    SID = $Account["objectSid"].Value.Value
                    ObjectClass = $Account["ObjectClass"].Value
                    IsPrivileged = If ($Account["objectSid"].Value -in $PrivilegedSIDs) { $True } Else { $False }
                    Description = $Account["Description"].Value
                    # Enabled = $Account["Enabled"].Value
                    WhenCreated = If ($Account["whenCreated"]) { $Account["whenCreated"].Value.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                    pwdLastSet = If ($Account["pwdLastSet"]) { Convert-UnixTimeToISO8601 -UnixTime $Account["pwdLastSet"].Value } Else { $null }
                    lastLogon = If ($Account["lastLogon"]) { Convert-UnixTimeToISO8601 -UnixTime $Account["lastLogon"].Value } Else { $null }
                    lastLogonTimestamp = If ($Account["lastLogonTimestamp"]) { Convert-UnixTimeToISO8601 -UnixTime $Account["lastLogonTimestamp"].Value } Else { $null }
                    logonCount = $Account["logonCount"].Value
                    KeyCredentialCount = $Account["msDS-keyCredentialLink"].Value.Count
                    KeyCredentialIndex = $i
                    KeyCredentialID = $KeyParsed.Id
                    KeyCredentialDeviceID = $KeyParsed.DeviceId
                    KeyCredentialSource = $KeyParsed.Source
                    KeyCredentialVersion = $KeyParsed.Version
                    KeyCredentialUsage = $KeyParsed.Usage
                    KeyCredentialCreated = $KeyParsed.Created
                    KeyCredentialApproximateLastUse = $KeyParsed.ApproximateLastUse
                    KeyCredentialRawValue = $KeyParsed.RawValue
                    #WhenLastkeyCredLink = $AccountReplicationMetadata.LastOriginatingChangeTime.ToString('yyyy-MM-dd HH:mm:ss.fff')
                    #LastChangedkeyCredLinkFrom = $AccountReplicationMetadata.LastOriginatingChangeDirectoryServerIdentity
                    #NbTimesChangedkeyCredLink = $AccountReplicationMetadata.Version
                })
            }
        }
        
        catch {
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingPrincipalsShadowCredentials][-] Error while processing principal $Account"
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingPrincipalsShadowCredentials][-] Exception: $_"
        }
    }
    
    If ($Output.Count -gt 0) {
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($PrincipalsCount.value) principals with their msDS-keyCredentialLink attribute set, for a total of $($Output.Count) key credentials"
        Write-Host "[$($MyInvocation.MyCommand)][*] Key sources: AD = $($KeyCredentialSourceAD.value) | AAD = $($KeyCredentialSourceAAD.value) | Unknown = $($KeyCredentialSourceUnknown.value)"
        If ($OutputType -eq "CSV") {
            $Output | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutputPath
        }
        ElseIf ($OutputType -eq "JSON") {
            $Output | ConvertTo-Json -depth 100 | Out-File -Encoding UTF8 -Path $OutputPath
        }
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] Principals with msDS-keyCredentialLink and parsed key credentials information written to '$OutputPath'"
    }
    Else {
        Write-Host -ForegroundColor DarkYellow "[$($MyInvocation.MyCommand)][-] Error while processing principals with their msDS-keyCredentialLink attribute set, no information exported"
    }
}

########################################################
#
#
# altSecurityIdentities / userPrincipalName persistence.
#
#
########################################################

function Export-ADHuntingPrincipalsUPNandAltSecID {
<#
.SYNOPSIS

Export to a CSV / JSON file the accounts that define a UserPrincipalName or AltSecurityIdentities attribute, highlighting potential anomalies.

Required Dependencies: ActiveDirectory module and Get-ADHuntingAllPrivilegedSIDs.

.DESCRIPTION

The UserPrincipalName (UPN) or the Alt-Security-Identities (AltSecID) attributes of a user are used in PKINIT authentication
(using public key cryptography as a Kerberos pre-authentication mechanism).
Both the altSecurityIdentities or userPrincipalName attribute could thus be leveraged for persistence. 

UserPrincipalName are composed as "prefix@suffix" and should by convention match the user email address:
  - The UPN should match the user’s mail attribute or the prefix should match the user’s SamAccountName / mailNickName attributes.
  - The suffix must match the DNS name of a domain in the forest or a name in the Partitions container’s upnSuffixes attribute.

Alt-Security-Identities supported format: 
  - X509:<I><S>
  - X509:<S>*
  - X509:<I><SR>
  - X509:<SKI>
  - X509:<SHA*-PUKEY>
  - X509:<RFC822>* 

Enumerate UPN and AltSecId to help investigation but doesn’t replace manual analysis (especially for AltSecId).

Highlight UPN that do not match the user SamAccountName, mail or mailNickName attribute.

UPN and AltSecId timestamp of last modification of the attribute through replication data.

Note: when in doubt, unknown / suspicious AltSecID entries should be deleted (especially for privileged principals).

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER PrivilegedSIDs

Specifies the privileged SIDs in the domain. If not specified, the privileged SIDs are enumerated using Get-ADHuntingAllPrivilegedSIDs.
Used for optimization purposes for subsequent calls to AD Hunting functions.

.PARAMETER OutputFolder

Specifies the CSV / JSON output file location (where the data will be exported to).

.PARAMETER OutputType

Specifies the format for the exported data (CSV or JSON). Defaults to CSV.

.OUTPUTS

CSV / JSON file written to disk.

#>

    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$False)]$PrivilegedSIDs = $null,
        [Parameter(Mandatory=$False)][String]$OutputFolder,
        [Parameter(Mandatory=$False)]
            [ValidateSet("JSON","CSV")]
            [string]$OutputType = "CSV"
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)
    $PSDefaultParameterValues.Add("Get-Class*:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
        $PSDefaultParameterValues.Add("Get-Class*:Credential", $Credential)
    }

    $DomainName = (Get-ADDomain).DNSRoot
    $OutputFolder = If (!$OutputFolder) { "." } Else { $OutputFolder }
    $OutputPath = "$OutputFolder\${DomainName}_ADCS_Principals_UserPrincipalName_and_AltSecID_$(Get-Date -f yyyy-MM-dd-HHmmss).$($OutputType.ToLower())"

    Write-Host "[$($MyInvocation.MyCommand)][*] Enumerating and parsing principals' UserPrincipalName or AltSecurityIdentities attributes..."
    
    # mailNickName / altSecurityIdentities may not be supported attributes for the schema.
    $MailAttributes = @("mail", "mailNickName", "UserPrincipalName", "altSecurityIdentities")
    $UserSupportedAttributes = Get-ClassSupportedAttributes -ClassName "user"
    $SpecificPropertiesSet = $ACCOUNT_MINIMAL_PROPERTIES_SET + $($MailAttributes | Where-Object { $_ -in $UserSupportedAttributes })
    $ADObjects = Get-ADObject -LDAPFilter "(|(altSecurityIdentities=*)(userPrincipalName=*))" -Properties $SpecificPropertiesSet
    If ($ADObjects.Count -eq 0) {
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] No principals with a UserPrincipalName or AltSecurityIdentities set found"
        return
    }

    If (!$PrivilegedSIDs) {
        $PrivilegedSIDs = Get-ADHuntingAllPrivilegedSIDs
    }

    $Output = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $UPNPrefixIsNotSamAccountNameOrMailCount = [ref] 0
    $UPNSuffixIsNotDomainCount = [ref] 0
    $OneAltSecIDPrefixIsNotSamAccountNameOrMailCount = [ref] 0
    $OneAltSecIDSuffixIsNotDomainCount = [ref] 0
    
    $funcDefConvertUnixTimeToISO8601 = ${function:Convert-UnixTimeToISO8601}.ToString()

    $ADObjects | ForEach-Object -Parallel {
        try {
            $Output = $using:Output
            $PSDefaultParameterValues = $using:PSDefaultParameterValues
            $DomainName = $using:DomainName
            $PrivilegedSIDs = $using:PrivilegedSIDs
            $UPNPrefixIsNotSamAccountNameOrMailCount = $using:UPNPrefixIsNotSamAccountNameOrMailCount
            $UPNSuffixIsNotDomainCount = $using:UPNSuffixIsNotDomainCount
            $OneAltSecIDPrefixIsNotSamAccountNameOrMailCount = $using:OneAltSecIDPrefixIsNotSamAccountNameOrMailCount
            $OneAltSecIDSuffixIsNotDomainCount = $using:OneAltSecIDSuffixIsNotDomainCount
            ${function:Convert-UnixTimeToISO8601} = $using:funcDefConvertUnixTimeToISO8601

            $Account = $_
            $AccountReplicationMetadata = @(Get-ADReplicationAttributeMetadata -IncludeDeletedObjects -ShowAllLinkedValues "$($Account.DistinguishedName)" -Properties userPrincipalName, altSecurityIdentities)
            $AccountReplicationMetadataUserPrincipalName = $AccountReplicationMetadata | Where-Object { $_.AttributeName -eq "userPrincipalName" }
            $AccountReplicationMetadataAltSecurityIdentities = $AccountReplicationMetadata | Where-Object { $_.AttributeName -eq "altSecurityIdentities" }

            $AccountSamAccountNameLowercase = If ($Account["SamAccountName"]) { $Account["SamAccountName"].Value.ToLower() } Else { $null }
            $AccountMailLowercase = If ($Account["mail"]) { $Account["mail"].Value.ToLower() } Else { $null }
            $AccountMailNickNameLowercase = If ($Account["mailNickName"]) { $Account["mailNickName"].Value.ToLower() } Else { $null }

            # Check if the UPN in the userPrincipalName attribute match the SamAccountName, mail, or mailNickName attributes.
            If ($Account["userPrincipalName"]) {
                $UPNLowerCase = $Account["userPrincipalName"].Value.ToLower()
                If ($Account["userPrincipalName"].Value -match '@') { 
                    $UPNSplited = $UPNLowerCase.Split('@')
                    $UPNPrefix = $UPNSplited[0]
                    $UPNSuffix = $UPNSplited[1]
                }
                Else {
                    $UPNLowerCase = $null
                    $UPNPrefix = If ($Account["userPrincipalName"]) { $Account["userPrincipalName"].Value.ToLower() } Else { $null }
                    $UPNSuffix = $null
                }
    
                $UPNPrefixIsSamAccountName = If ($UPNPrefix -eq $AccountSamAccountNameLowercase) { $True } Else { $False }
                $UPNPrefixIsMailNickName = If ($UPNPrefix -eq $AccountMailNickNameLowercase) { $True } Else { $False }
                $UPNIsMail = If ($UPNLowerCase -eq $AccountMailLowercase) { $True } Else { $False }
                $UPNPrefixIsNotSamAccountNameOrMail = !$UPNPrefixIsSamAccountName -and !$UPNIsMail -and !$UPNPrefixIsMailNickName
                $UPNSuffixIsNotDomain = !($UPNSuffix -eq $DomainName)
                
                If ($UPNPrefixIsNotSamAccountNameOrMail) { $null = [Threading.Interlocked]::Increment($UPNPrefixIsNotSamAccountNameOrMailCount) }        
                If ($UPNSuffixIsNotDomain) { $null = [Threading.Interlocked]::Increment($UPNSuffixIsNotDomainCount) }
            }
            
            Else {
                $UPNPrefixIsSamAccountName = $null
                $UPNPrefixIsMailNickName = $null
                $UPNIsMail = $null
                $UPNPrefixIsNotSamAccountNameOrMail = $null
                $UPNSuffixIsNotDomain = $null
            }

            $null = $Output.Add([PSCustomObject]@{
                Domain = $DomainName
                SamAccountName = $AccountSamAccountNameLowercase
                DistinguishedName = $Account["DistinguishedName"].Value
                SID = $Account["objectSid"].Value.Value
                IsPrivileged = If ($Account["objectSid"].Value -in $PrivilegedSIDs) { $True } Else { $False }
                WhenCreated = If ($Account["whenCreated"].Value) { $Account["whenCreated"].Value.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                pwdLastSet = If ($Account["pwdLastSet"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Account["pwdLastSet"].Value } Else { $null }
                lastLogon = If ($Account["lastLogon"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Account["lastLogon"].Value } Else { $null }
                lastLogonTimestamp = If ($Account["lastLogonTimestamp"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Account["lastLogonTimestamp"].Value } Else { $null }
                mail = $Account["mail"].Value
                mailNickName = $Account["mailNickName"].Value
                UserPrincipalName = $Account["userPrincipalName"].Value
                UPNPrefixIsSamAccountName = $UPNPrefixIsSamAccountName
                UPNIsMail = $UPNIsMail
                UPNPrefixIsMailNickName = $UPNPrefixIsMailNickName
                UPNPrefixIsNotSamAccountNameOrMail = $UPNPrefixIsNotSamAccountNameOrMail
                UPNSuffixIsNotDomain = $UPNSuffixIsNotDomain
                WhenLastChangedUPN = If ($AccountReplicationMetadataUserPrincipalName.LastOriginatingChangeTime) { $AccountReplicationMetadataUserPrincipalName.LastOriginatingChangeTime.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                LastChangedUPNFrom = If ($AccountReplicationMetadataUserPrincipalName.LastOriginatingChangeDirectoryServerIdentity) { $AccountReplicationMetadataUserPrincipalName.LastOriginatingChangeDirectoryServerIdentity } Else { $null }
                NbTimesChangedUPN = If ($AccountReplicationMetadataUserPrincipalName.Version) { $AccountReplicationMetadataUserPrincipalName.Version } Else { $null }
                AltSecurityIdentities = If ($Account["altSecurityIdentities"].Value) { [string]::join(";", [array] $Account["altSecurityIdentities"].Value) } Else { $null }
                WhenLastChangedAltSecID = If ($AccountReplicationMetadataAltSecurityIdentities.LastOriginatingChangeTime) { $AccountReplicationMetadataAltSecurityIdentities.LastOriginatingChangeTime.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                LastChangedAltSecIDFrom = If ($AccountReplicationMetadataAltSecurityIdentities.LastOriginatingChangeDirectoryServerIdentity) { $AccountReplicationMetadataAltSecurityIdentities.LastOriginatingChangeDirectoryServerIdentity } Else { $null }
                NbTimesChangedAltSecID = If ($AccountReplicationMetadataAltSecurityIdentities.Version) { $AccountReplicationMetadataAltSecurityIdentities.LastOriginatingChangeDirectoryServerIdentity } Else { $null }
            })
        }
        
        catch {
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingPrincipalsUPNandAltSecID][-] Error while processing principal $Account"
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingPrincipalsUPNandAltSecID][-] Exception: $_"
        }
    }

    If ($Output.Count -gt 0) {
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($Output.Count) principals with a UserPrincipalName or AltSecurityIdentities set found"
        Write-Host "[$($MyInvocation.MyCommand)][*] $($UPNPrefixIsNotSamAccountNameOrMailCount.Value) principals have a UserPrincipalName that do not match their SamAccountName, mail, or mailNickName attributes"
        Write-Host "[$($MyInvocation.MyCommand)][*] $($UPNSuffixIsNotDomainCount.Value) principals have a UserPrincipalName that do not match the current domain"
        Write-Host "[$($MyInvocation.MyCommand)][*] $($OneAltSecIDPrefixIsNotSamAccountNameOrMailCount.Value) principals have at least one UPN in their altSecurityIdentities that do not match their SamAccountName, mail, or mailNickName attributes"
        Write-Host "[$($MyInvocation.MyCommand)][*] $($OneAltSecIDSuffixIsNotDomainCount.Value) principals have at least one UPN in their altSecurityIdentities that do not match the current domain"
        If ($OutputType -eq "CSV") {
            $Output | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutputPath
        }
        ElseIf ($OutputType -eq "JSON") {
            $Output | ConvertTo-Json -depth 100 | Out-File -Encoding UTF8 -Path $OutputPath
        }
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] Principals UserPrincipalName or AltSecurityIdentities information written to '$OutputPath'"
    }
    Else {
        Write-Host -ForegroundColor DarkYellow "[$($MyInvocation.MyCommand)][-] Error while processing principals with a UserPrincipalName or AltSecurityIdentities set, no information exported"
    }
}

########################################################
#
#
#  ADCS - AD certificate (userCertificate) persistence.
#
#
########################################################

function Add-X509CertificateTypes {
    # If (-not ([System.Management.Automation.PSTypeName]'X509_ALTERNATIVE_NAME_TYPE').Type) {
    If (-not ('X509_ALTERNATIVE_NAME_TYPE' -as [Type])) {
        try {
            $X509_ALTERNATIVE_NAME_TYPE_STRING =
@"
            public enum X509_ALTERNATIVE_NAME_TYPE {
                XCN_CERT_ALT_NAME_UNKNOWN = 0,
                XCN_CERT_ALT_NAME_OTHER_NAME = 1,
                XCN_CERT_ALT_NAME_RFC822_NAME = 2,
                XCN_CERT_ALT_NAME_DNS_NAME = 3,
                XCN_CERT_ALT_NAME_X400_ADDRESS = 4,
                XCN_CERT_ALT_NAME_DIRECTORY_NAME = 5,
                XCN_CERT_ALT_NAME_EDI_PARTY_NAME = 6,
                XCN_CERT_ALT_NAME_URL = 7,
                XCN_CERT_ALT_NAME_IP_ADDRESS = 8,
                XCN_CERT_ALT_NAME_REGISTERED_ID = 9,
                XCN_CERT_ALT_NAME_GUID = 10,
                XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME = 11
              }
"@
            Add-Type -TypeDefinition $X509_ALTERNATIVE_NAME_TYPE_STRING
        }
        catch {}
    }
}

function Export-ADHuntingPrincipalsCertificates {
<#
.SYNOPSIS

Export to a CSV / JSON file parsed accounts' certificate(s) (for accounts having a non-empty userCertificate attribute).

The certificates are parsed to retrieve a number of parameters: certificate validity timestamps, certificate purpose, certificate subject and eventual SubjectAltName(s), ...

Required Dependencies: ActiveDirectory module.

.DESCRIPTION

Enumerate and parse users / computers certificates, identifying certificates valid for client authentication.

Extract each certificate eventual SubjectAltName(s), determining if any UPN do not match the current account UPN and if the UPN is linked to a privileged account.

Retrieve certificate validity timestamps (not before / not after) and timestamp of last modification of the account certificate attribute through replication data.

Note: while new certificates can be requested by a threat actor for persistence, already existing certificates may also have been retrieved following endpoints compromise or the CA certificate and private key stolen to forge arbitrary certificate. 
It is thus recommended to renew the CA certificate in a forest / domain recovery procedure.

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER PrivilegedSIDs

Specifies the privileged SIDs in the domain. If not specified, the privileged SIDs are enumerated using Get-ADHuntingAllPrivilegedSIDs.
Used for optimization purposes for subsequent calls to AD Hunting functions.

.PARAMETER OutputFolder

Specifies the CSV / JSON output file location (where the data will be exported to).

.PARAMETER OutputType

Specifies the format for the exported data (CSV or JSON). Defaults to CSV.

.OUTPUTS

CSV / JSON file written to disk.

#>
    
    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$False)]$PrivilegedSIDs = $null,
        [Parameter(Mandatory=$False)][String]$OutputFolder,
        [Parameter(Mandatory=$False)]
            [ValidateSet("JSON","CSV")]
            [string]$OutputType = "CSV"
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
    }

    $DomainName = (Get-ADDomain).DNSRoot
    $OutputFolder = If (!$OutputFolder) { "." } Else { $OutputFolder }
    $OutputPath = "$OutputFolder\${DomainName}_ADCS_Principals_Certificates_$(Get-Date -f yyyy-MM-dd-HHmmss).$($OutputType.ToLower())"
    
    Write-Host "[$($MyInvocation.MyCommand)][*] Enumerating and parsing accounts certificates..."

    $ADObjects = Get-ADObject -LDAPFilter "(userCertificate=*)" -Properties $($ACCOUNT_EXTENDED_PROPERTIES_SET + @("userCertificate"))
    If ($ADObjects.Count -eq 0) {
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] No principals with certificates found (all accounts have an empty userCertificate attribute)"
        return
    }

    If (!$PrivilegedSIDs) {
        $PrivilegedSIDs = Get-ADHuntingAllPrivilegedSIDs
    }

    $funcDefConvertUnixTimeToISO8601 = ${function:Convert-UnixTimeToISO8601}.ToString()
    $funcDefAddX509CertificateTypes = ${function:Add-X509CertificateTypes}.ToString()

    $Output = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $PrincipalsCount = [ref] 0
    $CertificateValidForClientAuth = [ref] 0
    $CertificateWithSubjectAltNameUPN = [ref] 0
    $CertificateWithSubjectAltNameUPNNotMatchCurrentObject = [ref] 0
    $CertificateWithSubjectAltNameUPNNotMatchCurrentObjectPriv = [ref] 0
    
    $ADObjects | ForEach-Object -Parallel {
        try {
            $Output = $using:Output
            $PSDefaultParameterValues = $using:PSDefaultParameterValues
            $CERT_EKU_CLIENT_AUTH_OID = $using:CERT_EKU_CLIENT_AUTH_OID
            $DomainName = $using:DomainName
            $PrivilegedSIDs = $using:PrivilegedSIDs
            $PrincipalsCount = $using:PrincipalsCount
            $CertificateWithSubjectAltNameUPN = $using:CertificateWithSubjectAltNameUPN
            $CertificateWithSubjectAltNameUPNNotMatchCurrentObject = $using:CertificateWithSubjectAltNameUPNNotMatchCurrentObject
            $CertificateWithSubjectAltNameUPNNotMatchCurrentObjectPriv = $using:CertificateWithSubjectAltNameUPNNotMatchCurrentObjectPriv
            $CertificateValidForClientAuth = $using:CertificateValidForClientAuth
            ${function:Convert-UnixTimeToISO8601} = $using:funcDefConvertUnixTimeToISO8601
            ${function:Add-X509CertificateTypes} = $using:funcDefAddX509CertificateTypes

            $Account = $_
            
            Add-X509CertificateTypes

            $usercertificate = $Account["userCertificate"].Value
            # If single certificate retrieved in the userCertificate attribute, cast into an array for harmonized parsing. 
            If ($usercertificate.GetType() -eq [byte[]]) {
                $usercertificate = [byte[][]]@(,($usercertificate))
            }
            $null = [Threading.Interlocked]::Increment($PrincipalsCount)
            
            $AccountReplicationMetadata = Get-ADReplicationAttributeMetadata -IncludeDeletedObjects -ShowAllLinkedValues "$($Account.DistinguishedName)" -Properties "userCertificate"

            for ($i = 0; $i -lt $usercertificate.Count; $i++) {
                try {
                    $X509Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]] $usercertificate[$i])
                }
                catch {
                    Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingPrincipalsCertificates][-] Error while processing the following certificate for principal '${Account}': '$($usercertificate[$i])'"
                    Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingPrincipalsCertificates][-] The certificate may not be correctly formated"
                    Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingPrincipalsCertificates][-] Exception: $_"
                    continue
                }

                If ($null -eq $X509Certificate -or $null -eq $X509Certificate.SerialNumber -or '' -eq $X509Certificate.SerialNumber) {
                    Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingPrincipalsCertificates][-] Error while parsing certificate number $($i + 1) for principal $Account"
                    continue
                }

                # Certificate usage.
                # If no OID is specified in the EKU extension, the certificate will by default be valid for all usages in Windows, including client authentication.
                $X509CertificateAllowClientAuth = If ($null -eq $X509Certificate.EnhancedKeyUsageList -or '' -eq $X509Certificate.EnhancedKeyUsageList -or $($X509Certificate.EnhancedKeyUsageList | Where-Object { $CERT_EKU_CLIENT_AUTH_OID -contains $_.ObjectID })) { $True } Else { $False }
                If ($X509CertificateAllowClientAuth) { $null = [Threading.Interlocked]::Increment($CertificateValidForClientAuth) }
                
                # Certificate eventual Subject Alternative Name(s).
                $X509CertificateSubjectAltNameExt = $X509Certificate.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
                $SubjectAltNameFormatedList = New-Object System.Collections.ArrayList
                $FoundUPNInSubjectAltName = $False
                $AllSubjectAltNameUPNMatchCurrentObject = $True
                $OneNonMatchingSubjectAltNameUPNIsPriv = $False
                If ($X509CertificateSubjectAltNameExt) {
                    $SubjectAltNameObject = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
                    $SubjectAltNameObject.InitializeDecode(1, [System.Convert]::ToBase64String($X509CertificateSubjectAltNameExt.RawData))

                    # A certificate SubjectAltName may contain multiple values (dns, UPN, etc.).
                    Foreach ($SubjectAltName in $SubjectAltNameObject.AlternativeNames) {
                        $SubjectAltNameType = [X509_ALTERNATIVE_NAME_TYPE] $SubjectAltName.Type
                        $SubjectAltNameValue = $SubjectAltName.strValue
                        $null = $SubjectAltNameFormatedList.Add("${SubjectAltNameType}:$SubjectAltNameValue")

                        # Specific analysis for SAN UPN.
                        If ($SubjectAltNameType -eq "XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME") {
                            $null = [Threading.Interlocked]::Increment($CertificateWithSubjectAltNameUPN)
                            $FoundUPNInSubjectAltName = $True

                            # The UPN in the certificate SAN doesn't match the current account UPN.
                            If ($SubjectAltNameValue -ne $Account["UserPrincipalName"].Value) {
                                $null = [Threading.Interlocked]::Increment($CertificateWithSubjectAltNameUPNNotMatchCurrentObject)
                                $AllSubjectAltNameUPNMatchCurrentObject = $False
                                
                                # The UPN defined in SAN is privileged.
                                $UPNMatchingSID = (Get-ADObject -LDAPFilter "(UserPrincipalName=$SubjectAltNameValue)" -Properties objectSid).objectSid.Value
                                $UPNIsPriv = If ($UPNMatchingSID -in $PrivilegedSIDs) { $True } Else { $False }
                                If ($UPNIsPriv) {
                                    $null = [Threading.Interlocked]::Increment($CertificateWithSubjectAltNameUPNNotMatchCurrentObjectPriv)
                                    $OneNonMatchingSubjectAltNameUPNIsPriv = $UPNIsPriv -or $OneNonMatchingSubjectAltNameUPNIsPriv
                                } 
                            }
                        }
                    }
                }
                $SubjectAltNameFormatedString = If ($SubjectAltNameFormatedList.Count -gt 0) { [string]::join(";", [array] $SubjectAltNameFormatedList) } Else { "" }

                $null = $Output.Add([PSCustomObject]@{
                    Domain = $DomainName
                    SamAccountName = $Account["SamAccountName"].Value
                    DistinguishedName = $Account["DistinguishedName"].Value
                    SID = $Account["objectSid"].Value.Value
                    UPN = $Account["UserPrincipalName"].Value
                    ObjectClass = $Account["ObjectClass"].Value
                    IsPrivileged = If ($Account["objectSid"].Value -in $PrivilegedSIDs) { $True } Else { $False }
                    Description = $Account["Description"].Value
                    WhenCreated = If ($Account["whenCreated"]) { $Account["whenCreated"].Value.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                    pwdLastSet = If ($Account["pwdLastSet"]) { Convert-UnixTimeToISO8601 -UnixTime $Account["pwdLastSet"].Value } Else { $null }
                    lastLogon = If ($Account["lastLogon"]) { Convert-UnixTimeToISO8601 -UnixTime $Account["lastLogon"].Value } Else { $null }
                    lastLogonTimestamp = If ($Account["lastLogonTimestamp"]) { Convert-UnixTimeToISO8601 -UnixTime $Account["lastLogonTimestamp"].Value } Else { $null }
                    CertificatesCount = $usercertificate.Count
                    CertificatesIndex = $i
                    WhenLastChangedCertificate = If ($AccountReplicationMetadata.LastOriginatingChangeTime) { $AccountReplicationMetadata.LastOriginatingChangeTime.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                    LastChangedCertificateFrom = If ($AccountReplicationMetadata.LastOriginatingChangeDirectoryServerIdentity) { $AccountReplicationMetadata.LastOriginatingChangeDirectoryServerIdentity } Else { $null }
                    NbTimesChangedCertificate = If ($AccountReplicationMetadata.Version) { $AccountReplicationMetadata.Version } Else { $null }
                    X509CertificateSerialNumber = $X509Certificate.SerialNumber
                    X509CertificateSubject = $X509Certificate.Subject
                    X509CertificateNotBefore = $X509Certificate.NotBefore
                    X509CertificateNotAfter = $X509Certificate.NotAfter
                    X509AllSANUPNMatchCurrentAccUPN = If ($FoundUPNInSubjectAltName) { $AllSubjectAltNameUPNMatchCurrentObject } Else { $null }
                    X509OneNonMatchingSANUPNIsPriv = If ($FoundUPNInSubjectAltName) { $OneNonMatchingSubjectAltNameUPNIsPriv } Else { $null }
                    X509CertificateSubjectAltName = $SubjectAltNameFormatedString
                    X509CertificateAllowClientAuth = $X509CertificateAllowClientAuth
                    X509CertificateEnhancedKeyUsageList = If ($X509Certificate.EnhancedKeyUsageList) { [string]::join(";", $X509Certificate.EnhancedKeyUsageList) } Else { "None" }
                    X509CertificateThumbprint = $X509Certificate.Thumbprint
                })
            }
        }
        
        catch {
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingPrincipalsCertificates][-] Error while processing principal $Account"
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingPrincipalsCertificates][-] Exception: $_"
        }
    }
    
    If ($Output.Count -gt 0) {
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($PrincipalsCount.value) principals having certificates, for a total of $($Output.Count) certificates (including $($CertificateValidForClientAuth.value) certificate(s) valid for client authentication)"
        Write-Host "[$($MyInvocation.MyCommand)][*] $($CertificateWithSubjectAltNameUPN.value) UPNs are defined in certificate(s)'s SubjectAltName"
        Write-Host "[$($MyInvocation.MyCommand)][*] Including $($CertificateWithSubjectAltNameUPNNotMatchCurrentObject.value) UPNs ($($CertificateWithSubjectAltNameUPNNotMatchCurrentObjectPriv.Value) privileged UPNs) that do not match the UPN of the user the certificate is associated to"
        If ($OutputType -eq "CSV") {
            $Output | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutputPath
        }
        ElseIf ($OutputType -eq "JSON") {
            $Output | ConvertTo-Json -depth 100 | Out-File -Encoding UTF8 -Path $OutputPath
        }
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] Principals certificates information written to '$OutputPath'"
    }
    Else {
        Write-Host "[$($MyInvocation.MyCommand)][-] No accounts with certifcates found and no information were exported"
    }
}

########################################################
#
#
#  ADCS - Certificate Authorities review.
#
#
########################################################

function Export-ADHuntingADCSPKSObjects {
<#
.SYNOPSIS

Export to a CSV / JSON file information and access rights on sensitive PKS objects (NTAuthCertificates, certificationAuthority, and pKIEnrollmentService).

Required Dependencies: ActiveDirectory module.

.DESCRIPTION

Enumerate and review Public Key Services objects (NTAuthCertificates, certificationAuthority, and pKIEnrollmentService), parsing certificates and attempting to find rogue CA certificates

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER ADDriveName

Specifies the name to use for the ActiveDirectory PSDrive that will be (temporarily) mounted by the cmdlet.
Defaults to ADHunting.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER PrivilegedSIDs

Specifies the privileged SIDs in the domain. If not specified, the privileged SIDs are enumerated using Get-ADHuntingAllPrivilegedSIDs.
Used for optimization purposes for subsequent calls to AD Hunting functions.

.PARAMETER OutputFolder

Specifies the CSV / JSON output file location (where the data will be exported to).

.PARAMETER OutputType

Specifies the format for the exported data (CSV or JSON). Defaults to CSV.

.OUTPUTS

CSV / JSON file written to disk.

#>
    
    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$False)][String]$ADDriveName = "ADHunting",
        [Parameter(Mandatory=$False)]$PrivilegedSIDs = $null,
        [Parameter(Mandatory=$False)][String]$OutputFolder,
        [Parameter(Mandatory=$False)]
            [ValidateSet("JSON","CSV")]
            [string]$OutputType = "CSV"
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)
    $PSDefaultParameterValues.Add("New-PSDrive:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
        $PSDefaultParameterValues.Add("New-PSDrive:Credential", $Credential)
    }

    Write-Host "[$($MyInvocation.MyCommand)][*] Enumerating Public Key Services objects..."

    If (!(Get-PSDrive $ADDriveName -ErrorAction SilentlyContinue)) {
        $Env:ADPS_LoadDefaultDrive = 0
        $null = New-PSDrive -Name $ADDriveName -PSProvider ActiveDirectory -Root "//RootDSE/"
    }
    
    Add-PrivilegeLevelType

    $DomainName = (Get-ADDomain).DNSRoot
    $OutputFolder = If (!$OutputFolder) { "." } Else { $OutputFolder }
    $OutputPKSObjectsPath = "$OutputFolder\${DomainName}_ADCS_Public_Key_Services_objects_$(Get-Date -f yyyy-MM-dd-HHmmss).$($OutputType.ToLower())"   
    $OutputRogueNTAuthCertificatesCAPath = "$OutputFolder\${DomainName}_ADCS_Possible_Rogue_NTAuthCertificates_CA_Certificate_$(Get-Date -f yyyy-MM-dd-HHmmss).$($OutputType.ToLower())"   

    If (!$PrivilegedSIDs) {
        $PrivilegedSIDs = Get-ADHuntingAllPrivilegedSIDs
    }
    $UnprivilegedSIDs = Get-ADHuntingUnprivilegedSIDs

    $ConfigurationNamingContext = $(Get-ADRootDSE).configurationNamingContext
    
    $OutputPKSObjects = New-Object System.Collections.ArrayList
    $OutputRogueNTAuthCertificatesCA = New-Object System.Collections.ArrayList

    # Enumerate the CA certificate(s) trusted under the NTAuthCertificates container.
    $NTAuthCertificates = Get-ADObject -SearchBase $ConfigurationNamingContext -LDAPFilter "(&(name=NTAuthCertificates)(objectClass=certificationAuthority))" -Properties cACertificate
    # Hashmap NTAuthCertificatesCACertificates key: (cert SerialNumber + Thumbprint) -> value: whether the cert was found among other PKS objects (root or intermediate certificates as well as CA enrollment services).
    $NTAuthCertificatesCACertificates = @{}
    Foreach ($NTAuthCertificate in $NTAuthCertificates.cACertificate) {
        try {
            $X509CACertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($NTAuthCertificate)
            $NTAuthCertificatesCACertificates["$($X509CACertificate.SerialNumber)|$($X509CACertificate.Thumbprint)"] = @{ "Found" = $False; "Certificate" = $NTAuthCertificate }
        }
        catch {
            Write-Host -ForegroundColor DarkYellow "[$($MyInvocation.MyCommand)][-] Error while parsing certificate from NTAuthCertificates: $NTAuthCertificate"
            Write-Host -ForegroundColor DarkYellow "[$($MyInvocation.MyCommand)][-] Exception: $_"
        }
    }

    # Enumerate all PKS objects.
    $PKSObjects = Get-ADObject -SearchBase "CN=Public Key Services,CN=Services,$ConfigurationNamingContext" -LDAPFilter "(|(objectClass=certificationAuthority)(objectClass=pKIEnrollmentService))" -Properties *
    
    $PKSObjectsCount = [ref] 0
    $PKSObjectModifiableByEveryoneCount = [ref] 0
    $PKSObjectModifiableByNonPrivCount = [ref] 0
    
    # Process all PKS objects independantly of their types.
    Foreach ($PKSObject in $PKSObjects) {
        try {
            $ReplicationMetadata = Get-ADReplicationAttributeMetadata -IncludeDeletedObjects -ShowAllLinkedValues "$($PKSObject["DistinguishedName"].Value)" -Properties "nTSecurityDescriptor", "cACertificate"
            $ReplicationMetadatanTSecurityDescriptor = $ReplicationMetadata | Where-Object { $_.AttributeName -eq "nTSecurityDescriptor" }
            $ReplicationMetadatacACertificate = $ReplicationMetadata | Where-Object { $_.AttributeName -eq "cACertificate" }

            $null = [Threading.Interlocked]::Increment($PKSObjectsCount)
            
            # Determine the object type to adapt the processing.
            $ObjectType = $null
            $ObjectTypeDescription = $null
            switch -Regex ($PKSObject["DistinguishedName"].Value) {
                "^CN=NTAuthCertificates,CN=Public Key Services,CN=Services,$ConfigurationNamingContext$" { 
                    $ObjectType = "NTAuthCertificates"
                    $ObjectTypeDescription = "CA certificates for client auth certificates"
                }
                "(.*)CN=AIA,CN=Public Key Services,CN=Services,$ConfigurationNamingContext$" { 
                    $ObjectType = "AIA"
                    $ObjectTypeDescription = "Trusted intermediate and cross CA certificates"
                }
                "(.*)CN=Certification Authorities,CN=Public Key Services,CN=Services,$ConfigurationNamingContext$" { 
                    $ObjectType = "certificationAuthority"
                    $ObjectTypeDescription = "Trusted root CA certificates"
                }
                "(.*)CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigurationNamingContext$" {
                    $ObjectType = "pKIEnrollmentService"
                    $ObjectTypeDescription = "Certification Authority for certificates enrollment"
                }
                default { $ObjectType = "Unknown";  $ObjectTypeDescription = "" }
            }

            # Process the object ACL.
            $PKSObjectACL = Get-Acl -Path "${ADDriveName}:\$($PKSObject["DistinguishedName"])"

            # Default values if the ACL couldn't be retrieved.
            $PKSObjectOwnerIs = "Parsing_error"
            $PKSObjectModificationRightGrantedTo = "Parsing_error"
            $PKSObjectModificationRightsAsString = "Parsing_error"
            $CAEnrollRightGrantedTo = "NA"
            $CAEnrollRightsAsString = "NA"

            If ($PKSObjectACL) {
                # Process object owner.
                $PKSObjectOwnerSID = $PKSObjectACL.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
                If ($PrivilegedSIDs.Contains($PKSObjectOwnerSID)) {
                    $PKSObjectOwnerIs = [PrivilegeLevel]::Privileged
                }
                ElseIf ($UnprivilegedSIDs.Contains($PKSObjectOwnerSID)) {
                    $PKSObjectOwnerIs = [PrivilegeLevel]::Everyone
                }
                Else {
                    $PKSObjectOwnerIs = [PrivilegeLevel]::NonPrivileged
                }

                # Modification rights are assumed to be granted by default to privileged principals.
                $PKSObjectModificationRightGrantedTo = [PrivilegeLevel]::Privileged
                $PKSObjectModificationRightsAsString = ""

                # Process object DACL.           
                Foreach ($PKSObjectACE in $PKSObjectACL.Access) {
                    # Attempt to retrieve SID from PKSObjectACE IdentityReference if automatically translated to principal name.
                    try { $PKSObjectACEAttributedToSID = $PKSObjectACE.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
                    catch { $PKSObjectACEAttributedToSID = $PKSObjectACE.IdentityReference }

                    # Skip access rights granted to privileged principals.
                    If ($PrivilegedSIDs.Contains($PKSObjectACEAttributedToSID)) {
                        continue
                    }
                    
                    # Determine if all or sensitive attributes of the object can be modified.
                    If (Is-DangerousADACE -ObjectClass $PKSObject["ObjectClass"].Value -ACE $PKSObjectACE -AttributedToSID $PKSObjectACEAttributedToSID -PrivilegedSIDs $PrivilegedSIDs) {
                        $AccessRightGUIDText = If ($null -ne $PKSObjectACE.ObjectType -and $ACE_GUID_MAPPING.ContainsKey($PKSObjectACE.ObjectType.ToString())) { $ACE_GUID_MAPPING[$PKSObjectACE.ObjectType.ToString()] } Else { "Undefined" }
                        $PKSObjectModificationRightsAsString += "GrantedTo=$($PKSObjectACE.IdentityReference) | GrantedToSID=$PKSObjectACEAttributedToSID | AccessType=$($PKSObjectACE.AccessControlType) | AccesRight=$($PKSObjectACE.ActiveDirectoryRights) | AccessGuid=$($PKSObjectACE.ObjectType) | AccessGuidText=$AccessRightGUIDText | IsInherited=$($PKSObjectACE.IsInherited) | PropagationFlags=$($PKSObjectACE.PropagationFlags);"

                        If ($UnprivilegedSIDs.Contains($PKSObjectACEAttributedToSID)) {
                            $PKSObjectModificationRightGrantedTo = [PrivilegeLevel]::Everyone
                        }
                        ElseIf (!$PrivilegedSIDs.Contains($PKSObjectACEAttributedToSID)) {
                            $PKSObjectModificationRightGrantedTo = [PrivilegeLevel] [math]::Min([int] [PrivilegeLevel]::NonPrivileged, [int] $PKSObjectModificationRightGrantedTo)
                        }
                    }

                    # Determine who can enroll / autoenroll if the object is a CA.
                    If ($ObjectType -eq "pKIEnrollmentService" -and $(Is-EnrollmentADACE -ACE $PKSObjectACE)) {
                        $CAEnrollRightsAsString += "GrantedTo=$($PKSObjectACE.IdentityReference) | GrantedToSID=$PKSObjectACEAttributedToSID | AccessType=$($PKSObjectACE.AccessControlType) | AccesRight=$($PKSObjectACE.ActiveDirectoryRights) | AccessGuid=$($PKSObjectACE.ObjectType) | IsInherited=$($PKSObjectACE.IsInherited) | PropagationFlags=$($PKSObjectACE.PropagationFlags);"

                        If ($UnprivilegedSIDs.Contains($PKSObjectACEAttributedToSID)) {
                            $CAEnrollRightGrantedTo = [PrivilegeLevel]::Everyone
                        }
                        ElseIf (!$PrivilegedSIDs.Contains($PKSObjectACEAttributedToSID)) {
                            $CAEnrollRightGrantedTo = [PrivilegeLevel] [math]::Min([int] [PrivilegeLevel]::NonPrivileged, [int] $CAEnrollRightGrantedTo)
                        }
                    }
                }

                If ($PKSObjectOwnerIs -eq [PrivilegeLevel]::Everyone -or $PKSObjectModificationRightGrantedTo -eq [PrivilegeLevel]::Everyone) {
                    $null = [Threading.Interlocked]::Increment($PKSObjectModifiableByEveryoneCount)
                }
                ElseIf ($PKSObjectOwnerIs -eq [PrivilegeLevel]::NonPrivileged -or $PKSObjectModificationRightGrantedTo -eq [PrivilegeLevel]::NonPrivileged) {
                    $null = [Threading.Interlocked]::Increment($PKSObjectModifiableByNonPrivCount)
                }
            }

            # Process the X509 certificate(s) in the object's cACertificate attribute.
            # One object is added per X509 certificates in the object's cACertificate attribute (usually only one, except for NTAuthCertificates).
            $index = 0
            Foreach ($PKSObjectCertificate in $NTAuthCertificates.cACertificate) {
                try {
                    $X509PKSCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PKSObjectCertificate)
                    
                    $X509PKSCertificateKey = "$($X509PKSCertificate.SerialNumber)|$($X509PKSCertificate.Thumbprint)"
                    If ($NTAuthCertificatesCACertificates.ContainsKey($X509PKSCertificateKey)) {
                        $NTAuthCertificatesCACertificates[$X509PKSCertificateKey]["Found"] = $True
                        $IsInNTAuthCertificates = $True
                    }
                    Else { 
                        $IsInNTAuthCertificates = $False
                    }
                   
                    $null = $OutputPKSObjects.Add([PSCustomObject]@{
                        Domain = $DomainName
                        ObjectType = $ObjectType
                        ObjectTypeDescription = $ObjectTypeDescription
                        Name = $PKSObject["Name"].Value
                        DisplayName = $PKSObject["displayName"].Value
                        DistinguishedName = $PKSObject["distinguishedName"].Value
                        Description = $PKSObject["description"].Value
                        WhenCreated = If ($PKSObject["whenCreated"].Value) { $PKSObject["whenCreated"].Value.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                        WhenChanged = If ($PKSObject["whenChanged"].Value) { $PKSObject["whenChanged"].Value.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                        PKSObjectOwnerIs = $PKSObjectOwnerIs
                        PKSObjectModificationRightGrantedTo = $PKSObjectModificationRightGrantedTo
                        PKSObjectModificationRightsAsString = $PKSObjectModificationRightsAsString
                        CAEnrollRightGrantedTo = $CAEnrollRightGrantedTo
                        CAEnrollRightsAsString = $CAEnrollRightsAsString
                        "nTSecurityDescriptor-WhenLastChanged" = If ($ReplicationMetadatanTSecurityDescriptor.LastOriginatingChangeTime) { $ReplicationMetadatanTSecurityDescriptor.LastOriginatingChangeTime.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                        "nTSecurityDescriptor-LastChangedFrom" = If ($ReplicationMetadatanTSecurityDescriptor.LastOriginatingChangeDirectoryServerIdentity) { $ReplicationMetadatanTSecurityDescriptor.LastOriginatingChangeDirectoryServerIdentity } Else { $null }
                        "nTSecurityDescriptor-NbTimesChanged" = If ($ReplicationMetadatanTSecurityDescriptor.Version) { $ReplicationMetadatanTSecurityDescriptor.Version } Else { $null }
                        "cACertificate-WhenLastChanged" = If ($ReplicationMetadatacACertificate.LastOriginatingChangeTime) { $ReplicationMetadatacACertificate.LastOriginatingChangeTime.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                        "cACertificate-LastChangedFrom" = If ($ReplicationMetadatacACertificate.LastOriginatingChangeDirectoryServerIdentity) { $ReplicationMetadatacACertificate.LastOriginatingChangeDirectoryServerIdentity } Else { $null }
                        "cACertificate-NbTimesChanged" = If ($ReplicationMetadatacACertificate.Version) { $ReplicationMetadatacACertificate.Version } Else { $null }
                        CertificatesCount = $NTAuthCertificates.cACertificate.Count
                        CertificateIndex = $index
                        CertificateSerialNumber = $X509PKSCertificate.SerialNumber
                        CertificateSubjectName = $X509PKSCertificate.SubjectName.Name
                        CertificateIsInNTAuthCertificates = $IsInNTAuthCertificates
                        CertificateIssuer = $X509PKSCertificate.Issuer
                        CertificateThumbprint = $X509PKSCertificate.Thumbprint
                        CertificateNotBefore = If ($X509PKSCertificate.NotBefore) { $X509PKSCertificate.NotBefore.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                        CertificateNotAfter = If ($X509PKSCertificate.NotAfter) { $X509PKSCertificate.NotAfter.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                        CertificatePublicKeyExchangeAlgorithm = $X509PKSCertificate.PublicKey.Key.KeyExchangeAlgorithm
                        CertificatePublicKeySignatureAlgorithm = $X509PKSCertificate.PublicKey.Key.SignatureAlgorithm
                        CertificatePublicKeySize = $X509PKSCertificate.PublicKey.Key.KeySize
                        CertificateSignatureAlgorithm = $X509PKSCertificate.SignatureAlgorithm.FriendlyName                        
                    })

                    $index = $index + 1
                }

                catch {
                    Write-Host -ForegroundColor DarkYellow "[$($MyInvocation.MyCommand)][-] Error while processing certificate from PKS object $($PKSObject["DistinguishedName"].Value): $PKSObjectCertificate"
                    Write-Host -ForegroundColor DarkYellow "[$($MyInvocation.MyCommand)][-] Exception: $_"
                    continue
                }
            }
        }

        catch {
            Write-Host -ForegroundColor DarkYellow "[$($MyInvocation.MyCommand)][-] Error while processing PKS object $PKSObject"
            Write-Host -ForegroundColor DarkYellow "[$($MyInvocation.MyCommand)][-] Exception: $_"
        }
    }

    If ($OutputPKSObjects.Count -gt 0) {
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($PKSObjectsCount.value) PKS objects for a total of $($OutputPKSObjects.Count) certificates"
        Write-Host "[$($MyInvocation.MyCommand)][*] Found PKS objects that can have sensitive attributes modified by: everyone $($PKSObjectModifiableByEveryoneCount.value) | non-privilege principals $($PKSObjectModifiableByNonPrivCount.value)"
        If ($OutputType -eq "CSV") {
            $OutputPKSObjects | Export-Csv -NoTypeInformation -Encoding UTF8 -Append -Path $OutputPKSObjectsPath
        }
        ElseIf ($OutputType -eq "JSON") {
            $OutputPKSObjects | ConvertTo-Json -depth 100 | Out-File -Encoding UTF8 -Path $OutputPKSObjectsPath
        }
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] PKS objects information written to '$OutputPKSObjectsPath'"
    }
    Else {
        Write-Host "[$($MyInvocation.MyCommand)][-] No PKS objects found, an error likely occured or AD CS is not present in the environment"
    }

    Foreach ($NTAuthCertificatesCACertificate in $NTAuthCertificatesCACertificates.GetEnumerator()) {
        # The certificate was found as a root / intermediate certificates or on a CA enrollment services object.
        If ($NTAuthCertificatesCACertificate.Value["Found"] -eq $True) {
            continue
        }

        $X509Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($NTAuthCertificatesCACertificate.Value["Certificate"])

        $null = $OutputRogueNTAuthCertificatesCA.Add([PSCustomObject]@{
            CertificateSerialNumber = $X509Certificate.SerialNumber
            CertificateSubjectName = $X509Certificate.SubjectName.Name
            CertificateIssuer = $X509Certificate.Issuer
            CertificateThumbprint = $X509Certificate.Thumbprint
            CertificateNotBefore = If ($X509Certificate.NotBefore) { $X509Certificate.NotBefore.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
            CertificateNotAfter = If ($X509Certificate.NotAfter) { $X509Certificate.NotAfter.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
            CertificatePublicKeyExchangeAlgorithm = $X509Certificate.PublicKey.Key.KeyExchangeAlgorithm
            CertificatePublicKeySignatureAlgorithm = $X509Certificate.PublicKey.Key.SignatureAlgorithm
            CertificatePublicKeySize = $X509Certificate.PublicKey.Key.KeySize
            CertificateSignatureAlgorithm = $X509Certificate.SignatureAlgorithm.FriendlyName                        
        })
    }

    If ($OutputRogueNTAuthCertificatesCA.Count -gt 0) {
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($OutputRogueNTAuthCertificatesCA.Count) possible rogue CA certificates in NTAuthCertificates"
        If ($OutputType -eq "CSV") {
            $OutputRogueNTAuthCertificatesCA | Export-Csv -NoTypeInformation -Encoding UTF8 -Append -Path $OutputRogueNTAuthCertificatesCAPath
        }
        ElseIf ($OutputType -eq "JSON") {
            $OutputRogueNTAuthCertificatesCA | ConvertTo-Json -depth 100 | Out-File -Encoding UTF8 -Path $OutputRogueNTAuthCertificatesCAPath
        }
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] Possible rogue CA certificates information written to '$OutputRogueNTAuthCertificatesCAPath'"
    }
    Else {
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] No rogue CA certificates in NTAuthCertificates found"
    }
}

########################################################
#
#
#  ADCS - Certificate templates review.
#
#
########################################################

function Export-ADHuntingADCSCertificateTemplates {
<#
.SYNOPSIS

Export to a CSV / JSON file information and access rights on certificate templates.

The following notable parameters are retrieved: certificate template publish status, certificate usage, if the subject is constructed from user-supplied data, and access control (enrollment / modification).

Required Dependencies: ActiveDirectory module.

.DESCRIPTION

Export to a CSV / JSON file certificate templates, checking for each templates:
   - Whether the template is published by at least one CA (listing the CA that publish it)
   - If it allows client authentication (listing the template's EKU)
   - If user-supplied data is used to construct the subject
   - If manager approval is required to create the certificate
   - If the owner is privileged
   - If non-privileged principals can modify all or sensitive properties of the template

A number of timestamps are also gathered:
  - When the template was created / last changed
  - When the msPKI-Certificate-Name-Flag, msPKI-Enrollment-Flag, and nTSecurityDescriptor attributes were last changed and from which DC (using replication metadata)

Mapping from Certified pre-owned:
  - Misconfigured Certificate Templates - ESC1 & ESC2
  - Vulnerable Certificate Template Access Control - ESC4
  - Malicious Misconfiguration - DPERSIST3 (limited to certificate templates)

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER ADDriveName

Specifies the name to use for the ActiveDirectory PSDrive that will be (temporarily) mounted by the cmdlet.
Defaults to ADHunting.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER PrivilegedSIDs

Specifies the privileged SIDs in the domain. If not specified, the privileged SIDs are enumerated using Get-ADHuntingAllPrivilegedSIDs.
Used for optimization purposes for subsequent calls to AD Hunting functions.

.PARAMETER OutputFolder

Specifies the CSV / JSON output file location (where the data will be exported to).

.PARAMETER OutputType

Specifies the format for the exported data (CSV or JSON). Defaults to CSV.

.OUTPUTS

CSV / JSON file written to disk.

#>
    
    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$False)][String]$ADDriveName = "ADHunting",
        [Parameter(Mandatory=$False)]$PrivilegedSIDs = $null,
        [Parameter(Mandatory=$False)][String]$OutputFolder,
        [Parameter(Mandatory=$False)]
            [ValidateSet("JSON","CSV")]
            [string]$OutputType = "CSV"
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)
    $PSDefaultParameterValues.Add("New-PSDrive:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
        $PSDefaultParameterValues.Add("New-PSDrive:Credential", $Credential)
    }

    $DomainName = (Get-ADDomain).DNSRoot
    $OutputFolder = If (!$OutputFolder) { "." } Else { $OutputFolder }
    $OutputPath = "$OutputFolder\${DomainName}_ADCS_Certificates_Templates_$(Get-Date -f yyyy-MM-dd-HHmmss).$($OutputType.ToLower())"
   
    Write-Host "[$($MyInvocation.MyCommand)][*] Enumerating certificates templates..."

    If (!$PrivilegedSIDs) {
        $PrivilegedSIDs = Get-ADHuntingAllPrivilegedSIDs
    }
    $UnprivilegedSIDs = Get-ADHuntingUnprivilegedSIDs

    $ConfigurationNamingContext = $(Get-ADRootDSE).configurationNamingContext
    
    $Output = New-Object System.Collections.ArrayList
    $CTPublishedCount = [ref] 0
    $CTPublishedAndClientAuthCount = [ref] 0
    $CTPublishedAndClientAuthAndUserSuppSubCount = [ref] 0
    $CTPublishedAndClientAuthAndUserSuppSubAndNoMngApprovCount = [ref] 0
    $CTEnrollableByEveryoneCount = [ref] 0
    $CTModifiableByNonPrivCount = [ref] 0
    $CTModifiableByEveryoneCount = [ref] 0

    # Retrieves the Certificate Templates published by Certificate Authorities.
    $CACertificateTemplatesTable = @{}
    $CAs = Get-ADObject -SearchBase $ConfigurationNamingContext -LDAPFilter "(objectClass=pKIEnrollmentService)" -Properties name, certificateTemplates
    Foreach ($CA in $CAs) {
        Foreach ($PublishedCertTemplate in $CAs.certificateTemplates) {
            If ($CACertificateTemplatesTable.ContainsKey($PublishedCertTemplate)) { 
                $CACertificateTemplatesTable[$PublishedCertTemplate] += $CA.name
            }

            Else {
                $CACertificateTemplatesTable[$PublishedCertTemplate] = @()
                $CACertificateTemplatesTable[$PublishedCertTemplate] += $CA.name
            }
        }
    }

    $CertTemplates = Get-ADObject -SearchBase $ConfigurationNamingContext -LDAPFilter "(objectClass=pKICertificateTemplate)" -Properties *
    # $CertTemplates | ForEach-Object {
    Foreach ($CertTemplate in $CertTemplates) {
        try {
            # $CertTemplate = $_

            # A new PSDrive must be created in the ForEach-Object -Parallel loop manually, until transfer current runspace state is implemented.
            # https://github.com/PowerShell/PowerShell/issues/12240
            # https://github.com/PowerShell/PowerShell/issues/11745
            If (!(Get-PSDrive $ADDriveName -ErrorAction SilentlyContinue)) {
                $Env:ADPS_LoadDefaultDrive = 0
                $null = Import-Module ActiveDirectory -DisableNameChecking -SkipEditionCheck -Cmdlet Get-ADReplicationAttributeMetadata
                $null = New-PSDrive -Name $ADDriveName -PSProvider ActiveDirectory -Root "//RootDSE/"
            }

            Add-PrivilegeLevelType

            $ReplicationMetadata = Get-ADReplicationAttributeMetadata -IncludeDeletedObjects -ShowAllLinkedValues "$($CertTemplate["DistinguishedName"].Value)" -Properties "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag", "nTSecurityDescriptor"
            $ReplicationMetadatanTSecurityDescriptor = $ReplicationMetadata | Where-Object { $_.AttributeName -eq "nTSecurityDescriptor" }
            $ReplicationMetadatamsPKICertificateNameFlag = $ReplicationMetadata | Where-Object { $_.AttributeName -eq "msPKI-Certificate-Name-Flag" }
            $ReplicationMetadatamsPKIEnrollmentFlag = $ReplicationMetadata | Where-Object { $_.AttributeName -eq "msPKI-Enrollment-Flag" }

            # Publish status.
            $CertTemplatePublishedBy = $null
            If ($CACertificateTemplatesTable.ContainsKey($CertTemplate["name"].Value)) {
                $CertTemplatePublishedBy = [string]::join(";", $CACertificateTemplatesTable[$CertTemplate["name"].Value])
            }
            $CertTemplateIsPublished = If ($null -ne $CertTemplatePublishedBy) { $True } Else { $False }
            If ($CertTemplateIsPublished) {
                $null = [Threading.Interlocked]::Increment($CTPublishedCount)
            }

            # Client auth.
            $CertTemplateEnhancedKeyUsageList = If ($CertTemplate["pKIExtendedKeyUsage"].Value) { [string]::join(";", $CertTemplate["pKIExtendedKeyUsage"].Value) } Else { "None" }
            $CertTemplateAllowClientAuth = If ($null -eq $CertTemplate["pKIExtendedKeyUsage"].Value -or '' -eq $CertTemplate["pKIExtendedKeyUsage"].Value -or $($CertTemplate["pKIExtendedKeyUsage"].Value | Where-Object { $CERT_EKU_CLIENT_AUTH_OID -contains $_})) { $True } Else { $False }
            If ($CertTemplateIsPublished -and $CertTemplateAllowClientAuth) {
                $null = [Threading.Interlocked]::Increment($CTPublishedAndClientAuthCount)
            }

            # User-supplied subject.
            # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT 0x00010000
            # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME 0x00010000
            $CertTemplateIsUserSuppliedSubject = If ((($CertTemplate["msPKI-Certificate-Name-Flag"].Value -band 0x00000001) -ne '0') -or ($CertTemplate["msPKI-Certificate-Name-Flag"].Value -band 0x00010000) -ne '0') { $True } Else { $False }
            If ($CertTemplateIsPublished -and $CertTemplateAllowClientAuth -and $CertTemplateIsUserSuppliedSubject) {
                $null = [Threading.Interlocked]::Increment($CTPublishedAndClientAuthAndUserSuppSubCount)
            }

            # Manager approval.
            # CT_FLAG_PEND_ALL_REQUESTS 0x00000002
            $CertTemplateRequireMngApproval = If (($CertTemplate["msPKI-Enrollment-Flag"].Value -band 0x00000002) -ne '0') { $True } Else { $False }
            If ($CertTemplateIsPublished -and $CertTemplateAllowClientAuth -and $CertTemplateIsUserSuppliedSubject -and !$CertTemplateRequireMngApproval) {
                $null = [Threading.Interlocked]::Increment($CTPublishedAndClientAuthAndUserSuppSubAndNoMngApprovCount)
            }

            $CertTemplateACL = Get-Acl -Path "${ADDriveName}:\$($CertTemplate["DistinguishedName"])"

            $CertTemplateOwnerIs = "Parsing_error"
            $CertTemplateModificationRightGrantedTo = "Parsing_error"
            $CertTemplateModificationRightsAsString = "Parsing_error"
            $CertTemplateEnrollRightGrantedTo = "Parsing_error"
            $CertTemplateEnrollRightsAsString = "Parsing_error"

            If ($CertTemplateACL) {
                # Process certificate template owner.
                $CertTemplateOwnerSID = $CertTemplateACL.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
                If ($PrivilegedSIDs.Contains($CertTemplateOwnerSID)) {
                    $CertTemplateOwnerIs = [PrivilegeLevel]::Privileged
                }
                ElseIf ($UnprivilegedSIDs.Contains($CertTemplateOwnerSID)) {
                    $CertTemplateOwnerIs = [PrivilegeLevel]::Everyone
                }
                Else {
                    $CertTemplateOwnerIs = [PrivilegeLevel]::NonPrivileged
                }

                $CertTemplateModificationRightGrantedTo = [PrivilegeLevel]::Privileged
                $CertTemplateModificationRightsAsString = ""
                $CertTemplateEnrollRightGrantedTo = [PrivilegeLevel]::Privileged
                $CertTemplateEnrollRightsAsString = ""

                # Process certificate template DACL.           
                Foreach ($CertTemplateACE in $CertTemplateACL.Access) {
                    # Attempt to retrieve SID from CertTemplateACE IdentityReference if automatically translated to principal name.
                    try { $CertTemplateACEAttributedToSID = $CertTemplateACE.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
                    catch { $CertTemplateACEAttributedToSID = $CertTemplateACE.IdentityReference }

                    # Skip access rights granted to privileged principals.
                    If ($PrivilegedSIDs.Contains($CertTemplateACEAttributedToSID)) {
                        continue
                    }
                
                    If (Is-DangerousADACE -ObjectClass $CertTemplate["ObjectClass"].Value -ACE $CertTemplateACE -AttributedToSID $CertTemplateACEAttributedToSID -PrivilegedSIDs $PrivilegedSIDs) {
                        $AccessRightGUIDText = If ($null -ne $CertTemplateACE.ObjectType -and $ACE_GUID_MAPPING.ContainsKey($CertTemplateACE.ObjectType.ToString())) { $ACE_GUID_MAPPING[$CertTemplateACE.ObjectType.ToString()] } Else { "Undefined" }
                        $CertTemplateModificationRightsAsString += "GrantedTo=$($CertTemplateACE.IdentityReference) | GrantedToSID=$CertTemplateACEAttributedToSID | AccessType=$($CertTemplateACE.AccessControlType) | AccesRight=$($CertTemplateACE.ActiveDirectoryRights) | AccessGuid=$($CertTemplateACE.ObjectType) | AccessGuidText=$AccessRightGUIDText | IsInherited=$($CertTemplateACE.IsInherited) | PropagationFlags=$($CertTemplateACE.PropagationFlags);"

                        If ($UnprivilegedSIDs.Contains($CertTemplateACEAttributedToSID)) {
                            $CertTemplateModificationRightGrantedTo = [PrivilegeLevel]::Everyone
                        }
                        ElseIf (!$PrivilegedSIDs.Contains($CertTemplateACEAttributedToSID)) {
                            $CertTemplateModificationRightGrantedTo = [PrivilegeLevel] [math]::Min([int] [PrivilegeLevel]::NonPrivileged, [int] $CertTemplateModificationRightGrantedTo)
                        }
                    }
                
                    If (Is-EnrollmentADACE -ACE $CertTemplateACE) {
                        $CertTemplateEnrollRightsAsString += "GrantedTo=$($CertTemplateACE.IdentityReference) | GrantedToSID=$CertTemplateACEAttributedToSID | AccessType=$($CertTemplateACE.AccessControlType) | AccesRight=$($CertTemplateACE.ActiveDirectoryRights) | AccessGuid=$($CertTemplateACE.ObjectType) | IsInherited=$($CertTemplateACE.IsInherited) | PropagationFlags=$($CertTemplateACE.PropagationFlags);"

                        If ($UnprivilegedSIDs.Contains($CertTemplateACEAttributedToSID)) {
                            $CertTemplateEnrollRightGrantedTo = [PrivilegeLevel]::Everyone
                        }
                        ElseIf (!$PrivilegedSIDs.Contains($CertTemplateACEAttributedToSID)) {
                            $CertTemplateEnrollRightGrantedTo = [PrivilegeLevel] [math]::Min([int] [PrivilegeLevel]::NonPrivileged, [int] $CertTemplateEnrollRightGrantedTo)
                        }
                    }
                }
            }

            If ($CertTemplateIsPublished -and $CertTemplateEnrollRightGrantedTo -eq [PrivilegeLevel]::Everyone) {
                $null = [Threading.Interlocked]::Increment($CTEnrollableByEveryoneCount)
            }
            
            If ($CertTemplateOwnerIs -eq [PrivilegeLevel]::Everyone -or $CertTemplateModificationRightGrantedTo -eq [PrivilegeLevel]::Everyone) {
                $null = [Threading.Interlocked]::Increment($CTModifiableByEveryoneCount)
            }
            ElseIf ($CertTemplateOwnerIs -eq [PrivilegeLevel]::NonPrivileged -or $CertTemplateModificationRightGrantedTo -eq [PrivilegeLevel]::NonPrivileged) {
                $null = [Threading.Interlocked]::Increment($CTModifiableByNonPrivCount)
            }

            $null = $Output.Add([PSCustomObject]@{
                Domain = $DomainName
                Name = $CertTemplate["Name"].Value
                DisplayName = $CertTemplate["displayName"].Value
                DistinguishedName = $CertTemplate["distinguishedName"].Value
                Description = $CertTemplate["description"].Value
                WhenCreated = If ($CertTemplate["whenCreated"].Value) { $CertTemplate["whenCreated"].Value.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                WhenChanged = If ($CertTemplate["whenChanged"].Value) { $CertTemplate["whenChanged"].Value.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                IsPublished = $CertTemplateIsPublished
                PublishedBy = $CertTemplatePublishedBy
                AllowClientAuth = $CertTemplateAllowClientAuth
                EnhancedKeyUsageList = $CertTemplateEnhancedKeyUsageList
                IsUserSuppliedSubject = $CertTemplateIsUserSuppliedSubject
                "msPKI-Certificate-Name-Flag" = $CertTemplate["msPKI-Certificate-Name-Flag"].Value
                "msPKI-Certificate-Name-Flag-WhenLastChanged" = If ($ReplicationMetadatamsPKICertificateNameFlag.LastOriginatingChangeTime) { $ReplicationMetadatamsPKICertificateNameFlag.LastOriginatingChangeTime.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                "msPKI-Certificate-Name-Flag-LastChangedFrom" = If ($ReplicationMetadatamsPKICertificateNameFlag.LastOriginatingChangeDirectoryServerIdentity) { $ReplicationMetadatamsPKICertificateNameFlag.LastOriginatingChangeDirectoryServerIdentity } Else { $null }
                "msPKI-Certificate-Name-Flag-NbTimesChanged" = If ($ReplicationMetadatamsPKICertificateNameFlag.Version) { $ReplicationMetadatamsPKICertificateNameFlag.Version } Else { $null }
                RequireManagerApproval = $CertTemplateRequireMngApproval
                "msPKI-Enrollment-Flag" = $CertTemplate["msPKI-Enrollment-Flag"].Value
                "msPKI-Enrollment-Flag-WhenLastChanged" = If ($ReplicationMetadatamsPKIEnrollmentFlag.LastOriginatingChangeTime) { $ReplicationMetadatamsPKIEnrollmentFlag.LastOriginatingChangeTime.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                "msPKI-Enrollment-Flag-LastChangedFrom" = If ($ReplicationMetadatamsPKIEnrollmentFlag.LastOriginatingChangeDirectoryServerIdentity) { $ReplicationMetadatamsPKIEnrollmentFlag.LastOriginatingChangeDirectoryServerIdentity } Else { $null }
                "msPKI-Enrollment-Flag-NbTimesChanged" = If ($ReplicationMetadatamsPKIEnrollmentFlag.Version) { $ReplicationMetadatamsPKIEnrollmentFlag.Version } Else { $null }
                "msPKI-Minimal-Key-Size" = $CertTemplate["msPKI-Minimal-Key-Size"].Value
                CertTemplateOwnerIs = $CertTemplateOwnerIs
                CertTemplateModificationRightGrantedTo = $CertTemplateModificationRightGrantedTo
                CertTemplateModificationRightsAsString = $CertTemplateModificationRightsAsString
                CertTemplateEnrollRightGrantedTo = $CertTemplateEnrollRightGrantedTo
                CertTemplateEnrollRightsAsString = $CertTemplateEnrollRightsAsString
                "nTSecurityDescriptor-WhenLastChanged" = If ($ReplicationMetadatanTSecurityDescriptor.LastOriginatingChangeTime) { $ReplicationMetadatanTSecurityDescriptor.LastOriginatingChangeTime.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                "nTSecurityDescriptor-LastChangedFrom" = If ($ReplicationMetadatanTSecurityDescriptor.LastOriginatingChangeDirectoryServerIdentity) { $ReplicationMetadatanTSecurityDescriptor.LastOriginatingChangeDirectoryServerIdentity } Else { $null }
                "nTSecurityDescriptor-NbTimesChanged" = If ($ReplicationMetadatanTSecurityDescriptor.Version) { $ReplicationMetadatanTSecurityDescriptor.Version } Else { $null }
            })
        }

        catch {
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingADCSCertificateTemplates][-] Error while processing certificate template '$CertTemplate'"
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingADCSCertificateTemplates][-] Exception: $_"
        }

    }

    If ($Output.Count -gt 0) {
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($Output.Count) certificate templates, for a total of $($CTPublishedCount.Value) certificate templates published by at least one CA"
        Write-Host "[$($MyInvocation.MyCommand)][*] $($CTPublishedAndClientAuthCount.value) published certificate templates allow client authentication"
        Write-Host "[$($MyInvocation.MyCommand)][*] Among those $($CTPublishedAndClientAuthAndUserSuppSubCount.value) certificate templates use user-supplied input for the subject (with $($CTPublishedAndClientAuthAndUserSuppSubAndNoMngApprovCount.value) not requiring manager approval)"
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($CTEnrollableByEveryoneCount.value) published certificate templates can be enrolled by everyone"
        Write-Host "[$($MyInvocation.MyCommand)][*] Found certificate templates that can have sensitive attributes modified by: everyone $($CTModifiableByEveryoneCount.value) | non-privilege principals $($CTModifiableByNonPrivCount.value)"
        If ($OutputType -eq "CSV") {
            $Output | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutputPath
        }
        ElseIf ($OutputType -eq "JSON") {
            $Output | ConvertTo-Json -depth 100 | Out-File -Encoding UTF8 -Path $OutputPath
        }
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] Certificate templates information written to '$OutputPath'"
    }
    Else {
        Write-Host "[$($MyInvocation.MyCommand)][-] No certificate templates found, an error likely occured or AD CS is not present in the environment"
    }
}

########################################################
#
#
# kerberos DONT_REQ_PREAUTH persistence.
#
#
########################################################

function Export-ADHuntingPrincipalsDontRequirePreAuth {
<#
.SYNOPSIS

Export to a CSV / JSON file the accounts that do not require Kerberos pre-authentication.

Required Dependencies: ActiveDirectory module and Get-ADHuntingAllPrivilegedSIDs.

.DESCRIPTION

Export accounts that do not require Kerberos pre-authentication, i.e accounts with the DONT_REQ_PREAUTH flag set in their UserAccountControl attribute.

Such accounts are vulnerable to the AS_REP roasting attack.

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER PrivilegedSIDs

Specifies the privileged SIDs in the domain. If not specified, the privileged SIDs are enumerated using Get-ADHuntingAllPrivilegedSIDs.
Used for optimization purposes for subsequent calls to AD Hunting functions.

.PARAMETER OutputFolder

Specifies the CSV / JSON output file location (where the data will be exported to).

.PARAMETER OutputType

Specifies the format for the exported data (CSV or JSON). Defaults to CSV.

.OUTPUTS

CSV / JSON file written to disk.

#>

    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$False)]$PrivilegedSIDs = $null,
        [Parameter(Mandatory=$False)][String]$OutputFolder,
        [Parameter(Mandatory=$False)]
            [ValidateSet("JSON","CSV")]
            [string]$OutputType = "CSV"
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
    }

    $DomainName = (Get-ADDomain).DNSRoot
    $OutputFolder = If (!$OutputFolder) { "." } Else { $OutputFolder }
    $OutputPath = "$OutputFolder\${DomainName}_Principals_DontRequirePreAuth_$(Get-Date -f yyyy-MM-dd-HHmmss).$($OutputType.ToLower())"

    Write-Host "[$($MyInvocation.MyCommand)][*] Enumerating principals that do not require Kerberos pre-authentication..."

    $ADObjects =  Get-ADObject -LDAPFilter "(useraccountcontrol:1.2.840.113556.1.4.803:=4194304)" -Properties $ACCOUNT_EXTENDED_PROPERTIES_SET
    If ($ADObjects.Count -eq 0) {
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] No principals that do not require Kerberos pre-authentication found"
        return
    }

    If (!$PrivilegedSIDs) {
        $PrivilegedSIDs = Get-ADHuntingAllPrivilegedSIDs
    }
    
    $funcDefConvertUnixTimeToISO8601 = ${function:Convert-UnixTimeToISO8601}.ToString()

    $Output = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $PrivilegedPrincipalsCount = [ref] 0

    $ADObjects | ForEach-Object -Parallel {
        try {
            $Output = $using:Output
            $PSDefaultParameterValues = $using:PSDefaultParameterValues
            $DomainName = $using:DomainName
            $PrivilegedSIDs = $using:PrivilegedSIDs
            $PrivilegedPrincipalsCount = $using:PrivilegedPrincipalsCount
            ${function:Convert-UnixTimeToISO8601} = $using:funcDefConvertUnixTimeToISO8601

            $Account = $_
            $AccountReplicationMetadata = Get-ADReplicationAttributeMetadata -IncludeDeletedObjects -ShowAllLinkedValues "$($Account.DistinguishedName)" -Properties userAccountControl
        
            $IsPrivileged = $False
            If ($Account["objectSid"].Value -in $PrivilegedSIDs) { 
                $IsPrivileged = $True
                $null = [Threading.Interlocked]::Increment($PrivilegedPrincipalsCount)
            }

            $null = $Output.Add([PSCustomObject]@{
                Domain = $DomainName
                Name = $Account["Name"].Value
                DistinguishedName = $Account["DistinguishedName"].Value
                SID = $Account["objectSid"].Value.Value
                IsPrivileged = $IsPrivileged
                CurrentUAC = $Account["userAccountControl"].Value
                LastReplicatedUAC = If ($AccountReplicationMetadata.AttributeValue) { $AccountReplicationMetadata.AttributeValue } Else { $null }
                WhenLastChangedUAC = If ($AccountReplicationMetadata.LastOriginatingChangeTime) { $AccountReplicationMetadata.LastOriginatingChangeTime.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                LastChangedUACFrom = If ($AccountReplicationMetadata.LastOriginatingChangeDirectoryServerIdentity) { $AccountReplicationMetadata.LastOriginatingChangeDirectoryServerIdentity } Else { $null }
                NbTimesChangedUAC = If ($AccountReplicationMetadata.Version) { $AccountReplicationMetadata.Version } Else { $null }
                WhenCreated = If ($Account["whenCreated"].Value) { $Account["whenCreated"].Value.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                pwdLastSet = If ($Account["pwdLastSet"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Account["pwdLastSet"].Value } Else { $null }
                lastLogon = If ($Account["lastLogon"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Account["lastLogon"].Value } Else { $null }
                lastLogonTimestamp = If ($Account["lastLogonTimestamp"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Account["lastLogonTimestamp"].Value } Else { $null }
            })
        }
        
        catch {
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingPrincipalsDontRequirePreAuth][-] Error while processing principal $Account"
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingPrincipalsDontRequirePreAuth][-] Exception: $_"
        }
    }
    If ($Output.Count -gt 0) {
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($Output.Count) principals, including $($PrivilegedPrincipalsCount.Value) privileged principals, that do not require Kerberos pre-authentication"
        If ($OutputType -eq "CSV") {
            $Output | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutputPath
        }
        ElseIf ($OutputType -eq "JSON") {
            $Output | ConvertTo-Json -depth 100 | Out-File -Encoding UTF8 -Path $OutputPath
        }
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] Principals that do not require Kerberos pre-authentication information written to '$OutputPath'"
    }
    Else {
        Write-Host -ForegroundColor DarkYellow "[$($MyInvocation.MyCommand)][-] Error while processing principals that do not require Kerberos pre-authentication, no information exported"
    }
}

########################################################
#
#
# ACL persistence.
#
#
########################################################

function Export-ADHuntingACLPrivilegedObjects {
<#
.SYNOPSIS

Export to a CSV / JSON file the ACL configured on the privileged objects in the domain and highlight potentially dangerous access rights.

Required Dependencies: ActiveDirectory module, Get-ADHuntingAllPrivilegedSIDs, Get-ADHuntingUnprivilegedSIDs, Get-ADHuntingAllPrivilegedObjects, and Is-DangerousADACE.

.DESCRIPTION

Export to a CSV / JSON file the ACL configured on the following privileged objects (retrieved using Get-ADHuntingAllPrivilegedObjects):
  - The Domain Root object.
  - The Domain Root object's linked GPO(s).
  - The AdminSDHolder container.
  - The privileged principals (even if protected by SDProp), retrieved using Get-ADHuntingAllPrivilegedSIDs.
  - The OUs any privileged users / computers reside (processed recursively until the root OU).
  - The GPO(s) linked to "privileged" OU (only returning enforced GPO after an OU that block inheritance is found).
  - The Domain schema container.
  - The CN=MicrosoftDNS,CN=System container.
  - The msDFSR-GlobalSettings and msDFSR-ReplicationGroup containers.
  - The Domain Controllers group.
  - The Domain Controller machine accounts.
  - The Domain Controllers OU.
  - The Domain Controllers OU's linked GPO(s).
  - For each Domain Controller machine account, its site and site's linked GPO(s).
  - The "Dns Admins" group and its member(s).
  - DPAPI domain backup keys.
  - Key Distribution Service (KDS) root keys.

Multiple privileged objects are based on work from ANSSI: https://www.cert.ssi.gouv.fr/uploads/guide-ad.html

Potentially dangerous ACE are identified using ADHunting's Is-DangerousADACE.

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER ADDriveName

Specifies the name to use for the ActiveDirectory PSDrive that will be (temporarily) mounted by the cmdlet.
Defaults to ADHunting.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER PrivilegedSIDs

Specifies the privileged SIDs in the domain. If not specified, the privileged SIDs are enumerated using Get-ADHuntingAllPrivilegedSIDs.
Used for optimization purposes for subsequent calls to AD Hunting functions.

.PARAMETER OutputFolder

Specifies the CSV / JSON output file location (where the data will be exported to).

.PARAMETER OutputType

Specifies the format for the exported data (CSV or JSON). Defaults to CSV.

.OUTPUTS

CSV / JSON file written to disk.

#>

    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$False)][String]$ADDriveName = "ADHunting",
        [Parameter(Mandatory=$False)]$PrivilegedSIDs = $null,
        [Parameter(Mandatory=$False)][switch]$OnlyDangerous = $False,
        [Parameter(Mandatory=$False)][String]$OutputFolder,
        [Parameter(Mandatory=$False)]
            [ValidateSet("JSON","CSV")]
            [string]$OutputType = "CSV"
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)
    $PSDefaultParameterValues.Add("New-PSDrive:Server", $Server)
    $PSDefaultParameterValues.Add("Is-DangerousADACE:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
        $PSDefaultParameterValues.Add("New-PSDrive:Credential", $Credential)
        $PSDefaultParameterValues.Add("Is-DangerousADACE:Credential", $Credential)
    }

    $DomainName = (Get-ADDomain).DNSRoot
    $OutputFolder = If (!$OutputFolder) { "." } Else { $OutputFolder }
    $OutputPath = "$OutputFolder\${DomainName}_ACL_Privileged_Objects_$(Get-Date -f yyyy-MM-dd-HHmmss).$($OutputType.ToLower())"

    Write-Host "[$($MyInvocation.MyCommand)][*] Enumerating privileged objects access rights..."

    # Determine once the privileged / unprivileged SIDs to filter out for performance.
    If (!$PrivilegedSIDs) {
        $PrivilegedSIDs = Get-ADHuntingAllPrivilegedSIDs
    }
    $UnprivilegedSIDs = Get-ADHuntingUnprivilegedSIDs
    $AllPrivilegedObjects = Get-ADHuntingAllPrivilegedObjects -PrivilegedSIDs $PrivilegedSIDs
    
    $ObjectsTodo = $AllPrivilegedObjects.Count
    Write-Host "[$($MyInvocation.MyCommand)][*] Will enumerate access rights of $ObjectsTodo privileged objects"
    
    $funcDefIsDangerousACE = ${function:Is-DangerousADACE}.ToString()
    
    $Output = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $ObjectsCount = [ref] 0
    $DangerousACECount = [ref] 0
    $DangerousACECountGrantedToEveryone = [ref] 0

    $AllPrivilegedObjects | ForEach-Object -Parallel {
        try {
            $Output = $using:Output
            $PSDefaultParameterValues = $using:PSDefaultParameterValues
            $ACE_GUID_MAPPING = $using:ACE_GUID_MAPPING
            $ADDriveName = $using:ADDriveName
            $DomainName = $using:DomainName
            $OnlyDangerous = $using:OnlyDangerous
            $PrivilegedSIDs = $using:PrivilegedSIDs
            $UnprivilegedSIDs = $using:UnprivilegedSIDs
            $ObjectsCount = $using:ObjectsCount
            $DangerousACECount = $using:DangerousACECount
            $DangerousACECountGrantedToEveryone = $using:DangerousACECountGrantedToEveryone
            ${function:Is-DangerousADACE} = $using:funcDefIsDangerousACE

            # A new PSDrive must be created in the ForEach-Object -Parallel loop manually, until transfer current runspace state is implemented.
            # https://github.com/PowerShell/PowerShell/issues/12240
            # https://github.com/PowerShell/PowerShell/issues/11745
            If (!(Get-PSDrive $ADDriveName -ErrorAction SilentlyContinue)) {
                $Env:ADPS_LoadDefaultDrive = 0
                $null = Import-Module ActiveDirectory -DisableNameChecking -SkipEditionCheck -Cmdlet Get-ADReplicationAttributeMetadata
                $null = New-PSDrive -Name $ADDriveName -PSProvider ActiveDirectory -Root "//RootDSE/"
            }

            $PrivilegedObject = $_
            $ObjectACL = Get-Acl -Path "${ADDriveName}:\$($PrivilegedObject.DistinguishedName)"
            If (!$ObjectACL) { continue }
            $ObjectReplicationMetadata = Get-ADReplicationAttributeMetadata -IncludeDeletedObjects -ShowAllLinkedValues "$($PrivilegedObject.DistinguishedName)" -Properties nTSecurityDescriptor
            $null = [Threading.Interlocked]::Increment($ObjectsCount)
        
            # Owner have implicit control rights over the object.
            $OwnerSID = $ObjectACL.GetOwner([System.Security.Principal.SecurityIdentifier]).Value

            foreach ($ACE in $ObjectACL.Access) {
                # Attempt to retrieve SID from ACE IdentityReference if automatically translated to principal name.
                try { $AttributedToSID = $ACE.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
                catch { $AttributedToSID = $ACE.IdentityReference.Value }

                $IsGrantedToEveryone = If ($AttributedToSID -in $UnprivilegedSIDs) { $True } Else { $False }

                $IsDangerous = $False
                If (Is-DangerousADACE -ObjectClass $PrivilegedObject["ObjectClass"].Value -ACE $ACE -AttributedToSID $AttributedToSID -PrivilegedSIDs $PrivilegedSIDs) {
                    $IsDangerous = $True
                    $null = [Threading.Interlocked]::Increment($DangerousACECount)
                    If ($IsGrantedToEveryone) { $null = [Threading.Interlocked]::Increment($DangerousACECountGrantedToEveryone) }
                }

                If ($OnlyDangerous -and !$IsDangerous) {
                    continue
                }

                $null = $Output.Add([PSCustomObject]@{
                    Domain = $DomainName
                    Name = $PrivilegedObject["Name"].Value
                    DistinguishedName = $PrivilegedObject["DistinguishedName"].Value
                    ObjectClass = $PrivilegedObject["ObjectClass"].Value
                    OwnerName = $ObjectACL.Owner
                    OwnerSID = $OwnerSID
                    AccessControlType = $ACE.AccessControlType
                    AttributedToName = $ACE.IdentityReference.Value
                    AttributedToSID = $AttributedToSID
                    AccessRights = $ACE.ActiveDirectoryRights
                    AccessRightGUID = $ACE.ObjectType
                    AccessRightGUIDText = If ($ACE.ObjectType) { $ACE_GUID_MAPPING[$ACE.ObjectType.ToString()] } Else { $null }
                    InheritanceFlags = $ACE.InheritanceFlags
                    PropagationFlags = $ACE.PropagationFlags
                    PotentiallyDangerousRight = $IsDangerous
                    SourcePrincipalIsEveryone = $IsGrantedToEveryone
                    WhenLastChangedSecurityDescriptor = If ($ObjectReplicationMetadata.LastOriginatingChangeTime) { $ObjectReplicationMetadata.LastOriginatingChangeTime.ToString('yyyy-MM-dd HH:mm:ss.fff')} Else { $null }
                    LastChangedSecurityDescriptorFrom = If ($ObjectReplicationMetadata.LastOriginatingChangeDirectoryServerIdentity) { $ObjectReplicationMetadata.LastOriginatingChangeDirectoryServerIdentity } Else { $null }
                    NbTimesChangedSecurityDescriptor = If ($ObjectReplicationMetadata.Version) { $ObjectReplicationMetadata.Version } Else { $null }
                })
            }
        }
        
        catch {
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingACLPrivilegedObjects][-] Error while processing object $($PrivilegedObject.DistinguishedName)"
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingACLPrivilegedObjects][-] Exception: $_"
        }
        
    }
    
    If ($Output.Count -gt 0) {
        Write-Host "[$($MyInvocation.MyCommand)][*] Enumerated ACL of $($ObjectsCount.Value) privileged objects (initial objects count: $ObjectsTodo) and $($Output.Count) total access rights"
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($DangerousACECount.Value) dangerous access rights that allow object takeover granted to non privileged principals"
        Write-Host "[$($MyInvocation.MyCommand)][*] Including $($DangerousACECountGrantedToEveryone.Value) dangerous access rights granted to everyone"
        If ($OutputType -eq "CSV") {
            $Output | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutputPath
        }
        ElseIf ($OutputType -eq "JSON") {
            $Output | ConvertTo-Json -depth 100 | Out-File -Encoding UTF8 -Path $OutputPath
        }
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] Privileged objects access rights information written to '$OutputPath'"
    }
    ElseIf ($OnlyDangerous) {
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] No dangerous access rights found on privileged objects"
    }
    Else { Write-Host -ForegroundColor DarkYellow "[$($MyInvocation.MyCommand)][*] No privileged principals found, an error likely occurred" }
}

function Export-ADHuntingACLDefaultFromSchema {
<#
.SYNOPSIS

Export to a CSV / JSON file the ACL configured in the defaultSecurityDescriptor attribute of Schema classes.

Non-default (as defined in the Microsoft documentation) ACLs are identified and potentially dangerous ACEs are highlighted. 

Required Dependencies: ActiveDirectory module, Get-ADHuntingAllPrivilegedSIDs, Get-ADHuntingUnprivilegedSIDs, and Is-DangerousADACE.

.DESCRIPTION

Export to a CSV / JSON file the ACL configured in the defaultSecurityDescriptor attribute of Schema classes.

These ACL are used for newly created objects as well as for restoring default ACL on an object.
    
Compare the domain default ACL, from defaultSecurityDescriptor attribute of Schema classes, to their expected values from Microsoft documentation / fresh AD install.

Additionally check if any dangerous rights are positioned and retrieve the defaultSecurityDescriptor’s last modification timestamps through replication metadata.

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER PrivilegedSIDs

Specifies the privileged SIDs in the domain. If not specified, the privileged SIDs are enumerated using Get-ADHuntingAllPrivilegedSIDs.
Used for optimization purposes for subsequent calls to AD Hunting functions.

.PARAMETER OutputFolder

Specifies the CSV / JSON output file location (where the data will be exported to).

.PARAMETER OutputType

Specifies the format for the exported data (CSV or JSON). Defaults to CSV.

.OUTPUTS

CSV / JSON file written to disk.

#>

    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$False)]$PrivilegedSIDs = $null,
        [Parameter(Mandatory=$False)][switch]$OnlyDangerous = $False,
        [Parameter(Mandatory=$False)][String]$OutputFolder,
        [Parameter(Mandatory=$False)]
            [ValidateSet("JSON","CSV")]
            [string]$OutputType = "CSV"
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)
    $PSDefaultParameterValues.Add("Is-DangerousADACE:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
        $PSDefaultParameterValues.Add("Is-DangerousADACE:Credential", $Credential)
    }

    Write-Host "[$($MyInvocation.MyCommand)][*] Enumerating default ACL from Schema Classes..."

    $Domain = Get-ADDomain
    $DomainName = $Domain.DNSRoot
    $DomainSID = $Domain.DomainSID

    $OutputFolder = If (!$OutputFolder) { "." } Else { $OutputFolder }
    $OutputPath = "$OutputFolder\${DomainName}_ACL_Schema_Classes_$(Get-Date -f yyyy-MM-dd-HHmmss).$($OutputType.ToLower())"

    # Retrieve the forest root domain SID base. 
    try {
        If ($null -eq $Domain.ParentDomain) {
            $ForestSID = $DomainSID  
        }
        Else {
            $RootDomainName = $(Get-ADForest).RootDomain
            $ForestSID = $(Get-ADObject -LDAPFilter "(&(ObjectClass=trustedDomain)(Name=$RootDomainName)" -Properties securityIdentifier).securityIdentifier
        }
    }
    catch {
        Write-Host -ForegroundColor DarkYellow "[$($MyInvocation.MyCommand)][-] Couldn't determine the forest's root domain SID"
        Write-Host -ForegroundColor DarkYellow "[$($MyInvocation.MyCommand)][-] Exception: $_"
    }

    # Work around if the Enterprise Admins SID (S-1-5-<FOREST>-519) of the forest couldn't be resolved, to replace EA by DA SID, in order to consider that the right is granted to a privileged principal.
    $EASID = ""
    If ($ForestSID) {
        $EASID = (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AccountEnterpriseAdminsSid, $ForestSID)).Value
    }
    Else {
        $EASID = (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AccountDomainAdminsSid, $ForestSID)).Value
    }

    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f4296d69-1c0f-491f-9587-a960b292d070
    $SDDL_ALIAS_TO_SID = @{
        # CERT_PUBLISHERS.
        "CA" = (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AccountCertAdminsSid, $DomainSID)).Value
        # DOMAIN_ADMINS.
        "DA" = (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AccountDomainAdminsSid, $DomainSID)).Value
        # DOMAIN_COMPUTERS.
        "DC" = (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AccountComputersSid, $DomainSID)).Value
        # DOMAIN_DOMAIN_CONTROLLERS.
        "DD" = (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AccountControllersSid, $DomainSID)).Value
        # DOMAIN_GUESTS.
        "DG" = (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AccountGuestSid, $DomainSID)).Value
        # DOMAIN_USERS.
        "DU" = (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AccountDomainUsersSid, $DomainSID)).Value
        # ENTERPRISE_ADMINS.
        "EA" = $EASID
        # ENTERPRISE_DOMAIN_CONTROLLERS.
        "ED" = (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::EnterpriseControllersSid, $DomainSID)).Value
        # GROUP_POLICY_CREATOR_OWNER.
        "PA" = (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AccountPolicyAdminsSid, $DomainSID)).Value
        # RAS_SERVERS.
        "RS" = (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AccountRasAndIasServersSid, $DomainSID)).Value
        # SCHEMA_ADMINISTRATORS.
        "SA" = (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::AccountSchemaAdminsSid, $DomainSID)).Value
        # EVERYONE.
        "WD" = (New-Object System.Security.Principal.SecurityIdentifier ([System.Security.Principal.WellKnownSidType]::WorldSid, $DomainSID)).Value
    }
    
    # https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/find-current-schema-version
    $SCHEMA_OBJECT_VERSION_MAPPING = @{
        "13" = "Windows 2000 Server"
        "30" = "Windows Server 2003"
        "31" = "Windows Server 2003 R2"
        "44" = "Windows Server 2008 RTM"
        "47" = "Windows Server 2008 R2"
        "56" = "Windows Server 2012"
        "69" = "Windows Server 2012 R2"
        "87" = "Windows Server 2016"
        "88" = "Windows Server 2019"
        "89" = "Windows Server 2022"
    }

    # Default security descriptor for Schema classes retrieved from the official Microsoft documentation.
    # For Windows Server 2003 / Windows Server 2003 R2 / Windows Server 2008 / Windows Server 2008 R2 / Windows Server 2012: https://docs.microsoft.com/en-us/windows/win32/adschema/classes-all
    # For Windows Server 2016 / 2019 (no defaultSecurityDescriptor change in 2019): https://docs.microsoft.com/fr-fr/windows-server/identity/ad-ds/deploy/schema-updates
    $CLASSES_DEFAULT_SECURITY_DESCRIPTORS = @{
        "account" = @{
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ACS-Policy" = @{
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ACS-Resource-Limits" = @{
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ACS-Subnet" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Address-Book-Container" = @{
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(OA;;CR;a1990816-4298-11d1-ade2-00c04fd8d5cd;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(OA;;CR;a1990816-4298-11d1-ade2-00c04fd8d5cd;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(OA;;CR;a1990816-4298-11d1-ade2-00c04fd8d5cd;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(OA;;CR;a1990816-4298-11d1-ade2-00c04fd8d5cd;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(OA;;CR;a1990816-4298-11d1-ade2-00c04fd8d5cd;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(OA;;CR;a1990816-4298-11d1-ade2-00c04fd8d5cd;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(OA;;CR;a1990816-4298-11d1-ade2-00c04fd8d5cd;;AU)"
        }
        "Address-Template" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Application-Entity" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Application-Process" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Application-Site-Settings" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Application-Version" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Attribute-Schema" = @{
            "Windows Server 2003" = "D:S:"
            "Windows 2000 Server" = "D:S:"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows Server 2003 R2" = "D:S:"
            "Windows Server 2012" = "D:S:"
            "default" = "D:S:"
            "Windows Server 2008 R2" = "D:S:"
            "Windows Server 2008" = "D:S:"
        }
        "bootableDevice" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Builtin-Domain" = @{
            "Windows 2000 Server" = "D:(A;;RPLCLORC;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPLCLORC;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPLCLORC;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPLCLORC;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPLCLORC;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPLCLORC;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPLCLORC;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Category-Registration" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Certification-Authority" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Class-Registration" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Class-Schema" = @{
            "Windows Server 2003" = "D:S:"
            "Windows 2000 Server" = "D:S:"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows Server 2003 R2" = "D:S:"
            "Windows Server 2012" = "D:S:"
            "default" = "D:S:"
            "Windows Server 2008 R2" = "D:S:"
            "Windows Server 2008" = "D:S:"
        }
        "Class-Store" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Com-Connection-Point" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Computer" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCRLCLORCSDDT;;;CO)(OA;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;CO)(A;;RPLCLORC;;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(A;;CCDC;;;PS)(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;PS)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;CO)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;CO)(OA;;WP;3e0abfd0-126a-11d0-a060-00aa006c33ed;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;bf967950-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCRLCLORCSDDT;;;CO)(OA;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;CO)(A;;RPLCLORC;;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(A;;CCDC;;;PS)(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;PS)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;CO)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;CO)(OA;;WP;3e0abfd0-126a-11d0-a060-00aa006c33ed;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;bf967950-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCRLCLORCSDDT;;;CO)(OA;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;CO)(A;;RPLCLORC;;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(A;;CCDC;;;PS)(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;PS)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;CO)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;CO)(OA;;WP;3e0abfd0-126a-11d0-a060-00aa006c33ed;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;bf967950-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCRLCLORCSDDT;;;CO)(OA;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;CO)(A;;RPLCLORC;;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;;CCDC;;;PS)(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;PS)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;CO)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;CO)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCRLCLORCSDDT;;;CO)(OA;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;CO)(A;;RPLCLORC;;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(A;;CCDC;;;PS)(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;PS)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;CO)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;CO)(OA;;WP;3e0abfd0-126a-11d0-a060-00aa006c33ed;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;bf967950-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCRLCLORCSDDT;;;CO)(OA;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;CO)(A;;RPLCLORC;;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(A;;CCDC;;;PS)(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;PS)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;CO)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;CO)(OA;;WP;3e0abfd0-126a-11d0-a060-00aa006c33ed;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;bf967950-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCRLCLORCSDDT;;;CO)(OA;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;CO)(A;;RPLCLORC;;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(A;;CCDC;;;PS)(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;PS)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;CO)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;CO)(OA;;WP;3e0abfd0-126a-11d0-a060-00aa006c33ed;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;bf967950-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)"
        }
        "Configuration" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 Extended Rights" = "D:S:"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Connection-Point" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Contact" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Container" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Control-Access-Right" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Country" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "CRL-Distribution-Point" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Cross-Ref" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Cross-Ref-Container" = @{
            "Windows Server 2003" = "D:(A;;GA;;;SY)"
            "Windows Server 2008" = "D:(A;;GA;;;SY)"
            "Windows Server 2003 Extended Rights" = "D:S:"
            "Windows 2000 Server" = "D:(A;;GA;;;SY)"
            "Windows Server 2012" = "D:(A;;GA;;;SY)"
            "default" = "D:(A;;GA;;;SY)"
            "Windows Server 2003 R2" = "D:(A;;GA;;;SY)"
            "Windows Server 2008 R2" = "D:(A;;GA;;;SY)"
        }
        "Device" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Dfs-Configuration" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "DHCP-Class" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Display-Specifier" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Display-Template" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "DMD" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 Extended Rights" = "D:S:"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Dns-Node" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;ED)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)(A;;RPLCLORC;;;WD)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;ED)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)(A;;RPLCLORC;;;WD)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;ED)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)(A;;RPLCLORC;;;WD)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;ED)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)(A;;RPLCLORC;;;WD)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;ED)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)(A;;RPLCLORC;;;WD)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;ED)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)(A;;RPLCLORC;;;WD)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;ED)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)(A;;RPLCLORC;;;WD)"
        }
        "Dns-Zone" = @{
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;ED)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;CC;;;AU)(A;;RPLCLORC;;;WD)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;ED)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;CC;;;AU)(A;;RPLCLORC;;;WD)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;ED)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;CC;;;AU)(A;;RPLCLORC;;;WD)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;ED)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;CC;;;AU)(A;;RPLCLORC;;;WD)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;ED)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;CC;;;AU)(A;;RPLCLORC;;;WD)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;ED)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;CC;;;AU)(A;;RPLCLORC;;;WD)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;ED)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;CC;;;AU)(A;;RPLCLORC;;;WD)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
        }
        "Dns-Zone-Scope" = @{
            "Windows Server 2016" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;ED)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;CC;;;AU)(A;;RPLCLORC;;;WD)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;ED)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;CC;;;AU)(A;;RPLCLORC;;;WD)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
        }
        "Dns-Zone-Scope-Container" = @{
            "Windows Server 2016" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;ED)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;CC;;;AU)(A;;RPLCLORC;;;WD)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;ED)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;CC;;;AU)(A;;RPLCLORC;;;WD)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
        }
        "document" = @{
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "documentSeries" = @{
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Domain-DNS" = @{
            "Windows Server 2008" = "D:(A;;RP;;;WD)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCRCWDWOSW;;;DA)(A;CI;RPWPCRLCLOCCRCWDWOSDSW;;;BA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;EA)(A;CI;LC;;;RU)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;c7407360-20bf-11d0-a768-00aa006e0529;;RU)(OA;CIIO;RPLCLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(A;;RPRC;;;RU)(OA;CIIO;RPLCLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(A;;LCRPLORC;;;ED)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RPLCLORC;;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;RU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;AU)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;DD)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;ED)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;BA)(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;S-1-5-32-557)(OA;;CR;280f369c-67c7-438e-ae98-1d46f3c6f541;;AU)(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501;;AU)(OA;;CR;05c74c5e-4deb-43b4-bd9f-86664c2a7fd5;;AU)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;CIIO;CRRPWP;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)S:(AU;SA;WDWOWP;;;WD)(AU;SA;CR;;;BA)(AU;SA;CR;;;DU)(OU;CISA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CISA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"
            "Windows Server 2003" = "D:(A;;RP;;;WD)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCRCWDWOSW;;;DA)(A;CI;RPWPCRLCLOCCRCWDWOSDSW;;;BA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;EA)(A;CI;LC;;;RU)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;c7407360-20bf-11d0-a768-00aa006e0529;;RU)(OA;CIIO;RPLCLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(A;;RPRC;;;RU)(OA;CIIO;RPLCLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(A;;LCRPLORC;;;ED)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RPLCLORC;;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;RU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;AU)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;DD)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;S-1-5-32-557)(OA;;CR;280f369c-67c7-438e-ae98-1d46f3c6f541;;AU)(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501;;AU)(OA;;CR;05c74c5e-4deb-43b4-bd9f-86664c2a7fd5;;AU)S:(AU;SA;WDWOWP;;;WD)(AU;SA;CR;;;BA)(AU;SA;CR;;;DU)(OU;CISA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CISA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"
            "Windows Server 2012" = "D:(A;;RP;;;WD)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCRCWDWOSW;;;DA)(A;CI;RPWPCRLCLOCCRCWDWOSDSW;;;BA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;EA)(A;CI;LC;;;RU)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;c7407360-20bf-11d0-a768-00aa006e0529;;RU)(OA;CIIO;RPLCLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(A;;RPRC;;;RU)(OA;CIIO;RPLCLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(A;;LCRPLORC;;;ED)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RPLCLORC;;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;RU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;AU)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;DD)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;ED)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;BA)(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;S-1-5-32-557)(OA;;CR;280f369c-67c7-438e-ae98-1d46f3c6f541;;AU)(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501;;AU)(OA;;CR;05c74c5e-4deb-43b4-bd9f-86664c2a7fd5;;AU)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;CIIO;CRRPWP;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(OA;;CR;3e0f7e18-2c7a-4c10-ba82-4d926db99a3e;;CN)S:(AU;SA;WDWOWP;;;WD)(AU;SA;CR;;;BA)(AU;SA;CR;;;DU)(OU;CISA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CISA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"
            "default" = "D:(A;;RP;;;WD)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCRCWDWOSW;;;DA)(A;CI;RPWPCRLCLOCCRCWDWOSDSW;;;BA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;EA)(A;CI;LC;;;RU)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;c7407360-20bf-11d0-a768-00aa006e0529;;RU)(OA;CIIO;RPLCLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(A;;RPRC;;;RU)(OA;CIIO;RPLCLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(A;;LCRPLORC;;;ED)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RPLCLORC;;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;RU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;AU)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;DD)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;ED)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;BA)(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;S-1-5-32-557)(OA;;CR;280f369c-67c7-438e-ae98-1d46f3c6f541;;AU)(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501;;AU)(OA;;CR;05c74c5e-4deb-43b4-bd9f-86664c2a7fd5;;AU)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;CIIO;CRRPWP;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(OA;;CR;3e0f7e18-2c7a-4c10-ba82-4d926db99a3e;;CN)S:(AU;SA;WDWOWP;;;WD)(AU;SA;CR;;;BA)(AU;SA;CR;;;DU)(OU;CISA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CISA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"
            "Windows Server 2003 Property Sets" = "D:S:"
            "Windows Server 2003 R2" = "D:(A;;RP;;;WD)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCRCWDWOSW;;;DA)(A;CI;RPWPCRLCLOCCRCWDWOSDSW;;;BA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;EA)(A;CI;LC;;;RU)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;c7407360-20bf-11d0-a768-00aa006e0529;;RU)(OA;CIIO;RPLCLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(A;;RPRC;;;RU)(OA;CIIO;RPLCLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(A;;LCRPLORC;;;ED)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RPLCLORC;;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;RU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;AU)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;DD)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;S-1-5-32-557)(OA;;CR;280f369c-67c7-438e-ae98-1d46f3c6f541;;AU)(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501;;AU)(OA;;CR;05c74c5e-4deb-43b4-bd9f-86664c2a7fd5;;AU)S:(AU;SA;WDWOWP;;;WD)(AU;SA;CR;;;BA)(AU;SA;CR;;;DU)(OU;CISA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CISA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"
            "Windows 2000 Server" = "D:(A;;RP;;;WD)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCRCWDWOSW;;;DA)(A;CI;RPWPCRLCLOCCRCWDWOSDSW;;;BA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;EA)(A;CI;LC;;;RU)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RPLCLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(A;;RC;;;RU)(OA;CIIO;RPLCLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)S:(AU;CISAFA;WDWOSDDTWPCRCCDCSW;;;WD)"
            "Windows Server 2008 R2" = "D:(A;;RP;;;WD)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCRCWDWOSW;;;DA)(A;CI;RPWPCRLCLOCCRCWDWOSDSW;;;BA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;EA)(A;CI;LC;;;RU)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;c7407360-20bf-11d0-a768-00aa006e0529;;RU)(OA;CIIO;RPLCLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(A;;RPRC;;;RU)(OA;CIIO;RPLCLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(A;;LCRPLORC;;;ED)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RPLCLORC;;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;RU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;AU)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;DD)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;ED)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;BA)(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;S-1-5-32-557)(OA;;CR;280f369c-67c7-438e-ae98-1d46f3c6f541;;AU)(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501;;AU)(OA;;CR;05c74c5e-4deb-43b4-bd9f-86664c2a7fd5;;AU)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;CIIO;CRRPWP;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)S:(AU;SA;WDWOWP;;;WD)(AU;SA;CR;;;BA)(AU;SA;CR;;;DU)(OU;CISA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CISA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"
        }
        "Domain-Policy" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "domainRelatedObject" = @{
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "DSA" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "DS-UI-Settings" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Dynamic-Object" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "File-Link-Tracking" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "File-Link-Tracking-Entry" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Foreign-Security-Principal" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a54-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B2-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B3-9455-11d1-AEBD-0000F80367C1;;PS)(A;;RC;;;AU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;AU)(OA;;RP;77B5B886-944A-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;E45795B3-9455-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a54-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B2-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B3-9455-11d1-AEBD-0000F80367C1;;PS)(A;;RC;;;AU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;AU)(OA;;RP;77B5B886-944A-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;E45795B3-9455-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a54-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B2-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B3-9455-11d1-AEBD-0000F80367C1;;PS)(A;;RC;;;AU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;AU)(OA;;RP;77B5B886-944A-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;E45795B3-9455-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a54-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B2-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B3-9455-11d1-AEBD-0000F80367C1;;PS)(A;;RC;;;AU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;AU)(OA;;RP;77B5B886-944A-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;E45795B3-9455-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a54-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B2-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B3-9455-11d1-AEBD-0000F80367C1;;PS)(A;;RC;;;AU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;AU)(OA;;RP;77B5B886-944A-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;E45795B3-9455-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a54-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B2-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B3-9455-11d1-AEBD-0000F80367C1;;PS)(A;;RC;;;AU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;AU)(OA;;RP;77B5B886-944A-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;E45795B3-9455-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a54-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B2-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B3-9455-11d1-AEBD-0000F80367C1;;PS)(A;;RC;;;AU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;AU)(OA;;RP;77B5B886-944A-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;E45795B3-9455-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)"
        }
        "friendlyCountry" = @{
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "FT-Dfs" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)(A;;RPLCLORC;;;AU)"
        }
        "Group" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)"
            "Windows Server 2003 Property Sets" = "D:S:"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)"
        }
        "Group-Of-Names" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "groupOfUniqueNames" = @{
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)"
        }
        "Group-Policy-Container" = @{
            "Windows Server 2008" = "D:P(A;CI;RPWPCCDCLCLOLORCWOWDSDDTSW;;;DA)(A;CI;RPWPCCDCLCLOLORCWOWDSDDTSW;;;EA)(A;CI;RPWPCCDCLCLOLORCWOWDSDDTSW;;;CO)(A;CI;RPWPCCDCLCLORCWOWDSDDTSW;;;SY)(A;CI;RPLCLORC;;;AU)(OA;CI;CR;edacfd8f-ffb3-11d1-b41d-00a0c968f939;;AU)(A;CI;LCRPLORC;;;ED)"
            "Windows Server 2003" = "D:P(A;CI;RPWPCCDCLCLOLORCWOWDSDDTSW;;;DA)(A;CI;RPWPCCDCLCLOLORCWOWDSDDTSW;;;EA)(A;CI;RPWPCCDCLCLOLORCWOWDSDDTSW;;;CO)(A;CI;RPWPCCDCLCLORCWOWDSDDTSW;;;SY)(A;CI;RPLCLORC;;;AU)(OA;CI;CR;edacfd8f-ffb3-11d1-b41d-00a0c968f939;;AU)(A;CI;LCRPLORC;;;ED)"
            "Windows 2000 Server" = "D:P(A;CI;RPWPCCDCLCLOLORCWOWDSDDTSW;;;DA)(A;CI;RPWPCCDCLCLOLORCWOWDSDDTSW;;;EA)(A;CI;RPWPCCDCLCLOLORCWOWDSDDTSW;;;CO)(A;CI;RPWPCCDCLCLORCWOWDSDDTSW;;;SY)(A;CI;RPLCLORC;;;AU)(OA;CI;CR;edacfd8f-ffb3-11d1-b41d-00a0c968f939;;AU)"
            "Windows Server 2012" = "D:P(A;CI;RPWPCCDCLCLOLORCWOWDSDDTSW;;;DA)(A;CI;RPWPCCDCLCLOLORCWOWDSDDTSW;;;EA)(A;CI;RPWPCCDCLCLOLORCWOWDSDDTSW;;;CO)(A;CI;RPWPCCDCLCLORCWOWDSDDTSW;;;SY)(A;CI;RPLCLORC;;;AU)(OA;CI;CR;edacfd8f-ffb3-11d1-b41d-00a0c968f939;;AU)(A;CI;LCRPLORC;;;ED)"
            "default" = "D:P(A;CI;RPWPCCDCLCLOLORCWOWDSDDTSW;;;DA)(A;CI;RPWPCCDCLCLOLORCWOWDSDDTSW;;;EA)(A;CI;RPWPCCDCLCLOLORCWOWDSDDTSW;;;CO)(A;CI;RPWPCCDCLCLORCWOWDSDDTSW;;;SY)(A;CI;RPLCLORC;;;AU)(OA;CI;CR;edacfd8f-ffb3-11d1-b41d-00a0c968f939;;AU)(A;CI;LCRPLORC;;;ED)"
            "Windows Server 2003 R2" = "D:P(A;CI;RPWPCCDCLCLOLORCWOWDSDDTSW;;;DA)(A;CI;RPWPCCDCLCLOLORCWOWDSDDTSW;;;EA)(A;CI;RPWPCCDCLCLOLORCWOWDSDDTSW;;;CO)(A;CI;RPWPCCDCLCLORCWOWDSDDTSW;;;SY)(A;CI;RPLCLORC;;;AU)(OA;CI;CR;edacfd8f-ffb3-11d1-b41d-00a0c968f939;;AU)(A;CI;LCRPLORC;;;ED)"
            "Windows Server 2008 R2" = "D:P(A;CI;RPWPCCDCLCLOLORCWOWDSDDTSW;;;DA)(A;CI;RPWPCCDCLCLOLORCWOWDSDDTSW;;;EA)(A;CI;RPWPCCDCLCLOLORCWOWDSDDTSW;;;CO)(A;CI;RPWPCCDCLCLORCWOWDSDDTSW;;;SY)(A;CI;RPLCLORC;;;AU)(OA;CI;CR;edacfd8f-ffb3-11d1-b41d-00a0c968f939;;AU)(A;CI;LCRPLORC;;;ED)"
        }
        "ieee802Device" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Index-Server-Catalog" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "inetOrgPerson" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a54-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B2-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B3-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;;RS)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;;RS)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;;RS)(A;;RC;;;AU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;AU)(OA;;RP;77B5B886-944A-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;E45795B3-9455-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;;RS)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;WPRP;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)(OA;;WPRP;5805bc62-bdc9-4428-a5e2-856a0f4c185e;;S-1-5-32-561)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a54-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B2-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B3-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;;RS)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;;RS)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;;RS)(A;;RC;;;AU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;AU)(OA;;RP;77B5B886-944A-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;E45795B3-9455-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;;RS)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;WPRP;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)(OA;;WPRP;5805bc62-bdc9-4428-a5e2-856a0f4c185e;;S-1-5-32-561)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a54-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B2-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B3-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;;RS)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;;RS)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;;RS)(A;;RC;;;AU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;AU)(OA;;RP;77B5B886-944A-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;E45795B3-9455-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;;RS)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;WPRP;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a54-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B2-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B3-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;;RS)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;;RS)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;;RS)(A;;RC;;;AU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;AU)(OA;;RP;77B5B886-944A-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;E45795B3-9455-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;;RS)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;WPRP;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)(OA;;WPRP;5805bc62-bdc9-4428-a5e2-856a0f4c185e;;S-1-5-32-561)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a54-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B2-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B3-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;;RS)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;;RS)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;;RS)(A;;RC;;;AU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;AU)(OA;;RP;77B5B886-944A-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;E45795B3-9455-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;;RS)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;WPRP;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)(OA;;WPRP;5805bc62-bdc9-4428-a5e2-856a0f4c185e;;S-1-5-32-561)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a54-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B2-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B3-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;;RS)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;;RS)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;;RS)(A;;RC;;;AU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;AU)(OA;;RP;77B5B886-944A-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;E45795B3-9455-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;;RS)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;WPRP;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)"
        }
        "Infrastructure-Update" = @{
            "Windows Server 2003" = "D:(A;;GA;;;SY)"
            "Windows Server 2008" = "D:(A;;GA;;;SY)"
            "Windows 2000 Server" = "D:(A;;GA;;;SY)"
            "Windows Server 2012" = "D:(A;;GA;;;SY)"
            "default" = "D:(A;;GA;;;SY)"
            "Windows Server 2003 R2" = "D:(A;;GA;;;SY)"
            "Windows Server 2008 R2" = "D:(A;;GA;;;SY)"
        }
        "Intellimirror-Group" = @{
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;CCDC;;;CO)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;CCDC;;;CO)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;CCDC;;;CO)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;CCDC;;;CO)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;CCDC;;;CO)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;CCDC;;;CO)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;CCDC;;;CO)(A;;RPLCLORC;;;AU)"
        }
        "Intellimirror-SCP" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Inter-Site-Transport" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Inter-Site-Transport-Container" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ipHost" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ipNetwork" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ipProtocol" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Ipsec-Base" = @{
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:"
            "default" = "D:"
            "Windows Server 2003 R2" = "D:"
            "Windows Server 2008 R2" = "D:"
            "Windows Server 2003" = "D:"
            "Windows Server 2008" = "D:"
        }
        "Ipsec-Filter" = @{
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:"
            "default" = "D:"
            "Windows Server 2003 R2" = "D:"
            "Windows Server 2008 R2" = "D:"
            "Windows Server 2003" = "D:"
            "Windows Server 2008" = "D:"
        }
        "Ipsec-ISAKMP-Policy" = @{
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:"
            "default" = "D:"
            "Windows Server 2003 R2" = "D:"
            "Windows Server 2008 R2" = "D:"
            "Windows Server 2003" = "D:"
            "Windows Server 2008" = "D:"
        }
        "Ipsec-Negotiation-Policy" = @{
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:"
            "default" = "D:"
            "Windows Server 2003 R2" = "D:"
            "Windows Server 2008 R2" = "D:"
            "Windows Server 2003" = "D:"
            "Windows Server 2008" = "D:"
        }
        "Ipsec-NFA" = @{
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:"
            "default" = "D:"
            "Windows Server 2003 R2" = "D:"
            "Windows Server 2008 R2" = "D:"
            "Windows Server 2003" = "D:"
            "Windows Server 2008" = "D:"
        }
        "Ipsec-Policy" = @{
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:"
            "default" = "D:"
            "Windows Server 2003 R2" = "D:"
            "Windows Server 2008 R2" = "D:"
            "Windows Server 2003" = "D:"
            "Windows Server 2008" = "D:"
        }
        "ipService" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Leaf" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Licensing-Site-Settings" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Link-Track-Object-Move-Table" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Link-Track-OMT-Entry" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Link-Track-Vol-Entry" = @{
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
        }
        "Link-Track-Volume-Table" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Locality" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Lost-And-Found" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Mail-Recipient" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Meeting" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-Authz-Central-Access-Policies" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-Authz-Central-Access-Policy" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-Authz-Central-Access-Rule" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-Authz-Central-Access-Rules" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-COM-Partition" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-COM-PartitionSet" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-DFS-Deleted-Link-v2" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-DFS-Link-v2" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-DFS-Namespace-Anchor" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
        }
        "ms-DFS-Namespace-v2" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-DFSR-Connection" = @{
            "Windows Server 2008" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2008 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2003 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2012" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "default" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
        }
        "ms-DFSR-Content" = @{
            "Windows Server 2008" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2008 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2003 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2012" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "default" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
        }
        "ms-DFSR-ContentSet" = @{
            "Windows Server 2008" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2008 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2003 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2012" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "default" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
        }
        "ms-DFSR-GlobalSettings" = @{
            "Windows Server 2008" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2008 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2003 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2012" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "default" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
        }
        "ms-DFSR-LocalSettings" = @{
            "Windows Server 2008" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2008 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2003 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2012" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "default" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
        }
        "ms-DFSR-Member" = @{
            "Windows Server 2008" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2008 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2003 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2012" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "default" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
        }
        "ms-DFSR-ReplicationGroup" = @{
            "Windows Server 2008" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2008 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2003 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2012" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "default" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
        }
        "ms-DFSR-Subscriber" = @{
            "Windows Server 2008" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2008 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2003 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2012" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "default" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
        }
        "ms-DFSR-Subscription" = @{
            "Windows Server 2008" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2008 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2003 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2012" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "default" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
        }
        "ms-DFSR-Topology" = @{
            "Windows Server 2008" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2008 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2003 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2012" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "default" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
        }
        "ms-DNS-Server-Settings" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-DS-App-Configuration" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-DS-App-Data" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-DS-AuthN-Policies" = @{
            "Windows Server 2012 R2" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2016" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-DS-AuthN-Policy" = @{
            "Windows Server 2012 R2" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2016" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-DS-AuthN-Policy-Silo" = @{
            "Windows Server 2012 R2" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2016" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-DS-AuthN-Policy-Silos" = @{
            "Windows Server 2012 R2" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2016" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-DS-Az-Admin-Manager" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
        }
        "ms-DS-Az-Application" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
        }
        "ms-DS-Az-Operation" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
        }
        "ms-DS-Az-Role" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
        }
        "ms-DS-Az-Scope" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
        }
        "ms-DS-Az-Task" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
        }
        "ms-DS-Claims-Transformation-Policies" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
        }
        "ms-DS-Claims-Transformation-Policy-Type" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
        }
        "ms-DS-Claim-Type" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-DS-Claim-Type-Property-Base" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-DS-Claim-Types" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-DS-Cloud-Extensions" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-DS-Device" = @{
            "Windows Server 2012 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "Windows Server 2016" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "default" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
        }
        "ms-DS-Device-Container" = @{
            "Windows Server 2012 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "Windows Server 2016" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "default" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
        }
        # Default values from Sch64.ldf (previous modifications for Windows Server 2012 R2 Schema in Sch62 and Sch63). 
        "ms-DS-Device-Registration-Service" = @{
            "Windows Server 2012 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "Windows Server 2016" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "default" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
        }
        # Default values from Sch64.ldf (previous modifications for Windows Server 2012 R2 Schema in Sch62 and Sch63).
        "ms-DS-Device-Registration-Service-Container" = @{
            "Windows Server 2012 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "Windows Server 2016" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "default" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
        }
        "ms-DS-Group-Managed-Service-Account" = @{
            "Windows Server 2012" = "D:(OD;;CR;00299570-246d-11d0-a768-00aa006e0529;;WD)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCRLCLORCSDDT;;;CO)(OA;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;CO)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;CO)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;CO)(OA;;WP;3e0abfd0-126a-11d0-a060-00aa006c33ed;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;bf967950-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;PS)(A;;RPLCLORC;;;AU)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;RP;e362ed86-b728-0842-b27d-2dea7a9df218;;WD)"
            "default" = "D:(OD;;CR;00299570-246d-11d0-a768-00aa006e0529;;WD)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCRLCLORCSDDT;;;CO)(OA;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;CO)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;CO)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;CO)(OA;;WP;3e0abfd0-126a-11d0-a060-00aa006c33ed;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;bf967950-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;PS)(A;;RPLCLORC;;;AU)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;RP;e362ed86-b728-0842-b27d-2dea7a9df218;;WD)"
        }
        "ms-DS-Key-Credential" = @{
            "Windows Server 2016" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "default" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
        }
        "ms-DS-Managed-Service-Account" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCRLCLORCSDDT;;;CO)(OA;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;CO)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;CO)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;CO)(OA;;WP;3e0abfd0-126a-11d0-a060-00aa006c33ed;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;bf967950-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;PS)(A;;RPLCLORC;;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;;ED)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCRLCLORCSDDT;;;CO)(OA;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;CO)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;CO)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;CO)(OA;;WP;3e0abfd0-126a-11d0-a060-00aa006c33ed;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;bf967950-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;PS)(A;;RPLCLORC;;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;;ED)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCRLCLORCSDDT;;;CO)(OA;;WP;4c164200-20c0-11d0-a768-00aa006e0529;;CO)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;CO)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;CO)(OA;;WP;3e0abfd0-126a-11d0-a060-00aa006c33ed;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;bf967950-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;WP;bf967953-0de6-11d0-a285-00aa003049e2;bf967a86-0de6-11d0-a285-00aa003049e2;CO)(OA;;SW;f3a64788-5306-11d1-a9c5-0000f80367c1;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;SW;72e39547-7b18-11d1-adef-00c04fd8d5cd;;PS)(A;;RPLCLORC;;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;;ED)"
        }
        "ms-DS-Optional-Feature" = @{
            "Windows Server 2008 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;EA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2012" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;EA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "default" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;EA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
        }
        "ms-DS-Password-Settings" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
        }
        "ms-DS-Password-Settings-Container" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
        }
        "ms-DS-Quota-Container" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPLCLORC;;;BA)(OA;;CR;4ecc03fe-ffc0-4947-b630-eb672a8a9dbc;;WD)"
            "Windows Server 2003 Extended Rights" = "D:S:"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPLCLORC;;;BA)(OA;;CR;4ecc03fe-ffc0-4947-b630-eb672a8a9dbc;;WD)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPLCLORC;;;BA)(OA;;CR;4ecc03fe-ffc0-4947-b630-eb672a8a9dbc;;WD)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPLCLORC;;;BA)(OA;;CR;4ecc03fe-ffc0-4947-b630-eb672a8a9dbc;;WD)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPLCLORC;;;BA)(OA;;CR;4ecc03fe-ffc0-4947-b630-eb672a8a9dbc;;WD)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPLCLORC;;;BA)(OA;;CR;4ecc03fe-ffc0-4947-b630-eb672a8a9dbc;;WD)"
        }
        "ms-DS-Quota-Control" = @{
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPLCLORC;;;BA)"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPLCLORC;;;BA)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPLCLORC;;;BA)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPLCLORC;;;BA)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPLCLORC;;;BA)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPLCLORC;;;BA)"
        }
        "ms-DS-Resource-Properties" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-DS-Resource-Property" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-DS-Resource-Property-List" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-DS-Service-Connection-Point-Publication-Service" = @{
            "default" = "D:S:"
        }
        "ms-DS-Shadow-Principal-Container" = @{
            "Windows Server 2016" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-DS-Value-Type" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)"
        }
        "ms-Exch-Configuration-Container" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-Exch-Advanced-Security-Container" = @{
            "default" = "D:(A;;LC;;;AU)"
        }
        "ms-Exch-Conference-Container" = @{
            "default" = "D:(A;CI;LCLORPRC;;;WD)"
        }
        "ms-Exch-Dynamic-Distribution-List" = @{
            "default" = "D:(A;;RP;;;AU)"
        }
        "ms-Exch-Encryption-Cfg" = @{
            "default" = "D:(A;;RP;;;AU)"
        }
        "ms-Exch-Exchange-Server" = @{
            "default" = "D:(A;;RP;;;AU)"
        }
        "ms-Exch-Key-Management-Server" = @{
            "default" = "D:(A;;RP;;;AU)"
        }
        "ms-Exch-Oma-Carrier" = @{
            "default" = "D:(A;;LCLORPRC;;;AU)"
        }
        "ms-Exch-Oma-Configuration-Container" = @{
            "default" = "D:(A;;LCLORPRC;;;AU)"
        }
        "ms-Exch-Oma-Data-Source" = @{
            "default" = "D:(A;;LCLORPRC;;;AU)"
        }
        "ms-Exch-Oma-Device-Capability" = @{
            "default" = "D:(A;;LCLORPRC;;;AU)"
        }
        "ms-Exch-Oma-Device-Type" = @{
            "default" = "D:(A;;LCLORPRC;;;AU)"
        }
        "ms-Exch-Public-Folder" = @{
            "default" = "D:(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;AU)(OA;;RP;77B5B886-944A-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;E45795B3-9455-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)"
        }
        "ms-Exch-Servers-Container" = @{
            "default" = "D:(A;;LC;;;AU)"
        }
        "ms-Exch-System-Objects-Container" = @{
            "default" = "D:(A;;RPLCLORC;;;AU)"
        }
        "ms-FVE-RecoveryInformation" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
        }
        "ms-ieee-80211-Policy" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-Imaging-PostScanProcess" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-Imaging-PSPs" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-Kds-Prov-RootKey" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)"
        }
        "ms-Kds-Prov-ServerConfiguration" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;EA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)"
        }
        "ms-SPP-Activation-Object" = @{
            "default" = "O:BAG:BAD: (A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPLCLORC;;;AU)"
        }
        "ms-SPP-Activation-Objects-Container" = @{
            "default" = "O:BAG:BAD: (A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPLCLORC;;;AU)"
        }
        "MSMQ-Configuration" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "MSMQ-Custom-Recipient" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "MSMQ-Enterprise-Settings" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "MSMQ-Group" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "MSMQ-Migrated-User" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "MSMQ-Queue" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "MSMQ-Settings" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "MSMQ-Site-Link" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-net-ieee-80211-GroupPolicy" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-net-ieee-8023-GroupPolicy" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-PKI-Enterprise-Oid" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-PKI-Key-Recovery-Agent" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-PKI-Private-Key-Recovery-Agent" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-Print-ConnectionPolicy" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "msSFU-30-Domain-Info" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "msSFU-30-Mail-Aliases" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "msSFU-30-Net-Id" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "msSFU-30-Network-User" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "msSFU-30-NIS-Map-Config" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "MS-SQL-OLAPCube" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "MS-SQL-OLAPDatabase" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "MS-SQL-OLAPServer" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "MS-SQL-SQLDatabase" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "MS-SQL-SQLPublication" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "MS-SQL-SQLRepository" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "MS-SQL-SQLServer" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-TAPI-Rt-Conference" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-TAPI-Rt-Person" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-TPM-Information-Object" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLO;;;DC)(A;;WP;;;CO)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLO;;;DC)(A;;WP;;;CO)"
        }
        "ms-TPM-Information-Objects-Container" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;LOLCCCRP;;;DC)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;LOLCCCRP;;;DC)"
        }
        "ms-WMI-IntRangeParam" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-WMI-IntSetParam" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
        }
        "ms-WMI-MergeablePolicyTemplate" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
        }
        "ms-WMI-ObjectEncoding" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-WMI-PolicyTemplate" = @{
            "Windows Server 2008 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSW;;;DA)(A;;CC;;;PA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2003" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSW;;;DA)(A;;CC;;;PA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2008" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSW;;;DA)(A;;CC;;;PA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2012" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSW;;;DA)(A;;CC;;;PA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "default" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSW;;;DA)(A;;CC;;;PA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2003 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSW;;;DA)(A;;CC;;;PA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
        }
        "ms-WMI-PolicyType" = @{
            "Windows Server 2008 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSW;;;DA)(A;;CC;;;PA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2003" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSW;;;DA)(A;;CC;;;PA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2008" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSW;;;DA)(A;;CC;;;PA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2012" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSW;;;DA)(A;;CC;;;PA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "default" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSW;;;DA)(A;;CC;;;PA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2003 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSW;;;DA)(A;;CC;;;PA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
        }
        "ms-WMI-RangeParam" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
        }
        "ms-WMI-RealRangeParam" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-WMI-Rule" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-WMI-ShadowObject" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-WMI-SimplePolicyTemplate" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
        }
        "ms-WMI-Som" = @{
            "Windows Server 2008 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSW;;;DA)(A;;CC;;;PA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2003" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSW;;;DA)(A;;CC;;;PA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2008" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSW;;;DA)(A;;CC;;;PA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2012" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSW;;;DA)(A;;CC;;;PA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "default" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSW;;;DA)(A;;CC;;;PA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2003 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSW;;;DA)(A;;CC;;;PA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
        }
        "ms-WMI-StringSetParam" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
        }
        "ms-WMI-UintRangeParam" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-WMI-UintSetParam" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPCCDCLCLODTRC;;;AU)"
        }
        "ms-WMI-UnknownRangeParam" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "ms-WMI-WMIGPO" = @{
            "Windows Server 2008 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSW;;;DA)(A;;CC;;;PA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2003" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSW;;;DA)(A;;CC;;;PA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2008" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSW;;;DA)(A;;CC;;;PA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2012" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSW;;;DA)(A;;CC;;;PA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "default" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSW;;;DA)(A;;CC;;;PA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2003 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSW;;;DA)(A;;CC;;;PA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
        }
        "nisMap" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "nisNetgroup" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "nisObject" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "NTDS-Connection" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "NTDS-DSA" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 Extended Rights" = "D:S:"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "NTDS-DSA-RO" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "NTDS-Service" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "NTDS-Site-Settings" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "NTFRS-Member" = @{
            "Windows 2000 Server" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2012" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "default" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2003 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2008 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2003" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2008" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
        }
        "NTFRS-Replica-Set" = @{
            "Windows 2000 Server" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2008 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)(OA;;CCDC;2a132586-9373-11d1-aebc-0000f80367c1;;ED)"
            "Windows Server 2008" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)(OA;;CCDC;2a132586-9373-11d1-aebc-0000f80367c1;;ED)"
            "Windows Server 2003 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2003" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2012" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)(OA;;CCDC;2a132586-9373-11d1-aebc-0000f80367c1;;ED)"
            "default" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)(OA;;CCDC;2a132586-9373-11d1-aebc-0000f80367c1;;ED)"
        }
        "NTFRS-Settings" = @{
            "Windows 2000 Server" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2012" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "default" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2003 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2008 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2003" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2008" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
        }
        "NTFRS-Subscriber" = @{
            "Windows Server 2008" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows 2000 Server" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2012" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "default" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2003 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2008 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2003" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
        }
        "NTFRS-Subscriptions" = @{
            "Windows Server 2008" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows 2000 Server" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2012" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "default" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2003 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2008 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2003" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
        }
        "oncRpc" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Organization" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Organizational-Person" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Organizational-Role" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Organizational-Unit" = @{
            "Windows Server 2003 Extended Rights" = "D:S:"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(OA;;CCDC;bf967a86-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967a9c-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)(A;;RPLCLORC;;;AU)(A;;LCRPLORC;;;ED)(OA;;CCDC;4828CC14-1437-45bc-9B07-AD6F015E5F28;;AO)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(OA;;CCDC;bf967a86-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967a9c-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)(A;;RPLCLORC;;;AU)(A;;LCRPLORC;;;ED)(OA;;CCDC;4828CC14-1437-45bc-9B07-AD6F015E5F28;;AO)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(OA;;CCDC;bf967a86-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967a9c-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)(A;;RPLCLORC;;;AU)(A;;LCRPLORC;;;ED)(OA;;CCDC;4828CC14-1437-45bc-9B07-AD6F015E5F28;;AO)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(OA;;CCDC;bf967a86-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967a9c-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)(A;;RPLCLORC;;;AU)(A;;LCRPLORC;;;ED)(OA;;CCDC;4828CC14-1437-45bc-9B07-AD6F015E5F28;;AO)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(OA;;CCDC;bf967a86-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967a9c-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(OA;;CCDC;bf967a86-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967a9c-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)(A;;RPLCLORC;;;AU)(A;;LCRPLORC;;;ED)(OA;;CCDC;4828CC14-1437-45bc-9B07-AD6F015E5F28;;AO)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(OA;;CCDC;bf967a86-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967a9c-0de6-11d0-a285-00aa003049e2;;AO)(OA;;CCDC;bf967aa8-0de6-11d0-a285-00aa003049e2;;PO)(A;;RPLCLORC;;;AU)(A;;LCRPLORC;;;ED)(OA;;CCDC;4828CC14-1437-45bc-9B07-AD6F015E5F28;;AO)"
        }
        "Package-Registration" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Person" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Physical-Location" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "PKI-Certificate-Template" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "PKI-Enrollment-Service" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "posixAccount" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "posixGroup" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Print-Queue" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;PO)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;PO)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;PO)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;PO)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;PO)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;PO)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;PO)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)(A;;RPLCLORC;;;AU)"
        }
        "Query-Policy" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Remote-Mail-Recipient" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;AU)"
        }
        "Remote-Storage-Service-Point" = @{
            "Windows 2000 Server" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2012" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "default" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2003 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2008 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2003" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2008" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
        }
        "Residential-Person" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "rFC822LocalPart" = @{
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "RID-Manager" = @{
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)S:(AU;SA;CRWP;;;WD)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)S:(AU;SA;CRWP;;;WD)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)S:(AU;SA;CRWP;;;WD)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)S:(AU;SA;CRWP;;;WD)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)S:(AU;SA;CRWP;;;WD)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)S:(AU;SA;CRWP;;;WD)"
        }
        "RID-Set" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "room" = @{
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Rpc-Container" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "rpc-Entry" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "rpc-Group" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "rpc-Profile" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "rpc-Profile-Element" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "rpc-Server" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "rpc-Server-Element" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "RRAS-Administration-Connection-Point" = @{
            "Windows 2000 Server" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2012" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "default" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2003 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2008 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2003" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
            "Windows Server 2008" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;DA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;CO)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)"
        }
        "RRAS-Administration-Dictionary" = @{
            "Windows Server 2008" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows 2000 Server" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2012" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "default" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2003 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2008 R2" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
            "Windows Server 2003" = "D:(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)"
        }
        "Sam-Domain" = @{
            "Windows Server 2008" = "D:(A;;RP;;;WD)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCRCWDWOSW;;;DA)(A;CI;RPWPCRLCLOCCRCWDWOSDSW;;;BA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;EA)(A;CI;LC;;;RU)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;c7407360-20bf-11d0-a768-00aa006e0529;;RU)(OA;CIIO;RPLCLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(A;;RPRC;;;RU)(OA;CIIO;RPLCLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(A;;LCRPLORC;;;ED)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RPLCLORC;;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;RU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;AU)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;DD)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;ED)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;BA)(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;S-1-5-32-557)(OA;;CR;280f369c-67c7-438e-ae98-1d46f3c6f541;;AU)(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501;;AU)(OA;;CR;05c74c5e-4deb-43b4-bd9f-86664c2a7fd5;;AU)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;CIIO;CRRPWP;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)S:(AU;SA;WDWOWP;;;WD)(AU;SA;CR;;;BA)(AU;SA;CR;;;DU)(OU;CISA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CISA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"
            "Windows Server 2003" = "D:(A;;RP;;;WD)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCRCWDWOSW;;;DA)(A;CI;RPWPCRLCLOCCRCWDWOSDSW;;;BA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;EA)(A;CI;LC;;;RU)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;c7407360-20bf-11d0-a768-00aa006e0529;;RU)(OA;CIIO;RPLCLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(A;;RPRC;;;RU)(OA;CIIO;RPLCLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(A;;LCRPLORC;;;ED)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RPLCLORC;;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;RU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;AU)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;DD)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;S-1-5-32-557)(OA;;CR;280f369c-67c7-438e-ae98-1d46f3c6f541;;AU)(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501;;AU)(OA;;CR;05c74c5e-4deb-43b4-bd9f-86664c2a7fd5;;AU)S:(AU;SA;WDWOWP;;;WD)(AU;SA;CR;;;BA)(AU;SA;CR;;;DU)(OU;CISA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CISA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"
            "Windows Server 2012" = "D:(A;;RP;;;WD)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCRCWDWOSW;;;DA)(A;CI;RPWPCRLCLOCCRCWDWOSDSW;;;BA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;EA)(A;CI;LC;;;RU)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;c7407360-20bf-11d0-a768-00aa006e0529;;RU)(OA;CIIO;RPLCLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(A;;RPRC;;;RU)(OA;CIIO;RPLCLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(A;;LCRPLORC;;;ED)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RPLCLORC;;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;RU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;AU)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;DD)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;ED)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;BA)(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;S-1-5-32-557)(OA;;CR;280f369c-67c7-438e-ae98-1d46f3c6f541;;AU)(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501;;AU)(OA;;CR;05c74c5e-4deb-43b4-bd9f-86664c2a7fd5;;AU)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;CIIO;CRRPWP;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(OA;;CR;3e0f7e18-2c7a-4c10-ba82-4d926db99a3e;;CN)S:(AU;SA;WDWOWP;;;WD)(AU;SA;CR;;;BA)(AU;SA;CR;;;DU)(OU;CISA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CISA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"
            "default" = "D:(A;;RP;;;WD)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCRCWDWOSW;;;DA)(A;CI;RPWPCRLCLOCCRCWDWOSDSW;;;BA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;EA)(A;CI;LC;;;RU)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;c7407360-20bf-11d0-a768-00aa006e0529;;RU)(OA;CIIO;RPLCLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(A;;RPRC;;;RU)(OA;CIIO;RPLCLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(A;;LCRPLORC;;;ED)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RPLCLORC;;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;RU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;AU)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;PS)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;DD)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;ED)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;BA)(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;S-1-5-32-557)(OA;;CR;280f369c-67c7-438e-ae98-1d46f3c6f541;;AU)(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501;;AU)(OA;;CR;05c74c5e-4deb-43b4-bd9f-86664c2a7fd5;;AU)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;CIIO;CRRPWP;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)(OA;;CR;3e0f7e18-2c7a-4c10-ba82-4d926db99a3e;;CN)S:(AU;SA;WDWOWP;;;WD)(AU;SA;CR;;;BA)(AU;SA;CR;;;DU)(OU;CISA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CISA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"
            "Windows Server 2003 R2" = "D:(A;;RP;;;WD)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCRCWDWOSW;;;DA)(A;CI;RPWPCRLCLOCCRCWDWOSDSW;;;BA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;EA)(A;CI;LC;;;RU)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;c7407360-20bf-11d0-a768-00aa006e0529;;RU)(OA;CIIO;RPLCLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(A;;RPRC;;;RU)(OA;CIIO;RPLCLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(A;;LCRPLORC;;;ED)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RPLCLORC;;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;RU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;AU)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;DD)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;S-1-5-32-557)(OA;;CR;280f369c-67c7-438e-ae98-1d46f3c6f541;;AU)(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501;;AU)(OA;;CR;05c74c5e-4deb-43b4-bd9f-86664c2a7fd5;;AU)S:(AU;SA;WDWOWP;;;WD)(AU;SA;CR;;;BA)(AU;SA;CR;;;DU)(OU;CISA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CISA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"
            "Windows 2000 Server" = "D:(A;;RP;;;WD)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCRCWDWOSW;;;DA)(A;CI;RPWPCRLCLOCCRCWDWOSDSW;;;BA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;EA)(A;CI;LC;;;RU)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RPLCLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(A;;RC;;;RU)(OA;CIIO;RPLCLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)S:(AU;CISAFA;WDWOSDDTWPCRCCDCSW;;;WD)"
            "Windows Server 2008 R2" = "D:(A;;RP;;;WD)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;BA)(A;;RPLCLORC;;;AU)(A;;RPWPCRLCLOCCRCWDWOSW;;;DA)(A;CI;RPWPCRLCLOCCRCWDWOSDSW;;;BA)(A;;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;SY)(A;CI;RPWPCRLCLOCCDCRCWDWOSDDTSW;;;EA)(A;CI;LC;;;RU)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(OA;;RP;c7407360-20bf-11d0-a768-00aa006e0529;;RU)(OA;CIIO;RPLCLORC;;bf967a9c-0de6-11d0-a285-00aa003049e2;RU)(A;;RPRC;;;RU)(OA;CIIO;RPLCLORC;;bf967aba-0de6-11d0-a285-00aa003049e2;RU)(A;;LCRPLORC;;;ED)(OA;CIIO;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;CIIO;RPLCLORC;;4828CC14-1437-45bc-9B07-AD6F015E5F28;RU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;RU)(OA;;RP;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;AU)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;ED)(OA;CIIO;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;ED)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;DD)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;ED)(OA;;CR;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;;CR;89e95b76-444d-4c62-991a-0facbeda640c;;BA)(OA;;CR;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;S-1-5-32-557)(OA;;CR;280f369c-67c7-438e-ae98-1d46f3c6f541;;AU)(OA;;CR;ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501;;AU)(OA;;CR;05c74c5e-4deb-43b4-bd9f-86664c2a7fd5;;AU)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;ED)(OA;;CR;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;BA)(OA;CIIO;CRRPWP;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;PS)S:(AU;SA;WDWOWP;;;WD)(AU;SA;CR;;;BA)(AU;SA;CR;;;DU)(OU;CISA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CISA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)"
        }
        "Sam-Server" = @{
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPLCLORC;;;RU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPLCLORC;;;RU)(OA;;CR;91d67418-0135-4acc-8d79-c08e857cfbec;;AU)(OA;;CR;91d67418-0135-4acc-8d79-c08e857cfbec;;RU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPLCLORC;;;RU)(OA;;CR;91d67418-0135-4acc-8d79-c08e857cfbec;;AU)(OA;;CR;91d67418-0135-4acc-8d79-c08e857cfbec;;RU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPLCLORC;;;RU)(OA;;CR;91d67418-0135-4acc-8d79-c08e857cfbec;;AU)(OA;;CR;91d67418-0135-4acc-8d79-c08e857cfbec;;RU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPLCLORC;;;RU)(OA;;CR;91d67418-0135-4acc-8d79-c08e857cfbec;;AU)(OA;;CR;91d67418-0135-4acc-8d79-c08e857cfbec;;RU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPLCLORC;;;RU)(OA;;CR;91d67418-0135-4acc-8d79-c08e857cfbec;;AU)(OA;;CR;91d67418-0135-4acc-8d79-c08e857cfbec;;RU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPLCLORC;;;RU)(OA;;CR;91d67418-0135-4acc-8d79-c08e857cfbec;;AU)(OA;;CR;91d67418-0135-4acc-8d79-c08e857cfbec;;RU)"
        }
        "Secret" = @{
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)"
        }
        "Security-Object" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Server" = @{
            "Windows Server 2008 R2" = "D:(A;CI;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;CI;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows Server 2008" = "D:(A;CI;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;CI;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;CI;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;CI;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;CI;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Servers-Container" = @{
            "Windows 2000 Server" = "D:(A;;CC;;;BA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows Server 2003 R2" = "D:(A;;CC;;;BA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;CC;;;BA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;CC;;;BA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;CC;;;BA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;CC;;;BA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;CC;;;BA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Service-Administration-Point" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Service-Class" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Service-Connection-Point" = @{
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Service-Instance" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "shadowAccount" = @{
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "simpleSecurityObject" = @{
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLOLORCWOWDSDDTDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Site" = @{
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;LCRPLORC;;;ED)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 Extended Rights" = "D:S:"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;LCRPLORC;;;ED)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;LCRPLORC;;;ED)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;LCRPLORC;;;ED)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;LCRPLORC;;;ED)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;LCRPLORC;;;ED)"
        }
        "Site-Link" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Site-Link-Bridge" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Sites-Container" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Storage" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Subnet" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Subnet-Container" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "SubSchema" = @{
            "Windows Server 2003" = "D:S:"
            "Windows 2000 Server" = "D:S:"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows Server 2003 R2" = "D:S:"
            "Windows Server 2012" = "D:S:"
            "default" = "D:S:"
            "Windows Server 2008 R2" = "D:S:"
            "Windows Server 2008" = "D:S:"
        }
        "Top" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 Attributes" = "D:S:"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "Trusted-Domain" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(OA;;WP;736e4812-af31-11d2-b7df-00805f48caeb;bf967ab8-0de6-11d0-a285-00aa003049e2;CO)(A;;SD;;;CO)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(OA;;WP;736e4812-af31-11d2-b7df-00805f48caeb;bf967ab8-0de6-11d0-a285-00aa003049e2;CO)(A;;SD;;;CO)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(OA;;WP;736e4812-af31-11d2-b7df-00805f48caeb;bf967ab8-0de6-11d0-a285-00aa003049e2;CO)(A;;SD;;;CO)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(OA;;WP;736e4812-af31-11d2-b7df-00805f48caeb;bf967ab8-0de6-11d0-a285-00aa003049e2;CO)(A;;SD;;;CO)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(OA;;WP;736e4812-af31-11d2-b7df-00805f48caeb;bf967ab8-0de6-11d0-a285-00aa003049e2;CO)(A;;SD;;;CO)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(OA;;WP;736e4812-af31-11d2-b7df-00805f48caeb;bf967ab8-0de6-11d0-a285-00aa003049e2;CO)(A;;SD;;;CO)"
        }
        "Type-Library" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
        "User" = @{
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a54-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B2-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B3-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;;RS)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;;RS)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;;RS)(A;;RC;;;AU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;AU)(OA;;RP;77B5B886-944A-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;E45795B3-9455-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;;RS)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;WPRP;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)(OA;;WPRP;5805bc62-bdc9-4428-a5e2-856a0f4c185e;;S-1-5-32-561)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a54-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B2-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B3-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;;RS)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;;RS)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;;RS)(A;;RC;;;AU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;AU)(OA;;RP;77B5B886-944A-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;E45795B3-9455-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;;RS)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;WPRP;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)(OA;;WPRP;5805bc62-bdc9-4428-a5e2-856a0f4c185e;;S-1-5-32-561)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a54-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B2-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B3-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;;RS)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;;RS)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;;RS)(A;;RC;;;AU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;AU)(OA;;RP;77B5B886-944A-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;E45795B3-9455-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;;RS)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a54-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B2-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B3-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;;RS)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;;RS)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;;RS)(A;;RC;;;AU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;AU)(OA;;RP;77B5B886-944A-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;E45795B3-9455-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;;RS)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;WPRP;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a54-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B2-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B3-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;;RS)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;;RS)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;;RS)(A;;RC;;;AU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;AU)(OA;;RP;77B5B886-944A-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;E45795B3-9455-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;;RS)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;WPRP;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)(OA;;WPRP;5805bc62-bdc9-4428-a5e2-856a0f4c185e;;S-1-5-32-561)"
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a54-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B2-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B3-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;;RS)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;;RS)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;;RS)(A;;RC;;;AU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;AU)(OA;;RP;77B5B886-944A-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;E45795B3-9455-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;;RS)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;WPRP;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)(OA;;WPRP;5805bc62-bdc9-4428-a5e2-856a0f4c185e;;S-1-5-32-561)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;AO)(A;;RPLCLORC;;;PS)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a54-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;CR;ab721a56-1e2f-11d0-9819-00aa0040529b;;PS)(OA;;RPWP;77B5B886-944A-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B2-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RPWP;E45795B3-9455-11d1-AEBD-0000F80367C1;;PS)(OA;;RP;037088f8-0ae1-11d2-b422-00a0c968f939;;RS)(OA;;RP;4c164200-20c0-11d0-a768-00aa006e0529;;RS)(OA;;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;;RS)(A;;RC;;;AU)(OA;;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;;AU)(OA;;RP;77B5B886-944A-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;E45795B3-9455-11d1-AEBD-0000F80367C1;;AU)(OA;;RP;e48d0154-bcf8-11d1-8702-00c04fb96050;;AU)(OA;;CR;ab721a53-1e2f-11d0-9819-00aa0040529b;;WD)(OA;;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;;RS)(OA;;RPWP;bf967a7f-0de6-11d0-a285-00aa003049e2;;CA)(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;WPRP;6db69a1c-9422-11d1-aebd-0000f80367c1;;S-1-5-32-561)"
        }
        "Volume" = @{
            "Windows Server 2008 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2008" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows 2000 Server" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2012" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "default" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
            "Windows Server 2003 R2" = "D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)"
        }
    }
    
    # Determine once the privileged / unprivileged SIDs to filter out for performance.
    If (!$PrivilegedSIDs) {
        $PrivilegedSIDs = Get-ADHuntingAllPrivilegedSIDs
    }
    $UnprivilegedSIDs = Get-ADHuntingUnprivilegedSIDs
           
    $funcDefIsDangerousACE = ${function:Is-DangerousADACE}.ToString()
    
    $ADRootDSE = Get-ADRootDSE
    $SchemaNamingContext = $ADRootDSE.schemaNamingContext
    
    # Retrive the Schema version, defaulting to 2012 if the version retrieved is not known.
    $SchemaVersionDigit = (Get-ADObject $SchemaNamingContext -Properties objectVersion).objectVersion
    If ($SCHEMA_OBJECT_VERSION_MAPPING.ContainsKey($SchemaVersionDigit)) {
        $SchemaVersion = $SCHEMA_OBJECT_VERSION_MAPPING[$SchemaVersionDigit]
    }
    Else {
        $SchemaVersion = "Windows Server 2012"
    }

    $SchemaClasses = Get-ADObject -SearchBase $SchemaNamingContext -LDAPFilter "(&(objectClass=classSchema)(defaultSecurityDescriptor=*)(!(defaultSecurityDescriptor=D:S:))(!(defaultSecurityDescriptor=D:)))" -Properties lDAPDisplayName, adminDescription, defaultSecurityDescriptor, schemaIDGUID
    
    $Output = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    
    $SchemaClassCount = [ref] 0
    $UnknownDefaultSecDesc = [ref] 0
    $NonDefaultSecDesc = [ref] 0
    $DangerousACECount = [ref] 0
    $DangerousACECountGrantedToEveryone = [ref] 0

    $SchemaClasses | ForEach-Object -Parallel {
        try {
            $Output = $using:Output
            $PSDefaultParameterValues = $using:PSDefaultParameterValues
            $ACE_GUID_MAPPING = $using:ACE_GUID_MAPPING
            $DomainName = $using:DomainName
            $OnlyDangerous = $using:OnlyDangerous
            $SDDL_ALIAS_TO_SID = $using:SDDL_ALIAS_TO_SID
            $SchemaVersion = $using:SchemaVersion
            $CLASSES_DEFAULT_SECURITY_DESCRIPTORS = $using:CLASSES_DEFAULT_SECURITY_DESCRIPTORS
            $PrivilegedSIDs = $using:PrivilegedSIDs
            $UnprivilegedSIDs = $using:UnprivilegedSIDs
            $SchemaClassCount = $using:SchemaClassCount
            $UnknownDefaultSecDesc = $using:UnknownDefaultSecDesc
            $NonDefaultSecDesc = $using:NonDefaultSecDesc
            $DangerousACECount = $using:DangerousACECount
            $DangerousACECountGrantedToEveryone = $using:DangerousACECountGrantedToEveryone
            ${function:Is-DangerousADACE} = $using:funcDefIsDangerousACE
            
            $SchemaClass = $_

            $null = [Threading.Interlocked]::Increment($SchemaClassCount)

            $SchemaClassReplicationMetadata = Get-ADReplicationAttributeMetadata -IncludeDeletedObjects -ShowAllLinkedValues "$($SchemaClass.DistinguishedName)" -Properties defaultSecurityDescriptor

            $ClassName = $SchemaClass["Name"].Value
            $SecDescriptorAsSDDL = $SchemaClass["defaultSecurityDescriptor"].Value

            $IsSecurityDescriptorDefault = $null
            If ($CLASSES_DEFAULT_SECURITY_DESCRIPTORS.ContainsKey($ClassName)) {
                # If a security descriptor for the given Schema Class and version is not known, use the "default" key. 
                $ClassSchemaVersion = If ($CLASSES_DEFAULT_SECURITY_DESCRIPTORS[$ClassName].ContainsKey($SchemaVersion)) { $SchemaVersion } Else { "default" }
                $DefaultSecDescriptorAsSDDL = $CLASSES_DEFAULT_SECURITY_DESCRIPTORS[$ClassName][$ClassSchemaVersion]
                $IsSecurityDescriptorDefault = If ($SecDescriptorAsSDDL -eq $DefaultSecDescriptorAsSDDL) { $True } Else { $False }
            }
            Else {
                $IsSecurityDescriptorDefault = "UnknownACLForClass"
                $null = [Threading.Interlocked]::Increment($UnknownDefaultSecDesc)
            }

            If ($IsSecurityDescriptorDefault -eq $False) {
                $null = [Threading.Interlocked]::Increment($NonDefaultSecDesc)
            }

            # Use SDDL_ALIAS_TO_SID to replace domain principals aliases (DA, EA, etc.) by their SID.
            foreach ($Alias in $SDDL_ALIAS_TO_SID.GetEnumerator()) {
                # The alias to replace is not present in the SDDL.
                If (!$SecDescriptorAsSDDL -match ";$($Alias.Key)\)") {
                    continue
                }
                $SecDescriptorAsSDDL = $SecDescriptorAsSDDL -ireplace ";$($Alias.Key)\)", ";$($Alias.Value))"
            }

            $SchemaClassACL = New-Object System.DirectoryServices.ActiveDirectorySecurity
            $SchemaClassACL.SetSecurityDescriptorSddlForm($SecDescriptorAsSDDL)
            
            If ($SchemaClassACL.Access.Count -eq 0) {
                throw "SetSecurityDescriptorSddlForm returned a security descriptor with no (D)ACL"
            }
            
            foreach ($ACE in $SchemaClassACL.Access) {
                # Attempt to retrieve SID from ACE IdentityReference if automatically translated to principal name.
                try { $AttributedToSID = $ACE.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
                catch { $AttributedToSID = $ACE.IdentityReference.Value }

                $IsGrantedToEveryone = If ($AttributedToSID -in $UnprivilegedSIDs) { $True } Else { $False }

                $IsDangerous = $False
                If (Is-DangerousADACE -ObjectClass $SchemaClass["ObjectClass"].Value -ACE $ACE -AttributedToSID $AttributedToSID -PrivilegedSIDs $PrivilegedSIDs) {
                    $IsDangerous = $True
                    $null = [Threading.Interlocked]::Increment($DangerousACECount)
                    If ($IsGrantedToEveryone) { $null = [Threading.Interlocked]::Increment($DangerousACECountGrantedToEveryone) }
                }

                If ($OnlyDangerous -and !$IsDangerous) {
                    continue
                }

                $null = $Output.Add([PSCustomObject]@{
                    Domain = $DomainName
                    Name = $ClassName
                    LDAPDisplayName = $SchemaClass["lDAPDisplayName"].Value
                    DistinguishedName = $SchemaClass["DistinguishedName"].Value
                    SchemaIDGUID = $SchemaClass["schemaIDGUID"].Value -as [guid]
                    Description = $SchemaClass["adminDescription"].Value
                    DefaultSecurityDescriptorAsSDDL = $SchemaClass["defaultSecurityDescriptor"].Value
                    IsSecurityDescriptorDefault = $IsSecurityDescriptorDefault
                    AccessControlType = $ACE.AccessControlType
                    AttributedToName = $ACE.IdentityReference.Value
                    AttributedToSID = $AttributedToSID
                    AccessRights = $ACE.ActiveDirectoryRights
                    AccessRightGUID = $ACE.ObjectType
                    AccessRightGUIDText = If ($ACE.ObjectType) { $ACE_GUID_MAPPING[$ACE.ObjectType.ToString()] } Else { $null }
                    InheritanceFlags = $ACE.InheritanceFlags
                    PropagationFlags = $ACE.PropagationFlags
                    PotentiallyDangerousRight = $IsDangerous
                    SourcePrincipalIsEveryone = $IsGrantedToEveryone
                    WhenLastdefaultSecurityDescriptor = If ($SchemaClassReplicationMetadata.LastOriginatingChangeTime) { $SchemaClassReplicationMetadata.LastOriginatingChangeTime.ToString('yyyy-MM-dd HH:mm:ss.fff')} Else { $null }
                    LastChangeddefaultSecurityDescriptorFrom = If ($SchemaClassReplicationMetadata.LastOriginatingChangeDirectoryServerIdentity) { $SchemaClassReplicationMetadata.LastOriginatingChangeDirectoryServerIdentity } Else { $null }
                    NbTimesChangeddefaultSecurityDescriptor = If ($SchemaClassReplicationMetadata.Version) { $SchemaClassReplicationMetadata.Version } Else { $null }
                })
            }
        }

        catch {
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingACLDefaultFromSchema][-] Error while processing schema class $($SchemaClass.DistinguishedName)"
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingACLDefaultFromSchema][-] defaultSecurityDescriptor is: $SchemaClass["defaultSecurityDescriptor"].Value"
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingACLDefaultFromSchema][-] Exception: $_"
        }
    }
    
    If ($Output.Count -gt 0) {
        Write-Host "[$($MyInvocation.MyCommand)][*] Enumerated default ACL of $($SchemaClassCount.Value) Schema classes with defaultSecurityDescriptor, for a total of $($Output.Count) access rights found"
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($NonDefaultSecDesc.Value) defaultSecurityDescriptor with a non-default value (and $($UnknownDefaultSecDesc.Value) defaultSecurityDescriptor for unknown Schema classes)"
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($DangerousACECount.Value) dangerous access rights that would allow new objects takeover granted to non privileged principals"
        Write-Host "[$($MyInvocation.MyCommand)][*] Including $($DangerousACECountGrantedToEveryone.Value) dangerous access rights granted to everyone"
        If ($OutputType -eq "CSV") {
            $Output | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutputPath
        }
        ElseIf ($OutputType -eq "JSON") {
            $Output | ConvertTo-Json -depth 100 | Out-File -Encoding UTF8 -Path $OutputPath
        }
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] Privileged objects access rights information written to '$OutputPath'"
    }
    ElseIf ($OnlyDangerous) {
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] No dangerous access rights found on Schema classes"
    }
    Else { Write-Host -ForegroundColor DarkYellow "[$($MyInvocation.MyCommand)][*] No ACL found on Schema classes, an error likely occurred" }
}

function Export-ADHuntingACLDangerousAccessRights {
<#
.SYNOPSIS

Export to a CSV / JSON file the dangerous ACEs, i.e ACE that allow takeover of the underlying object, on all the domain's objects.

May take a while on larger domain.

Required Dependencies: ActiveDirectory module, Get-ADHuntingAllPrivilegedSIDs, and Is-DangerousADACE.

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER ADDriveName

Specifies the name to use for the ActiveDirectory PSDrive that will be (temporarily) mounted by the cmdlet.
Defaults to ADHunting.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER PrivilegedSIDs

Specifies the privileged SIDs in the domain. If not specified, the privileged SIDs are enumerated using Get-ADHuntingAllPrivilegedSIDs.
Used for optimization purposes for subsequent calls to AD Hunting functions.

.PARAMETER OutputFolder

Specifies the CSV / JSON output file location (where the data will be exported to).

.PARAMETER OutputType

Specifies the format for the exported data (CSV or JSON). Defaults to CSV.

.OUTPUTS

CSV / JSON file written to disk.

#>

    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$False)][String]$ADDriveName = "ADHunting",
        [Parameter(Mandatory=$False)]$PrivilegedSIDs = $null,
        [Parameter(Mandatory=$False)][String]$OutputFolder,
        [Parameter(Mandatory=$False)]
            [ValidateSet("JSON","CSV")]
            [string]$OutputType = "CSV"
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)
    $PSDefaultParameterValues.Add("New-PSDrive:Server", $Server)
    $PSDefaultParameterValues.Add("Is-DangerousADACE:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
        $PSDefaultParameterValues.Add("New-PSDrive:Credential", $Credential)
        $PSDefaultParameterValues.Add("Is-DangerousADACE:Credential", $Credential)
    }

    $DomainName = (Get-ADDomain).DNSRoot
    
    $OutputFolder = If (!$OutputFolder) { "." } Else { $OutputFolder }
    $OutputPathAccessRights = "$OutputFolder\${DomainName}_ACL_Dangerous_Access_Rights_$(Get-Date -f yyyy-MM-dd-HHmmss).$($OutputType.ToLower())"
    $OutputPathOwner = "$OutputFolder\${DomainName}_ACL_Dangerous_Owners_$(Get-Date -f yyyy-MM-dd-HHmmss).$($OutputType.ToLower())"
    $OutputPathErrors = "$OutputFolder\${DomainName}_ACL_Export-ADHuntingACLDangerousAccessRights_errors_$(Get-Date -f yyyy-MM-dd-HHmmss).$($OutputType.ToLower())"
    Write-Host "[$($MyInvocation.MyCommand)][*] Enumerating dangerous access rights that allow objects takeover..."

    # $ADObjects = (Get-ADRootDSE).namingContexts | ForEach-Object { $(Get-ADObject -SearchBase "$_" -LDAPFIlter "(nTSecurityDescriptor=*)" -Properties DistinguishedName) }
    $ADObjects = Get-ADObject -LDAPFilter "(nTSecurityDescriptor=*)" -Properties DistinguishedName

    If (!$PrivilegedSIDs) {
        $PrivilegedSIDs = [System.Collections.Generic.HashSet[String]] $(Get-ADHuntingAllPrivilegedSIDs)
    }
    $UnprivilegedSIDs = [System.Collections.Generic.HashSet[String]] $(Get-ADHuntingUnprivilegedSIDs)

    $funcDefIsDangerousACE = ${function:Is-DangerousADACE}.ToString()

    $OutputAccessRights = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $OutputOwner = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $OutputErrors = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    
    $OwnerEveryoneCount = [ref] 0
    $AccessRightGrantedToEveryoneCount = [ref] 0

    # $OwnerEveryoneCount = [ref] 0
    # $AccessRightGrantedToEveryoneCount = [ref] 0
    # $SyncCounter = [hashtable]::Synchronized(@{ OwnerEveryoneCount = $OwnerEveryoneCount; AccessRightGrantedToEveryoneCount = $AccessRightGrantedToEveryoneCount})

    $ADObjects | ForEach-Object -ThrottleLimit 15 -Parallel {
        try {
            $OutputAccessRights = $using:OutputAccessRights
            $OutputOwner = $using:OutputOwner
            $OutputErrors = $using:OutputErrors
            $PSDefaultParameterValues = $using:PSDefaultParameterValues
            $ACE_GUID_MAPPING = $using:ACE_GUID_MAPPING
            $ADDriveName = $using:ADDriveName
            $DomainName = $using:DomainName
            $PrivilegedSIDs = $using:PrivilegedSIDs
            $UnprivilegedSIDs = $using:UnprivilegedSIDs
            $OwnerEveryoneCount = $using:OwnerEveryoneCount
            $AccessRightGrantedToEveryoneCount = $using:AccessRightGrantedToEveryoneCount
            ${function:Is-DangerousADACE} = $using:funcDefIsDangerousACE

            $Object = $_
            # Five attempts (max) to help with connectivity error due to multi-threading ("A connection to the directory on which to process the request was unavailable. This is likely a transient condition.")
            $TryCounter = 0
            while ($True) {
                $TryCounter += 1
                try {
                    # A new PSDrive must be created in the ForEach-Object -Parallel loop manually, until transfer current runspace state is implemented.
                    # https://github.com/PowerShell/PowerShell/issues/12240
                    # https://github.com/PowerShell/PowerShell/issues/11745
                    If (!(Get-PSDrive $ADDriveName -ErrorAction SilentlyContinue)) {
                        Start-Sleep -Seconds 1
                        $Env:ADPS_LoadDefaultDrive = 0
                        $null = Import-Module ActiveDirectory -DisableNameChecking -SkipEditionCheck -Cmdlet Get-ADReplicationAttributeMetadata
                        $null = New-PSDrive -Name $ADDriveName -PSProvider ActiveDirectory -Root "//RootDSE/"
                    }
                    $ObjectACL = Get-Acl -Path "${ADDriveName}:\$($Object.DistinguishedName)" 2>$null
                    If (!$ObjectACL) { throw "Error object ACL parsed with Get-Acl are null" }
                    $ObjectReplicationMetadata = Get-ADReplicationAttributeMetadata -IncludeDeletedObjects -ShowAllLinkedValues "$($Object.DistinguishedName)" -Properties nTSecurityDescriptor       
                    $OwnerSID = $ObjectACL.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
                    # If code reaches the break it means that the ACL and replication metadata were retrieved with out throwing an exception.
                    break
                }
                catch {
                    If ($TryCounter -eq 5) {
                        Start-Sleep -Milliseconds 100
                        throw $_
                    }
                }
            }

            # Process ownership.
            If (!$PrivilegedSIDs.Contains($OwnerSID)) {
            
                $OwnerIsEveryone = $False
                If ($UnprivilegedSIDs.Contains($OwnerSID)) {
                    $OwnerIsEveryone = $True
                    $null = [Threading.Interlocked]::Increment($OwnerEveryoneCount)
                }

                $null = $OutputOwner.Add([PSCustomObject]@{
                    Domain = $DomainName
                    ObjectName = $Object["Name"].Value
                    ObjectDistinguishedName = $Object["DistinguishedName"].Value
                    OwnerName = $ObjectACL.Owner
                    OwnerSID = $OwnerSID
                    OwnerIsEveryone = $OwnerIsEveryone
                    WhenLastChangedSecurityDescriptor = If ($ObjectReplicationMetadata.LastOriginatingChangeTime) { $ObjectReplicationMetadata.LastOriginatingChangeTime.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                    LastChangedSecurityDescriptorFrom = If ($ObjectReplicationMetadata.LastOriginatingChangeDirectoryServerIdentity) { $ObjectReplicationMetadata.LastOriginatingChangeDirectoryServerIdentity } Else { $null }
                    NbTimesChangedSecurityDescriptor = If ($ObjectReplicationMetadata.Version) { $ObjectReplicationMetadata.Version } Else { $null }
                })
            }
            
            # Process access rights.
            foreach ($ACE in $ObjectACL.Access) {
                # Attempt to retrieve SID from ACE IdentityReference if automatically translated to principal name.
                try { $AttributedToSID = $ACE.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
                catch { $AttributedToSID = $ACE.IdentityReference.Value }
                
                If (!(Is-DangerousADACE -ObjectClass $Object["ObjectClass"].Value -ACE $ACE -AttributedToSID $AttributedToSID -PrivilegedSIDs $PrivilegedSIDs)) {
                    continue
                }
                
                $IsGrantedToEveryone = $False
                If ($UnprivilegedSIDs.Contains($AttributedToSID)) {
                    $IsGrantedToEveryone  = $True
                    $null = [Threading.Interlocked]::Increment($AccessRightGrantedToEveryoneCount)
                }

                $null = $OutputAccessRights.Add([PSCustomObject]@{
                    Domain = $DomainName
                    ObjectName = $Object["Name"].Value
                    ObjectDistinguishedName = $Object["DistinguishedName"].Value
                    ObjectClass = $Object["ObjectClass"].Value
                    SourcePrincipalName = $ACE.IdentityReference.Value
                    SourcePrincipalSID = $AttributedToSID
                    SourcePrincipalIsEveryone = $IsGrantedToEveryone
                    AccessControlType = $ACE.AccessControlType
                    AccessRights = $ACE.ActiveDirectoryRights
                    AccessRightGUID = $ACE.ObjectType
                    AccessRightGUIDText = If ($ACE.ObjectType) { $ACE_GUID_MAPPING[$ACE.ObjectType.ToString()] } Else { $null }
                    InheritanceFlags = $ACE.InheritanceFlags
                    PropagationFlags = $ACE.PropagationFlags
                    WhenLastChangedSecurityDescriptor = If ($ObjectReplicationMetadata.LastOriginatingChangeTime) { $ObjectReplicationMetadata.LastOriginatingChangeTime.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                    LastChangedSecurityDescriptorFrom = If ($ObjectReplicationMetadata.LastOriginatingChangeDirectoryServerIdentity) { $ObjectReplicationMetadata.LastOriginatingChangeDirectoryServerIdentity } Else { $null }
                    NbTimesChangedSecurityDescriptor = If ($ObjectReplicationMetadata.Version) { $ObjectReplicationMetadata.Version } Else { $null }
                })
            }
        }
        
        catch {
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingACLDangerousAccessRights][-] Error while processing object $($Object.DistinguishedName)"
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingACLDangerousAccessRights][-] Exception: $_"
            $null = $OutputErrors.Add([PSCustomObject]@{
                Domain = $DomainName
                ObjectName = $Object["Name"].Value
                ObjectDistinguishedName = $Object["DistinguishedName"].Value
                ObjectClass = $Object["ObjectClass"].Value
                Error = $_
            })
        }
    }

    If ($OutputOwner.Count -gt 0) {
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($OutputOwner.Count) objects with a non-privileged principal owner, including $($OwnerEveryoneCount.Value) objects where everyone is owner"
        If ($OutputType -eq "CSV") {
            $OutputOwner | Export-Csv -NoTypeInformation -Encoding UTF8 -Append -Path $OutputPathOwner
        }
        ElseIf ($OutputType -eq "JSON") {
            $OutputOwner | ConvertTo-Json -depth 100 | Out-File -Encoding UTF8 -Path $OutputPathOwner
        }
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] Dangerous ownership information written to '$OutputPathOwner'"
    }
    Else { Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] No non-privileged owners found" }

    If ($OutputAccessRights.Count -gt 0) {
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($OutputAccessRights.Count) access rights allowing objects takeover granted to non-privileged principals, including $($AccessRightGrantedToEveryoneCount.Value) access rights granted to everyone"
        If ($OutputType -eq "CSV") {
            $OutputAccessRights | Export-Csv -NoTypeInformation -Encoding UTF8 -Append -Path $OutputPathAccessRights
        }
        ElseIf ($OutputType -eq "JSON") {
            $OutputAccessRights | ConvertTo-Json -depth 100 | Out-File -Encoding UTF8 -Path $OutputPathAccessRights
        }
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] Dangerous access rights information written to '$OutputPathAccessRights'"
    }
    Else { Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] No dangerous access rights found" }

    If ($OutputErrors.Count -gt 0) {
        Write-Host "[$($MyInvocation.MyCommand)][*] Encountered $($OutputErrors.Count) errors"
        If ($OutputType -eq "CSV") {
            $OutputErrors | Export-Csv -NoTypeInformation -Encoding UTF8 -Append -Path $OutputPathErrors
        }
        ElseIf ($OutputType -eq "JSON") {
            $OutputErrors | ConvertTo-Json -depth 100 | Out-File -Encoding UTF8 -Path $OutputPathErrors
        }
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] Errors information written to '$OutputPathErrors'"
    }
}

########################################################
#
#
# Kerberos persistence.
#
#
########################################################

function Parse-SPN {
<#
.SYNOPSIS

Parse a ServicePrincipalName string into an object.

Original author: Adam Bertram

.DESCRIPTION

Parse a ServicePrincipalName string into the following components:
  - ServiceClass, as a SPN always starts with a service class (HTTP, CIFS, LDAP, etc.).
  - HostName, either NetBIOS or DNS hostname of the service.
  - Port, optionnal port of the service.
  - ServiceName, optionnal service name trailing the SPN.

More information on SPN format: https://docs.microsoft.com/en-us/windows/win32/ad/name-formats-for-unique-spns

Original author: Adam Bertram
Source: https://github.com/adbertram/Random-PowerShell-Work/blob/master/ActiveDirectory/ActiveDirectorySPN.psm1

.PARAMETER SPN

Specifies the SPN string to parse.

.OUTPUTS

[PSCustomObject]

.EXAMPLE

Parse-SPN -SPN "www/LabAD-DC1.forest1.loc"

www/LabAD-DC1.forest1.loc

ServiceClass Port HostName              ServiceName
------------ ---- --------              -----------
www               LabAD-DC1.forest1.loc

.EXAMPLE

Parse-SPN -SPN "www/LabAD-DC1.forest1.loc:1337/forest1.loc"

www/LabAD-DC1.forest1.loc:1337/forest1.loc

ServiceClass Port HostName              ServiceName
------------ ---- --------              -----------
www          1337 LabAD-DC1.forest1.loc forest1.loc

#>

    Param(
        [Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][String]$SPN
    )

	try {
		$Output = @{
			ServiceClass = $null
			HostName = $null
			Port = $null
			ServiceName = $null
		}

		$DashSplit = $SPN.Split('/')

        # The SPN always start by the service class (HTTP, CIFS, LDAP, etc.)
		$Output.ServiceClass = $dashSplit[0]

		# If the SPN contains a port.
		If ($SPN -match ':') {
			$Output.Port = $spn.Split(':')[1].Split('/')[0]
		}

		# The SPN has an optionnal service name (example: rpcss/LabAD-DC1.forest1.loc/forest1).
        # More information: https://docs.microsoft.com/en-us/windows/win32/ad/name-formats-for-unique-spns
		If ($SPN -like '*/*/*') {
			$Output.ServiceName = $dashSplit[$dashSplit.Length - 1]
		}

		$Output.HostName = $spn.Split(':')[0].Split('/')[1]

        [PSCustomObject] $Output
	}

	catch {
		Write-Error $_.Exception.Message
	}
}

function Is-DangerousKerberosDelegation {
<#
.SYNOPSIS

Determine if a Keberos delegation is dangerous.

Required Dependencies: ActiveDirectory module and Get-ADHuntingAllPrivilegedSIDs.

.DESCRIPTION

Return True if the object passed as parameter is configured with a potentially dangerous Kerberos delegation, False otherwise.

A Kerberos delegation is judged to be dangerous if one the following conditions is meet:
  - The delegation is unconstrained.
  - The delegation is constrained and (one of) the service account targeted by the constrained delegation is privileged.
  - The delegation is resources-based constrained and the object itself is privileged.

.PARAMETER Object

Specifies the object (configured with one form of a Kerberos delegation) to evaluate.

.PARAMETER DelegationType

Specifies the type of the Kerberos delegation (Unconstrained, constrained, or RBCD).

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER PrivilegedSIDs

Specifies the privileged SIDs in the domain. If not specified, the privileged SIDs are enumerated using Get-ADHuntingAllPrivilegedSIDs.
Used for optimization purposes for subsequent calls to AD Hunting functions.

.OUTPUTS

[System.ValueType.Boolean]

#>

    Param(
        [Parameter(Mandatory=$True)][Microsoft.ActiveDirectory.Management.ADObject]$Object,
        [Parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [ValidateSet('Unconstrained','Constrained','RBCD')]
            [string]$DelegationType,
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$False)]$PrivilegedSIDs = $null
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)
    
    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
    }

    If (!$PrivilegedSIDs) {
        $PrivilegedSIDs = Get-ADHuntingAllPrivilegedSIDs
    }

    # Unconstrained delegations are dangerous by design.
    If ($DelegationType -eq 'Unconstrained') {
        return $True
    }
    
    # Constrained delegations to privileged services are potentially dangerous.
    Elseif ($DelegationType -eq 'Constrained') {
        foreach ($SPN in $Object["msDS-AllowedToDelegateTo"].Value) {
            $TargetService = Parse-SPN $SPN
            $TargetServiceSID = $(Get-ADObject -Properties objectSid -LDAPFilter "(|(Name=$(($TargetService.HostName)))(DNSHostName=$($TargetService.HostName)))").objectSid.Value
            If ($null -eq $TargetServiceSID) {
                Write-Host -ForegroundColor DarkYellow "[Is-DangerousKerberosDelegation][-] Couldn't resolve SID for $TargetService"
                return $True
            }
            ElseIf ($TargetServiceSID -in $PrivilegedSIDs) { return $True }
        }
        return $False
    }

    # Resources-based constrained delegations on privileged services are potentially dangerous.
    ElseIf ($DelegationType -eq 'RBCD') {
        If ($Object.objectSid.Value -in $PrivilegedSIDs) { return $True }
        Else { return $False }
    }
}

function Export-ADHuntingKerberosDelegations {
<#
.SYNOPSIS

Export to a CSV / JSON file the Kerberos delegations that are considered dangerous (unconstrained, constrained to a privileged service, or resources-based constrained on a privileged service).

Required Dependencies: ActiveDirectory module and Get-ADHuntingAllPrivilegedSIDs.

.DESCRIPTION

Enumerate all Kerberos delegations (unconstrained delegations, constrained delegations, and RBCD).

Parse services SPN in constrained delegations and RBCD, determining the target user or computer service SID.

Determine dangerous Kerberos delegations, that is:
  - Unconstrained delegations (except for DCs)
  - Constrained delegations where the target service is privileged
  - RBCD where the source service account is privileged

msDS-AllowedToDelegateTo and sDS-AllowedToActOnBehalfOfOtherIdentity attributes timestamp of last modification through replication data.


.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER PrivilegedSIDs

Specifies the list of privileged SIDs in the domain. If not specified, the list is determined using Get-ADHuntingAllPrivilegedSIDs.
Used for optimization purposes for subsequent calls to the function.

.PARAMETER OutputFolder

Specifies the CSV / JSON output file location (where the data will be exported to).

.PARAMETER OutputType

Specifies the format for the exported data (CSV or JSON). Defaults to CSV.

.OUTPUTS

[System.ValueType.Boolean]

#>

    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$False)]$PrivilegedSIDs = $null,
        [Parameter(Mandatory=$False)][String]$OutputFolder,
        [Parameter(Mandatory=$False)]
            [ValidateSet("JSON","CSV")]
            [string]$OutputType = "CSV"
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)
    $PSDefaultParameterValues.Add("Is-DangerousKerberosDelegation:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
        $PSDefaultParameterValues.Add("Is-DangerousKerberosDelegation:Credential", $Credential)
    }

    $DomainName = (Get-ADDomain).DNSRoot
    $OutputFolder = If (!$OutputFolder) { "." } Else { $OutputFolder }
    $OutputPath = "$OutputFolder\${DomainName}_Kerberos_Delegations_$(Get-Date -f yyyy-MM-dd-HHmmss).$($OutputType.ToLower())"

    If (!$PrivilegedSIDs) {
        $PrivilegedSIDs = Get-ADHuntingAllPrivilegedSIDs
    }

    Write-Host "[$($MyInvocation.MyCommand)][*] Enumerating Kerberos delegations (unconstrained, constrained, and resource-based constrained)..."

    $funcDefIsDangerousKerberosDelegation = ${function:Is-DangerousKerberosDelegation}.ToString()
    $funcDefConvertUnixTimeToISO8601 = ${function:Convert-UnixTimeToISO8601}.ToString()
    $funcDefParseSPN = ${function:Parse-SPN}.ToString()

    [System.Collections.ArrayList] $KerberosDelegations = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $SpecificPropertiesSet = $ACCOUNT_EXTENDED_PROPERTIES_SET + @("primaryGroupID", "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity")

    # Unconstrained delegations.
    $UnconstrainedDelegationsCount = [ref] 0
    Get-ADObject -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!userAccountControl:1.2.840.113556.1.4.803:=8192)(!userAccountControl:1.2.840.113556.1.4.803:=67108864))" -Properties $SpecificPropertiesSet | ForEach-Object -Parallel {
        try {
            $KerberosDelegations = $using:KerberosDelegations
            $PSDefaultParameterValues = $using:PSDefaultParameterValues
            $DomainName = $using:DomainName
            $PrivilegedSIDs = $using:PrivilegedSIDs
            $UnconstrainedDelegationsCount = $using:UnconstrainedDelegationsCount
            ${function:Convert-UnixTimeToISO8601} = $using:funcDefConvertUnixTimeToISO8601
            ${function:Is-DangerousKerberosDelegation} = $using:funcDefIsDangerousKerberosDelegation
            ${function:Parse-SPN} = $using:funcDefParseSPN

            $Object = $_
            $null = [Threading.Interlocked]::Increment($UnconstrainedDelegationsCount)
            
            $null = $KerberosDelegations.Add([PSCustomObject]@{
                Domain = $DomainName
                DelegationType = "Unconstrainted"
                IsTrustedPrincipalPriviliged = If ($PrivilegedSIDs.Contains($Object["objectSid"].Value)) { $True } Else { $False }
                IsDelegationDangerous = Is-DangerousKerberosDelegation -Object $Object -DelegationType 'Unconstrained' -PrivilegedSIDs $PrivilegedSIDs
                TrustedPrincipalsAMAccountName = $Object["sAMAccountName"].Value
                TrustedPrincipalSID = $Object["objectSid"].Value.Value
                TrustedPrincipalDistinguishedName = $Object["DistinguishedName"].Value
                TrustedPrincipalObjectClass = $Object["ObjectClass"].Value
                TrustedPrincipalWhenCreated = If ($Object["whenCreated"].Value) { $Object["whenCreated"].Value.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                TrustedPrincipalpwdLastSet = If ($Object["pwdLastSet"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Object["pwdLastSet"].Value } Else { $null }
                TrustedPrincipallastLogon = If ($Object["lastLogon"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Object["lastLogon"].Value } Else { $null }
                TrustedPrincipallastLogonTimestamp = If ($Object["lastLogonTimestamp"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Object["lastLogonTimestamp"].Value } Else { $null }
                TrustedPrincipalServicePrincipalName = If ($Object["servicePrincipalName"].Value.Count -gt 0) { [string]::join(";", [array] $Object["servicePrincipalName"].Value) } Else { $null }                
                TrustedPrincipalAllowedToDelegateTo = $null
                # TRUSTED_TO_AUTH_FOR_DELEGATION flag = 0x1000000 / 16777216.
                'Constrained_TRUSTED_TO_AUTH_FOR_DELEGATION' = $null
                WhenLastChangedAllowedToDelegateTo = $null
                LastChangedAllowedToDelegateToFrom = $null
                NbTimesChangedAllowedToDelegateTo = $null
                TrustedPrincipalAllowedToActOnBehalfOfOtherIdentity = $null
                WhenLastChangedAllowedToActOnBehalfOfOtherIdentity = $null
                LastChangedAllowedToActOnBehalfOfOtherIdentityFrom = $null
                NbTimesChangedAllowedToActOnBehalfOfOtherIdentity = $null
            })
        }

        catch {
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingKerberosDelegations][-] Error while processing object $($Object.DistinguishedName) during unconstrained delegations enumeration"
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingKerberosDelegations][-] Exception: $_"
        }
    }

    If ($UnconstrainedDelegationsCount.Value -gt 0) {
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($UnconstrainedDelegationsCount.Value) Kerberos unconstrained delegations granted to non-privileged principal"
    }
    Else {
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] No Kerberos unconstrained constrained delegations found"
    }

    # Constrained delegations.
    $ConstrainedDelegationsCount = [ref] 0
    $ConstrainedDelegationsCountDangerous = [ref] 0
    # No -Parallel to avoid transient issues due to resolving SPNs SID.
    Get-ADObject -LDAPFilter "(msDS-AllowedToDelegateTo=*)" -Properties $SpecificPropertiesSet | ForEach-Object <#-Parallel#> {
        try {
            # $KerberosDelegations = $using:KerberosDelegations
            # $PSDefaultParameterValues = $using:PSDefaultParameterValues
            # $DomainName = $using:DomainName
            # $PrivilegedSIDs = $using:PrivilegedSIDs
            # $ConstrainedDelegationsCount = $using:ConstrainedDelegationsCount
            # $ConstrainedDelegationsCountDangerous = $using:ConstrainedDelegationsCountDangerous
            # ${function:Convert-UnixTimeToISO8601} = $using:funcDefConvertUnixTimeToISO8601
            # ${function:Is-DangerousKerberosDelegation} = $using:funcDefIsDangerousKerberosDelegation
            # ${function:Parse-SPN} = $using:funcDefParseSPN

            $Object = $_
            $null = [Threading.Interlocked]::Increment($ConstrainedDelegationsCount)
        
            $IsDangerous = Is-DangerousKerberosDelegation -Object $Object -DelegationType 'Constrained' -PrivilegedSIDs $PrivilegedSIDs
            If ($IsDangerous) {  $null = [Threading.Interlocked]::Increment($ConstrainedDelegationsCountDangerous) }

            $ObjectReplicationMetadata = Get-ADReplicationAttributeMetadata -IncludeDeletedObjects -ShowAllLinkedValues "$($Object.DistinguishedName)" -Properties "msDS-AllowedToDelegateTo"

            $null = $KerberosDelegations.Add([PSCustomObject]@{
                Domain = $DomainName
                DelegationType = "Constrained"
                IsTrustedPrincipalPriviliged = If ($PrivilegedSIDs.Contains($Object["objectSid"].Value)) { $True } Else { $False }
                IsDelegationDangerous = $IsDangerous
                TrustedPrincipalsAMAccountName = $Object["sAMAccountName"].Value
                TrustedPrincipalDistinguishedName = $Object["DistinguishedName"].Value
                TrustedPrincipalObjectClass = $Object["ObjectClass"].Value
                TrustedPrincipalPrimaryGroupID = $Object["primaryGroupID"].Value
                TrustedPrincipalWhenCreated = If ($Object["whenCreated"].Value) { $Object["whenCreated"].Value.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                TrustedPrincipalpwdLastSet = If ($Object["pwdLastSet"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Object["pwdLastSet"].Value } Else { $null }
                TrustedPrincipallastLogon = If ($Object["lastLogon"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Object["lastLogon"].Value } Else { $null }
                TrustedPrincipallastLogonTimestamp = If ($Object["lastLogonTimestamp"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Object["lastLogonTimestamp"].Value } Else { $null }
                TrustedPrincipalServicePrincipalName = If ($Object["servicePrincipalName"].Value.Count -gt 0) { [string]::join(";", [array] $Object["servicePrincipalName"].Value) } Else { $null }
                TrustedPrincipalAllowedToDelegateTo = If ($Object["msDS-AllowedToDelegateTo"].Value) { [string]::join(";", [array] $Object["msDS-AllowedToDelegateTo"].Value) } Else { $null }
                # TRUSTED_TO_AUTH_FOR_DELEGATION flag = 0x1000000 / 16777216.
                'Constrained_TRUSTED_TO_AUTH_FOR_DELEGATION' = If (($Object["userAccountControl"].Value -band 16781344) -eq 16781344) { $True } Else { $False }
                WhenLastChangedAllowedToDelegateTo = If ($ObjectReplicationMetadata.LastOriginatingChangeTime) { $ObjectReplicationMetadata.LastOriginatingChangeTime.ToString('yyyy-MM-dd HH:mm:ss.fff')} Else { $null }
                LastChangedAllowedToDelegateToFrom = If ($ObjectReplicationMetadata.LastOriginatingChangeDirectoryServerIdentity) { $ObjectReplicationMetadata.LastOriginatingChangeDirectoryServerIdentity} Else { $null }
                NbTimesChangedAllowedToDelegateTo = If ($ObjectReplicationMetadata.Version) { $ObjectReplicationMetadata.Version} Else { $null }
                TrustedPrincipalAllowedToActOnBehalfOfOtherIdentity = $null
                WhenLastChangedAllowedToActOnBehalfOfOtherIdentity = $null
                LastChangedAllowedToActOnBehalfOfOtherIdentityFrom = $null
                NbTimesChangedAllowedToActOnBehalfOfOtherIdentity = $null
            })
        }

        catch {
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingKerberosDelegations][-] Error while processing object $($Object.DistinguishedName) during constrained delegations enumeration"
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingKerberosDelegations][-] Exception: $_"
        }
    }
    
    If ($ConstrainedDelegationsCount.Value -gt 0) {
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($ConstrainedDelegationsCount.Value) Kerberos constrained delegations, including $($ConstrainedDelegationsCountDangerous.Value) potentially dangerous constrained delegations to privileged principals"
    }
    Else {
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] No Kerberos constrained delegations found"
    }

    # Resource-based constrained delegation (RBCD).
    $RBCDCount = [ref] 0
    $RBCDCountDangerous = [ref] 0
    Get-ADObject -LDAPFilter "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" -Properties $SpecificPropertiesSet | ForEach-Object -Parallel {
        try {
            $KerberosDelegations = $using:KerberosDelegations
            $PSDefaultParameterValues = $using:PSDefaultParameterValues
            $DomainName = $using:DomainName
            $PrivilegedSIDs = $using:PrivilegedSIDs
            $RBCDCount = $using:RBCDCount
            $RBCDCountDangerous = $using:RBCDCountDangerous
            ${function:Convert-UnixTimeToISO8601} = $using:funcDefConvertUnixTimeToISO8601
            ${function:Is-DangerousKerberosDelegation} = $using:funcDefIsDangerousKerberosDelegation
            ${function:Parse-SPN} = $using:funcDefParseSPN

            $Object = $_
            $null = [Threading.Interlocked]::Increment($RBCDCount)

            $IsDangerous = Is-DangerousKerberosDelegation -Object $Object -DelegationType 'RBCD' -PrivilegedSIDs $PrivilegedSIDs
            If ($IsDangerous) { $null = [Threading.Interlocked]::Increment($RBCDCountDangerous) }

            $ObjectReplicationMetadata = Get-ADReplicationAttributeMetadata -IncludeDeletedObjects -ShowAllLinkedValues "$($Object.DistinguishedName)" -Properties "msDS-AllowedToActOnBehalfOfOtherIdentity"

            $null = $KerberosDelegations.Add([PSCustomObject]@{
                Domain = $DomainName
                DelegationType = "RBCD"
                IsTrustedPrincipalPriviliged = If ($PrivilegedSIDs.Contains($Object["objectSid"].Value)) { $True } Else { $False }
                IsDelegationDangerous = $IsDangerous
                TrustedPrincipalsAMAccountName = $Object["sAMAccountName"].Value
                TrustedPrincipalDistinguishedName = $Object["DistinguishedName"].Value
                TrustedPrincipalObjectClass = $Object["ObjectClass"].Value
                TrustedPrincipalPrimaryGroupID = $Object["primaryGroupID"].Value
                TrustedPrincipalWhenCreated = If ($Object["whenCreated"].Value) { $Object["whenCreated"].Value.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                TrustedPrincipalpwdLastSet = If ($Object["pwdLastSet"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Object["pwdLastSet"].Value } Else { $null }
                TrustedPrincipallastLogon = If ($Object["lastLogon"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Object["lastLogon"].Value } Else { $null }
                TrustedPrincipallastLogonTimestamp = If ($Object["lastLogonTimestamp"].Value) { Convert-UnixTimeToISO8601 -UnixTime $Object["lastLogonTimestamp"].Value } Else { $null }
                TrustedPrincipalServicePrincipalName = If ($Object["servicePrincipalName"].Value.Count -gt 0) { [string]::join(";", [array] $Object["servicePrincipalName"].Value) } Else { $null }
                TrustedPrincipalAllowedToDelegateTo = $null
                'Constrained_TRUSTED_TO_AUTH_FOR_DELEGATION' = $null
                WhenLastChangedAllowedToDelegateTo = $null
                LastChangedAllowedToDelegateToFrom = $null
                NbTimesChangedAllowedToDelegateTo = $null
                TrustedPrincipalAllowedToActOnBehalfOfOtherIdentity = $Object["msDS-AllowedToActOnBehalfOfOtherIdentity"].Value.Access.IdentityReference.Value
                WhenLastChangedAllowedToActOnBehalfOfOtherIdentity = If ($ObjectReplicationMetadata.LastOriginatingChangeTime) { $ObjectReplicationMetadata.LastOriginatingChangeTime.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                LastChangedAllowedToActOnBehalfOfOtherIdentityFrom = If ($ObjectReplicationMetadata.LastOriginatingChangeDirectoryServerIdentity) { $ObjectReplicationMetadata.LastOriginatingChangeDirectoryServerIdentity } Else { $null }
                NbTimesChangedAllowedToActOnBehalfOfOtherIdentity = If ($ObjectReplicationMetadata.Version) { $ObjectReplicationMetadata.Version } Else { $null }
            })
        }
        
        catch {
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingKerberosDelegations][-] Error while processing object $($Object.DistinguishedName) during RBCD enumeration"
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingKerberosDelegations][-] Exception: $_"
        }
    }

    If ($RBCDCount.Value -gt 0) {
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($RBCDCount.Value) Kerberos resource-based constrained delegations, including $($RBCDCountDangerous.Value) potentially dangerous RBCD on privileged principals"
    }
    Else {
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] No Kerberos resource-based constrained constrained delegations found"
    }

    If ($KerberosDelegations.Count -gt 0) {
        If ($OutputType -eq "CSV") {
            $KerberosDelegations | Export-Csv -NoTypeInformation -Encoding UTF8 -Append -Path $OutputPath
        }
        ElseIf ($OutputType -eq "JSON") {
            $KerberosDelegations | ConvertTo-Json -depth 100 | Out-File -Encoding UTF8 -Path $OutputPath
        }
    }

    Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] Kerberos delegations information written to '$OutputPath'"
}

########################################################
#
#
# Domain and forest trusts enumeration.
#
#
########################################################

function Test-TcpConnection {
<#
.SYNOPSIS

Test if the specified TCP port is accessible on the remote system using System.Net.Sockets.TcpClient.

.PARAMETER Server

Specifies the remote server.

.PARAMETER Port

Specifies the remote TCP port.

.OUTPUTS

[System.ValueType.Boolean]

#>
    Param(
        [Parameter(Mandatory=$True)][String]$Server,
        [Parameter(Mandatory=$True)][String]$Port
    )

    try {
        $socket = New-Object System.Net.Sockets.TcpClient($Server, $Port)
        return $socket.Connected
    }

    catch {
        return $False
    }

    finally {
        if ($socket) { $socket.Dispose() }
    }
}

function Export-ADHuntingTrusts {
<#
.SYNOPSIS

Export to a CSV / JSON file the trusts of all the domains in the forest.

A number of parameters are retrieved for each trust: transivity, SID filtering, TGT delegation.

Required Dependencies: ActiveDirectory module.

.DESCRIPTION

Export to a CSV / JSON file the trusts of all the domains in the forest.

In order to enumerate the trusts of a given domain, a Domain Controller of the domain must be reachable (on port TCP 9389).

A number of security parameters are returned for each trust (SID filtering, TGT delegation, and trust transivity notably).

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER OutputFolder

Specifies the CSV / JSON output file location (where the data will be exported to).

.PARAMETER OutputType

Specifies the format for the exported data (CSV or JSON). Defaults to CSV.

.OUTPUTS

CSV / JSON file written to disk.

#>

    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$False)][String]$OutputFolder,
        [Parameter(Mandatory=$False)]
            [ValidateSet("JSON","CSV")]
            [string]$OutputType = "CSV"
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("Get-ADDomain:Server", $Server)
    $PSDefaultParameterValues.Add("Get-ADForest:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
    }

    $DomainName = (Get-ADDomain).DNSRoot
    $OutputFolder = If (!$OutputFolder) { "." } Else { $OutputFolder }
    $OutputPath = "$OutputFolder\${DomainName}_Trusts_$(Get-Date -f yyyy-MM-dd-HHmmss).$($OutputType.ToLower())"

    Write-Host "[$($MyInvocation.MyCommand)][*] Enumerating trusts for each reachable domain(s) in the forest..."

    $Output = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $funcDefTestTcpConnection = ${function:Test-TcpConnection}.ToString()

    $Domains = New-Object System.Collections.ArrayList
    # Process first the trust of the current domain, defined by the server parameter.
    # As using the DNS hostname rather than the eventually provided server can create issue for execution on non-domain joined system.
    $null = $Domains.Add($Server)
    $null = $Domains.AddRange(@((Get-ADForest).Domains | Where-Object { $_ -cne $DomainName}))
    $Domains | ForEach-Object -Parallel {
        try {
            $Output = $using:Output
            $DomainName = $using:DomainName
            $Server = $using:Server
            $PSDefaultParameterValues = $using:PSDefaultParameterValues
            ${function:Test-TcpConnection} = $using:funcDefTestTcpConnection

            $TargetDomain = $_
            $NetConnectionResult = Test-TcpConnection $TargetDomain 9389
            If ($NetConnectionResult) {
                $Trusts = Get-ADTrust -Server $TargetDomain -Filter * -Properties Name,Direction,DisallowTransivity,SIDFilteringQuarantined,SIDFilteringForestAware,TGTDelegation
                              
                $null = foreach ($Trust in $Trusts) {
                    $Output.Add([PSCustomObject]@{
                        ExecutingFromDomain = $DomainName
                        Domain = If ($TargetDomain -eq $Server) { $DomainName } Else { $TargetDomain }
                        TrustPartnerDomain = $Trust["Name"].Value
                        Direction = $Trust["Direction"].Value
                        DisallowTransivity = $Trust["DisallowTransivity"].Value
                        SIDFilteringQuarantined = $Trust["SIDFilteringQuarantined"].Value
                        SIDFilteringForestAware = $Trust["SIDFilteringForestAware"].Value
                        TGTDelegation = $Trust["TGTDelegation"].Value
                    })
                }
            }
            Else {
                Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingTrusts][-] Could not enumerate trust(s) of domain $_ as a domain controller ADWS port couldn't be reached"
            }
        }
        catch {
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingTrusts][-] Error while processing trusts for domain $CurrentDomain"
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingTrusts][-] Exception: $_"
        }
    }

    If ($Output.Count -gt 0) {
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($Output.Count) trusts across the domains of the forest"
        If ($OutputType -eq "CSV") {
            $Output | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutputPath
        }
        ElseIf ($OutputType -eq "JSON") {
            $Output | ConvertTo-Json -depth 100 | Out-File -Encoding UTF8 -Path $OutputPath
        }
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] Trusts information written to '$OutputPath'"
    }
    Else {
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] No trusts found"
    }
}

########################################################
#
#
# GPO persistence.
#
#
########################################################

function Get-ADHuntingGPOLinkedHashMap {
<#
.SYNOPSIS

Retrieve the GPOs linked on OUs, Sites, or the Domain root objects. 

The GPOs are returned in two separate Hashtables: one for GPOs linked on privileged objects, one for GPOs linked on non-privileged objects.

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER PrivilegedSIDs

Specifies the list of privileged SIDs in the domain. If not specified, the list is determined using Get-ADHuntingAllPrivilegedSIDs.
Used for optimization purposes for subsequent calls to the function.

.OUTPUTS

([System.Object.Hashtable], [System.Object.Hashtable])

#>

    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$True)]$PrivilegedContainers
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
    }

    # Add GPO links on any objects on the Domain partition and the Sites partition to two hashmaps, for privileged or non-privileged container.
    # Hashmap key: GPO DistinguishedName | Hashmap value: ArrayList of containers DistinguishedName on which the GPO is linked.
    $GPOLinkedOnPrivilegedContainers = @{}
    $GPOLinkedOnNonPrivilegedContainers = @{}
    
    $ObjectsWithgPLinks = New-Object System.Collections.ArrayList
    $null = $ObjectsWithgPLinks.AddRange($(Get-ADObject -LDAPFilter "(gPLink=*)" -Properties gPLink))
    $null = $ObjectsWithgPLinks.AddRange(@($(Get-ADObject -SearchBase "CN=Sites,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter "(gPLink=*)" -Properties gPLink)))
    
    # Parse GPO Distinguished Names in each gPLink attribute and add to linked GPO hashmap.
    foreach ($ObjectsWithgPLink in $ObjectsWithgPLinks) {
        $gPLinkGPOs = Get-GPOFromGPLink -gPLinkAttribute $ObjectsWithgPLink.gPLink
        
        foreach ($gPLinkGPO in $gPLinkGPOs) {
            
            If ($PrivilegedContainers.Contains($ObjectsWithgPLink.DistinguishedName)) {
                If ($GPOLinkedOnPrivilegedContainers.ContainsKey($gPLinkGPO.DistinguishedName) -and !$GPOLinkedOnPrivilegedContainers[$gPLinkGPO.DistinguishedName].Contains($ObjectsWithgPLink.DistinguishedName)) {
                    $null = $GPOLinkedOnPrivilegedContainers[$gPLinkGPO.DistinguishedName].Add($ObjectsWithgPLink.DistinguishedName)
                }

                Else {
                    $null = $GPOLinkedOnPrivilegedContainers.Add($gPLinkGPO.DistinguishedName, [System.Collections.ArrayList]@($ObjectsWithgPLink.DistinguishedName))
                }
            }

            # Non-privileged container.
            Else {
                If ($GPOLinkedOnNonPrivilegedContainers.ContainsKey($gPLinkGPO.DistinguishedName) -and !$GPOLinkedOnNonPrivilegedContainers[$gPLinkGPO.DistinguishedName].Contains($ObjectsWithgPLink.DistinguishedName)) {
                    $null = $GPOLinkedOnNonPrivilegedContainers[$gPLinkGPO.DistinguishedName].Add($ObjectsWithgPLink.DistinguishedName)
                }

                Else {
                    $null = $GPOLinkedOnNonPrivilegedContainers.Add($gPLinkGPO.DistinguishedName, [System.Collections.ArrayList]@($ObjectsWithgPLink.DistinguishedName))
                }
            }
        }
    }

    return $GPOLinkedOnPrivilegedContainers, $GPOLinkedOnNonPrivilegedContainers
}

function Export-ADHuntingGPOObjectsAndFilesACL {
<#
.SYNOPSIS

Export to a CSV / JSON file ACL access rights information on GPO objects and files, highlighting GPOs are applied on privileged users or computers.

.DESCRIPTION

Determine if the GPOs are applied on privileged users or computers (at OU, Domain or Site level, and by processing OU inheritance block / GPO enforcement).

Check GPO objects and GPO files ownership and access rights, highlighting takeover / modifications rights granted to non-privileged principals or everyone.

Check if the GPO files are hosted on DCs by parsing the gPCFileSysPath attribute.

Retrieve multiple timestamps: GPOs creation and last modification, GPOs security descriptor and gPCFileSysPath attributes last modification through replication data.

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER ADDriveName

Specifies the name to use for the ActiveDirectory PSDrive that will be (temporarily) mounted by the cmdlet.
Defaults to ADHunting.

.PARAMETER SYSVOLDriveName

Specifies the name to use for the Filesystem PSDrive to the Domain Controller SYSVOL directory that will be (temporarily) mounted by the cmdlet.
Defaults to $ADDriveName_SYSVOL.

.PARAMETER PrivilegedSIDs

Specifies the list of privileged SIDs in the domain. If not specified, the list is determined using Get-ADHuntingAllPrivilegedSIDs.
Used for optimization purposes for subsequent calls to the function.

.PARAMETER OutputFolder

Specifies the CSV / JSON output file location (where the data will be exported to).

.PARAMETER OutputType

Specifies the format for the exported data (CSV or JSON). Defaults to CSV.

.OUTPUTS

CSV / JSON file written to disk.

#>

    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$False)][String]$ADDriveName = "ADHunting",
        [Parameter(Mandatory=$False)][String]$SYSVOLDriveName = "$($ADDriveName)_SYSVOL",
        [Parameter(Mandatory=$False)]$PrivilegedSIDs = $null,
        [Parameter(Mandatory=$False)][String]$OutputFolder,
        [Parameter(Mandatory=$False)]
            [ValidateSet("JSON","CSV")]
            [string]$OutputType = "CSV"
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)
    $PSDefaultParameterValues.Add("New-PSDrive:Server", $Server)
    $PSDefaultParameterValues.Add("Is-DangerousADACE:Server", $Server)
    $PSDefaultParameterValues.Add("Is-DangerousFileACE:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
        $PSDefaultParameterValues.Add("New-PSDrive:Credential", $Credential)
        $PSDefaultParameterValues.Add("Is-DangerousADACE:Credential", $Credential)
        $PSDefaultParameterValues.Add("Is-DangerousFileACE:Credential", $Credential)
    }

    $DomainName = (Get-ADDomain).DNSRoot
    $OutputFolder = If (!$OutputFolder) { "." } Else { $OutputFolder }
    $OutputPath = "$OutputFolder\${DomainName}_GPO_ownership_and_access_rights_$(Get-Date -f yyyy-MM-dd-HHmmss).$($OutputType.ToLower())"

    Write-Host "[$($MyInvocation.MyCommand)][*] Enumerating GPO objects and files ownership and access rights..."


    $DomainDnsName = (Get-ADDomain).DNSRoot
    $SYSVOLPath = "\\$DomainDnsName\SYSVOL"
    $SYSVOLMountPath = "\\$Server\SYSVOL"
    $DCRegex = "^\\\\($DomainName|$DomainDnsName|$Server)"
    
    # Determine once the privileged / unprivileged SIDs to filter out for performance.
    If (!$PrivilegedSIDs) {
        $PrivilegedSIDs = Get-ADHuntingAllPrivilegedSIDs
    }
    $UnprivilegedSIDs = Get-ADHuntingUnprivilegedSIDs
    
    $AllPrivilegedObjects = Get-ADHuntingAllPrivilegedObjects -PrivilegedSIDs $PrivilegedSIDs
    
    # Enumerate all GPOs linked on privileged containers (filtering from all objects first enumerated using Get-ADHuntingAllPrivilegedObjects).
    $PrivilegedContainers, $GPOObjectsLinkedOnPrivilegedContainer = Get-ADHuntingPrivilegedContainersAndGPOs -AllPrivilegedAccounts $($AllPrivilegedObjects | Where-Object { $_.objectClass -eq "user" -or $_.objectClass -eq "computer" })

    # Add GPO links on any objects on the Domain partition and the Sites partition to a hashmap.
    $GPOLinkedOnPrivilegedContainers, $GPOLinkedOnNonPrivilegedContainers = Get-ADHuntingGPOLinkedHashMap -PrivilegedContainers $PrivilegedContainers

    # Enumerate all GPOs.
    $GPOObjects = Get-ADObject -SearchBase "$((Get-ADDomain).SystemsContainer)" -LDAPFilter "(objectClass=groupPolicyContainer)" -Properties displayName,gPCFileSysPath,whenCreated,whenChanged
    
    $funcDefAddPrivilegeLevelType = ${function:Add-PrivilegeLevelType}.ToString()
    $funcDefIsDangerousADACE = ${function:Is-DangerousADACE}.ToString()
    $funcDefIsDangerousFileACE = ${function:Is-DangerousFileACE}.ToString()
    $funcDefGetHuntingFileParsedACL = ${function:Get-ADHuntingFileParsedACL}.ToString()
    
    $Output = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    
    $GPOObjectOwnedByNonPriv = [ref] 0
    $GPOObjectOwnedByNonPrivAndLinkedOnPriv = [ref] 0
    $GPOObjectOwnedByEveryone = [ref] 0
    $GPOObjectOwnedByEveryoneAndLinkedOnPriv = [ref] 0
    $GPOObjectModifiableByNonPriv = [ref] 0
    $GPOObjectModifiableByNonPrivAndLinkedOnPriv = [ref] 0
    $GPOObjectModifiableByEveryone = [ref] 0
    $GPOObjectModifiableByEveryoneAndLinkedOnPriv = [ref] 0

    $GPOFileNotOnDC = [ref] 0
    $GPOFileNotOnDCAndLinkedOnPriv = [ref] 0
    $GPOFileOwnedByNonPriv = [ref] 0
    $GPOFileOwnedByNonPrivAndLinkedOnPriv = [ref] 0
    $GPOFileOwnedByEveryone = [ref] 0
    $GPOFileOwnedByEveryoneAndLinkedOnPriv = [ref] 0
    $GPOFileModifiableByNonPriv = [ref] 0
    $GPOFileModifiableByNonPrivAndLinkedOnPriv = [ref] 0
    $GPOFileModifiableByEveryone = [ref] 0
    $GPOFileModifiableByEveryoneAndLinkedOnPriv = [ref] 0

    $GPOObjects | ForEach-Object -Parallel {
        try {
            $Output = $using:Output
            $PSDefaultParameterValues = $using:PSDefaultParameterValues
            $ADDriveName = $using:ADDriveName
            $DCRegex = $using:DCRegex
            $SYSVOLDriveName = $using:SYSVOLDriveName
            $DomainName = $using:DomainName
            $DomainDnsName = $using:DomainDnsName
            $SYSVOLPath = $using:SYSVOLPath
            $SYSVOLMountPath = $using:SYSVOLMountPath
            $GPOObjectsLinkedOnPrivilegedContainer = $using:GPOObjectsLinkedOnPrivilegedContainer
            $GPOLinkedOnPrivilegedContainers = $using:GPOLinkedOnPrivilegedContainers
            $GPOLinkedOnNonPrivilegedContainers = $using:GPOLinkedOnNonPrivilegedContainers
            $PrivilegedSIDs= $using:PrivilegedSIDs
            $UnprivilegedSIDs = $using:UnprivilegedSIDs
            $GPOObjectOwnedByNonPriv = $using:GPOObjectOwnedByNonPriv
            $GPOObjectOwnedByNonPrivAndLinkedOnPriv = $using:GPOObjectOwnedByNonPrivAndLinkedOnPriv
            $GPOObjectOwnedByEveryone = $using:GPOObjectOwnedByEveryone
            $GPOObjectOwnedByEveryoneAndLinkedOnPriv = $using:GPOObjectOwnedByEveryoneAndLinkedOnPriv
            $GPOObjectModifiableByNonPriv = $using:GPOObjectModifiableByNonPriv
            $GPOObjectModifiableByNonPrivAndLinkedOnPriv = $using:GPOObjectModifiableByNonPrivAndLinkedOnPriv
            $GPOObjectModifiableByEveryone = $using:GPOObjectModifiableByEveryone
            $GPOObjectModifiableByEveryoneAndLinkedOnPriv = $using:GPOObjectModifiableByEveryoneAndLinkedOnPriv
            $GPOFileNotOnDC = $using:GPOFileNotOnDC
            $GPOFileNotOnDCAndLinkedOnPriv = $using:GPOFileNotOnDCAndLinkedOnPriv
            $GPOFileOwnedByNonPriv = $using:GPOFileOwnedByNonPriv
            $GPOFileOwnedByNonPrivAndLinkedOnPriv = $using:GPOFileOwnedByNonPrivAndLinkedOnPriv
            $GPOFileOwnedByEveryone = $using:GPOFileOwnedByEveryone
            $GPOFileOwnedByEveryoneAndLinkedOnPriv = $using:GPOFileOwnedByEveryoneAndLinkedOnPriv
            $GPOFileModifiableByNonPriv = $using:GPOFileModifiableByNonPriv
            $GPOFileModifiableByNonPrivAndLinkedOnPriv = $using:GPOFileModifiableByNonPrivAndLinkedOnPriv
            $GPOFileModifiableByEveryone = $using:GPOFileModifiableByEveryone
            $GPOFileModifiableByEveryoneAndLinkedOnPriv = $using:GPOFileModifiableByEveryoneAndLinkedOnPriv
            ${function:Add-PrivilegeLevelType} = $using:funcDefAddPrivilegeLevelType
            ${function:Is-DangerousADACE} = $using:funcDefIsDangerousADACE
            ${function:Is-DangerousFileACE} = $using:funcDefIsDangerousFileACE
            ${function:Get-ADHuntingFileParsedACL} = $using:funcDefGetHuntingFileParsedACL

            $GPOObject = $_

            Add-PrivilegeLevelType
            
            # Lookup GPO DN in GPOObjectsLinkedOnPrivilegedContainer hashmap.
            If ($GPOObjectsLinkedOnPrivilegedContainer.Contains($GPOObject.DistinguishedName)) { 
                $IsGPOLinkedOnPrivilegedObjects = $True
                $IsGPOLinkEnabledOnPrivilegedObjects = If ($GPOObjectsLinkedOnPrivilegedContainer[$GPOObject.DistinguishedName] | Where-Object { $_.IsLinkEnabled -eq $True }) { $True } Else { $False }
                $IsGPOEnforcedOnPrivilegedObjects = If ($GPOObjectsLinkedOnPrivilegedContainer[$GPOObject.DistinguishedName] | Where-Object { $_.IsLinkEnforced -eq $True }) { $True } Else { $False }
                $IsGPOAppliedOnPrivilegedObjects = If ($GPOObjectsLinkedOnPrivilegedContainer[$GPOObject.DistinguishedName] | Where-Object { $_.IsApplied -eq $True }) { $True } Else { $False }
            }
            Else { 
                $IsGPOLinkedOnPrivilegedObjects = $False
                $IsGPOLinkEnabledOnPrivilegedObjects = $False
                $IsGPOEnforcedOnPrivilegedObjects = $False
                $IsGPOAppliedOnPrivilegedObjects = $False
            }

            # Retrieve GPO object and files ACL using new AD and SYSVOL PS drives.
            If (!(Get-PSDrive $ADDriveName -ErrorAction SilentlyContinue)) {
                $Env:ADPS_LoadDefaultDrive = 0
                $null = Import-Module ActiveDirectory -DisableNameChecking -SkipEditionCheck -Cmdlet Get-ADReplicationAttributeMetadata
                $null = New-PSDrive -Name $ADDriveName -PSProvider ActiveDirectory -Root "//RootDSE/"
                $null = New-PSDrive -ErrorAction Stop -Name "$SYSVOLDriveName" -PSProvider FileSystem -Root $SYSVOLMountPath
            }

            $GPOObjectACL = Get-Acl -Path "${ADDriveName}:\$($GPOObject.DistinguishedName)"
            
            <#
            # Process GPO object ownership.
            #>
            $GPOObjectOwnerSID = $GPOObjectACL.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
            If ($PrivilegedSIDs.Contains($GPOObjectOwnerSID)) {
                $GPOObjectOwnerIs = [PrivilegeLevel]::Privileged
            }
            ElseIf ($UnprivilegedSIDs.Contains($GPOObjectOwnerSID)) {
                $GPOObjectOwnerIs = [PrivilegeLevel]::Everyone
                $null = [Threading.Interlocked]::Increment($GPOObjectOwnedByEveryone)
                If ($IsGPOLinkedOnPrivilegedObjects) { $null = [Threading.Interlocked]::Increment($GPOObjectOwnedByEveryoneAndLinkedOnPriv) }
            }
            Else {
                $GPOObjectOwnerIs = [PrivilegeLevel]::NonPrivileged
                $null = [Threading.Interlocked]::Increment($GPOObjectOwnedByNonPriv)
                If ($IsGPOLinkedOnPrivilegedObjects) { $null = [Threading.Interlocked]::Increment($GPOObjectOwnedByNonPrivAndLinkedOnPriv) }
            }

            <#
            # Process GPO object access rights.
            #>
            $GPOObjectSenstiveRightGrantedTo = [PrivilegeLevel]::Privileged
            $GPOObjectSenstiveRightsAsString = ""
            foreach ($GPOObjectACE in $GPOObjectACL.Access) {
                # Attempt to retrieve SID from GPOObjectACE IdentityReference if automatically translated to principal name.
                try { $GPOObjectACEAttributedToSID = $GPOObjectACE.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
                catch { $GPOObjectACEAttributedToSID = $GPOObjectACE.IdentityReference }
                
                # Keep only dangerous access right that allow modification of the GPO object or some of its critical attributes.
                If (!(Is-DangerousADACE -ObjectClass $GPOObject["ObjectClass"].Value -ACE $GPOObjectACE -AttributedToSID $GPOObjectACEAttributedToSID -PrivilegedSIDs $PrivilegedSIDs)) {
                    continue
                }

                # Parse the sensitive access right as a custom string format.
                $GPOObjectSenstiveRightsAsString += "GrantedTo=$($GPOObjectACE.IdentityReference) | GrantedToSID=$GPOObjectACEAttributedToSID | AccessType=$($GPOObjectACE.AccessControlType) | AccesRight=$($GPOObjectACE.ActiveDirectoryRights) | AccessGuid=$($GPOObjectACE.ObjectType) | IsInherited=$($GPOObjectACE.IsInherited) | PropagationFlags=$($GPOObjectACE.PropagationFlags);"

                # Once a dangerous right granted to everyone has been found, stop determining to whom is granted the current dangerous right
                # as the worst case scenario has already been matched.
                If ($GPOObjectSenstiveRightGrantedTo -eq [PrivilegeLevel]::Everyone) { continue }
                If ($UnprivilegedSIDs.Contains($GPOObjectACEAttributedToSID)) {
                    $GPOObjectSenstiveRightGrantedTo = [PrivilegeLevel]::Everyone
                    $null = [Threading.Interlocked]::Increment($GPOObjectModifiableByEveryone)
                    If ($IsGPOLinkedOnPrivilegedObjects) { $null = [Threading.Interlocked]::Increment($GPOObjectModifiableByNonPrivAndLinkedOnPriv) }
                }
                ElseIf (!$PrivilegedSIDs.Contains($GPOObjectACEAttributedToSID)) {
                    $GPOObjectSenstiveRightGrantedTo = [PrivilegeLevel]::NonPrivileged
                    $null = [Threading.Interlocked]::Increment($GPOObjectModifiableByNonPriv)
                    If ($IsGPOLinkedOnPrivilegedObjects) { $null = [Threading.Interlocked]::Increment($GPOObjectModifiableByNonPrivAndLinkedOnPriv) }
                }
            }

            <#
            # Process GPO files owernship and access rights.
            #>
            $IsGPOFolderOnDC = If ($GPOObject["gPCFileSysPath"].Value -match $DCRegex) { $True } Else { $False }

            # Skip checks if GPO files are not on DC as it's not default and anormal.
            If ($IsGPOFolderOnDC) {
                $GPOFilesOwnerIs = [PrivilegeLevel]::Privileged
                $GPODangerousFilesOwnerAsString = ""
                $GPOFilesSensitiveRightGrantedTo = [PrivilegeLevel]::Privileged
                $GPOFilesSensitiveRightsAsString = ""

                $GPOPathOnDrive = $GPOObject["gPCFileSysPath"].Value -ireplace [regex]::Escape($SYSVOLPath), "${SYSVOLDriveName}:"
                $GPOFiles = Get-ChildItem -File -Recurse -LiteralPath "$GPOPathOnDrive"

                foreach ($GPOFile in $GPOFiles) {
                    $GPOFileFullNameOnDrive = $GPOFile.FullName -ireplace [regex]::Escape($SYSVOLMountPath), "${SYSVOLDriveName}:"
                    $ParsedACLObject = Get-ADHuntingFileParsedACL -PrivilegedSIDs $PrivilegedSIDs -UnprivilegedSIDs $UnprivilegedSIDs -FilePath $GPOFileFullNameOnDrive
                    If (!$ParsedACLObject) {
                        Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingGPOObjectsAndFilesACL][-] Couldn't parse ACL of $GPOFileFullNameOnDrive"
                        continue
                    }

                    If ($ParsedACLObject.DangerousFileOwner) {
                        $GPOFilesOwnerIs = [PrivilegeLevel][Math]::Min([int]$GPOFilesOwnerIs, [int]$ParsedACLObject.DangerousFileOwner)
                        $GPODangerousFilesOwnerAsString += $ParsedACLObject.DangerousFilesOwnerAsString
                    }

                    If ($ParsedACLObject.FileSenstiveRightGrantedTo) {
                        $GPOFilesSensitiveRightGrantedTo = [PrivilegeLevel][Math]::Min([int]$GPOFilesSensitiveRightGrantedTo, [int]$ParsedACLObject.FileSenstiveRightGrantedTo)
                        $GPOFilesSensitiveRightsAsString += $ParsedACLObject.FilesSenstiveRightsAsString
                    }
                }

                # Increment counters related to GPO files ownership and access rights.
                If ($GPOFilesOwnerIs -eq [PrivilegeLevel]::Everyone) {
                    $null = [Threading.Interlocked]::Increment($GPOFileOwnedByEveryone)
                    If ($IsGPOLinkedOnPrivilegedObjects) { $null = [Threading.Interlocked]::Increment($GPOFileOwnedByEveryoneAndLinkedOnPriv) }
                }
                ElseIf ($GPOFilesOwnerIs -eq [PrivilegeLevel]::NonPrivileged) {
                    $null = [Threading.Interlocked]::Increment($GPOFileOwnedByNonPriv)
                    If ($IsGPOLinkedOnPrivilegedObjects) { $null = [Threading.Interlocked]::Increment($GPOFileOwnedByNonPrivAndLinkedOnPriv) }
                }
                If ($GPOFilesSensitiveRightGrantedTo -eq [PrivilegeLevel]::Everyone) {
                    $null = [Threading.Interlocked]::Increment($GPOFileModifiableByEveryone)
                    If ($IsGPOLinkedOnPrivilegedObjects) { $null = [Threading.Interlocked]::Increment($GPOFileModifiableByEveryoneAndLinkedOnPriv) }
                }
                ElseIf ($GPOFilesSensitiveRightGrantedTo -eq [PrivilegeLevel]::NonPrivileged) {
                    [Threading.Interlocked]::Increment($GPOFileModifiableByNonPriv)
                    If ($IsGPOLinkedOnPrivilegedObjects) { $null = [Threading.Interlocked]::Increment($GPOFileModifiableByNonPrivAndLinkedOnPriv) }
                }
            }

            Else {
                $GPOFilesOwnerIs = $null
                $GPODangerousFilesOwnerAsString = $null
                $GPOFilesSensitiveRightGrantedTo = $null
                $GPOFilesSensitiveRightsAsString = $null
    
                [Threading.Interlocked]::Increment($GPOFileNotOnDC)
                If ($IsGPOLinkedOnPrivilegedObjects) { [Threading.Interlocked]::Increment($GPOFileNotOnDCAndLinkedOnPriv) }
            }

            # Retrieve GPO object replication metadata.
            $ObjectReplicationMetadata = Get-ADReplicationAttributeMetadata -IncludeDeletedObjects -ShowAllLinkedValues "$($GPOObject.DistinguishedName)" -Properties nTSecurityDescriptor,gPCFileSysPath
            $ObjectReplicationMetadatanTSecurityDescriptor = $ObjectReplicationMetadata | Where-Object { $_.AttributeName -eq "nTSecurityDescriptor" }
            $ObjectReplicationMetadatagPCFileSysPath = $ObjectReplicationMetadata | Where-Object { $_.AttributeName -eq "gPCFileSysPath" }

            $null = $Output.Add([PSCustomObject]@{
                Domain = $DomainName
                GPOName = $GPOObject["Name"].Value
                GPODisplayName = $GPOObject["displayName"].Value
                GPODistinguishedName = $GPOObject["DistinguishedName"].Value
                whenCreated = $GPOObject["whenCreated"].Value
                whenChanged = $GPOObject["whenChanged"].Value
                IsGPOLinkedOnPrivilegedObjects = $IsGPOLinkedOnPrivilegedObjects
                IsGPOLinkEnabledOnPrivilegedObjects = $IsGPOLinkEnabledOnPrivilegedObjects
                IsGPOEnforcedOnPrivilegedObjects = $IsGPOEnforcedOnPrivilegedObjects
                IsGPOAppliedOnPrivilegedObjects = $IsGPOAppliedOnPrivilegedObjects
                PrivilegedContainerLinkedOn = If ($GPOLinkedOnPrivilegedContainers.ContainsKey($GPOObject.DistinguishedName)) { [string]::join(";", [array] $GPOLinkedOnPrivilegedContainers[$GPOObject.DistinguishedName]) } Else { "No-link" }
                NonPrivilegedContainerLinkedOn = If ($GPOLinkedOnNonPrivilegedContainers.ContainsKey($GPOObject.DistinguishedName)) { [string]::join(";", [array] $GPOLinkedOnNonPrivilegedContainers[$GPOObject.DistinguishedName]) } Else { "No-link" }
                GPOOwner = $GPOObjectACL.Owner
                GPOOwnerSID = $GPOObjectOwnerSID
                GPOObjectOwnerIs = $GPOObjectOwnerIs
                GPOObjectIsModifiableBy = $GPOObjectSenstiveRightGrantedTo
                GPOObjectSensitiveAccesRights = $GPOObjectSenstiveRightsAsString
                GPOObjectSecurityDescriptorWhenLastChanged = If ($ObjectReplicationMetadatanTSecurityDescriptor.LastOriginatingChangeTime) { $ObjectReplicationMetadatanTSecurityDescriptor.LastOriginatingChangeTime.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                GPOObjectSecurityDescriptorLastChangedFrom = If ($ObjectReplicationMetadatanTSecurityDescriptor.LastOriginatingChangeDirectoryServerIdentity) { $ObjectReplicationMetadatanTSecurityDescriptor.LastOriginatingChangeDirectoryServerIdentity } Else { $null }
                GPOObjectgPCFileSysPath = $GPOObject["gPCFileSysPath"].Value
                GPOObjectgPCFileSysPathWhenLastChanged = If ($ObjectReplicationMetadatagPCFileSysPath.LastOriginatingChangeTime) { $ObjectReplicationMetadatagPCFileSysPath.LastOriginatingChangeTime.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                GPOObjectgPCFileSysPathLastChangedFrom = If ($ObjectReplicationMetadatagPCFileSysPath.LastOriginatingChangeDirectoryServerIdentity) { $ObjectReplicationMetadatagPCFileSysPath.LastOriginatingChangeDirectoryServerIdentity } Else { $null }
                IsGPOFolderOnDC = $IsGPOFolderOnDC
                GPOFilesOwnedBy = $GPOFilesOwnerIs
                GPODangerousFilesOwnerAsString = $GPODangerousFilesOwnerAsString
                GPOFilesModifiableBy = $GPOFilesSensitiveRightGrantedTo
                GPOFilesSensitiveRightGrantedTo = $GPOFilesSensitiveRightsAsString
            })
        }
        catch {
            If ($_.Exception.Message -eq "Access is denied." -and $_.InvocationInfo.MyCommand.Name -eq "New-PSDrive") {
                Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingGPOObjectsAndFilesACL][-] Access denied error while trying to mount the SYSVOL at $SYSVOLMountPath"
                Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingGPOObjectsAndFilesACL][-] New hardening on UNC path may prevent mounting the SYSVOL folder. Use 'New-ItemProperty ""HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"" -Name ""\\<DC | *>\SYSVOL"" -Value ""RequireMutualAuthentication=0"" -Property ""String""'"
                break
            }
            Else {
                Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingGPOObjectsAndFilesACL][-] Error while processing GPO $GPOObject"
                Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingGPOObjectsAndFilesACL][-] Exception: $_"
            }
        }
    }

    If ($Output.Count -gt 0) {
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($Output.Count) GPOs, including $($GPOObjectsLinkedOnPrivilegedContainer.Count) linked on privileged containers"
        Write-Host "[$($MyInvocation.MyCommand)][*] $($GPOObjectOwnedByNonPriv.Value) GPO objects are owned by non privileged users, including $($GPOObjectOwnedByNonPrivAndLinkedOnPriv.Value) GPOs linked on privileged containers"
        Write-Host "[$($MyInvocation.MyCommand)][*] $($GPOObjectOwnedByEveryone.Value) GPO objects are owned by everyone, including $($GPOObjectOwnedByEveryoneAndLinkedOnPriv.Value) GPOs linked on privileged containers"
        Write-Host "[$($MyInvocation.MyCommand)][*] $($GPOObjectModifiableByNonPriv.Value) GPO objects are modifiable by non privileged users, including $($GPOObjectModifiableByNonPrivAndLinkedOnPriv.Value) GPOs linked on privileged containers"
        Write-Host "[$($MyInvocation.MyCommand)][*] $($GPOObjectModifiableByEveryone.Value) GPO objects are modifiable by everyone, including $($GPOObjectModifiableByEveryoneAndLinkedOnPriv.Value) GPOs linked on privileged containers"
        Write-Host "[$($MyInvocation.MyCommand)][*] $($GPOFileNotOnDC.Value) GPO files are not hosted in SYSVOL, including $($GPOFileNotOnDCAndLinkedOnPriv.Value) GPOs linked on privileged containers"
        Write-Host "[$($MyInvocation.MyCommand)][*] $($GPOFileOwnedByNonPriv.Value) GPO files are owned by non privileged users, including $($GPOFileOwnedByNonPrivAndLinkedOnPriv.Value) GPOs linked on privileged containers"
        Write-Host "[$($MyInvocation.MyCommand)][*] $($GPOFileOwnedByEveryone.Value) GPO files are owned by everyone, including $($GPOFileOwnedByEveryoneAndLinkedOnPriv.Value) GPOs linked on privileged containers"
        Write-Host "[$($MyInvocation.MyCommand)][*] $($GPOFileModifiableByNonPriv.Value) GPO files are modifiable by non privileged users, including $($GPOFileModifiableByNonPrivAndLinkedOnPriv.Value) GPOs linked on privileged containers"
        Write-Host "[$($MyInvocation.MyCommand)][*] $($GPOFileModifiableByEveryone.Value) GPO files are modifiable by everyone, including $($GPOFileModifiableByEveryoneAndLinkedOnPriv.Value) GPOs linked on privileged containers"
        If ($OutputType -eq "CSV") {
            $Output | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutputPath
        }
        ElseIf ($OutputType -eq "JSON") {
            $Output | ConvertTo-Json -depth 100 | Out-File -Encoding UTF8 -Path $OutputPath
        }
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] GPO objects and files ownership and access rights information written to '$OutputPath'"
    }
    Else {
        Write-Host -ForegroundColor DarkYellow "[$($MyInvocation.MyCommand)][-] No GPO found, an error likely occurred"
    }
}

function Get-GPOPrivilegesFromGptTmplPath {
<#
.SYNOPSIS

Get local privileges and logon rights defined in a GPO GptTmplPath file.

.PARAMETER GptTmplPath

Specifies the GptTmplPath file path.

.OUTPUTS

[System.Collections.ArrayList]

#>

    Param(
        [Parameter(Mandatory=$True)][String]$GptTmplPath
    )

    $WindowsPrivilegesSensitives = @(
        "^SeAssignPrimaryTokenPrivilege\s{1,}=",
        "^SeAuditPrivilege\s{1,}=",
        "^SeBackupPrivilege\s{1,}=",
        "^SeCreateTokenPrivilege\s{1,}=",
        "^SeDebugPrivilege\s{1,}=",
        "^SeDelegateSessionUserImpersonatePrivilege\s{1,}=",
        "^SeEnableDelegationPrivilege\s{1,}=",
        "^SeImpersonatePrivilege\s{1,}=",
        "^SeLoadDriverPrivilege\s{1,}=",
        "^SeManageVolumePrivilege\s{1,}=",
        "^SeRemoteShutdownPrivilege\s{1,}=",
        "^SeRestorePrivilege\s{1,}=",
        "^SeSecurityPrivilege\s{1,}=",
        "^SeSyncAgentPrivilege\s{1,}=",
        "^SeSystemEnvironmentPrivilege\s{1,}=",
        "^SeTakeOwnershipPrivilege\s{1,}=",
        "^SeTcbPrivilege\s{1,}=",
        "^SeTrustedCredManAccessPrivilege\s{1,}="
    )

    $WindowsPrivilegesNonSensitives = @(
        "^SeChangeNotifyPrivilege\s{1,}=",
        "^SeCreateGlobalPrivilege\s{1,}=",
        "^SeCreatePagefilePrivilege\s{1,}=",
        "^SeCreatePermanentPrivilege\s{1,}=",
        "^SeCreateSymbolicLinkPrivilege\s{1,}=",
        "^SeIncreaseBasePriorityPrivilege\s{1,}=",
        "^SeIncreaseQuotaPrivilege\s{1,}=",
        "^SeIncreaseWorkingSetPrivilege\s{1,}=",
        "^SeLockMemoryPrivilege\s{1,}=",
        "^SeMachineAccountPrivilege\s{1,}=",
        "^SeProfileSingleProcessPrivilege\s{1,}=",
        "^SeRelabelPrivilege\s{1,}=",
        "^SeShutdownPrivilege\s{1,}=",
        "^SeSystemProfilePrivilege\s{1,}=",
        "^SeSystemtimePrivilege\s{1,}=",
        "^SeTimeZonePrivilege\s{1,}=",
        "^SeUndockPrivilege\s{1,}=",
        "^SeUnsolicitedInputPrivilege\s{1,}="
    )

    $WindowsLogonRightsSenstives = @(
        "^SeInteractiveLogonRight\s{1,}=",
        "^SeRemoteInteractiveLogonRight\s{1,}="
    )
    
    $WindowsLogonRightsNonSenstives = @(
        "^SeBatchLogonRight\s{1,}=",
        "^SeNetworkLogonRight\s{1,}=",
        "^SeServiceLogonRight\s{1,}="
    )

    $Lines = Get-Content -Path $GptTmplPath | Select-String -Pattern @($WindowsPrivilegesSensitives + $WindowsPrivilegesNonSensitives + $WindowsLogonRightsSenstives + $WindowsLogonRightsNonSenstives)
    $Output = New-Object System.Collections.ArrayList

    # Expected line format: 
    # SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555
    foreach ($line in $Lines) {
        $lineEgalSplited = $line.ToString().Split('=')
        If ($lineEgalSplited.Count -ne 2 -or $lineEgalSplited[1].Length -eq 0) { continue }

        $Privilege = $lineEgalSplited[0].Trim()
        $IsPrivilegeSensitive = If ($WindowsPrivilegesSensitives.Contains("^$Privilege\s{1,}=") -or $WindowsLogonRightsSenstives.Contains("^$Privilege\s{1,}=")) { $True } Else { $False }
        
        $SIDList = $lineEgalSplited[1].Trim().Split(',')
        foreach ($SID in $SIDList) {
            $SID = If ($SID[0] -eq "*") { $SID.SubString(1) }
            $null = $Output.Add([PSCustomObject]@{
                Privilege = $Privilege
                IsPrivilegeSensitive = $IsPrivilegeSensitive
                SID = $SID
            })
        }
    }

    return $Output
}

function Get-GPORestrictedGroupsMembershipFromGptTmplPath {
<#
.SYNOPSIS

Get the restricted groups membership defined in a GPO GptTmplPath file.

.PARAMETER GptTmplPath

Specifies the GptTmplPath file path.

.OUTPUTS

[System.Collections.ArrayList]

#>

    Param(
        [Parameter(Mandatory=$True)][String]$GptTmplPath
    )

    $MemberofRegex = "^.*__Memberof\s{1,}=\s{1,}"
    $MembersRegex = "^.*__Members\s{1,}=\s{1,}"

    # Retrieve only the lines that match __Memberof or __Members.
    $Lines = Get-Content -Path $GptTmplPath | Select-String -Pattern $MemberofRegex, $MembersRegex
    $Output = New-Object System.Collections.ArrayList

    foreach ($Line in $Lines) {
        $line_matches = [regex]::Matches($Line, "(.*)__(Members|Memberof)\s{1,}=\s{1,}(.*)")
        
        # Members / Memberof
        $Operation = $line_matches.Groups[2].Value
        # Local group impacted by the GPO.
        $LeftObject = $line_matches.Groups[1].Value
        # Members or Memberof users / groups concerned.
        $RightObjects = $line_matches.Groups[3].Value.Trim()

        # Extract the left group SID or Name (either one being used).
        If ($LeftObject.StartsWith("*S-")) {
            $LeftObject = $LeftObject.SubString(1)
        }
        
        # Retrieve each objects in the RightObjects or convert RightObjects in list if there is only a single object
        If ($RightObjects.Contains(',')) {
            $RightObjects = $RightObjects.Split(',')
        }
        Else {
            $RightObjects = @($RightObjects)
        }

        foreach ($RightObject in $RightObjects) {
            # Extract the right object SID or Name (either one being used).
            If ($RightObject.StartsWith("*S-")) {
                $RightObject = $RightObject.SubString(1)
            }

            # If the operation is Members, the right element is added to the left group.  
            If ($Operation -eq "Members") {
                $Group = $LeftObject
                $Member = $RightObject
            }
            # If the operation is Memberof, the left group is added to the right elements (normally a group).  
            Else {
                $Group = $RightObject
                $Member = $LeftObject
            }

            $null = $Output.Add([PSCustomObject]@{
                Group = $Group
                Member = $Member
                # LeftObjectName = $LeftObjectName
                # LeftObjectSID = $LeftObjectSID
                # Operation = $Operation
                # RightObjectName = $RightObjectName
                # RightObjectSID = $RightObjectSID
                RawEntry = "$LeftObject--$Operation--$RightObject"
            })
        }
    }

    return ,$Output
}

function Get-GPOLogonLogoffScripts {
<#
.SYNOPSIS

Get the logon / logoff scripts defined in a GPO GPOScriptPath file.

Based on https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpscr/ff1fd13e-1e18-4160-9b50-0263e108e5e1

.PARAMETER GPOScriptPath

Specifies the GPOScriptPath file path.

.OUTPUTS

[System.Collections.ArrayList]

#>

    Param(
        [Parameter(Mandatory=$True)][String]$GPOScriptPath
    )

    $Lines = Get-Content -Path $GPOScriptPath

    $Output = New-Object System.Collections.ArrayList
    
    $GPOScope = if ($GPOScriptPath -match "(.*)\\Machine\\(.*)") { "Machine" } Else { "User" }
    $CurrentFileSection = ""
    
    $Commands = @{}
    $Parameters = @{}

    foreach ($line in $Lines) {
        # Extract the section ([Logon] -> Logon).
        If ($line -match "^\s*?\[(.*)\]\s*?$") { $CurrentFileSection = $Matches[0].Substring(1, $Matches[0].Length - 2) }
                
        # Match the CmdLine key.
        # Example format: 0CmdLine=PATH
        ElseIf ($line -match "^\s*?(\d+)CmdLine\s*?=(.*)$") {
            $lineEgalSplited = $line.Split('=')
            $CurrentLineKeyNumber = $lineEgalSplited[0].Split("CmdLine")
            $CurrentLineScript = $lineEgalSplited[1].Trim()
            $null = $Commands.Add("$CurrentFileSection-$CurrentLineKeyNumber", $CurrentLineScript)
        }
        
        # Match the Parameters key.
        # Example format: 0Parameters=Parameters
        ElseIf ($line -match "^\s*?(\d+)Parameters\s*?=(.*)$") {
            $lineEgalSplited = $line.Split('=')
            $CurrentLineKeyNumber = $lineEgalSplited[0].Split("Parameters")
            $CurrentLineParameters = $lineEgalSplited[1].Trim()
            $null = $Parameters.Add("$CurrentFileSection-$CurrentLineKeyNumber", $CurrentLineParameters)
        }

        Else {
            continue
        }
    }

    foreach ($Elt in $Commands.GetEnumerator()) {
        $null = $Output.Add([PSCustomObject]@{
            GPOScope = $GPOScope
            Section = $Elt.Key.ToString().Split("-")[0]
            Command = $Elt.Value
            Parameters = If ($Parameters.ContainsKey($Elt.Key)) { $Parameters[$Elt.Key] } Else { $null }
        })
    }

    return $Output
}

function Get-DaysStringFromWeeklyTriggerDaysOfWeek {
<#
.SYNOPSIS

Get the days as a formated string from a GPO immediate / scheduled task WeeklyTrigger.DaysOfWeek property.

Based on https://docs.microsoft.com/en-us/windows/win32/taskschd/weeklytrigger-daysofweek

.PARAMETER DaysOfWeek

Specifies the DaysOfWeek string.

.OUTPUTS

[System.Object.String]

#>

    Param(
        [Parameter(Mandatory=$True)][String]$DaysOfWeek
    )

    $DAYSOFWEEK_TABLE = @{
        0X01 = "Sunday"
        0x02 = "Monday"
        0X04 = "Tuesday"
        0X08 = "Wednesday"
        0X10 = "Thursday"
        0x20 = "Friday"
        0X40 = "Saturday"
    }

    $DaysOfWeekMatched = New-Object System.Collections.ArrayList

    foreach($DayOfWeekBit in $DAYSOFWEEK_TABLE.Keys | Sort-Object){
        If ($DaysOfWeek -band $DayOfWeekBit){
            $null = $DaysOfWeekMatched.Add($DAYSOFWEEK_TABLE[$DayOfWeekBit])
        }
    }

    return [string]::join("-", [array] $DaysOfWeekMatched)
}

function Get-DaysStringFromMonthlyTriggerDaysOfMonth {
<#
.SYNOPSIS

Get the days digit as a formated string from a GPO immediate / scheduled task MonthlyTrigger.DaysOfMonth property.

Based on https://docs.microsoft.com/en-us/windows/win32/taskschd/monthlytrigger-daysofmonth

.PARAMETER DaysOfMonth

Specifies the DaysOfMonth string.

.OUTPUTS

[System.Object.String]

#>

    Param(
        [Parameter(Mandatory=$True)][String]$DaysOfMonth
    )

    $DAYSOMONTHS_TABLE = @{
        0x01 = "1"
        0x02 = "2"
        0x04 = "3"
        0x08 = "4"
        0x10 = "5"
        0x20 = "6"
        0x40 = "7"
        0x80 = "8"
        0x100 = "9"
        0x200 = "10"
        0x400 = "11"
        0x800 = "12"
        0x1000 = "13"
        0x2000 = "14"
        0x4000 = "15"
        0x8000 = "16"
        0x10000 = "17"
        0x20000 = "18"
        0x40000 = "19"
        0x80000 = "20"
        0x100000 = "21"
        0x200000 = "22"
        0x400000 = "23"
        0x800000 = "24"
        0x1000000 = "25"
        0x2000000 = "26"
        0x4000000 = "27"
        0x8000000 = "28"
        0x10000000 = "29"
        0x20000000 = "30"
        0x40000000 = "31"
    }

    $DaysOfMonthMatched = New-Object System.Collections.ArrayList

    foreach($DayOfMonthBit in $DAYSOMONTHS_TABLE.Keys | Sort-Object){
        If ($DaysOfMonth -band $DayOfMonthBit){
            $null = $DaysOfMonthMatched.Add($DAYSOMONTHS_TABLE[$DayOfMonthBit])
        }
    }

    return [string]::join("-", [array] $DaysOfMonthMatched)
}

function Get-MonthsStringFromMonthlyTriggerMonthsOfYear {
<#
.SYNOPSIS

Get the months as a formated string from a GPO immediate / scheduled task MonthlyTrigger.MonthsOfYear property.

Based on https://docs.microsoft.com/en-us/windows/win32/taskschd/monthlytrigger-monthsofyear

.PARAMETER MonthsOfYear

Specifies the MonthsOfYear string.

.OUTPUTS

[System.Object.String]

#>

    Param(
        [Parameter(Mandatory=$True)][String]$MonthsOfYear
    )

    $MONTHSOFYEAR_TABLE = @{
        0X01 = "January"
        0x02 = "February"
        0X04 = "March"
        0X08 = "April"
        0X10 = "May"
        0X20 = "June"
        0x40 = "July"
        0X80 = "August"
        0X100 = "September"
        0X200 = "October"
        0X400 = "November"
        0X800 = "December"
    }
    
    $MonthsOfYearMatched = New-Object System.Collections.ArrayList

    foreach($MonthsOfYearBit in $MONTHSOFYEAR_TABLE.Keys | Sort-Object){
        If ($MonthsOfYear -band $MonthsOfYearBit){
            $null = $MonthsOfYearMatched.Add($MONTHSOFYEAR_TABLE[$MonthsOfYearBit])
        }
    }

    return [string]::join("-", [array] $MonthsOfYearMatched)
}

function Get-GPOScheduledTasks {
<#
.SYNOPSIS

Get the immediate and scheduled tasks defined in a GPO ScheduledTasks file by partially parsing the tasks XML defintion.

Two ArrayLists are returned: one for immediate / scheduled tasks v1, and one for immediate / scheduled tasks v2.

Based on https://docs.microsoft.com/fr-fr/windows/win32/taskschd/task-scheduler-schema

.PARAMETER ScheduledTasksPath

Specifies the ScheduledTasksPath file path.

.OUTPUTS

([System.Collections.ArrayList], [System.Collections.ArrayList])

#>

    Param(
        [Parameter(Mandatory=$True)][String]$ScheduledTasksPath
    )

    $TASK_ACTIONS = @{
        "C" = "CreateTask"
        "U" = "UpdateTask"
        "R" = "ReplaceTask"
        "D" = "DeleteTask"
    } 

    $OutputTasksV1 = New-Object System.Collections.ArrayList
    $OutputTasksV2 = New-Object System.Collections.ArrayList

    $ScheduledTasksXML = $(Select-Xml -Xml $([xml] $(Get-Content -Path $ScheduledTasksPath)) -XPath "/ScheduledTasks").Node

    # Process Tasks v1.
    $ScheduledTasksXML.Task | Where-Object { $null -ne $_ } | ForEach-Object {
        $TaskObject = $_

        $GPOTaskAction = $TASK_ACTIONS[$TaskObject.Properties.action]

        $TaskOutputObject = [PSCustomObject]@{
            GPOAction = $GPOTaskAction
            TaskType = "ScheduledTaskv1"
            TaskName = $TaskObject.name
            TaskUID = $TaskObject.uid
            TaskLastChanged = $TaskObject.changed
        }

        If ($GPOTaskAction -ne "DeleteTask") {
            $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "TaskEnabled" -Value $([System.Convert]::ToBoolean([int] $TaskObject.Properties.enabled))
            $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "TaskExecute" -Value $TaskObject.Properties.appName
            $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "TaskArguments" -Value $TaskObject.Properties.args
            $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "TaskStartIn" -Value $TaskObject.Properties.StartIn
            $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "TaskComment" -Value $TaskObject.Properties.Comment
            $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "TaskDeleteWhenDone" -Value $([System.Convert]::ToBoolean([int] $TaskObject.Properties.deleteWhenDone))
            
            $TriggerCount = 0
            foreach ($Trigger in $TaskObject.Properties.Triggers.Trigger) {
                # $Trigger = $TriggerRoot.Trigger
                $TaskOutputObjectWithTrigger = $TaskOutputObject.PsObject.Copy()
                $TaskOutputObjectWithTrigger | Add-Member -MemberType NoteProperty -Name "TaskTriggerIndex" -Value $TriggerCount
                $TaskOutputObjectWithTrigger | Add-Member -MemberType NoteProperty -Name "TaskTriggerType" -Value $Trigger.type
                
                If ($Trigger.type -eq "DAILY") {
                    $TaskOutputObjectWithTrigger | Add-Member -MemberType NoteProperty -Name "TriggerBasicDetails" -Value "Execute every $($Trigger.interval) day(s) at $($Trigger.startHour):$($Trigger.startMinutes)"
                }
                ElseIf ($Trigger.type -eq "WEEKLY") {
                    $DaysString = Get-DaysStringFromWeeklyTriggerDaysOfWeek -DaysOfWeek $Trigger.days
                    $TaskOutputObjectWithTrigger | Add-Member -MemberType NoteProperty -Name "TaskTriggerBasicDetails" -Value "Execute every $($Trigger.interval) week(s) at $($Trigger.startHour):$($Trigger.startMinutes) on $DaysString"
                }
                ElseIf ($Trigger.type -eq "MONTHLY") {
                    $MonthsString = Get-MonthsStringFromMonthlyTriggerMonthsOfYear -MonthsOfYear $Trigger.months
                    If ($null -ne $Trigger.week) {
                        $TaskOutputObjectWithTrigger | Add-Member -MemberType NoteProperty -Name "TaskTriggerBasicDetails" -Value "Execute monthly on $($Trigger.days) of $($Trigger.week) week in $MonthsString"
                    }
                    Else {
                        $DaysString = Get-DaysStringFromMonthlyTriggerDaysOfMonth -DaysOfMonth $Trigger.days
                        $TaskOutputObjectWithTrigger | Add-Member -MemberType NoteProperty -Name "TaskTriggerBasicDetails" -Value "Execute monthly the $DaysString th in $MonthsString"
                    }
                }
                ElseIf ($Trigger.type -eq "ONCE") {
                    $TaskOutputObjectWithTrigger | Add-Member -MemberType NoteProperty -Name "TaskTriggerBasicDetails" -Value "Execute (at least) once at $($Trigger.startHour):$($Trigger.startMinutes) on $($Trigger.beginYear)-$($Trigger.beginMonth)-$($Trigger.beginDay)"
                }
                ElseIf ($Trigger.type -eq "IDLE") {
                    $TaskOutputObjectWithTrigger | Add-Member -MemberType NoteProperty -Name "TaskTriggerBasicDetails" -Value "Execute on idle"
                }
                ElseIf ($Trigger.type -eq "STARTUP") {
                    $TaskOutputObjectWithTrigger | Add-Member -MemberType NoteProperty -Name "TaskTriggerBasicDetails" -Value "Execute on startup"
                }
                ElseIf ($Trigger.type -eq "LOGON") {
                    $TaskOutputObjectWithTrigger | Add-Member -MemberType NoteProperty -Name "TaskTriggerBasicDetails" -Value "Execute on logon"
                }

                $TaskOutputObjectWithTrigger | Add-Member -MemberType NoteProperty -Name "TaskTriggerRaw" -Value $Trigger.OuterXml

                $null = $OutputTasksV1.Add($TaskOutputObjectWithTrigger)
                $TriggerCount = $TriggerCount + 1
            }
        }

        Else {
            $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "Enabled" -Value $null
            $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "Execute" -Value $null
            $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "Arguments" -Value $null
            $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "StartIn" -Value $null
            $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "Comment" -Value $null
            $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "DeleteWhenDone" -Value $null
            $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "TaskTriggerIndex" -Value $null
            $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "TaskTriggerType" -Value $null
            $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "TaskTriggerBasicDetails" -Value $null
            $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "TaskTriggerRaw" -Value $null
            $null = $OutputTasksV1.Add($TaskOutputObject)
        }
    }

    # Process immediate Tasks v1.
    $ScheduledTasksXML.ImmediateTask | Where-Object { $null -ne $_ } | ForEach-Object {
        $TaskObject = $_

        $TaskOutputObject = [PSCustomObject]@{
            GPOAction = "CreateTask"
            TaskType = "ImmediateScheduledTaskv1"
            TaskName = $TaskObject.name
            TaskUID = $TaskObject.uid
            TaskLastChanged = $TaskObject.changed
        }

        $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "TaskEnabled" -Value $([System.Convert]::ToBoolean([int] $TaskObject.Properties.enabled))
        $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "TaskExecute" -Value $TaskObject.Properties.appName
        $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "TaskArguments" -Value $TaskObject.Properties.args
        $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "TaskStartIn" -Value $TaskObject.Properties.StartIn
        $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "TaskComment" -Value $TaskObject.Properties.Comment
        $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "TaskDeleteWhenDone" -Value $null
        $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "TaskTriggerIndex" -Value $null
        $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "TaskTriggerType" -Value $null
        $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "TriggerBasicDetails" -Value $null
        $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "TaskTriggerRaw" -Value $null
        $null = $OutputTasksV1.Add($TaskOutputObject)
    }

    # Process Tasks v2.
    @($ScheduledTasksXML.TaskV2 + $ScheduledTasksXML.ImmediateTaskV2) | Where-Object { $null -ne $_ } | ForEach-Object {
        $TaskObject = $_

        $GPOTaskAction = $TASK_ACTIONS[$TaskObject.Properties.action]

        $TaskOutputObject = [PSCustomObject]@{
            GPOAction = $GPOTaskAction
            TaskType = If ($TaskObject.LocalName -eq "ImmediateTaskV2") { "ImmediateTaskV2" } Else { "ScheduledTaskv2" }
            TaskName = $TaskObject.name
            TaskUID = $TaskObject.uid
            TaskLastChanged = $TaskObject.changed
            TaskRunAS = $TaskObject.Properties.runAs
            TaskLogonType = $TaskObject.Properties.logonType
        }

        # Parse each registration information fields of the task and add them to a list for later concatenation.
        $RegistrationInfo = $TaskObject.Properties.Task.RegistrationInfo
        $RegistrationInfoList = New-Object System.Collections.ArrayList
        foreach ($PropertyField in $RegistrationInfo | Get-Member -Type Properties | Select-Object -ExpandProperty Name) {
            If ($null -ne $RegistrationInfo.$PropertyField -and "" -ne $RegistrationInfo.$PropertyField) {
                $null = $RegistrationInfoList.Add("$PropertyField=$($RegistrationInfo.$PropertyField)")
            }
        }
        $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "TaskRegistrationInfo" -Value $([string]::join(";", [array] $RegistrationInfoList))

        # Add task actions raw XML.        
        $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "TaskPrincipalsXML" -Value $($TaskObject.Properties.Task.Principals.OuterXml)

        # Add task actions raw XML.        
        $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "TaskActionsXML" -Value $($TaskObject.Properties.Task.Actions.OuterXml)

        # Add task triggers raw XML.
        $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "TaskTriggersXML" -Value $($TaskObject.Properties.Task.Triggers.OuterXml)

        # $TriggerCount = 1
        # $TriggersList = New-Object System.Collections.ArrayList
        # foreach ($PropertyField in $Triggers | Get-Member -Type Properties | Select-Object -ExpandProperty Name) {
        #     $TriggerCount = $TriggerCount + 1
        #     If ($null -eq $Triggers.$PropertyField -or "" -eq $Triggers.$PropertyField) {
        #         continue
        #     }
            
        #     Elseif ($Triggers.$PropertyField.GetType() -eq [string]) {
        #         $null = $TriggersList.Add("$PropertyField=$($Triggers.$PropertyField)")
        #     }
        #     Elseif ($Triggers.$PropertyField.GetType() -eq [System.Xml.XmlElement]) {
        #         foreach ($NestedPropertyField in $Triggers.$PropertyField | Get-Member -Type Properties | Select-Object -ExpandProperty Name) {
        #             $null = $TriggersList.Add("$($PropertyField)__$($NestedPropertyField)=$($Triggers.$PropertyField.$NestedPropertyField)")
        #         }
        #     }
        #     Elseif ($Triggers.$PropertyField.GetType() -eq [System.Object[]]) {           
        #         foreach ($Object in $Triggers.$PropertyField) {
        #             $null = $TriggersList.Add("$($PropertyField)__$($Object.Name)=$($Object.InnerText)")
        #         }
        #     }
        # }
        # $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "TriggerCount" -Value $TriggerCount
        # $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "TaskTriggers" -Value $([string]::join(";", [array] $TriggersList))

        # Parse each settings fields of the task and add them to a list for later concatenation.
        $Settings = $TaskObject.Properties.Task.Settings
        $SettingsList = New-Object System.Collections.ArrayList
        foreach ($PropertyField in $Settings | Get-Member -Type Properties | Select-Object -ExpandProperty Name) {
            If ($null -eq $Settings.$PropertyField -or "" -eq $Settings.$PropertyField) {
                continue
            }
            Elseif ($Settings.$PropertyField.GetType() -eq [string]) {
                $null = $SettingsList.Add("$PropertyField=$($Settings.$PropertyField)")
            }
            Elseif ($Settings.$PropertyField.GetType() -eq [System.Xml.XmlElement]) {
                foreach ($NestedPropertyField in $Settings.$PropertyField | Get-Member -Type Properties | Select-Object -ExpandProperty Name) {
                    $null = $SettingsList.Add("$($PropertyField)__$($NestedPropertyField)=$($Settings.$PropertyField.$NestedPropertyField)")
                }
            }
        }
        $TaskOutputObject | Add-Member -MemberType NoteProperty -Name "TaskSettings" -Value $([string]::join(";", [array] $SettingsList))

        $null = $OutputTasksV2.Add($TaskOutputObject)
    }

    return $OutputTasksV1, $OutputTasksV2
}

function Export-ADHuntingGPOSettings {
<#
.SYNOPSIS

Export to multiple CSV / JSON files information on various settings configured by GPOs that could be leveraged for persistence that could be leveraged for persistence (privileges and logon rights, restricted groups membership, scheduled and immediate tasks V1 / V2, machine and user logon / logoff scripts)..

.DESCRIPTION

Determine if the GPOs are applied on privileged users or computers (at OU, Domain or Site level, and by processing OU inheritance block / GPO enforcement).

Directly parse the GPO files on the SYSVOL to retrieve (some) settings deployed by the GPOs and track GPO that couldn’t be evaluated, notably to identify access denied errors.

The following settings are retrieved: 
  - the privileges and logon rights, determining if dangerous privileges* / logon rights are granted to non-privileged principals or everyone
  - the restricted groups membership, highlighting privileged groups and unprivileged members
  - the scheduled and immediate tasks configured, by (somewhat) parsing the XML tasks definition
  - the machine and user logon / logoff scripts, checking if the target scripts are hosted on the DC, if takeover / modification rights are granted to non-privileged or everyone, and the scripts MACB timestamps

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER ADDriveName

Specifies the name to use for the ActiveDirectory PSDrive that will be (temporarily) mounted by the cmdlet.
Defaults to ADHunting.

.PARAMETER SYSVOLDriveName

Specifies the name to use for the Filesystem PSDrive to the Domain Controller SYSVOL directory that will be (temporarily) mounted by the cmdlet.
Defaults to $ADDriveName_SYSVOL.

.PARAMETER PrivilegedSIDs

Specifies the list of privileged SIDs in the domain. If not specified, the list is determined using Get-ADHuntingAllPrivilegedSIDs.
Used for optimization purposes for subsequent calls to the function.

.PARAMETER OutputFolder

Specifies the CSV / JSON output file location (where the data will be exported to).

.PARAMETER OutputType

Specifies the format for the exported data (CSV or JSON). Defaults to CSV.

.OUTPUTS

Multipe CSV / JSON files written to disk, one file per GPO settings type.

#>

    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$False)][String]$SYSVOLDriveName = "ADHunting_SYSVOL",
        [Parameter(Mandatory=$False)][String]$NETLOGONDriveName = "ADHunting_NETLOGON",
        [Parameter(Mandatory=$False)]$PrivilegedSIDs = $null,
        [Parameter(Mandatory=$False)][String]$OutputFolder,
        [Parameter(Mandatory=$False)]
            [ValidateSet("JSON","CSV")]
            [string]$OutputType = "CSV"
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)
    $PSDefaultParameterValues.Add("New-PSDrive:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
        $PSDefaultParameterValues.Add("New-PSDrive:Credential", $Credential)
    }

    $ADDomainObject = Get-ADDomain
    $DomainName = $ADDomainObject.Name
    $DomainDnsName = $ADDomainObject.DNSRoot
    $SystemContainer = $ADDomainObject.SystemsContainer
    
    $timestamp = $(Get-Date -f yyyy-MM-dd-HHmmss)
    $OutputFolder = If (!$OutputFolder) { "." } Else { $OutputFolder }
    $OutputPrivilegesPath = "$OutputFolder\${DomainDnsName}_GPO_privileges_and_logon_rights_$timestamp.$($OutputType.ToLower())"
    $OutputRestrictedGroupsPath = "$OutputFolder\${DomainDnsName}_GPO_restricted_groups_$timestamp.$($OutputType.ToLower())"
    $OutputLogonLogoffScriptsPath = "$OutputFolder\${DomainDnsName}_GPO_logon_and_logoff_scripts_$timestamp.$($OutputType.ToLower())"
    $OutputScheduledTasksV1Path = "$OutputFolder\${DomainDnsName}_GPO_scheduled_and_immediate_tasks_v1_$timestamp.$($OutputType.ToLower())"
    $OutputScheduledTasksV2Path = "$OutputFolder\${DomainDnsName}_GPO_scheduled_and_immediate_tasks_v2_$timestamp.$($OutputType.ToLower())"
    $OutputErrorsPath = "$OutputFolder\${DomainDnsName}_GPO_access_errors_$timestamp.$($OutputType.ToLower())"
    
    Write-Host "[$($MyInvocation.MyCommand)][*] Enumerating GPO settings: privileges and logon rights, restricted groups, logon / logoff scripts, scheduled tasks,..."

    $SYSVOLPath = "\\$DomainDnsName\SYSVOL"
    $SYSVOLMountPath = "\\$Server\SYSVOL"
    $NETLOGONPath = "\\$Server\NETLOGON"
    $DCRegex = "^\\\\($DomainName|$DomainDnsName|$Server)"
    $SYSVOLRegex = "$DCRegex\\SYSVOL"
    $NETLOGONRegex = "$DCRegex\\NETLOGON"
    $GPORootPath = "$SYSVOLPath\$DomainDnsName\Policies\"
    
    # Determine once the privileged / unprivileged SIDs to filter out for performance.
    If (!$PrivilegedSIDs) {
        $PrivilegedSIDs = Get-ADHuntingAllPrivilegedSIDs
    }
    $UnprivilegedSIDs = Get-ADHuntingUnprivilegedSIDs
    
    $AllPrivilegedObjects = Get-ADHuntingAllPrivilegedObjects -PrivilegedSIDs $PrivilegedSIDs
    
    # Enumerate all GPOs linked on privileged containers (filtering from all objects first enumerated using Get-ADHuntingAllPrivilegedObjects).
    $PrivilegedContainers, $GPOObjectsLinkedOnPrivilegedContainer = Get-ADHuntingPrivilegedContainersAndGPOs -AllPrivilegedAccounts $($AllPrivilegedObjects | Where-Object { $_.objectClass -eq "user" -or $_.objectClass -eq "computer" })

    # Add GPO links on any objects on the Domain partition and the Sites partition to a hashmap.
    # $GPOLinkedOnPrivilegedContainers, $GPOLinkedOnNonPrivilegedContainers = Get-ADHuntingGPOLinkedHashMap -PrivilegedContainers $PrivilegedContainers

    # Enumerate all GPOs objects.
    $GPOObjects = Get-ADObject -SearchBase "$SystemContainer" -LDAPFilter "(objectClass=groupPolicyContainer)" -Properties displayName,gPCFileSysPath,whenCreated,whenChanged

    # Enumerate all GPO root folders on SYSVOL.
    If (!(Get-PSDrive "$SYSVOLDriveName" -ErrorAction SilentlyContinue)) {
        try {
            $null = New-PSDrive -ErrorAction Stop -Name "$SYSVOLDriveName" -PSProvider FileSystem -Root $SYSVOLMountPath
        }
        catch {
            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingGPOSettings][-] Error while trying to mount the SYSVOL at $SYSVOLMountPath"
            If ($_.InvocationInfo.MyCommand -eq "New-PSDrive" -and $_.Exception.Message -eq "Access is denied.") {
                Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingGPOSettings][-] New hardening on UNC path may prevent mounting the SYSVOL folder. Use 'New-ItemProperty ""HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"" -Name ""\\<DC | *>\SYSVOL"" -Value ""RequireMutualAuthentication=0"" -Property ""String""'"
            }
            return
        }
    }
    
    $GPOFolders = Get-ChildItem -Directory -LiteralPath "${SYSVOLDriveName}:\$DomainDnsName\Policies\"
    
    $funcDefAddPrivilegeLevelType = ${function:Add-PrivilegeLevelType}.ToString()
    $funcDefGetGPOPrivilegesFromGptTmplPath = ${function:Get-GPOPrivilegesFromGptTmplPath}.ToString()
    $funcDefGetGPORestrictedGroupsMembershipFromGptTmplPath = ${function:Get-GPORestrictedGroupsMembershipFromGptTmplPath}.ToString()
    $funcDefGetGPOLogonLogoffScripts = ${function:Get-GPOLogonLogoffScripts}.ToString()
    $funcDefGetGPOScheduledTasks = ${function:Get-GPOScheduledTasks}.ToString()
    $funcDefIsDangerousFileACE = ${function:Is-DangerousFileACE}.ToString()
    $funcDefGetHuntingFileParsedACL = ${function:Get-ADHuntingFileParsedACL}.ToString()
    $funcGetDaysStringFromWeeklyTriggerDaysOfWeek = ${function:Get-DaysStringFromWeeklyTriggerDaysOfWeek}.ToString()
    $funcGetDaysStringFromMonthlyTriggerDaysOfMonth = ${function:Get-DaysStringFromMonthlyTriggerDaysOfMonth}.ToString()
    $funcGetDaysStringFromWeeklyTriggerDaysOfWeek = ${function:Get-DaysStringFromWeeklyTriggerDaysOfWeek}.ToString()
    $funcGetMonthsStringFromMonthlyTriggerMonthsOfYear = ${function:Get-MonthsStringFromMonthlyTriggerMonthsOfYear}.ToString()

    $OutputPrivileges = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $OutputRestrictedGroups = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $OutputLogonLogoffScripts = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $OutputScheduledTasksV1 = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $OutputScheduledTasksV2 = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $AccessErrors = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))

    $GPOGrantingPrivileges = [ref] 0
    $GPOGrantingPrivilegesAndLinkedOnPriv = [ref] 0
    $GPODefiningRestrictedGroups = [ref] 0
    $GPODefiningRestrictedGroupsAndLinkedOnPriv = [ref] 0
    $GPODefiningLogonLogoffScripts = [ref] 0
    $GPODefiningLogonLogoffScriptsAndLinkedOnPriv = [ref] 0
    $GPODefiningScheduledTasks = [ref] 0
    $GPODefiningScheduledTasksAndLinkedOnPriv = [ref] 0

    $GPOFolders | ForEach-Object -Parallel {
        try {
            $OutputPrivileges = $using:OutputPrivileges
            $OutputRestrictedGroups = $using:OutputRestrictedGroups
            $OutputLogonLogoffScripts = $using:OutputLogonLogoffScripts
            $OutputScheduledTasksV1 = $using:OutputScheduledTasksV1
            $OutputScheduledTasksV2 = $using:OutputScheduledTasksV2
            $GPODefiningScheduledTasks = $using:GPODefiningScheduledTasks
            $GPODefiningScheduledTasksAndLinkedOnPriv = $using:GPODefiningScheduledTasksAndLinkedOnPriv
            $AccessErrors = $using:AccessErrors
            $PSDefaultParameterValues = $using:PSDefaultParameterValues
            $DomainName = $using:DomainName
            $DomainDnsName = $using:DomainDnsName
            $SystemContainer = $using:SystemContainer
            $SYSVOLDriveName = $using:SYSVOLDriveName
            $NETLOGONDriveName = $using:NETLOGONDriveName
            $SYSVOLPath = $using:SYSVOLPath
            $SYSVOLMountPath = $using:SYSVOLMountPath
            $NETLOGONPath = $using:NETLOGONPath
            $DCRegex = $using:DCRegex
            $SYSVOLRegex = $using:SYSVOLRegex
            $NETLOGONRegex = $using:NETLOGONRegex
            $GPORootPath = $using:GPORootPath
            $GPOObjects = $using:GPOObjects
            $GPOObjectsLinkedOnPrivilegedContainer = $using:GPOObjectsLinkedOnPrivilegedContainer
            $PrivilegedSIDs = $using:PrivilegedSIDs
            $UnprivilegedSIDs = $using:UnprivilegedSIDs
            $GPOGrantingPrivileges = $using:GPOGrantingPrivileges
            $GPOGrantingPrivilegesAndLinkedOnPriv = $using:GPOGrantingPrivilegesAndLinkedOnPriv
            $GPODefiningRestrictedGroups = $using:GPODefiningRestrictedGroups
            $GPODefiningRestrictedGroupsAndLinkedOnPriv = $using:GPODefiningRestrictedGroupsAndLinkedOnPriv
            $GPODefiningLogonLogoffScripts = $using:GPODefiningLogonLogoffScripts
            $GPODefiningLogonLogoffScriptsAndLinkedOnPriv = $using:GPODefiningLogonLogoffScriptsAndLinkedOnPriv
            ${function:Add-PrivilegeLevelType} = $using:funcDefAddPrivilegeLevelType
            ${function:Get-GPOPrivilegesFromGptTmplPath} = $using:funcDefGetGPOPrivilegesFromGptTmplPath
            ${function:Get-GPORestrictedGroupsMembershipFromGptTmplPath} = $using:funcDefGetGPORestrictedGroupsMembershipFromGptTmplPath
            ${function:Get-GPOLogonLogoffScripts} = $using:funcDefGetGPOLogonLogoffScripts
            ${function:Get-GPOScheduledTasks} = $using:funcDefGetGPOScheduledTasks
            ${function:Is-DangerousFileACE} = $using:funcDefIsDangerousFileACE
            ${function:Get-ADHuntingFileParsedACL} = $using:funcDefGetHuntingFileParsedACL
            ${function:Get-DaysStringFromWeeklyTriggerDaysOfWeek} = $using:funcGetDaysStringFromWeeklyTriggerDaysOfWeek
            ${function:Get-DaysStringFromMonthlyTriggerDaysOfMonth} = $using:funcGetDaysStringFromMonthlyTriggerDaysOfMonth
            ${function:Get-DaysStringFromWeeklyTriggerDaysOfWeek} = $using:funcGetDaysStringFromWeeklyTriggerDaysOfWeek
            ${function:Get-MonthsStringFromMonthlyTriggerMonthsOfYear} = $using:funcGetMonthsStringFromMonthlyTriggerMonthsOfYear

            $GPOFolder = $_

            Add-PrivilegeLevelType

            If (!(Get-PSDrive "$SYSVOLDriveName" -ErrorAction SilentlyContinue)) {
                $null = New-PSDrive -ErrorAction Stop -Name "$SYSVOLDriveName" -PSProvider FileSystem -Root $SYSVOLMountPath
            }
            
            If (!(Get-PSDrive "$NETLOGONDriveName" -ErrorAction SilentlyContinue)) {
                $null = New-PSDrive -ErrorAction Stop -Name "$NETLOGONDriveName" -PSProvider FileSystem -Root $NETLOGONPath
            }
            
            $GPOFolderPathOnDrive = $GPOFolder.FullName -ireplace [regex]::Escape($SYSVOLMountPath), "${SYSVOLDriveName}:"

            $GPOGuid = $GPOFolder.PSChildName
            $GPOObject = $GPOObjects | Where-Object { $_.Name -eq "$GPOGuid" }
            
            $GPODistinguishedName = "CN=$GPOGuid,CN=Policies,$SystemContainer"

            # Lookup GPO DN in GPOObjectsLinkedOnPrivilegedContainer hashmap.
            If ($GPOObjectsLinkedOnPrivilegedContainer.Contains($GPODistinguishedName)) { 
                $IsGPOLinkedOnPrivilegedObjects = $True
                $IsGPOLinkEnabledOnPrivilegedObjects = If ($GPOObjectsLinkedOnPrivilegedContainer[$GPODistinguishedName] | Where-Object { $_.IsLinkEnabled -eq $True }) { $True } Else { $False }
                $IsGPOEnforcedOnPrivilegedObjects = If ($GPOObjectsLinkedOnPrivilegedContainer[$GPODistinguishedName] | Where-Object { $_.IsLinkEnforced -eq $True }) { $True } Else { $False }
                $IsGPOAppliedOnPrivilegedObjects = If ($GPOObjectsLinkedOnPrivilegedContainer[$GPODistinguishedName] | Where-Object { $_.IsApplied -eq $True }) { $True } Else { $False }
            }
            Else { 
                $IsGPOLinkedOnPrivilegedObjects = $False
                $IsGPOLinkEnabledOnPrivilegedObjects = $False
                $IsGPOEnforcedOnPrivilegedObjects = $False
                $IsGPOAppliedOnPrivilegedObjects = $False
            }
            
            $GPOOutputBaseObject = [PSCustomObject]@{
                Domain = $DomainName
                GPOGuid = $GPOGuid
                GPODisplayName = If ($GPOObject) { $GPOObject["DisplayName"].Value } Else { "GPO object no longer exist / not accessible" }
                GPODistinguishedName = $GPODistinguishedName
                IsGPOLinkedOnPrivilegedObjects = $IsGPOLinkedOnPrivilegedObjects
                IsGPOLinkEnabledOnPrivilegedObjects = $IsGPOLinkEnabledOnPrivilegedObjects
                IsGPOEnforcedOnPrivilegedObjects = $IsGPOEnforcedOnPrivilegedObjects
                IsGPOAppliedOnPrivilegedObjects = $IsGPOAppliedOnPrivilegedObjects
                GPOwhenCreated = If ($GPOObject) {  $GPOObject["whenCreated"].Value } Else { $null }
                GPOwhenChanged = If ($GPOObject) {  $GPOObject["whenChanged"].Value } Else { $null }
            }

            $GPOFiles = Get-ChildItem -Force -File -Recurse -LiteralPath "$GPOFolderPathOnDrive" -ErrorAction SilentlyContinue -ErrorVariable AccessError

            # Keep track of file access errors and continue.
            If ($AccessError) {
                foreach ($AccessErrorObject in $AccessError) {
                    $ErrorOutputObject = $GPOOutputBaseObject.PsObject.Copy()
                    $ErrorOutputObject | Add-Member -MemberType NoteProperty -Name "ExceptionMessage" -Value $AccessErrorObject.Exception.Message
                    $ErrorOutputObject | Add-Member -MemberType NoteProperty -Name "ExceptionHResult" -Value $AccessErrorObject.Exception.HResult
                    $ErrorOutputObject | Add-Member -MemberType NoteProperty -Name "ExceptionStackTrace" -Value $AccessErrorObject.Exception.StackTrace
                    $null = $AccessErrors.Add($ErrorOutputObject)
                }
                continue
            }

            foreach ($GPOFile in $GPOFiles) {
                $GPOFilePathOnDrive = $GPOFile.FullName -ireplace [regex]::Escape($SYSVOLMountPath), "${SYSVOLDriveName}:"
                $GPOFileTrailingPath = [regex]::Matches($GPOFile.FullName, "Policies\\(.*)$").Groups[1].Value # $GPOFile.FullName.SubString($GPORootPath.Length)
                
                switch -Regex ($GPOFileTrailingPath) {
                
                    "(.*)\\Machine\\microsoft\\windows nt\\SecEdit\\GptTmpl.inf$" {
                        
                        # Privileges / logon rights.
                        $GPOPrivileges = Get-GPOPrivilegesFromGptTmplPath -GptTmplPath $GPOFilePathOnDrive
                        If ($GPOPrivileges.Count -gt 0) {
                            $null = [Threading.Interlocked]::Increment($GPOGrantingPrivileges)
                            If ($IsGPOLinkedOnPrivilegedObjects) { $null = [Threading.Interlocked]::Increment($GPOGrantingPrivilegesAndLinkedOnPriv) }
                            
                            foreach ($GPOPrivilege in $GPOPrivileges) {
                                $GrantedToIs = [PrivilegeLevel]::Privileged
                                If ($UnprivilegedSIDs.Contains($GPOPrivilege.SID)) { $GrantedToIs = [PrivilegeLevel]::Everyone }
                                ElseIf (!$PrivilegedSIDs.Contains($GPOPrivilege.SID)) { $GrantedToIs = [PrivilegeLevel]::NonPrivileged }

                                $PrivilegeOutputObject = $GPOOutputBaseObject.PsObject.Copy()
                                $PrivilegeOutputObject | Add-Member -MemberType NoteProperty -Name "GPOFile" -Value $GPOFile.FullName
                                $PrivilegeOutputObject | Add-Member -MemberType NoteProperty -Name "Privilege" -Value $GPOPrivilege.Privilege
                                $PrivilegeOutputObject | Add-Member -MemberType NoteProperty -Name "GrantedToSID" -Value $GPOPrivilege.SID
                                $PrivilegeOutputObject | Add-Member -MemberType NoteProperty -Name "IsPrivilegeSensitive" -Value $GPOPrivilege.IsPrivilegeSensitive
                                $PrivilegeOutputObject | Add-Member -MemberType NoteProperty -Name "GrantedToIs" -Value $GrantedToIs
                                $null = $OutputPrivileges.Add($PrivilegeOutputObject)
                            }
                        }
                        
                        # Restricted groups.
                        $GPORestrictedGroupMemberships = Get-GPORestrictedGroupsMembershipFromGptTmplPath -GptTmplPath $GPOFilePathOnDrive
                        If ($GPORestrictedGroupMemberships.Count -gt 0) {
                            $null = [Threading.Interlocked]::Increment($GPODefiningRestrictedGroups)
                            If ($IsGPOLinkedOnPrivilegedObjects) { $null = [Threading.Interlocked]::Increment($GPODefiningRestrictedGroupsAndLinkedOnPriv) }
                            
                            foreach ($GPORestrictedGroupMembership in $GPORestrictedGroupMemberships) {
                                $IsGroupPrivileged = If ($PrivilegedSIDs.Contains($GPORestrictedGroupMembership.Group)) { $True } Else { $False }
                                $IsMemberEveryone = If ($UnprivilegedSIDs.Contains($GPORestrictedGroupMembership.Member)) { $True } Else { $False }

                                $RestrictedGroupMembershipOutputObject = $GPOOutputBaseObject.PsObject.Copy()
                                $RestrictedGroupMembershipOutputObject | Add-Member -MemberType NoteProperty -Name "GPOFile" -Value $GPOFile.FullName
                                $RestrictedGroupMembershipOutputObject | Add-Member -MemberType NoteProperty -Name "Group" -Value $GPORestrictedGroupMembership.Group
                                $RestrictedGroupMembershipOutputObject | Add-Member -MemberType NoteProperty -Name "IsGroupPrivileged" -Value $IsGroupPrivileged
                                $RestrictedGroupMembershipOutputObject | Add-Member -MemberType NoteProperty -Name "Member" -Value $GPORestrictedGroupMembership.Member
                                $RestrictedGroupMembershipOutputObject | Add-Member -MemberType NoteProperty -Name "IsMemberEveryone" -Value $IsMemberEveryone
                                $RestrictedGroupMembershipOutputObject | Add-Member -MemberType NoteProperty -Name "RawEntry" -Value $GPORestrictedGroupMembership.RawEntry
                                $null = $OutputRestrictedGroups.Add($RestrictedGroupMembershipOutputObject)
                            }
                        }
                    }

                    # Defines logon / logoff scripts.
                    "(.*)\\(Machine|User)\\Scripts\\(scripts|psscripts).ini$" {
                        $GPOScripts = Get-GPOLogonLogoffScripts -GPOScriptPath $GPOFilePathOnDrive
                        If ($GPOScripts.Count -gt 0) {
                            $null = [Threading.Interlocked]::Increment($GPODefiningLogonLogoffScripts)
                            If ($IsGPOLinkedOnPrivilegedObjects) { $null = [Threading.Interlocked]::Increment($GPODefiningLogonLogoffScriptsAndLinkedOnPriv) }
                            
                            foreach ($GPOScript in $GPOScripts) {
                                $ScriptOutputObject = $GPOOutputBaseObject.PsObject.Copy()
                                $ScriptOutputObject | Add-Member -MemberType NoteProperty -Name "GPOFile" -Value $GPOFile.FullName
                                $ScriptOutputObject | Add-Member -MemberType NoteProperty -Name "GPOScope" -Value $GPOScript.GPOScope
                                $ScriptOutputObject | Add-Member -MemberType NoteProperty -Name Section -Value $GPOScript.Section
                                $ScriptOutputObject | Add-Member -MemberType NoteProperty -Name Command -Value $GPOScript.Command
                                $ScriptOutputObject | Add-Member -MemberType NoteProperty -Name Parameters -Value $GPOScript.Parameters

                                $IsScriptFileOnDC = If ($GPOScript.Command -match $DCRegex) { $True } Else { $False }
                                $ScriptOutputObject | Add-Member -MemberType NoteProperty -Name IsScriptFileOnDC -Value $IsScriptFileOnDC

                                # Process script file ACL only if the file is hosted on a Domain Controller.
                                $ScriptFileCreationTime = $null
                                $ScriptFileLastWriteTime = $null
                                $ScriptFileLastAccessTime = $null
                                $ScriptDangerousFileOwner = $null
                                $ScriptFileOwnerAsString = $null
                                $ScriptFileSenstiveRightGrantedTo = $null
                                $ScriptFileSenstiveRightsAsString = $null
                                If ($IsScriptFileOnDC) {
                                    $ScriptFilePathOnDrive = $GPOScript.Command
                                    $ScriptFilePathOnDrive = $ScriptFilePathOnDrive -replace $SYSVOLRegex, "${SYSVOLDriveName}:"
                                    $ScriptFilePathOnDrive = $ScriptFilePathOnDrive -replace $NETLOGONRegex, "${NETLOGONDriveName}:"
                                    
                                    If (Test-Path -Path $ScriptFilePathOnDrive -PathType Leaf) {
                                        $ScriptFileMetadata = Get-Item -Path $ScriptFilePathOnDrive
                                        $ScriptFileCreationTime = If ($ScriptFileMetadata.CreationTime) { $ScriptFileMetadata.CreationTime.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                                        $ScriptFileLastWriteTime = If ($ScriptFileMetadata.LastWriteTime) { $ScriptFileMetadata.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                                        $ScriptFileLastAccessTime = If ($ScriptFileMetadata.LastAccessTime) { $ScriptFileMetadata.LastAccessTime.ToString('yyyy-MM-dd HH:mm:ss.fff') } Else { $null }
                                        
                                        $ParsedScriptFileACLObject = Get-ADHuntingFileParsedACL -PrivilegedSIDs $PrivilegedSIDs -UnprivilegedSIDs $UnprivilegedSIDs -IncludeFileInOutput $False -FilePath $ScriptFilePathOnDrive
                                        If ($ParsedScriptFileACLObject) {
                                            $ScriptDangerousFileOwner = $ParsedScriptFileACLObject.DangerousFileOwner
                                            $ScriptFileOwnerAsString = $ParsedScriptFileACLObject.DangerousFilesOwnerAsString
                                            $ScriptFileSenstiveRightGrantedTo = $ParsedScriptFileACLObject.FileSenstiveRightGrantedTo
                                            $ScriptFileSenstiveRightsAsString = $ParsedScriptFileACLObject.FilesSenstiveRightsAsString
                                        }
                                        Else {
                                            Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingGPOSettings][-] Couldn't parse ACL of file: $ScriptFilePathOnDrive"
                                        } 
                                    }
                                }
                                $ScriptOutputObject | Add-Member -MemberType NoteProperty -Name ScriptFileCreationTime -Value $ScriptFileCreationTime
                                $ScriptOutputObject | Add-Member -MemberType NoteProperty -Name ScriptFileLastWriteTime -Value $ScriptFileLastWriteTime
                                $ScriptOutputObject | Add-Member -MemberType NoteProperty -Name ScriptFileLastAccessTime -Value $ScriptFileLastAccessTime
                                $ScriptOutputObject | Add-Member -MemberType NoteProperty -Name ScriptDangerousFileOwner -Value $ScriptDangerousFileOwner
                                $ScriptOutputObject | Add-Member -MemberType NoteProperty -Name ScriptFileOwnerAsString -Value $ScriptFileOwnerAsString
                                $ScriptOutputObject | Add-Member -MemberType NoteProperty -Name ScriptFileSenstiveRightGrantedTo -Value $ScriptFileSenstiveRightGrantedTo
                                $ScriptOutputObject | Add-Member -MemberType NoteProperty -Name ScriptFileSenstiveRightsAsString -Value $ScriptFileSenstiveRightsAsString

                                $null = $OutputLogonLogoffScripts.Add($ScriptOutputObject)
                            }
                        }
                    }
                    
                    # Defines machine / user scheduled and immediate tasks.
                    "(.*)\\(Machine|User)\\Preferences\\ScheduledTasks\\ScheduledTasks.xml" {
                        $GPOScheduledTasksV1, $GPOScheduledTasksV2 = Get-GPOScheduledTasks -ScheduledTasksPath $GPOFilePathOnDrive
                        $GPOScope = if ($GPOFilePathOnDrive -match "(.*)\\Machine\\(.*)") { "Machine" } Else { "User" }

                        If ($GPOScheduledTasksV1.Count -gt 0 -or $GPOScheduledTasksV2.Count -gt 0) {

                            $null = [Threading.Interlocked]::Increment($GPODefiningScheduledTasks)
                            If ($IsGPOLinkedOnPrivilegedObjects) { $null = [Threading.Interlocked]::Increment($GPODefiningScheduledTasksAndLinkedOnPriv) }
                            
                            foreach ($GPOScheduledTaskV1 in $GPOScheduledTasksV1) {
                                $ScheduledTaskV1OutputObject = $GPOOutputBaseObject.PsObject.Copy()
                                $ScheduledTaskV1OutputObject | Add-Member -MemberType NoteProperty -Name "TaskScope" -Value $GPOScope
                                
                                # foreach ($Property in @($GPOScheduledTaskV1 | Get-Member -type Properties)) {
                                #     $PropertyName = $Property.Name
                                #     $PropertyValue = $GPOScheduledTaskV1.$PropertyName
                                #     $ScheduledTaskV1OutputObject | Add-Member -MemberType NoteProperty -Name $PropertyName -Value $PropertyValue
                                # }

                                $ScheduledTaskV1OutputObject | Add-Member -MemberType NoteProperty -Name "GPOAction" -Value $GPOScheduledTaskV1.GPOAction
                                $ScheduledTaskV1OutputObject | Add-Member -MemberType NoteProperty -Name "TaskType" -Value $GPOScheduledTaskV1.TaskType
                                $ScheduledTaskV1OutputObject | Add-Member -MemberType NoteProperty -Name "TaskName" -Value $GPOScheduledTaskV1.TaskName
                                $ScheduledTaskV1OutputObject | Add-Member -MemberType NoteProperty -Name "TaskUID" -Value $GPOScheduledTaskV1.TaskUID
                                $ScheduledTaskV1OutputObject | Add-Member -MemberType NoteProperty -Name "TaskLastChanged" -Value $GPOScheduledTaskV1.TaskLastChanged
                                $ScheduledTaskV1OutputObject | Add-Member -MemberType NoteProperty -Name "TaskEnabled" -Value $GPOScheduledTaskV1.TaskEnabled
                                $ScheduledTaskV1OutputObject | Add-Member -MemberType NoteProperty -Name "TaskExecute" -Value $GPOScheduledTaskV1.TaskExecute
                                $ScheduledTaskV1OutputObject | Add-Member -MemberType NoteProperty -Name "TaskArguments" -Value $GPOScheduledTaskV1.TaskArguments
                                $ScheduledTaskV1OutputObject | Add-Member -MemberType NoteProperty -Name "TaskStartIn" -Value $GPOScheduledTaskV1.TaskStartIn
                                $ScheduledTaskV1OutputObject | Add-Member -MemberType NoteProperty -Name "TaskComment" -Value $GPOScheduledTaskV1.TaskComment
                                $ScheduledTaskV1OutputObject | Add-Member -MemberType NoteProperty -Name "TaskDeleteWhenDone" -Value $GPOScheduledTaskV1.TaskDeleteWhenDone
                                $ScheduledTaskV1OutputObject | Add-Member -MemberType NoteProperty -Name "TaskTriggerIndex" -Value $GPOScheduledTaskV1.TaskTriggerIndex
                                $ScheduledTaskV1OutputObject | Add-Member -MemberType NoteProperty -Name "TaskTriggerType" -Value $GPOScheduledTaskV1.TaskTriggerType
                                $ScheduledTaskV1OutputObject | Add-Member -MemberType NoteProperty -Name "TaskTriggerBasicDetails" -Value $GPOScheduledTaskV1.TaskTriggerBasicDetails
                                $ScheduledTaskV1OutputObject | Add-Member -MemberType NoteProperty -Name "TaskTriggerRaw" -Value $GPOScheduledTaskV1.TaskTriggerRaw
                                    
                                $null = $OutputScheduledTasksV1.Add($ScheduledTaskV1OutputObject)
                            }

                            foreach ($GPOScheduledTaskV2 in $GPOScheduledTasksV2) {
                                $ScheduledTaskV2OutputObject = $GPOOutputBaseObject.PsObject.Copy()
                                $ScheduledTaskV2OutputObject | Add-Member -MemberType NoteProperty -Name "TaskScope" -Value $GPOScope
                                
                                # foreach ($Property in @($GPOScheduledTaskV2 | Get-Member -type Properties)) {
                                #     $PropertyName = $Property.Name
                                #     $PropertyValue = $GPOScheduledTaskV2.$PropertyName
                                #     $ScheduledTaskV2OutputObject | Add-Member -MemberType NoteProperty -Name $PropertyName -Value $PropertyValue
                                # }
                                
                                $ScheduledTaskV2OutputObject | Add-Member -MemberType NoteProperty -Name "GPOAction" -Value $GPOScheduledTaskV2.GPOAction
                                $ScheduledTaskV2OutputObject | Add-Member -MemberType NoteProperty -Name "TaskType" -Value $GPOScheduledTaskV2.TaskType
                                $ScheduledTaskV2OutputObject | Add-Member -MemberType NoteProperty -Name "TaskName" -Value $GPOScheduledTaskV2.TaskName
                                $ScheduledTaskV2OutputObject | Add-Member -MemberType NoteProperty -Name "TaskUID" -Value $GPOScheduledTaskV2.TaskUID
                                $ScheduledTaskV2OutputObject | Add-Member -MemberType NoteProperty -Name "TaskLastChanged" -Value $GPOScheduledTaskV2.TaskLastChanged
                                $ScheduledTaskV2OutputObject | Add-Member -MemberType NoteProperty -Name "TaskRunAS" -Value $GPOScheduledTaskV2.TaskRunAS
                                $ScheduledTaskV2OutputObject | Add-Member -MemberType NoteProperty -Name "TaskLogonType" -Value $GPOScheduledTaskV2.TaskLogonType
                                $ScheduledTaskV2OutputObject | Add-Member -MemberType NoteProperty -Name "TaskRegistrationInfo" -Value $GPOScheduledTaskV2.TaskRegistrationInfo
                                $ScheduledTaskV2OutputObject | Add-Member -MemberType NoteProperty -Name "TaskPrincipalsXML" -Value $GPOScheduledTaskV2.TaskPrincipalsXML
                                $ScheduledTaskV2OutputObject | Add-Member -MemberType NoteProperty -Name "TaskActionsXML" -Value $GPOScheduledTaskV2.TaskActionsXML
                                $ScheduledTaskV2OutputObject | Add-Member -MemberType NoteProperty -Name "TaskTriggersXML" -Value $GPOScheduledTaskV2.TaskTriggersXML
                                $ScheduledTaskV2OutputObject | Add-Member -MemberType NoteProperty -Name "TaskSettings" -Value $GPOScheduledTaskV2.TaskSettings

                                $null = $OutputScheduledTasksV2.Add($ScheduledTaskV2OutputObject)
                            }
                        }
                    }

                    # Defines registry settings.
                    "(.*)\\(Machine|User)\\registry.pol" {
                        #Write-Host $GPOFilePathOnDrive
                    }
                }
            }

        }
        catch {
            If ($_.Exception.Message -eq "Access is denied." -and $_.InvocationInfo.MyCommand.Name -eq "New-PSDrive") {
                Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingGPOSettings][-] Access denied error while trying to mount the SYSVOL / NETLOGON folder"
                Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingGPOSettings][-] New hardening on UNC path may prevent mounting the SYSVOL folder. Use 'New-ItemProperty ""HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"" -Name ""\\<DC | *>\SYSVOL"" -Value ""RequireMutualAuthentication=0"" -Property ""String""'"
                Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingGPOSettings][-] New hardening on UNC path may prevent mounting the NETLOGON folder. Use 'New-ItemProperty ""HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"" -Name ""\\<DC | *>\NETLOGON"" -Value ""RequireMutualAuthentication=0"" -Property ""String""'"
                break
            }
            
            Else {
                Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingGPOSettings][-] Error while processing GPO folder $GPOFolder"
                Write-Host -ForegroundColor DarkYellow "[Export-ADHuntingGPOSettings][-] Exception: $_"
            }
        }
    }

    # Privileges and logon rights output.
    If ($OutputPrivileges.Count -gt 0) {
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($GPOGrantingPrivileges.Value) GPO granting privileges, including $($GPOGrantingPrivilegesAndLinkedOnPriv.Value) GPOs linked on privileged containers, for a total of $($OutputPrivileges.Count) privileges"
        If ($OutputType -eq "CSV") {
            $OutputPrivileges | Export-Csv -NoTypeInformation -Encoding UTF8 -Append -Path $OutputPrivilegesPath
        }
        ElseIf ($OutputType -eq "JSON") {
            $OutputPrivileges | ConvertTo-Json -depth 100 | Out-File -Encoding UTF8 -Path $OutputPrivilegesPath
        }
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] Privileges and logon rights information written to '$OutputPrivilegesPath'"
    }
    Else {
        Write-Host -ForegroundColor DarkYellow "[$($MyInvocation.MyCommand)][+] No privileges or logon rights granted through GPOs found, an error likely occurred"
    }

    # Restricted groups output.
    If ($OutputRestrictedGroups.Count -gt 0) {
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($GPODefiningRestrictedGroups.Value) GPO defining restricted groups, including $($GPODefiningRestrictedGroupsAndLinkedOnPriv.Value) GPOs linked on privileged containers, for a total of $($OutputRestrictedGroups.Count) group memberships"
        If ($OutputType -eq "CSV") {
            $OutputRestrictedGroups | Export-Csv -NoTypeInformation -Encoding UTF8 -Append -Path $OutputRestrictedGroupsPath
        }
        ElseIf ($OutputType -eq "JSON") {
            $OutputRestrictedGroups | ConvertTo-Json -depth 100 | Out-File -Encoding UTF8 -Path $OutputRestrictedGroupsPath
        }
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] Restricted groups information written to '$OutputRestrictedGroupsPath'"
    }
    Else {
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] No restricted groups defined through GPOs found"
    }

    # Logon and logoff scripts output.
    If ($OutputLogonLogoffScripts.Count -gt 0) {
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($GPODefiningLogonLogoffScripts.Value) GPO defining logon / logoff scripts, including $($GPODefiningLogonLogoffScriptsAndLinkedOnPriv.Value) GPOs linked on privileged containers, for a total of $($OutputLogonLogoffScripts.Count) scripts"
        If ($OutputType -eq "CSV") {
            $OutputLogonLogoffScripts | Export-Csv -NoTypeInformation -Encoding UTF8 -Append -Path $OutputLogonLogoffScriptsPath
        }
        ElseIf ($OutputType -eq "JSON") {
            $OutputLogonLogoffScripts | ConvertTo-Json -depth 100 | Out-File -Encoding UTF8 -Path $OutputLogonLogoffScriptsPath
        }
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] Login / logoff information written to '$OutputLogonLogoffScriptsPath'"
    }
    Else {
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] No logon / logoff scripts defined through GPOs found"
    }

    # Scheduled and immediate tasks v1 / v2 output.
    If ($OutputScheduledTasksV1.Count -gt 0 -or $OutputScheduledTasksV2.Count -gt 0) {
        Write-Host "[$($MyInvocation.MyCommand)][*] Found $($GPODefiningScheduledTasks.Value) GPO defining scheduled / immediate (v1 and / or V2), including $($GPODefiningScheduledTasksAndLinkedOnPriv.Value) GPOs linked on privileged containers"
        Write-Host "[$($MyInvocation.MyCommand)][*] -- $($OutputScheduledTasksV1.Count) scheduled / immediate tasks v1"
        Write-Host "[$($MyInvocation.MyCommand)][*] -- $($OutputScheduledTasksV2.Count) scheduled / immediate tasks v2"        
        If ($OutputScheduledTasksV1.Count -gt 0) {
            If ($OutputType -eq "CSV") {
                $OutputScheduledTasksV1 | Export-Csv -NoTypeInformation -Encoding UTF8 -Append -Path $OutputScheduledTasksV1Path
            }
            ElseIf ($OutputType -eq "JSON") {
                $OutputScheduledTasksV1 | ConvertTo-Json -depth 100 | Out-File -Encoding UTF8 -Path $OutputScheduledTasksV1Path
            }
            Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] Scheduled / immediate tasks v1 information written to '$OutputScheduledTasksV1Path'"
        }
        If ($OutputScheduledTasksV2.Count -gt 0) {
            If ($OutputType -eq "CSV") {
                $OutputScheduledTasksV2 | Export-Csv -NoTypeInformation -Encoding UTF8 -Append -Path $OutputScheduledTasksV2Path
            }
            ElseIf ($OutputType -eq "JSON") {
                $OutputScheduledTasksV2 | ConvertTo-Json -depth 100 | Out-File -Encoding UTF8 -Path $OutputScheduledTasksV2Path
            }
            Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] Scheduled / immediate tasks v2 information written to '$OutputScheduledTasksV2Path'"
        }
    }
    Else {
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] No scheduled / immediate tasks (v1 and v2) defined through GPOs found"
    }

    # Errors (notably access errors) output.
    If ($AccessErrors.Count -gt 0) {
        Write-Host -ForegroundColor DarkYellow "[$($MyInvocation.MyCommand)][-] Encountered $($AccessErrors.Count) errors while enumerating GPO objects and files"
        If ($OutputType -eq "CSV") {
            $AccessErrors | Export-Csv -NoTypeInformation -Encoding UTF8 -Append -Path $OutputErrorsPath
        }
        ElseIf ($OutputType -eq "JSON") {
            $AccessErrors | ConvertTo-Json -depth 100 | Out-File -Encoding UTF8 -Path $OutputErrorsPath
        }
        Write-Host "[$($MyInvocation.MyCommand)][*] Errors information written to '$OutputErrorsPath'"
    }
    Else {
        Write-Host -ForegroundColor Green "[$($MyInvocation.MyCommand)][+] No access errors encountered!"
    }
}

########################################################
#
#
# All hunting!
#
#
########################################################

function Invoke-ADHunting {
<#
.SYNOPSIS

Execute all the FarsightAD AD hunting cmdlets.

.PARAMETER Server

Specifies the Active Directory Domain Services instance to connect to.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER Credential

Specifies the user account credentials to use to perform this task.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER ADDriveName

Specifies the name to use for the ActiveDirectory PSDrive that will be (temporarily) mounted by the cmdlet.
Defaults to ADHunting.
If set, passed through the cmdlets of the ActiveDirectory module as a default parameter.

.PARAMETER OutputFolder

Specifies the CSV / JSON output file location (where the data will be exported to).

.PARAMETER OutputType

Specifies the format for the exported data (CSV or JSON). Defaults to CSV.

.OUTPUTS

CSV / JSON file written to disk.

#>
    Param(
        [Parameter(Mandatory=$False)][String]$Server = $null,
        [Parameter(Mandatory=$False)][System.Management.Automation.PSCredential]$Credential = $null,
        [Parameter(Mandatory=$False)][String]$ADDriveName = "ADHunting",
        [Parameter(Mandatory=$False)][String]$OutputFolder,
        [Parameter(Mandatory=$False)]
            [ValidateSet("JSON","CSV")]
            [string]$OutputType = "CSV"
    )

    $PSDefaultParameterValues = @{}

    If (!$Server) {
        $Server = (Get-ADDomain).PDCEmulator
    }
    $PSDefaultParameterValues.Add("*-AD*:Server", $Server)
    $PSDefaultParameterValues.Add("*-ADHunting*:Server", $Server)

    If ($Credential) {
        $PSDefaultParameterValues.Add("*-AD*:Credential", $Credential)
        $PSDefaultParameterValues.Add("*-ADHunting*:Credential", $Credential)
    }

    $PSDefaultParameterValues.Add("*-ADHunting*:ADDriveName", $ADDriveName)
    $PSDefaultParameterValues.Add("*-ADHunting*:OutputFolder", $OutputFolder)
    $PSDefaultParameterValues.Add("*-ADHunting*:OutputType", $OutputType)

    $banner = @"
     ______             _       _     _            _____  
    |  ____|           (_)     | |   | |     /\   |  __ \ 
    | |__ ____ _ __ ___ _  ____| |__ | |_   /  \  | |  | |
    |  __/ _  | '__/ __| |/ _  | '_ \| __| / /\ \ | |  | |
    | | | (_| | |  \__ \ | (_| | | | | |_ / ____ \| |__| |
    |_|  \__,_|_|  |___/_|\__, |_| |_|\__/_/    \_\_____/ 
                           __/ |                          
                          |___/                           
                      
                             v1.0 -- Thomas DIOT (_Qazeer)

"@

    Write-Host $banner
    $sw = [Diagnostics.Stopwatch]::StartNew()

    Write-Host "[$($MyInvocation.MyCommand)][*] Starting AD Hunting...`n"
    
    Write-Host "[$($MyInvocation.MyCommand)][*] Enumeration of all privileged principals SIDs..."
    $PrivilegedSIDs = Get-ADHuntingAllPrivilegedSIDs
    Write-Host "[*] Enumeration done in: $([math]::Round($sw.Elapsed.TotalSeconds, 2)) seconds`n"
    $IntermediateCheckup = $sw.Elapsed.TotalSeconds

    Export-ADHuntingPrincipalsPrivilegedAccounts
    Write-Host ""
    Write-Host "[*] Enumeration done in: $([math]::Round($sw.Elapsed.TotalSeconds - $IntermediateCheckup, 2)) seconds`n"
    $IntermediateCheckup = $sw.Elapsed.TotalSeconds

    Export-ADHuntingHiddenObjectsWithDRSRepData
    Write-Host ""
    Write-Host "[*] Enumeration done in: $([math]::Round($sw.Elapsed.TotalSeconds - $IntermediateCheckup, 2)) seconds`n"
    $IntermediateCheckup = $sw.Elapsed.TotalSeconds
        
    Export-ADHuntingPrincipalsOncePrivileged
    Write-Host ""
    Write-Host "[*] Enumeration done in: $([math]::Round($sw.Elapsed.TotalSeconds - $IntermediateCheckup, 2)) seconds`n"
    $IntermediateCheckup = $sw.Elapsed.TotalSeconds

    Export-ADHuntingPrincipalsTechnicalPrivileged
    Write-Host ""
    Write-Host "[*] Enumeration done in: $([math]::Round($sw.Elapsed.TotalSeconds - $IntermediateCheckup, 2)) seconds`n"
    $IntermediateCheckup = $sw.Elapsed.TotalSeconds

    Export-ADHuntingPrincipalsPrivilegedGroupsMembership
    Write-Host ""
    Write-Host "[*] Enumeration done in: $([math]::Round($sw.Elapsed.TotalSeconds - $IntermediateCheckup, 2)) seconds`n"
    $IntermediateCheckup = $sw.Elapsed.TotalSeconds

    Export-ADHuntingPrincipalsPrimaryGroupID -PrivilegedSIDs $PrivilegedSIDs
    Write-Host ""
    Write-Host "[*] Enumeration done in: $([math]::Round($sw.Elapsed.TotalSeconds - $IntermediateCheckup, 2)) seconds`n"
    $IntermediateCheckup = $sw.Elapsed.TotalSeconds

    Export-ADHuntingPrincipalsSIDHistory -PrivilegedSIDs $PrivilegedSIDs
    Write-Host ""
    Write-Host "[*] Enumeration done in: $([math]::Round($sw.Elapsed.TotalSeconds - $IntermediateCheckup, 2)) seconds`n"
    $IntermediateCheckup = $sw.Elapsed.TotalSeconds

    Export-ADHuntingPrincipalsShadowCredentials -PrivilegedSIDs $PrivilegedSIDs
    Write-Host ""
    Write-Host "[*] Enumeration done in: $([math]::Round($sw.Elapsed.TotalSeconds - $IntermediateCheckup, 2)) seconds`n"
    $IntermediateCheckup = $sw.Elapsed.TotalSeconds

    Export-ADHuntingPrincipalsUPNandAltSecID -PrivilegedSIDs $PrivilegedSIDs
    Write-Host ""
    Write-Host "[*] Enumeration done in: $([math]::Round($sw.Elapsed.TotalSeconds - $IntermediateCheckup, 2)) seconds`n"
    $IntermediateCheckup = $sw.Elapsed.TotalSeconds

    Export-ADHuntingPrincipalsCertificates -PrivilegedSIDs $PrivilegedSIDs
    Write-Host ""
    Write-Host "[*] Enumeration done in: $([math]::Round($sw.Elapsed.TotalSeconds - $IntermediateCheckup, 2)) seconds`n"
    $IntermediateCheckup = $sw.Elapsed.TotalSeconds

    Export-ADHuntingADCSPKSObjects -PrivilegedSIDs $PrivilegedSIDs
    Write-Host ""
    Write-Host "[*] Enumeration done in: $([math]::Round($sw.Elapsed.TotalSeconds - $IntermediateCheckup, 2)) seconds`n"
    $IntermediateCheckup = $sw.Elapsed.TotalSeconds

    Export-ADHuntingADCSCertificateTemplates -PrivilegedSIDs $PrivilegedSIDs
    Write-Host ""
    Write-Host "[*] Enumeration done in: $([math]::Round($sw.Elapsed.TotalSeconds - $IntermediateCheckup, 2)) seconds`n"
    $IntermediateCheckup = $sw.Elapsed.TotalSeconds

    Export-ADHuntingPrincipalsDontRequirePreAuth -PrivilegedSIDs $PrivilegedSIDs
    Write-Host ""
    Write-Host "[*] Enumeration done in: $([math]::Round($sw.Elapsed.TotalSeconds - $IntermediateCheckup, 2)) seconds`n"
    $IntermediateCheckup = $sw.Elapsed.TotalSeconds

    Export-ADHuntingPrincipalsAddedViaMachineAccountQuota
    Write-Host ""
    Write-Host "[*] Enumeration done in: $([math]::Round($sw.Elapsed.TotalSeconds - $IntermediateCheckup, 2)) seconds`n"
    $IntermediateCheckup = $sw.Elapsed.TotalSeconds

    Export-ADHuntingACLPrivilegedObjects -PrivilegedSIDs $PrivilegedSIDs
    Write-Host ""
    Write-Host "[*] Enumeration done in: $([math]::Round($sw.Elapsed.TotalSeconds - $IntermediateCheckup, 2)) seconds`n"
    $IntermediateCheckup = $sw.Elapsed.TotalSeconds

    Export-ADHuntingACLDefaultFromSchema -PrivilegedSIDs $PrivilegedSIDs
    Write-Host ""
    Write-Host "[*] Enumeration done in: $([math]::Round($sw.Elapsed.TotalSeconds - $IntermediateCheckup, 2)) seconds`n"
    $IntermediateCheckup = $sw.Elapsed.TotalSeconds

    Export-ADHuntingKerberosDelegations -PrivilegedSIDs $PrivilegedSIDs
    Write-Host ""
    Write-Host "[*] Enumeration done in: $([math]::Round($sw.Elapsed.TotalSeconds - $IntermediateCheckup, 2)) seconds`n"
    $IntermediateCheckup = $sw.Elapsed.TotalSeconds

    Export-ADHuntingGPOObjectsAndFilesACL  -PrivilegedSIDs $PrivilegedSIDs
    Write-Host ""
    Write-Host "[*] Enumeration done in: $([math]::Round($sw.Elapsed.TotalSeconds - $IntermediateCheckup, 2)) seconds`n"
    $IntermediateCheckup = $sw.Elapsed.TotalSeconds

    Export-ADHuntingGPOSettings -PrivilegedSIDs $PrivilegedSIDs
    Write-Host ""
    Write-Host "[*] Enumeration done in: $([math]::Round($sw.Elapsed.TotalSeconds - $IntermediateCheckup, 2)) seconds`n"
    $IntermediateCheckup = $sw.Elapsed.TotalSeconds

    Export-ADHuntingTrusts
    Write-Host ""
    Write-Host "[*] Enumeration done in: $([math]::Round($sw.Elapsed.TotalSeconds - $IntermediateCheckup, 2)) seconds`n"
    $IntermediateCheckup = $sw.Elapsed.TotalSeconds

    Write-Host "[$($MyInvocation.MyCommand)][*] Enumeration of access rights / ownership on all objects in the default naming context, this may take a while...`n"

    Export-ADHuntingACLDangerousAccessRights -PrivilegedSIDs $PrivilegedSIDs
    Write-Host ""
    Write-Host "[*] Enumeration done in: $([math]::Round($sw.Elapsed.TotalSeconds - $IntermediateCheckup, 2)) seconds`n"
    $IntermediateCheckup = $sw.Elapsed.TotalSeconds

    Write-Host "[$($MyInvocation.MyCommand)][+] AD Hunting finished!"
    Write-Host "[$($MyInvocation.MyCommand)][+] Total enumeration done in: $([math]::Round($sw.Elapsed.TotalSeconds, 2)) seconds`n"

    [System.GC]::Collect()
}

# Execution as the packaged executable.
If (!$MyInvocation.MyCommand.Name.EndsWith(".ps1")) {
    $PSDefaultParameterValues = @{}
    If ($Server) { $PSDefaultParameterValues.Add("Invoke-ADHunting:Server", $Server) }
    If ($Credential) { $PSDefaultParameterValues.Add("Invoke-ADHunting:Credential", $Credential) }
    If ($ADDriveName) { $PSDefaultParameterValues.Add("Invoke-ADHunting:ADDriveName", $ADDriveName) }
    If ($OutputFolder) { $PSDefaultParameterValues.Add("Invoke-ADHunting:OutputFolder", $OutputFolder) }
    If ($OutputType) { $PSDefaultParameterValues.Add("Invoke-ADHunting:OutputType", $OutputType) }
    Invoke-ADHunting
}