##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Active Directory Domain
# Version:  V3R4
# Class:    UNCLASSIFIED
# Updated:  5/13/2024
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-TrustAttributes {
    $TrustAttributes = @{
        1  = "Non-Transitive";
        2  = "Uplevel clients only (Windows 2000 or newer)";
        4  = "Quarantined Domain";
        8  = "Forest Trust";
        16 = "Cross-Organizational Trust (Selective Authorization)";
        32 = "Intra-Forest Trust";
        64 = "SID History Enabled"
    }
    Return $TrustAttributes
}

Function Get-V243466 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243466
        STIG ID    : AD.0001
        Rule ID    : SV-243466r723433_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Membership to the Enterprise Admins group must be restricted to accounts used only to manage the Active Directory Forest.
        DiscussMD5 : C1602A3A446F4347D9CAB5E7F68F0119
        CheckMD5   : D139919DA9CEE53C02D93BFEB5303BAF
        FixMD5     : E05BCC2A7340F3423872EB89DCF1A1D8
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $GroupsToCheck = @("Enterprise Admins")
    $OtherAdminGroups = @("Domain Admins", "Schema Admins", "Administrators")
    $Compliant = $true
    $OpenFinding = $false

    ForEach ($Group in $GroupsToCheck) {
        Try {
            If (Get-ADGroup -Identity $Group) {
                $Exists = $true
            }
        }
        Catch {
            $Exists = $false
        }
        If ($Exists) {
            $ReturnedUsers = Get-MembersOfADGroup -Identity $Group -Recursive | Sort-Object Name -Unique
            If (($ReturnedUsers | Measure-Object).Count -eq 0) {
                $Status = "NotAFinding"
                $FindingDetails += "No Users are in the '$($Group)' Group" | Out-String
            }
            Else {
                $FindingDetails += "Members of '$($Group)'" | Out-String
                $FindingDetails += "=========================" | Out-String
                ForEach ($User in $ReturnedUsers) {
                    $MemberOf = @()
                    ForEach ($DN in (Get-ADObject -Identity $User.objectGUID -Properties MemberOf).MemberOf) {
                        $MemberOfName = (Get-ADObject -Identity $DN).Name
                        If ($MemberOfName -eq $Group) {
                            $MemberOf += "$MemberOfName"
                        }
                        ElseIf ($MemberOfName -in $OtherAdminGroups) {
                            $Compliant = $false
                            $OpenFinding = $true
                            $User.Name = "$($User.Name) [FINDING]"
                            $MemberOf += "$MemberOfName [FINDING]"
                        }
                        Else {
                            $Compliant = $false
                            $MemberOf += "$MemberOfName"
                        }
                    }
                    $FindingDetails += "Name:`t`t`t`t$($User.name)" | Out-String
                    $FindingDetails += "objectClass:`t`t`t$($User.objectClass)" | Out-String
                    $FindingDetails += "objectSID:`t`t`t$($User.objectSID.Value)" | Out-String
                    $FindingDetails += "DistinguishedName:`t$($User.distinguishedName)" | Out-String
                    $FindingDetails += "MemberOfAdminGroup:`t$(($MemberOf | Select-Object -Unique) -join ', ')" | Out-String
                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    If ($OpenFinding = $true) {
                        $Status = "Open"
                    }
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "The group '$($Group)' does not exist within this domain." | Out-String
        }
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V243467 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243467
        STIG ID    : AD.0002
        Rule ID    : SV-243467r723436_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Membership to the Domain Admins group must be restricted to accounts used only to manage the Active Directory domain and domain controllers.
        DiscussMD5 : A4A34538E8735E3BB2ADB13396CC56C5
        CheckMD5   : E31EEFE9FA76CE0E4DD00658BD0F8555
        FixMD5     : 0D935DFACEA89D932BEA45D2DEC8D08E
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $GroupsToCheck = @("Domain Admins")
    $OtherAdminGroups = @("Enterprise Admins", "Schema Admins", "Administrators")
    $Compliant = $true
    $OpenFinding = $false

    ForEach ($Group in $GroupsToCheck) {
        Try {
            If (Get-ADGroup -Identity $Group) {
                $Exists = $true
            }
        }
        Catch {
            $Exists = $false
        }
        If ($Exists) {
            $ReturnedUsers = Get-MembersOfADGroup -Identity $Group -Recursive | Sort-Object Name -Unique
            If (($ReturnedUsers | Measure-Object).Count -eq 0) {
                $Status = "NotAFinding"
                $FindingDetails += "No Users are in the '$($Group)' Group" | Out-String
            }
            Else {
                $FindingDetails += "Members of '$($Group)'" | Out-String
                $FindingDetails += "=========================" | Out-String
                ForEach ($User in $ReturnedUsers) {
                    $MemberOf = @()
                    ForEach ($DN in (Get-ADObject -Identity $User.objectGUID -Properties MemberOf).MemberOf) {
                        $MemberOfName = (Get-ADObject -Identity $DN).Name
                        If ($MemberOfName -eq $Group) {
                            $MemberOf += "$MemberOfName"
                        }
                        ElseIf ($MemberOfName -in $OtherAdminGroups) {
                            $Compliant = $false
                            $OpenFinding = $true
                            $User.Name = "$($User.Name) [FINDING]"
                            $MemberOf += "$MemberOfName [FINDING]"
                        }
                        Else {
                            $Compliant = $false
                            $MemberOf += "$MemberOfName"
                        }
                    }
                    $FindingDetails += "Name:`t`t`t`t$($User.name)" | Out-String
                    $FindingDetails += "objectClass:`t`t`t$($User.objectClass)" | Out-String
                    $FindingDetails += "objectSID:`t`t`t$($User.objectSID.Value)" | Out-String
                    $FindingDetails += "DistinguishedName:`t$($User.distinguishedName)" | Out-String
                    $FindingDetails += "MemberOfAdminGroup:`t$(($MemberOf | Select-Object -Unique) -join ', ')" | Out-String
                    $FindingDetails += "" | Out-String
                }

                If ($Compliant -eq $true) {
                    $Status = "NotAFinding"
                }
                Else {
                    If ($OpenFinding = $true) {
                        $Status = "Open"
                    }
                }
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "The group '$($Group)' does not exist within this domain." | Out-String
        }
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V243473 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243473
        STIG ID    : AD.0013
        Rule ID    : SV-243473r723565_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Separate domain accounts must be used to manage public facing servers from any domain accounts used to manage internal servers.
        DiscussMD5 : AB1BEBD355D05A18AC49C41A1E7612B5
        CheckMD5   : 12FBCBF043E8A184C9FC7306506C3250
        FixMD5     : 83FE7BDC862FD9A6C4784C517C912A36
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Groups = @("Administrators")

    ForEach ($Group in $Groups) {
        $ReturnedObjects = Get-GroupMembership -Group $Group
        If (($ReturnedObjects | Measure-Object).Count -eq 0) {
            $Status = "NotAFinding"
            $FindingDetails += "No Users are in the '$($Group)' Group" | Out-String
        }
        Else {
            $FindingDetails += "Members of '$($Group)'" | Out-String
            $FindingDetails += "=========================" | Out-String
            ForEach ($Object in $ReturnedObjects) {
                $FindingDetails += "Name:`t`t$($Object.Name)" | Out-String
                $FindingDetails += "objectClass:`t$($Object.objectClass)" | Out-String
                $FindingDetails += "objectSID:`t$($Object.objectSID.Value)" | Out-String
                $FindingDetails += "" | Out-String
            }
            $FindingDetails += "" | Out-String
        }
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V243476 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243476
        STIG ID    : AD.0016
        Rule ID    : SV-243476r954038_rule
        CCI ID     : CCI-000199
        Rule Name  : SRG-OS-000076
        Rule Title : All accounts, privileged and unprivileged, that require smart cards must have the underlying NT hash rotated at least every 60 days.
        DiscussMD5 : 99FFF6EC74B1BD3FCAAB2786CF903752
        CheckMD5   : 89C042251BBC8446E99D2E7A0C8BD972
        FixMD5     : 3FB66B68BACE4B486335C60E10F0B809
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Domain = Get-ADDomain
    $RollingNTLMSecrets = $Domain.PublicKeyRequiredPasswordRolling

    $FindingDetails += "Domain Level:`t$($Domain.DomainMode)" | Out-String
    $FindingDetails += "" | Out-String
    If ($Domain.DomainMode -in @("Windows2016Domain")) {
        $FindingDetails += "Rolling of expiring NTLM Secrets:`t$($RollingNTLMSecrets)" | Out-String
        If ($RollingNTLMSecrets -eq $true) {
            $Status = "NotAFinding"
        }
        Else {
            $Status = "Open"
        }
    }
    Else {
        $FindingDetails += "Domain functional level does not support rolling of expiring NTLM secrets.  Verify the organization rotates the NT hash for smart card-enforced accounts every 60 days." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V243477 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243477
        STIG ID    : AD.0017
        Rule ID    : SV-243477r723466_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : User accounts with domain level administrative privileges must be members of the Protected Users group in domains with a domain functional level of Windows 2012 R2 or higher.
        DiscussMD5 : 1B7D39C4EA26A2DBBEBF9F0E5356F9BD
        CheckMD5   : 60D39FC7E59B7E29250B837A836B1DBB
        FixMD5     : 1F3E56D2148D90A349381D9F8CDDFBC8
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Domain = Get-ADDomain
    $AcceptedDomainLevels = @("Windows2012R2Domain", "Windows2016Domain")
    $Groups = @("Enterprise Admins", "Domain Admins", "Schema Admins", "Administrators", "Account Operators", "Backup Operators")

    If ($Domain.DomainMode -in $AcceptedDomainLevels) {
        $GroupMembers = @()
        $UserMembership = New-Object System.Collections.Generic.List[System.Object]
        $MissingUsers = New-Object System.Collections.Generic.List[System.Object]

        ForEach ($Group in $Groups) {
            $GroupUsers = Get-MembersOfADGroup -Identity $Group -Recursive | Where-Object {($_.objectSID.Value -match $Domain.DomainSID) -and ($_.objectClass -eq "user") -and ($_.Name -notmatch '\$$')}
            $GroupMembers += $GroupUsers
            ForEach ($User in $GroupUsers) {
                $Obj = [PSCustomObject]@{
                    objectSID = $User.objectSID.Value
                    MemberOf  = $Group
                }
                $UserMembership.Add($Obj)
            }
        }
        $GroupMembers = $GroupMembers | Sort-Object Name -Unique

        $ProtectedUsers = Get-MembersOfADGroup -Identity "Protected Users" -Recursive | Where-Object objectClass -EQ "user" | Sort-Object Name -Unique
        ForEach ($Member in $GroupMembers) {
            If ($Member.objectSID.Value -notin $ProtectedUsers.objectSID.Value) {
                $Obj = [PSCustomObject]@{
                    Name              = $Member.name
                    objectClass       = $Member.objectClass
                    objectSID         = $Member.objectSID.Value
                    DistinguishedName = $Member.distinguishedName
                    MemberOf          = (($UserMembership | Where-Object objectSID -EQ $Member.objectSID.Value).MemberOf | Select-Object -Unique | Sort-Object) -join ", "
                }
                $MissingUsers.Add($Obj)
            }
        }

        If (($MissingUsers | Measure-Object).Count -eq 0) {
            $Status = "NotAFinding"
            $FindingDetails += "No accounts were missing from the 'Protected Users' group" | Out-String
        }
        Else {
            $FindingDetails += "Accounts are missing from 'Protected Users'.  Only service accounts and one (1) user account with domain level administrative privileges may be excluded.  Please confirm for compliance." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Users Missing From 'Protected Users' Group" | Out-String
            $FindingDetails += "============================================" | Out-String
            ForEach ($User in $MissingUsers) {
                $FindingDetails += "Name:`t`t`t`t$($User.Name)" | Out-String
                $FindingDetails += "objectClass:`t`t`t$($User.ObjectClass)" | Out-String
                $FindingDetails += "objectSID:`t`t`t$($User.objectSID)" | Out-String
                $FindingDetails += "DistinguishedName:`t$($User.DistinguishedName)" | Out-String
                $FindingDetails += "MemberOf:`t`t`t$($User.MemberOf)" | Out-String
                $FindingDetails += "" | Out-String
            }
        }
    }
    Else {
        $Status = "Not_Applicable"
        $FindingDetails += "Domain Level: $($Domain.DomainMode)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "The domain functional level is not Windows 2012 R2 or higher, so this check is Not Applicable" | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V243478 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243478
        STIG ID    : AD.0018
        Rule ID    : SV-243478r723469_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Domain-joined systems (excluding domain controllers) must not be configured for unconstrained delegation.
        DiscussMD5 : 988D2F280B241C5B8DB4DC6AA79D276F
        CheckMD5   : 41F002D6CE182ACAFDCABC4F66708FCD
        FixMD5     : 2A53D1A8C44E2844C5B9C7BB96598796
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Computers = Get-ADComputer -Filter {(TrustedForDelegation -eq $True) -and (PrimaryGroupID -eq 515)} -Properties Name, DistinguishedName, Enabled, TrustedForDelegation, TrustedToAuthForDelegation, ServicePrincipalName, Description, PrimaryGroupID

    If (($Computers | Measure-Object).Count -gt 0) {
        $Status = "Open"
        ForEach ($Computer in $Computers) {
            $FindingDetails += "Name:`t`t`t`t`t`t$($Computer.Name)" | Out-String
            $FindingDetails += "Enabled:`t`t`t`t`t`t$($Computer.Enabled)" | Out-String
            $FindingDetails += "Trusted For Delegation:`t`t`t$($Computer.TrustedForDelegation)" | Out-String
            $FindingDetails += "Trusted To Auth For Delegation:`t$($Computer.TrustedToAuthForDelegation)" | Out-String
            ForEach ($SPN in $Computer.ServicePrincipalName) {
                $FindingDetails += "Service Principal Name:`t`t`t$($SPN)" | Out-String
            }
            $FindingDetails += "Description:`t`t`t`t`t$($Computer.Description)" | Out-String
            $FindingDetails += "PrimaryGroupID:`t`t`t`t$($Computer.PrimaryGroupID)" | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "No computers are Trusted for Delegation and have a Primary Group ID of '515'" | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V243480 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243480
        STIG ID    : AD.0160
        Rule ID    : SV-243480r956039_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : The domain functional level must be at a Windows Server version still supported by Microsoft.
        DiscussMD5 : BF511DDBD2355F8EC131C70699B187E8
        CheckMD5   : 3E24686B1D055B297357FD1AA8F51A95
        FixMD5     : 01C27C506EF5E14C07F0CE262EA69BD4
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Regex = "(?:Windows)(\d{4})"
    $DomainFunctionalLevel = (Get-ADDomain).DomainMode
    If ($DomainFunctionalLevel -match $Regex) {
        If ($Matches[1] -lt 2016) {
            $Status = "Open"
        }
        Else {
            $Status = "NotAFinding"
        }

    }
    $FindingDetails += "Domain Level: $($DomainFunctionalLevel)" | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V243481 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243481
        STIG ID    : AD.0170
        Rule ID    : SV-243481r890559_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Access to need-to-know information must be restricted to an authorized community of interest.
        DiscussMD5 : 771D0AFF10E522E29C586603F758B0F9
        CheckMD5   : A6C356692B97E095BF578DE68A223603
        FixMD5     : B038BACB79F04B8B9AD0C537B662EF0D
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $DomainTrusts = Get-ADTrust -Filter *

    If (($DomainTrusts | Measure-Object).Count -eq 0) {
        $Status = "NotAFinding"
        $FindingDetails += "No trusts are configured."
    }
    Else {
        $FindingDetails += "Domain Trusts" | Out-String
        $FindingDetails += "========================" | Out-String
        ForEach ($Trust in $DomainTrusts) {

            $Attributes = (Get-TrustAttributes).Keys | Where-Object {$_ -band $Trust.TrustAttributes} | ForEach-Object {(Get-TrustAttributes).Get_Item($_)}
            If ($Attributes -contains (Get-TrustAttributes).Get_Item(8)) {
                $FindingDetails += "Type:`t`t`t`t`tForest Trust" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t`t`t`tExternal Trust" | Out-String
            }
            $FindingDetails += "Domain:`t`t`t`t`t$($Trust.Target)" | Out-String
            $FindingDetails += "Direction:`t`t`t`t`t$($Trust.Direction)" | Out-String
            $FindingDetails += "Disallow Transitivity:`t`t$($Trust.DisallowTransivity)" | Out-String
            $FindingDetails += "Forest Transitive:`t`t`t$($Trust.ForestTransitive)" | Out-String
            $FindingDetails += "Selective Authentication:`t`t$($Trust.SelectiveAuthentication)" | Out-String
            $FindingDetails += "SID Filtering Forest Aware:`t$($Trust.SIDFilteringForestAware)" | Out-String
            $FindingDetails += "SID Filtering Quarantined:`t$($Trust.SIDFilteringQuarantined)" | Out-String
            $FindingDetails += "Trust Attributes: "
            If (($Attributes | Measure-Object).Count -gt 1) {
                For ($i = 0; $i -lt ($Attributes | Measure-Object).Count; $i++) {
                    If ($i -eq 0) {
                        $FindingDetails += "`t`t`t$($Attributes[$i])" | Out-String
                    }
                    Else {
                        $FindingDetails += "`t`t`t`t`t`t$($Attributes[$i])" | Out-String
                    }
                }
            }
            Else {
                $FindingDetails += "`t`t`t$($Attributes)" | Out-String
            }
            $FindingDetails += "" | Out-String
        }
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V243482 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243482
        STIG ID    : AD.0180
        Rule ID    : SV-243482r723481_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Interconnections between DoD directory services of different classification levels must use a cross-domain solution that is approved for use with inter-classification trusts.
        DiscussMD5 : 19459BC72C2C41C7DA245B052AC55C70
        CheckMD5   : 93817D9E5660762D72947C75B2AAC23B
        FixMD5     : 716556A05447C9E746D7FB80578A5894
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $DomainTrusts = Get-ADTrust -Filter *

    If (($DomainTrusts | Measure-Object).Count -eq 0) {
        $Status = "Not_Applicable"
        $FindingDetails += "No trusts are configured so this requirement is NA."
    }
    Else {
        $FindingDetails += "Domain Trusts" | Out-String
        $FindingDetails += "========================" | Out-String
        ForEach ($Trust in $DomainTrusts) {
            $Attributes = (Get-TrustAttributes).Keys | Where-Object {$_ -band $Trust.TrustAttributes} | ForEach-Object {(Get-TrustAttributes).Get_Item($_)}
            If ($Attributes -contains (Get-TrustAttributes).Get_Item(8)) {
                $FindingDetails += "Type:`t`t`t`t`tForest Trust" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t`t`t`tExternal Trust" | Out-String
            }
            $FindingDetails += "Domain:`t`t`t`t`t$($Trust.Target)" | Out-String
            $FindingDetails += "Direction:`t`t`t`t`t$($Trust.Direction)" | Out-String
            $FindingDetails += "Disallow Transitivity:`t`t$($Trust.DisallowTransivity)" | Out-String
            $FindingDetails += "Forest Transitive:`t`t`t$($Trust.ForestTransitive)" | Out-String
            $FindingDetails += "Selective Authentication:`t`t$($Trust.SelectiveAuthentication)" | Out-String
            $FindingDetails += "SID Filtering Forest Aware:`t$($Trust.SIDFilteringForestAware)" | Out-String
            $FindingDetails += "SID Filtering Quarantined:`t$($Trust.SIDFilteringQuarantined)" | Out-String
            $FindingDetails += "Trust Attributes: "
            If (($Attributes | Measure-Object).Count -gt 1) {
                For ($i = 0; $i -lt ($Attributes | Measure-Object).Count; $i++) {
                    If ($i -eq 0) {
                        $FindingDetails += "`t`t`t$($Attributes[$i])" | Out-String
                    }
                    Else {
                        $FindingDetails += "`t`t`t`t`t`t$($Attributes[$i])" | Out-String
                    }
                }
            }
            Else {
                $FindingDetails += "`t`t`t$($Attributes)" | Out-String
            }
            $FindingDetails += "" | Out-String
        }
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V243483 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243483
        STIG ID    : AD.0181
        Rule ID    : SV-243483r723559_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : A controlled interface must have interconnections among DoD information systems operating between DoD and non-DoD systems or networks.
        DiscussMD5 : 1A800498D6B3A26DE74CE7BAFD0E7C60
        CheckMD5   : 50B71771212D1DD1C847D4A6CC412A9F
        FixMD5     : BE2DCA0BB0B2B74C9E277DEB6DF27D5F
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $DomainTrusts = Get-ADTrust -Filter *

    If (($DomainTrusts | Measure-Object).Count -eq 0) {
        $Status = "Not_Applicable"
        $FindingDetails += "No trusts are configured so this requirement is NA."
    }
    Else {
        $FindingDetails += "Domain Trusts" | Out-String
        $FindingDetails += "========================" | Out-String
        ForEach ($Trust in $DomainTrusts) {
            $Attributes = (Get-TrustAttributes).Keys | Where-Object {$_ -band $Trust.TrustAttributes} | ForEach-Object {(Get-TrustAttributes).Get_Item($_)}
            If ($Attributes -contains (Get-TrustAttributes).Get_Item(8)) {
                $FindingDetails += "Type:`t`t`t`t`tForest Trust" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t`t`t`tExternal Trust" | Out-String
            }
            $FindingDetails += "Domain:`t`t`t`t`t$($Trust.Target)" | Out-String
            $FindingDetails += "Direction:`t`t`t`t`t$($Trust.Direction)" | Out-String
            $FindingDetails += "Disallow Transitivity:`t`t$($Trust.DisallowTransivity)" | Out-String
            $FindingDetails += "Forest Transitive:`t`t`t$($Trust.ForestTransitive)" | Out-String
            $FindingDetails += "Selective Authentication:`t`t$($Trust.SelectiveAuthentication)" | Out-String
            $FindingDetails += "SID Filtering Forest Aware:`t$($Trust.SIDFilteringForestAware)" | Out-String
            $FindingDetails += "SID Filtering Quarantined:`t$($Trust.SIDFilteringQuarantined)" | Out-String
            $FindingDetails += "Trust Attributes: "
            If (($Attributes | Measure-Object).Count -gt 1) {
                For ($i = 0; $i -lt ($Attributes | Measure-Object).Count; $i++) {
                    If ($i -eq 0) {
                        $FindingDetails += "`t`t`t$($Attributes[$i])" | Out-String
                    }
                    Else {
                        $FindingDetails += "`t`t`t`t`t`t$($Attributes[$i])" | Out-String
                    }
                }
            }
            Else {
                $FindingDetails += "`t`t`t$($Attributes)" | Out-String
            }
            $FindingDetails += "" | Out-String
        }
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V243484 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243484
        STIG ID    : AD.0190
        Rule ID    : SV-243484r890561_rule
        CCI ID     : CCI-000764
        Rule Name  : SRG-OS-000104
        Rule Title : Security identifiers (SIDs) must be configured to use only authentication data of directly trusted external or forest trust.
        DiscussMD5 : 5E0B4DF203317D6A5CE9CEC76EA8E178
        CheckMD5   : A8442DD04E978956B41BFBE81DD69D66
        FixMD5     : 2F1F12CBA5D0AD4B59AC6537C9111630
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $DomainTrusts = Get-ADTrust -Filter *

    If (($DomainTrusts | Measure-Object).Count -eq 0) {
        $Status = "Not_Applicable"
        $FindingDetails += "No trusts are configured so this requirement is NA."
    }
    Else {
        $Compliant = $true
        $BadTrust = @()
        $GoodTrust = @()
        ForEach ($Trust in $DomainTrusts) {
            $Attributes = (Get-TrustAttributes).Keys | Where-Object {$_ -band $Trust.TrustAttributes} | ForEach-Object {(Get-TrustAttributes).Get_Item($_)}
            If ($Attributes -contains (Get-TrustAttributes).Get_Item(8)) {
                If ($Trust.SIDFIlteringForestAware -eq $false) {
                    $Compliant = $False
                    $BadTrust += $Trust
                }
                Else {
                    $GoodTrust += $Trust
                }
            }
            Else {
                If ($Trust.SIDFilterQuarantined -eq $false) {
                    $Compliant = $false
                    $BadTrust += $Trust
                }
                Else {
                    $GoodTrust += $Trust
                }
            }
        }

        If (($BadTrust | Measure-Object).Count -gt 0) {
            $FindingDetails += "Non-Compliant Domain Trusts" | Out-String
            $FindingDetails += "========================" | Out-String
            ForEach ($Trust in $BadTrust) {
                $Attributes = (Get-TrustAttributes).Keys | Where-Object {$_ -band $Trust.TrustAttributes} | ForEach-Object {(Get-TrustAttributes).Get_Item($_)}
                If ($Attributes -contains (Get-TrustAttributes).Get_Item(8)) {
                    $FindingDetails += "Type:`t`t`t`t`tForest Trust" | Out-String
                }
                Else {
                    $FindingDetails += "Type:`t`t`t`t`tExternal Trust" | Out-String
                }
                $FindingDetails += "Domain:`t`t`t`t`t$($Trust.Target)" | Out-String
                $FindingDetails += "Direction:`t`t`t`t`t$($Trust.Direction)" | Out-String
                $FindingDetails += "Disallow Transitivity:`t`t$($Trust.DisallowTransivity)" | Out-String
                $FindingDetails += "Forest Transitive:`t`t`t$($Trust.ForestTransitive)" | Out-String
                $FindingDetails += "Selective Authentication:`t`t$($Trust.SelectiveAuthentication)" | Out-String
                $FindingDetails += "SID Filtering Forest Aware:`t$($Trust.SIDFilteringForestAware)" | Out-String
                $FindingDetails += "SID Filtering Quarantined:`t$($Trust.SIDFilteringQuarantined)" | Out-String
                $FindingDetails += "Trust Attributes: "
                If (($Attributes | Measure-Object).Count -gt 1) {
                    For ($i = 0; $i -lt ($Attributes | Measure-Object).Count; $i++) {
                        If ($i -eq 0) {
                            $FindingDetails += "`t`t`t$($Attributes[$i])" | Out-String
                        }
                        Else {
                            $FindingDetails += "`t`t`t`t`t`t$($Attributes[$i])" | Out-String
                        }
                    }
                }
                Else {
                    $FindingDetails += "`t`t`t$($Attributes)" | Out-String
                }
                $FindingDetails += "" | Out-String
            }
        }
        If (($GoodTrust | Measure-Object).Count -gt 0) {
            $FindingDetails += "Compliant Domain Trusts" | Out-String
            $FindingDetails += "========================" | Out-String
            ForEach ($Trust in $GoodTrust) {
                $Attributes = (Get-TrustAttributes).Keys | Where-Object {$_ -band $Trust.TrustAttributes} | ForEach-Object {(Get-TrustAttributes).Get_Item($_)}
                If ($Attributes -contains (Get-TrustAttributes).Get_Item(8)) {
                    $FindingDetails += "Type:`t`t`t`t`tForest Trust" | Out-String
                }
                Else {
                    $FindingDetails += "Type:`t`t`t`t`tExternal Trust" | Out-String
                }
                $FindingDetails += "Domain:`t`t`t`t`t$($Trust.Target)" | Out-String
                $FindingDetails += "Direction:`t`t`t`t`t$($Trust.Direction)" | Out-String
                $FindingDetails += "Disallow Transitivity:`t`t$($Trust.DisallowTransivity)" | Out-String
                $FindingDetails += "Forest Transitive:`t`t`t$($Trust.ForestTransitive)" | Out-String
                $FindingDetails += "Selective Authentication:`t`t$($Trust.SelectiveAuthentication)" | Out-String
                $FindingDetails += "SID Filtering Forest Aware:`t$($Trust.SIDFilteringForestAware)" | Out-String
                $FindingDetails += "SID Filtering Quarantined:`t$($Trust.SIDFilteringQuarantined)" | Out-String
                $FindingDetails += "Trust Attributes: "
                If (($Attributes | Measure-Object).Count -gt 1) {
                    For ($i = 0; $i -lt ($Attributes | Measure-Object).Count; $i++) {
                        If ($i -eq 0) {
                            $FindingDetails += "`t`t`t$($Attributes[$i])" | Out-String
                        }
                        Else {
                            $FindingDetails += "`t`t`t`t`t`t$($Attributes[$i])" | Out-String
                        }
                    }
                }
                Else {
                    $FindingDetails += "`t`t`t$($Attributes)" | Out-String
                }
                $FindingDetails += "" | Out-String
            }
        }
        If ($Compliant -eq $true) {
            $Status = "NotAFinding"
        }
        Else {
            $Status = "Open"
        }
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V243485 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243485
        STIG ID    : AD.0200
        Rule ID    : SV-243485r723490_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-OS-000080
        Rule Title : Selective Authentication must be enabled on outgoing forest trusts.
        DiscussMD5 : AF713C14A7F3B185362B1D5C846E789C
        CheckMD5   : 52686D946E71B3F46E6435A848CA5E66
        FixMD5     : 2A885A5460F15C3C4C4CA4D55E9ACEED
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Trusts = Get-ADTrust -Filter *
    If (($Trusts | Measure-Object).Count -eq 0) {
        $Status = "Not_Applicable"
        $FindingDetails += "No trusts are configured so this requirement is NA."
    }
    Else {
        $Compliant = $true
        $ForestTrusts = @()
        $BadTrust = @()
        $GoodTrust = @()
        ForEach ($Trust in $Trusts) {
            $Attributes = (Get-TrustAttributes).Keys | Where-Object {$_ -band $Trust.TrustAttributes} | ForEach-Object {(Get-TrustAttributes).Get_Item($_)}
            If ($Attributes -contains (Get-TrustAttributes).Get_Item(8)) {
                $ForestTrusts += $Trust
            }
        }

        If (($ForestTrusts | Measure-Object).Count -eq 0) {
            $Status = "NotAFinding"
            $FindingDetails += "No forest trusts are configured." | Out-String
        }
        ElseIf (-Not($ForestTrusts.Direction -eq "Outbound")) {
            $Status = "NotAFinding"
            $FindingDetails += "No outbound forest trusts are configured." | Out-String
        }
        Else {
            ForEach ($Trust in $ForestTrusts) {
                If ($Trust.SelectiveAuthentication -eq $false) {
                    $Compliant = $False
                    $BadTrust += $Trust
                }
                Else {
                    $GoodTrust += $Trust
                }
            }

            If (($BadTrust | Measure-Object).Count -gt 0) {
                $FindingDetails += "Non-Compliant Domain Trusts" | Out-String
                $FindingDetails += "========================" | Out-String

                ForEach ($Trust in $BadTrust) {
                    $Attributes = (Get-TrustAttributes).Keys | Where-Object {$_ -band $Trust.TrustAttributes} | ForEach-Object {(Get-TrustAttributes).Get_Item($_)}
                    If ($Attributes -contains (Get-TrustAttributes).Get_Item(8)) {
                        $FindingDetails += "Type:`t`t`t`t`tForest Trust" | Out-String
                    }
                    Else {
                        $FindingDetails += "Type:`t`t`t`t`tExternal Trust" | Out-String
                    }
                    $FindingDetails += "Domain:`t`t`t`t`t$($Trust.Target)" | Out-String
                    $FindingDetails += "Direction:`t`t`t`t`t$($Trust.Direction)" | Out-String
                    $FindingDetails += "Disallow Transitivity:`t`t$($Trust.DisallowTransivity)" | Out-String
                    $FindingDetails += "Forest Transitive:`t`t`t$($Trust.ForestTransitive)" | Out-String
                    $FindingDetails += "Selective Authentication:`t`t$($Trust.SelectiveAuthentication)" | Out-String
                    $FindingDetails += "SID Filtering Forest Aware:`t$($Trust.SIDFilteringForestAware)" | Out-String
                    $FindingDetails += "SID Filtering Quarantined:`t$($Trust.SIDFilteringQuarantined)" | Out-String
                    $FindingDetails += "Trust Attributes: "
                    If (($Attributes | Measure-Object).Count -gt 1) {
                        For ($i = 0; $i -lt ($Attributes | Measure-Object).Count; $i++) {
                            If ($i -eq 0) {
                                $FindingDetails += "`t`t`t$($Attributes[$i])" | Out-String
                            }
                            Else {
                                $FindingDetails += "`t`t`t`t`t`t$($Attributes[$i])" | Out-String
                            }
                        }
                    }
                    Else {
                        $FindingDetails += "`t`t`t$($Attributes)" | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }
            }

            If (($GoodTrust | Measure-Object).Count -gt 0) {
                $FindingDetails += "Compliant Domain Trusts" | Out-String
                $FindingDetails += "========================" | Out-String
                ForEach ($Trust in $GoodTrust) {
                    $Attributes = (Get-TrustAttributes).Keys | Where-Object {$_ -band $Trust.TrustAttributes} | ForEach-Object {(Get-TrustAttributes).Get_Item($_)}
                    If ($Attributes -contains (Get-TrustAttributes).Get_Item(8)) {
                        $FindingDetails += "Type:`t`t`t`t`tForest Trust" | Out-String
                    }
                    Else {
                        $FindingDetails += "Type:`t`t`t`t`tExternal Trust" | Out-String
                    }
                    $FindingDetails += "Domain:`t`t`t`t`t$($Trust.Target)" | Out-String
                    $FindingDetails += "Direction:`t`t`t`t`t$($Trust.Direction)" | Out-String
                    $FindingDetails += "Disallow Transitivity:`t`t$($Trust.DisallowTransivity)" | Out-String
                    $FindingDetails += "Forest Transitive:`t`t`t$($Trust.ForestTransitive)" | Out-String
                    $FindingDetails += "Selective Authentication:`t`t$($Trust.SelectiveAuthentication)" | Out-String
                    $FindingDetails += "SID Filtering Forest Aware:`t$($Trust.SIDFilteringForestAware)" | Out-String
                    $FindingDetails += "SID Filtering Quarantined:`t$($Trust.SIDFilteringQuarantined)" | Out-String
                    $FindingDetails += "Trust Attributes: "
                    If (($Attributes | Measure-Object).Count -gt 1) {
                        For ($i = 0; $i -lt ($Attributes | Measure-Object).Count; $i++) {
                            If ($i -eq 0) {
                                $FindingDetails += "`t`t`t$($Attributes[$i])" | Out-String
                            }
                            Else {
                                $FindingDetails += "`t`t`t`t`t`t$($Attributes[$i])" | Out-String
                            }
                        }
                    }
                    Else {
                        $FindingDetails += "`t`t`t$($Attributes)" | Out-String
                    }
                    $FindingDetails += "" | Out-String
                }
            }
            If ($Compliant -eq $true) {
                $Status = "NotAFinding"
            }
            Else {
                $Status = "Open"
            }
        }
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V243486 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243486
        STIG ID    : AD.0220
        Rule ID    : SV-243486r723493_rule
        CCI ID     : CCI-000804
        Rule Name  : SRG-OS-000121
        Rule Title : The Anonymous Logon and Everyone groups must not be members of the Pre-Windows 2000 Compatible Access group.
        DiscussMD5 : 6F728C07E5CE5EC947F0796A5F74871D
        CheckMD5   : C1441D38C9F4995AF33BC9D123283287
        FixMD5     : 17B28E75235D3E16F7F96EB521DDF6CF
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $MemberGroup = "Pre-Windows 2000 Compatible Access"
    $Users = Get-MembersOfADGroup -identity $MemberGroup -Recursive | Where-Object {$_.Name -eq "Everyone" -or $_.Name -eq "Anonymous Logon"}

    If (($Users | Measure-Object).Count -gt 0) {
        $Status = "Open"
        If ($Users -contains "Anonymous Logon") {
            $FindingDetails += "'Anonymous Logon' is a member of '$($MemberGroup)'" | Out-String
        }
        Else {
            $FindingDetails += "'Everyone' is a member of '$($MemberGroup)'" | Out-String
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "Both 'Anonymous Logon' and 'Everyone' are not members of '$MemberGroup'."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V243487 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243487
        STIG ID    : AD.0240
        Rule ID    : SV-243487r723496_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Membership in the Group Policy Creator Owners and Incoming Forest Trust Builders groups must be limited.
        DiscussMD5 : 5A0874037B414AAB211026AA91ACD525
        CheckMD5   : 963386734590F059367C25EE370751D2
        FixMD5     : 27C8047EF20DBD5CFDAE8E12F3C513C2
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Compliant = $true
    $Groups = @("Incoming Forest Trust Builders", "Group Policy Creator Owners")

    ForEach ($Group in $Groups) {
        $ReturnedUsers = Get-MembersOfADGroup -Identity $Group -Recursive
        If (($ReturnedUsers | Measure-Object).Count -eq 0) {
            $FindingDetails += "No Users are in the '$($Group)' Group" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "Members of '$($Group)'" | Out-String
            $FindingDetails += "=========================" | Out-String
            ForEach ($User in $ReturnedUsers) {
                $FindingDetails += "Name:`t`t`t`t$($User.name)" | Out-String
                $FindingDetails += "objectClass:`t`t`t$($User.objectClass)" | Out-String
                $FindingDetails += "objectSID:`t`t`t$($User.objectSID.Value)" | Out-String
                $FindingDetails += "DistinguishedName:`t$($User.distinguishedName)" | Out-String
                $FindingDetails += "" | Out-String
            }
        }
        $FindingDetails += "" | Out-String
    }

    If ($Compliant -eq $true) {
        $Status = "NotAFinding"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V243489 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243489
        STIG ID    : AD.0270
        Rule ID    : SV-243489r723564_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Read-only Domain Controller (RODC) architecture and configuration must comply with directory services requirements.
        DiscussMD5 : 69C3ECF4EF53B06E300FFD658F105CD5
        CheckMD5   : 8E9B923F9910DF8B46B22B8ABE92B36C
        FixMD5     : 624B6AE58F4926ADCBF07D2D51B4FE3A
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $DomainName = (Get-ADDomain).DNSRoot
    $AllDCs = Get-ADDomainController -Filter * -Server $DomainName | Select-Object HostName, OperatingSystem, IPv4Address, IPv6Address, Forest, Site, IsGlobalCatalog, IsReadOnly

    If ($AllDCs.IsReadOnly -eq $true) {
        $FindingDetails += "Read-only domain controllers (RODC):"
        $FindingDetails += "====================================" | Out-String
        ForEach ($DC in ($AllDCs | Where-Object IsReadOnly -EQ $true)) {
            $FindingDetails += "Hostname:`t`t$($DC.HostName)" | Out-String
            $FindingDetails += "OperatingSystem:`t$($DC.OperatingSystem)" | Out-String
            $FindingDetails += "IPv4Address:`t`t$($DC.IPv4Address)" | Out-String
            $FindingDetails += "IPv6Address:`t`t$($DC.IPv6Address)" | Out-String
            $FindingDetails += "Forest:`t`t`t$($DC.Forest)" | Out-String
            $FindingDetails += "Site:`t`t`t`t$($DC.Site)" | Out-String
            $FindingDetails += "IsGlobalCatalog:`t$($DC.IsGlobalCatalog)" | Out-String
            $FindingDetails += "IsReadOnly:`t`t$($DC.IsReadOnly)" | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "No read-only domain controllers (RODC) exist in the domain." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V243490 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243490
        STIG ID    : AD.AU.0001
        Rule ID    : SV-243490r723505_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Usage of administrative accounts must be monitored for suspicious and anomalous activity.
        DiscussMD5 : 476B92E61BE863347694192E92340292
        CheckMD5   : 322E707B90FA3FB1432565150AAFCD73
        FixMD5     : 69F5AAFB6E7E8BC3EF6613D5E0432DF6
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $AuditCategorys = @("Logon", "User Account Management", "Account Lockout", "Security Group Management") #As specified in the STIG
    #$SettingState = "Success" #As specified in the STIG
    ForEach ($AuditCategory in $AuditCategorys) {
        Try {

            $Policy = (auditpol /get /subcategory:$AuditCategory | Where-Object { $_ -Match "\s$($AuditCategory)" }).Trim() #Returns a string
            If ( $Policy -Match "  [SNF].*$") {
                #Regex to essentially grab the last phrase in the string. Either "Success", "Failure", "Success or Failure", or "No Auditing"
                $Policy = $Matches[0].Trim() #Trim the two spaces before what was matched. '$Policy -Match' returns true/false, '$Matches' is the system variable -Match places anything it finds.
            }
            $Status = "NotAFinding"
            $FindingDetails += "Category:`t`t$($AuditCategory)" | Out-String
            $FindingDetails += "Audit On:`t`t$($Policy)" | Out-String
            $FindingDetails += "" | Out-String

        }
        Catch {
            #If the policy isn't configured as we want, it won't be found and will throw an error.
            $Status = "Open"
            $FindingDetails += "'$($AuditCategory)' is NOT configured to audit." | Out-String
        }
    }

    $FindingDetails += "" | Out-String
    $FindingDetails += "Queries of Events" | Out-String
    $FindingDetails += "=====================" | Out-String

    $EventIDs = @("4740", "4728", "4732", "4756", "4624", "4625", "4648")

    ForEach ($EventID in $EventIDs) {
        $ReturnedEvent = Get-WinEvent -ErrorAction SilentlyContinue @{logname = 'system', 'application', 'security'; ID = $EventID} -MaxEvents 1 | Select-Object ContainerLog, ID, LevelDisplayName, Message, TimeCreated
        If ($Null -eq $ReturnedEvent) {
            $FindingDetails += "No event was found for EventID: $($EventID)" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $ReturnedEvent.Message -match "^.*?\." | Out-Null
            $Message = $matches[0]
            $FindingDetails += "Event ID:`t`t`t$($ReturnedEvent.ID)" | Out-String
            $FindingDetails += "Message:`t`t`t$($Message)" | Out-String
            $FindingDetails += "Level:`t`t`t$($ReturnedEvent.LevelDisplayName)" | Out-String
            $FindingDetails += "Container Log:`t`t$($ReturnedEvent.ContainerLog)" | Out-String
            $FindingDetails += "Time Created:`t`t$($ReturnedEvent.TimeCreated)" | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V243491 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243491
        STIG ID    : AD.AU.0002
        Rule ID    : SV-243491r723508_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Systems must be monitored for attempts to use local accounts to log on remotely from other systems.
        DiscussMD5 : 310D95035BAA0906406FD88DE4FA5CD3
        CheckMD5   : DB5C112F7ABE2426550E9DA55145EBBE
        FixMD5     : 41D2E9309CC9580703E1B2EDF1872115
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $AuditCategorys = @("Logon", "Account Lockout") #As specified in the STIG
    #$SettingState = "Success" #As specified in the STIG
    ForEach ($AuditCategory in $AuditCategorys) {
        Try {

            $Policy = (auditpol /get /subcategory:$AuditCategory | Where-Object { $_ -Match "\s$($AuditCategory)" }).Trim() #Returns a string
            If ( $Policy -Match "  [SNF].*$") {
                #Regex to essentially grab the last phrase in the string. Either "Success", "Failure", "Success or Failure", or "No Auditing"
                $Policy = $Matches[0].Trim() #Trim the two spaces before what was matched. '$Policy -Match' returns true/false, '$Matches' is the system variable -Match places anything it finds.
            }
            $Status = "NotAFinding"
            $FindingDetails += "Category:`t`t$($AuditCategory)" | Out-String
            $FindingDetails += "Audit On:`t`t$($Policy)" | Out-String
            $FindingDetails += "" | Out-String

        }
        Catch {
            #If the policy isn't configured as we want, it won't be found and will throw an error.
            $Status = "Open"
            $FindingDetails += "'$($AuditCategory)' is NOT configured to audit." | Out-String
        }
    }

    $FindingDetails += "" | Out-String
    $FindingDetails += "Queries of Events" | Out-String
    $FindingDetails += "=====================" | Out-String

    $EventIDs = @("4624", "4625")

    ForEach ($EventID in $EventIDs) {
        $params = @{
            logname                   = 'system', 'security'
            ID                        = $EventID
            LogonType                 = '3'
            AuthenticationPackageName = 'NTLM'
        }
        $ReturnedEvent = Get-WinEvent -ErrorAction SilentlyContinue $params | Select-Object ContainerLog, ID, LevelDisplayName, Message, TimeCreated, Properties | Where-Object {$_.Properties[5].Value -ne "ANONYMOUS LOGON" -and $_.Properties[6].Value -notin $(Get-CimInstance Win32_NTDomain).DomainName | Select-Object -First 1}

        If ($Null -eq $ReturnedEvent) {
            $FindingDetails += "No event was found for EventID: $($EventID)" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $ReturnedEvents[0].Message -match "^.*?\." | Out-Null
            $Message = $matches[0]
            $FindingDetails += "Event ID:`t`t`t$($ReturnedEvent.ID)" | Out-String
            $FindingDetails += "Message:`t`t`t$($Message)" | Out-String
            $FindingDetails += "User:`t`t`t$($ReturnedEvent.Properties[5].Value)" | Out-String
            $FindingDetails += "Domain:`t`t`t$($ReturnedEvent.Properties[6].Value)" | Out-String
            $FindingDetails += "Level:`t`t`t$($ReturnedEvent.LevelDisplayName)" | Out-String
            $FindingDetails += "Container Log:`t`t$($ReturnedEvent.ContainerLog)" | Out-String
            $FindingDetails += "Time Created:`t`t$($ReturnedEvent.TimeCreated)" | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V243492 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243492
        STIG ID    : AD.AU.0003
        Rule ID    : SV-243492r723511_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Systems must be monitored for remote desktop logons.
        DiscussMD5 : 2FC955A6E511747A8FECB54F64797FD0
        CheckMD5   : 3D50DF20FA909877553CD645A93769D6
        FixMD5     : B2E6489427F5971AFE21C231B58F755A
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $AuditCategorys = @("Logon") #As specified in the STIG
    #$SettingState = "Success" #As specified in the STIG
    ForEach ($AuditCategory in $AuditCategorys) {
        Try {

            $Policy = (auditpol /get /subcategory:$AuditCategory | Where-Object { $_ -Match "\s$($AuditCategory)" }).Trim() #Returns a string
            If ( $Policy -Match "  [SNF].*$") {
                #Regex to essentially grab the last phrase in the string. Either "Success", "Failure", "Success or Failure", or "No Auditing"
                $Policy = $Matches[0].Trim() #Trim the two spaces before what was matched. '$Policy -Match' returns true/false, '$Matches' is the system variable -Match places anything it finds.
            }
            $Status = "NotAFinding"
            $FindingDetails += "Category:`t`t$($AuditCategory)" | Out-String
            $FindingDetails += "Audit On:`t`t$($Policy)" | Out-String
            $FindingDetails += "" | Out-String

        }
        Catch {
            #If the policy isn't configured as we want, it won't be found and will throw an error.
            $Status = "Open"
            $FindingDetails += "'$($AuditCategory)' is NOT configured to audit." | Out-String
        }
    }

    $FindingDetails += "" | Out-String
    $FindingDetails += "Queries of Events" | Out-String
    $FindingDetails += "=====================" | Out-String

    $EventIDs = @("4624")

    ForEach ($EventID in $EventIDs) {

        $ReturnedEvent = Get-WinEvent -ErrorAction SilentlyContinue @{logname = 'system', 'application', 'security'; ID = $EventID; LogonType = '10'; AuthenticationPackageName = 'Negotiate'} | Select-Object -First 1 ContainerLog, ID, LevelDisplayName, Message, TimeCreated, Properties
        If ($Null -eq $ReturnedEvent) {
            $FindingDetails += "No event was found for EventID: $($EventID)" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $ReturnedEvent.Message -match "^.*?\." | Out-Null
            $Message = $matches[0]
            $FindingDetails += "Event ID:`t`t`t$($ReturnedEvent.ID)" | Out-String
            $FindingDetails += "Message:`t`t`t$($Message)" | Out-String
            $FindingDetails += "Logon Type:`t`t`t$($ReturnedEvent.Properties[8].Value)" | Out-String
            $FindingDetails += "Authentication Package Name:`t$($ReturnedEvent.Properties[10].Value)" | Out-String
            $FindingDetails += "Level:`t`t`t`t$($ReturnedEvent.LevelDisplayName)" | Out-String
            $FindingDetails += "Container Log:`t`t`t$($ReturnedEvent.ContainerLog)" | Out-String
            $FindingDetails += "Time Created:`t`t`t$($ReturnedEvent.TimeCreated)" | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V243494 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243494
        STIG ID    : DS00.1120_AD
        Rule ID    : SV-243494r723517_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Each cross-directory authentication configuration must be documented.
        DiscussMD5 : BC8D64FB5D0C40E6968964EBC3DA0DE7
        CheckMD5   : 5EF88BD796A7C721267309B2C046ED9C
        FixMD5     : 9EB5E9AC069020E6AB0756C93136825D
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $DomainTrusts = Get-ADTrust -Filter *

    If (($DomainTrusts | Measure-Object).Count -eq 0) {
        $Status = "Not_Applicable"
        $FindingDetails += "No trusts are configured so this requirement is NA."
    }
    Else {
        $FindingDetails += "Domain Trusts" | Out-String
        $FindingDetails += "========================" | Out-String
        ForEach ($Trust in $DomainTrusts) {

            $Attributes = (Get-TrustAttributes).Keys | Where-Object {$_ -band $Trust.TrustAttributes} | ForEach-Object {(Get-TrustAttributes).Get_Item($_)}
            If ($Attributes -contains (Get-TrustAttributes).Get_Item(8)) {
                $FindingDetails += "Type:`t`t`t`t`tForest Trust" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t`t`t`tExternal Trust" | Out-String
            }
            $FindingDetails += "Domain:`t`t`t`t`t$($Trust.Target)" | Out-String
            $FindingDetails += "Direction:`t`t`t`t`t$($Trust.Direction)" | Out-String
            $FindingDetails += "Disallow Transitivity:`t`t$($Trust.DisallowTransivity)" | Out-String
            $FindingDetails += "Forest Transitive:`t`t`t$($Trust.ForestTransitive)" | Out-String
            $FindingDetails += "Selective Authentication:`t`t$($Trust.SelectiveAuthentication)" | Out-String
            $FindingDetails += "SID Filtering Forest Aware:`t$($Trust.SIDFilteringForestAware)" | Out-String
            $FindingDetails += "SID Filtering Quarantined:`t$($Trust.SIDFilteringQuarantined)" | Out-String
            $FindingDetails += "Trust Attributes: "
            If (($Attributes | Measure-Object).Count -gt 1) {
                For ($i = 0; $i -lt ($Attributes | Measure-Object).Count; $i++) {
                    If ($i -eq 0) {
                        $FindingDetails += "`t`t`t$($Attributes[$i])" | Out-String
                    }
                    Else {
                        $FindingDetails += "`t`t`t`t`t`t$($Attributes[$i])" | Out-String
                    }
                }
            }
            Else {
                $FindingDetails += "`t`t`t$($Attributes)" | Out-String
            }
            $FindingDetails += "" | Out-String
        }
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V243495 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243495
        STIG ID    : DS00.1140_AD
        Rule ID    : SV-243495r854328_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-OS-000423
        Rule Title : A VPN must be used to protect directory network traffic for directory service implementation spanning enclave boundaries.
        DiscussMD5 : FEF5CBB69394DD59CEC391EABD467690
        CheckMD5   : 7FA4BD45B637C969B7565A359E6A41A5
        FixMD5     : 5FD79A513A50944D749E141ABE74EE19
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $DomainName = (Get-ADDomain).DNSRoot
    $AllDCs = Get-ADDomainController -Filter * -Server $DomainName | Select-Object HostName, OperatingSystem, IPv4Address, IPv6Address, Forest, Site, IsGlobalCatalog, IsReadOnly

    ForEach ($DC in $AllDCs) {
        $FindingDetails += "Hostname:`t`t$($DC.HostName)" | Out-String
        $FindingDetails += "OperatingSystem:`t$($DC.OperatingSystem)" | Out-String
        $FindingDetails += "IPv4Address:`t`t$($DC.IPv4Address)" | Out-String
        $FindingDetails += "IPv6Address:`t`t$($DC.IPv6Address)" | Out-String
        $FindingDetails += "Forest:`t`t`t$($DC.Forest)" | Out-String
        $FindingDetails += "Site:`t`t`t`t$($DC.Site)" | Out-String
        $FindingDetails += "IsGlobalCatalog:`t$($DC.IsGlobalCatalog)" | Out-String
        $FindingDetails += "IsReadOnly:`t`t$($DC.IsReadOnly)" | Out-String
        $FindingDetails += "" | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V243496 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243496
        STIG ID    : DS00.3200_AD
        Rule ID    : SV-243496r804648_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Accounts from outside directories that are not part of the same organization or are not subject to the same security policies must be removed from all highly privileged groups.
        DiscussMD5 : 85EF8B1FE370205505C284040A6FE73E
        CheckMD5   : D04E419E94AEB91A736C74730AB80DC2
        FixMD5     : 57CF2A84767882079FB22EEFD0116D49
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Compliant = $true
    $Groups = @("Incoming Forest Trust Builders", "Domain Admins", "Enterprise Admins", "Schema Admins", "Group Policy Creator Owners")
    $Forest = Get-ADForest
    $ForestDN = ""
    ForEach ($Item in (($Forest).Name).Split(".")) {
        $ForestDN += "DC=$($Item),"
    }
    $Pattern = [regex]::Escape($($ForestDN -replace ",$", "")) + "$"
    ForEach ($Group in $Groups) {
        $ReturnedMembers = Get-MembersOfADGroup -Identity $Group -Recursive
        If (($ReturnedMembers | Measure-Object).Count -eq 0) {
            $FindingDetails += "'$($Group)' - Contains no members" | Out-String
        }
        Else {
            $ExternalMembers = @()
            ForEach ($Member in $ReturnedMembers) {
                If (($Member.DistinguishedName -notmatch $Pattern) -or ($Member.objectClass -eq 'foreignSecurityPrincipal')) {
                    $ExternalMembers += $Member
                }
            }
            If (($ExternalMembers | Measure-Object).Count -gt 0) {
                $Compliant = $false
                $FindingDetails += "'$($Group)' - Contains external members:" | Out-String
                $FindingDetails += "=========================" | Out-String
                ForEach ($Member in $ExternalMembers) {
                    $FindingDetails += "Name:`t`t`t`t$($Member.name)" | Out-String
                    $FindingDetails += "objectClass:`t`t`t$($Member.objectClass)" | Out-String
                    $FindingDetails += "objectSID:`t`t`t$($Member.objectSID.Value)" | Out-String
                    $FindingDetails += "DistinguishedName:`t$($Member.distinguishedName)" | Out-String
                    $FindingDetails += "" | Out-String
                }
            }
            Else {
                $FindingDetails += "'$($Group)' - All members from '$($Forest.Name)' forest" | Out-String
            }
        }
        $FindingDetails += "" | Out-String
    }

    If ($compliant -eq $true) {
        $Status = "NotAFinding"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V243497 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243497
        STIG ID    : DS00.3230_AD
        Rule ID    : SV-243497r723526_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Inter-site replication must be enabled and configured to occur at least daily.
        DiscussMD5 : FC5B5F2A8CDC20DC3E23B142BC2A267E
        CheckMD5   : A359B8785BC4CAA8EFEAC198462FECE6
        FixMD5     : 5F64A13768971B8ECF064F614CB86020
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ADSites = Get-ADReplicationSite -Filter * -Properties *
    If (($ADSites | Measure-Object).Count -eq 1) {
        $Status = "Not_Applicable"
        $FindingDetails += "Only one site exists so this requirement is NA." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Site: $($ADSites.Name)" | Out-String
    }
    Else {
        $Compliant = $true
        $SiteLinks = Get-ADReplicationSiteLink -Filter * -Properties *
        $FindingDetails += "Site Link Replication Frequency" | Out-String
        $FindingDetails += "===============================" | Out-String
        $FindingDetails += "" | Out-String
        ForEach ($SiteLink in $SiteLinks) {
            $FindingDetails += "Name:`t`t$($SiteLink.Name)" | Out-String
            If ($SiteLink.ReplicationFrequencyInMinutes -gt 1440) {
                $Compliant = $false
                $FindingDetails += "Frequency:`t$($SiteLink.ReplicationFrequencyInMinutes) [Expected: 1440 or less]" | Out-String
            }
            Else {
                $FindingDetails += "Frequency:`t$($SiteLink.ReplicationFrequencyInMinutes)" | Out-String
            }

            $TimeSlotsWithoutReplication = 0
            For ($i = 20; $i -lt (($SiteLink.Schedule) | Measure-Object).Count; $i++) {
                #Run through the replication schedule. There are 288 bytes in total, with the first 20 being a header.
                If ($SiteLink.Schedule[$i] -eq 240) {
                    #If the value equals 255, replication is set to happen; if 240, replication will not happen.
                    $TimeSlotsWithoutReplication += 1
                    If ($TimeSlotsWithoutReplication -eq 24) {
                        $Compliant = $false
                        $FindingDetails += "There are 24 hour period(s) with no available replication schedule.  [Finding]" | Out-String
                    }
                }
                Else {
                    $TimeSlotsWithoutReplication = 0
                }
            }
            $FindingDetails += "" | Out-String
        }

        If ($Compliant -eq $true) {
            $Status = "NotAFinding"
        }
        Else {
            $Status = "Open"
        }
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V243498 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243498
        STIG ID    : DS00.4140_AD
        Rule ID    : SV-243498r723529_rule
        CCI ID     : CCI-000067
        Rule Name  : SRG-OS-000032
        Rule Title : If a VPN is used in the AD implementation, the traffic must be inspected by the network Intrusion detection system (IDS).
        DiscussMD5 : 13596707828FFF28E11B82225D90CF6B
        CheckMD5   : 2638A2EAD85C4A512087DE8650D9F648
        FixMD5     : FC5A22230981FD5607AE352E115AE4FD
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $DomainName = (Get-ADDomain).DNSRoot
    $AllDCs = Get-ADDomainController -Filter * -Server $DomainName | Select-Object HostName, OperatingSystem, IPv4Address, IPv6Address, Forest, Site, IsGlobalCatalog, IsReadOnly

    ForEach ($DC in $AllDCs) {
        $FindingDetails += "Hostname:`t`t$($DC.HostName)" | Out-String
        $FindingDetails += "OperatingSystem:`t$($DC.OperatingSystem)" | Out-String
        $FindingDetails += "IPv4Address:`t`t$($DC.IPv4Address)" | Out-String
        $FindingDetails += "IPv6Address:`t`t$($DC.IPv6Address)" | Out-String
        $FindingDetails += "Forest:`t`t`t$($DC.Forest)" | Out-String
        $FindingDetails += "Site:`t`t`t`t$($DC.Site)" | Out-String
        $FindingDetails += "IsGlobalCatalog:`t$($DC.IsGlobalCatalog)" | Out-String
        $FindingDetails += "IsReadOnly:`t`t$($DC.IsReadOnly)" | Out-String
        $FindingDetails += "" | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V243500 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243500
        STIG ID    : DS00.6140_AD
        Rule ID    : SV-243500r723535_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : Active Directory must be supported by multiple domain controllers where the Risk Management Framework categorization for Availability is moderate or high.
        DiscussMD5 : FFEA62BE1ECD26422B15F6E14AD97557
        CheckMD5   : CCB80FC26B24D7FE9276B046C797E783
        FixMD5     : CB5C2A2BC5CEE67C9994E6E31DAC82D9
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $DomainName = (Get-ADDomain).DNSRoot
    $AllDCs = Get-ADDomainController -Filter * -Server $DomainName | Select-Object HostName, OperatingSystem, IPv4Address, IPv6Address, Forest, Site, IsGlobalCatalog, IsReadOnly

    If (($AllDCs | Measure-Object).Count -eq 1) {
        $FindingDetails += "Only one domain controller exists in the domain.  If Availability categorization is low, mark as NA.  Otherwise, mark as Open." | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "Multiple domain controllers exist in the domain." | Out-String
        $FindingDetails += "" | Out-String
    }

    ForEach ($DC in $AllDCs) {
        $FindingDetails += "Hostname:`t`t$($DC.HostName)" | Out-String
        $FindingDetails += "OperatingSystem:`t$($DC.OperatingSystem)" | Out-String
        $FindingDetails += "IPv4Address:`t`t$($DC.IPv4Address)" | Out-String
        $FindingDetails += "IPv6Address:`t`t$($DC.IPv6Address)" | Out-String
        $FindingDetails += "Forest:`t`t`t$($DC.Forest)" | Out-String
        $FindingDetails += "Site:`t`t`t`t$($DC.Site)" | Out-String
        $FindingDetails += "IsGlobalCatalog:`t$($DC.IsGlobalCatalog)" | Out-String
        $FindingDetails += "IsReadOnly:`t`t$($DC.IsReadOnly)" | Out-String
        $FindingDetails += "" | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V243501 {
    <#
    .DESCRIPTION
        Vuln ID    : V-243501
        STIG ID    : DS00.7100_AD
        Rule ID    : SV-243501r723557_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480
        Rule Title : The impact of INFOCON changes on the cross-directory authentication configuration must be considered and procedures documented.
        DiscussMD5 : 7BBC72446B61BD1F70297DB075B0061E
        CheckMD5   : 0200A486EB99E56C3E3A337CBEBE6134
        FixMD5     : B55C8516A4B36185FDED9141C34AD2A9
    #>

    Param (
        [Parameter(Mandatory = $False)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $True)]
        [String]$ScanType,

        [Parameter(Mandatory = $True)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $False)]
        [String]$Username,

        [Parameter(Mandatory = $False)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $DomainTrusts = Get-ADTrust -Filter *

    If (($DomainTrusts | Measure-Object).Count -eq 0) {
        $Status = "Not_Applicable"
        $FindingDetails += "No trusts are configured so this requirement is NA."
    }
    Else {
        $FindingDetails += "Domain Trusts" | Out-String
        $FindingDetails += "========================" | Out-String
        ForEach ($Trust in $DomainTrusts) {

            $Attributes = (Get-TrustAttributes).Keys | Where-Object {$_ -band $Trust.TrustAttributes} | ForEach-Object {(Get-TrustAttributes).Get_Item($_)}
            If ($Attributes -contains (Get-TrustAttributes).Get_Item(8)) {
                $FindingDetails += "Type:`t`t`t`t`tForest Trust" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t`t`t`tExternal Trust" | Out-String
            }
            $FindingDetails += "Domain:`t`t`t`t`t$($Trust.Target)" | Out-String
            $FindingDetails += "Direction:`t`t`t`t`t$($Trust.Direction)" | Out-String
            $FindingDetails += "Disallow Transitivity:`t`t$($Trust.DisallowTransivity)" | Out-String
            $FindingDetails += "Forest Transitive:`t`t`t$($Trust.ForestTransitive)" | Out-String
            $FindingDetails += "Selective Authentication:`t`t$($Trust.SelectiveAuthentication)" | Out-String
            $FindingDetails += "SID Filtering Forest Aware:`t$($Trust.SIDFilteringForestAware)" | Out-String
            $FindingDetails += "SID Filtering Quarantined:`t$($Trust.SIDFilteringQuarantined)" | Out-String
            $FindingDetails += "Trust Attributes: "
            If (($Attributes | Measure-Object).Count -gt 1) {
                For ($i = 0; $i -lt ($Attributes | Measure-Object).Count; $i++) {
                    If ($i -eq 0) {
                        $FindingDetails += "`t`t`t$($Attributes[$i])" | Out-String
                    }
                    Else {
                        $FindingDetails += "`t`t`t`t`t`t$($Attributes[$i])" | Out-String
                    }
                }
            }
            Else {
                $FindingDetails += "`t`t`t$($Attributes)" | Out-String
            }
            $FindingDetails += "" | Out-String
        }
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

# SIG # Begin signature block
# MIIL+QYJKoZIhvcNAQcCoIIL6jCCC+YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA4BaDfySs7gwLd
# buLQzen6I6km/m3rxxrYrKE2qSu1J6CCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
# CSqGSIb3DQEBCwUAMFoxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVy
# bm1lbnQxDDAKBgNVBAsTA0RvRDEMMAoGA1UECxMDUEtJMRUwEwYDVQQDEwxET0Qg
# SUQgQ0EtNTkwHhcNMjAwNzE1MDAwMDAwWhcNMjUwNDAyMTMzODMyWjBpMQswCQYD
# VQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0Qx
# DDAKBgNVBAsTA1BLSTEMMAoGA1UECxMDVVNOMRYwFAYDVQQDEw1DUy5OU1dDQ0Qu
# MDAxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2/Z91ObHZ009DjsX
# ySa9T6DbT+wWgX4NLeTYZwx264hfFgUnIww8C9Mm6ht4mVfo/qyvmMAqFdeyhXiV
# PZuhbDnzdKeXpy5J+oxtWjAgnWwJ983s3RVewtV063W7kYIqzj+Ncfsx4Q4TSgmy
# ASOMTUhlzm0SqP76zU3URRj6N//NzxAcOPLlfzxcFPMpWHC9zNlVtFqGtyZi/STj
# B7ed3BOXmddiLNLCL3oJm6rOsidZstKxEs3I1llWjsnltn7fR2/+Fm+roWrF8B4z
# ekQOu9t8WRZfNohKoXVtVuwyUAJQF/8kVtIa2YyxTUAF9co9qVNZgko/nx0gIdxS
# hxmEvQIDAQABo4IBNzCCATMwHwYDVR0jBBgwFoAUdQmmFROuhzz6c5QA8vD1ebmy
# chQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5kaXNhLm1pbC9jcmwvRE9E
# SURDQV81OV9OQ09ERVNJR04uY3JsMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSAEDzAN
# MAsGCWCGSAFlAgELKjAdBgNVHQ4EFgQUVusXc6nN92xmQ3XNN+/76hosJFEwZQYI
# KwYBBQUHAQEEWTBXMDMGCCsGAQUFBzAChidodHRwOi8vY3JsLmRpc2EubWlsL3Np
# Z24vRE9ESURDQV81OS5jZXIwIAYIKwYBBQUHMAGGFGh0dHA6Ly9vY3NwLmRpc2Eu
# bWlsMB8GA1UdJQQYMBYGCisGAQQBgjcKAw0GCCsGAQUFBwMDMA0GCSqGSIb3DQEB
# CwUAA4IBAQBCSdogBcOfKqyGbKG45lLicG1LJ2dmt0Hwl7QkKrZNNEDh2Q2+uzB7
# SRmADtSOVjVf/0+1B4jBoyty90WL52rMPVttb8tfm0f/Wgw6niz5WQZ+XjFRTFQa
# M7pBNU54vI3bH4MFBTXUOEoSr0FELFQaByUWfWKrGLnEqYtpDde5FZEYKRv6td6N
# ZH7m5JOiCfEK6gun3luq7ckvx5zIXjr5VKhp+S0Aai3ZR/eqbBZ0wcUF3DOYlqVs
# LiPT0jWompwkfSnxa3fjNHD+FKvd/7EMQM/wY0vZyIObto3QYrLru6COAyY9cC/s
# Dj+R4K4392w1LWdo3KrNzkCFMAX6j/bWMIIEuTCCA6GgAwIBAgICAwUwDQYJKoZI
# hvcNAQELBQAwWzELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVu
# dDEMMAoGA1UECxMDRG9EMQwwCgYDVQQLEwNQS0kxFjAUBgNVBAMTDURvRCBSb290
# IENBIDMwHhcNMTkwNDAyMTMzODMyWhcNMjUwNDAyMTMzODMyWjBaMQswCQYDVQQG
# EwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MQwwCgYDVQQLEwNEb0QxDDAK
# BgNVBAsTA1BLSTEVMBMGA1UEAxMMRE9EIElEIENBLTU5MIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEAzBeEny3BCletEU01Vz8kRy8cD2OWvbtwMTyunFaS
# hu+kIk6g5VRsnvbhK3Ho61MBmlGJc1pLSONGBhpbpyr2l2eONAzmi8c8917V7Bpn
# JZvYj66qGRmY4FXX6UZQ6GdALKKedJKrMQfU8LmcBJ/LGcJ0F4635QocGs9UoFS5
# hLgVyflDTC/6x8EPbi/JXk6N6iod5JIAxNp6qW/5ZBvhiuMo19oYX5LuUy9B6W7c
# A0cRygvYcwKKYK+cIdBoxAj34yw2HJI8RQt490QPGClZhz0WYFuNSnUJgTHsdh2V
# NEn2AEe2zYhPFNlCu3gSmOSp5vxpZWbMIQ8cTv4pRWG47wIDAQABo4IBhjCCAYIw
# HwYDVR0jBBgwFoAUbIqUonexgHIdgXoWqvLczmbuRcAwHQYDVR0OBBYEFHUJphUT
# roc8+nOUAPLw9Xm5snIUMA4GA1UdDwEB/wQEAwIBhjBnBgNVHSAEYDBeMAsGCWCG
# SAFlAgELJDALBglghkgBZQIBCycwCwYJYIZIAWUCAQsqMAsGCWCGSAFlAgELOzAM
# BgpghkgBZQMCAQMNMAwGCmCGSAFlAwIBAxEwDAYKYIZIAWUDAgEDJzASBgNVHRMB
# Af8ECDAGAQH/AgEAMAwGA1UdJAQFMAOAAQAwNwYDVR0fBDAwLjAsoCqgKIYmaHR0
# cDovL2NybC5kaXNhLm1pbC9jcmwvRE9EUk9PVENBMy5jcmwwbAYIKwYBBQUHAQEE
# YDBeMDoGCCsGAQUFBzAChi5odHRwOi8vY3JsLmRpc2EubWlsL2lzc3VlZHRvL0RP
# RFJPT1RDQTNfSVQucDdjMCAGCCsGAQUFBzABhhRodHRwOi8vb2NzcC5kaXNhLm1p
# bDANBgkqhkiG9w0BAQsFAAOCAQEAOQUb0g6nPvWoc1cJ5gkhxSyGA3bQKu8HnKbg
# +vvMpMFEwo2p30RdYHGvA/3GGtrlhxBqAcOqeYF5TcXZ4+Fa9CbKE/AgloCuTjEY
# t2/0iaSvdw7y9Vqk7jyT9H1lFIAQHHN3TEwN1nr7HEWVkkg41GXFxU01UHfR7vgq
# TTz+3zZL2iCqADVDspna0W5pF6yMla6gn4u0TmWu2SeqBpctvdcfSFXkzQBZGT1a
# D/W2Fv00KwoQgB2l2eiVk56mEjN/MeI5Kp4n57mpREsHutP4XnLQ01ZN2qgn+844
# JRrzPQ0pazPYiSl4PeI2FUItErA6Ob/DPF0ba2y3k4dFkUTApzGCAhQwggIQAgEB
# MGIwWjELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEMMAoG
# A1UECxMDRG9EMQwwCgYDVQQLEwNQS0kxFTATBgNVBAMTDERPRCBJRCBDQS01OQIE
# AwIE1zANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAA
# MBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgor
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCV6nFHcIDRTK36m+P3KYLuRKWjDYPv
# SDa64k12PKNkzjANBgkqhkiG9w0BAQEFAASCAQBu/+lwts3+G/EKPmkfhPZs9Obo
# ni9wAkWsoFpbPivyzOtArtqatMWdbTUj+ua1VcGWuRvpwtz8D+3XCDY1nHZmr9hT
# VwLvqsZEiopi4bbLudAAwhEQHAyHR5dGOcm0HdLoPZr5cIVSgm/SGoyb5oMO7zl2
# E210DFWQ1m7leIcuEniJhgtk5geBTD08QXr3PNgqEdcmmktPIgCzA7JcxouNrHLE
# wM12RS/kBVU41C9kWL/TDt59JrznzVYOaDCG+kXIBEba50hdg5fnFXX4chp+1/BR
# +VX5WewHvIhuVYOQZWGVHRyz2TaiIEvSwonvMpsCNAg+wJuo5Qp0AIQrgH1X
# SIG # End signature block
