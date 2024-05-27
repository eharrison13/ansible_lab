##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Microsoft Windows Defender Firewall with Advanced Security
# Version:  V2R2
# Class:    UNCLASSIFIED
# Updated:  5/13/2024
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Confirm-FWProfileEnabled {
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Domain", "Private", "Public")]
        [String]$Profile
    )

    Switch ($Profile) {
        "Domain" {
            $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"  # Registry path identified in STIG
            $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"  # Registry path identified in STIG
        }
        "Private" {
            $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"  # Registry path identified in STIG
            $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"  # Registry path identified in STIG
        }
        "Public" {
            $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"  # Registry path identified in STIG
            $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"  # Registry path identified in STIG
        }
    }

    $ProfileValueName = "EnableFirewall"  # Value name identified in STIG
    $ProfileValue = "1"  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $Enabled = $false

    $Profile1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $ProfileValueName
    $Profile2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $ProfileValueName

    If ($Profile1.Value -eq $ProfileValue -and $Profile1.Type -eq $RegistryType) {
        $Enabled = $true
    }
    ElseIf ($Profile1.Value -eq "(NotFound)" -and $Profile2.Value -eq $ProfileValue -and $Profile2.Type -eq $RegistryType) {
        $Enabled = $true
    }

    Return $Enabled
}

Function Get-V241989 {
    <#
    .DESCRIPTION
        Vuln ID    : V-241989
        STIG ID    : WNFWA-000001
        Rule ID    : SV-241989r922928_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Windows Defender Firewall with Advanced Security must be enabled when connected to a domain.
        DiscussMD5 : A4ED1ACACBEDBF05FF6B6CB4599C3999
        CheckMD5   : 2CCF64661AE95B8CEE2A4F5421CBAF98
        FixMD5     : 1BA51E338E5281FED75E2B1959ADD0B3
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"  # Registry path identified in STIG
    $ProfileValueName = "EnableFirewall"  # Value name identified in STIG
    $ProfileValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Domain Profile"
    $Compliant = $true

    If ((Get-CimInstance Win32_ComputerSystem).DomainRole -notin @(1, 3, 4, 5)) {
        $Status = "Not_Applicable"
        $FindingDetails += "System is not a member of a domain so this requirement is NA." | Out-String
    }
    Else {
        $Profile1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $ProfileValueName
        $Profile2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $ProfileValueName

        # Format the DWORD values
        If ($Profile1.Type -in @("REG_DWORD", "REG_QWORD")) {
            $Profile1Value = "0x{0:x8}" -f $Profile1.Value + " ($($Profile1.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $Profile1Value = $Profile1.Value
        }

        If ($Profile2.Type -in @("REG_DWORD", "REG_QWORD")) {
            $Profile2Value = "0x{0:x8}" -f $Profile2.Value + " ($($Profile2.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $Profile2Value = $Profile2.Value
        }

        # Check if profile is enabled
        If ($Profile1.Type -eq "(NotFound)") {
            If ($Profile2.Value -in $ProfileValue -and $Profile2.Type -eq $RegistryType) {
                # Profile is enabled
                $ProfileEnabled = "Enabled"
            }
            Else {
                # Profile is disabled
                $ProfileEnabled = "Disabled (Finding)"
                $Compliant = $false
            }
        }
        ElseIf ($Profile1.Value -in $ProfileValue -and $Profile1.Type -eq $RegistryType) {
            # Profile is enabled
            $ProfileEnabled = "Enabled"
        }
        Else {
            # Profile is disabled
            $ProfileEnabled = "Disabled (Finding)"
            $Compliant = $false
        }

        Switch ($Compliant) {
            $true {
                $Status = "NotAFinding"
            }
            $false {
                $Status = "Open"
            }
        }

        $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$ProfileValueName" | Out-String
        $FindingDetails += "Value:`t`t$Profile1Value" | Out-String
        $FindingDetails += "Type:`t`t$($Profile1.Type)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
        $FindingDetails += "Value Name:`t$ProfileValueName" | Out-String
        $FindingDetails += "Value:`t`t$Profile2Value" | Out-String
        $FindingDetails += "Type:`t`t$($Profile2.Type)" | Out-String
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

Function Get-V241990 {
    <#
    .DESCRIPTION
        Vuln ID    : V-241990
        STIG ID    : WNFWA-000002
        Rule ID    : SV-241990r922930_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Windows Defender Firewall with Advanced Security must be enabled when connected to a private network.
        DiscussMD5 : 571B6F72CCBF43B43679ADB436581A17
        CheckMD5   : 318D75E78162D20FB97427AE8C3BA95C
        FixMD5     : 2FED2B43F468BAA925D8F78AD4F77BFF
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"  # Registry path identified in STIG
    $ProfileValueName = "EnableFirewall"  # Value name identified in STIG
    $ProfileValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Private Profile"
    $Compliant = $true

    $Profile1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $ProfileValueName
    $Profile2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $ProfileValueName

    # Format the DWORD values
    If ($Profile1.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Profile1Value = "0x{0:x8}" -f $Profile1.Value + " ($($Profile1.Value))" # Convert to hex and fomat to 0x00000000
    }
    Else {
        $Profile1Value = $Profile1.Value
    }

    If ($Profile2.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Profile2Value = "0x{0:x8}" -f $Profile2.Value + " ($($Profile2.Value))" # Convert to hex and fomat to 0x00000000
    }
    Else {
        $Profile2Value = $Profile2.Value
    }

    # Check if profile is enabled
    If ($Profile1.Type -eq "(NotFound)") {
        If ($Profile2.Value -in $ProfileValue -and $Profile2.Type -eq $RegistryType) {
            # Profile is enabled
            $ProfileEnabled = "Enabled"
        }
        Else {
            # Profile is disabled
            $ProfileEnabled = "Disabled (Finding)"
            $Compliant = $false
        }
    }
    ElseIf ($Profile1.Value -in $ProfileValue -and $Profile1.Type -eq $RegistryType) {
        # Profile is enabled
        $ProfileEnabled = "Enabled"
    }
    Else {
        # Profile is disabled
        $ProfileEnabled = "Disabled (Finding)"
        $Compliant = $false
    }

    Switch ($Compliant) {
        $true {
            $Status = "NotAFinding"
        }
        $false {
            $Status = "Open"
        }
    }

    $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
    $FindingDetails += "Value Name:`t$ProfileValueName" | Out-String
    $FindingDetails += "Value:`t`t$Profile1Value" | Out-String
    $FindingDetails += "Type:`t`t$($Profile1.Type)" | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
    $FindingDetails += "Value Name:`t$ProfileValueName" | Out-String
    $FindingDetails += "Value:`t`t$Profile2Value" | Out-String
    $FindingDetails += "Type:`t`t$($Profile2.Type)" | Out-String
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

Function Get-V241991 {
    <#
    .DESCRIPTION
        Vuln ID    : V-241991
        STIG ID    : WNFWA-000003
        Rule ID    : SV-241991r922932_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Windows Defender Firewall with Advanced Security must be enabled when connected to a public network.
        DiscussMD5 : 0387A88B744DF16B9780CA1065C7BA7D
        CheckMD5   : 1B98BFD2A5DCE67C33215F89609202D0
        FixMD5     : 5E939E88415CEF5C8DB3EF7B99DA1A3D
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"  # Registry path identified in STIG
    $ProfileValueName = "EnableFirewall"  # Value name identified in STIG
    $ProfileValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Public Profile"
    $Compliant = $true

    $Profile1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $ProfileValueName
    $Profile2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $ProfileValueName

    # Format the DWORD values
    If ($Profile1.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Profile1Value = "0x{0:x8}" -f $Profile1.Value + " ($($Profile1.Value))" # Convert to hex and fomat to 0x00000000
    }
    Else {
        $Profile1Value = $Profile1.Value
    }

    If ($Profile2.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Profile2Value = "0x{0:x8}" -f $Profile2.Value + " ($($Profile2.Value))" # Convert to hex and fomat to 0x00000000
    }
    Else {
        $Profile2Value = $Profile2.Value
    }

    # Check if profile is enabled
    If ($Profile1.Type -eq "(NotFound)") {
        If ($Profile2.Value -in $ProfileValue -and $Profile2.Type -eq $RegistryType) {
            # Profile is enabled
            $ProfileEnabled = "Enabled"
        }
        Else {
            # Profile is disabled
            $ProfileEnabled = "Disabled (Finding)"
            $Compliant = $false
        }
    }
    ElseIf ($Profile1.Value -in $ProfileValue -and $Profile1.Type -eq $RegistryType) {
        # Profile is enabled
        $ProfileEnabled = "Enabled"
    }
    Else {
        # Profile is disabled
        $ProfileEnabled = "Disabled (Finding)"
        $Compliant = $false
    }

    Switch ($Compliant) {
        $true {
            $Status = "NotAFinding"
        }
        $false {
            $Status = "Open"
        }
    }

    $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
    $FindingDetails += "Value Name:`t$ProfileValueName" | Out-String
    $FindingDetails += "Value:`t`t$Profile1Value" | Out-String
    $FindingDetails += "Type:`t`t$($Profile1.Type)" | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
    $FindingDetails += "Value Name:`t$ProfileValueName" | Out-String
    $FindingDetails += "Value:`t`t$Profile2Value" | Out-String
    $FindingDetails += "Type:`t`t$($Profile2.Type)" | Out-String
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

Function Get-V241992 {
    <#
    .DESCRIPTION
        Vuln ID    : V-241992
        STIG ID    : WNFWA-000004
        Rule ID    : SV-241992r922934_rule
        CCI ID     : CCI-000382
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Windows Defender Firewall with Advanced Security must block unsolicited inbound connections when connected to a domain.
        DiscussMD5 : 60EE4DE54D75021E16358FE8568CB850
        CheckMD5   : 4392212EACEE280D82EC2526287972DC
        FixMD5     : 22B1F4A681CFACB24FEAE872FD393798
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"  # Registry path identified in STIG
    $SettingValueName = "DefaultInboundAction"  # Value name identified in STIG
    $SettingValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Domain Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    If ((Get-CimInstance Win32_ComputerSystem).DomainRole -notin @(1, 3, 4, 5)) {
        $Status = "Not_Applicable"
        $FindingDetails += "System is not a member of a domain so this requirement is NA." | Out-String
    }
    Else {
        $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
        $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

        # Format the DWORD values
        If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
            $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $Setting1Value = $Setting1.Value
        }

        If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
            $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $Setting2Value = $Setting2.Value
        }

        # Check if profile is enabled
        If (Confirm-FWProfileEnabled -Profile Domain) {
            $ProfileEnabled = "Enabled"
        }
        Else {
            $ProfileEnabled = "Disabled (Finding)"
            $Compliant = $false
        }

        # Check if setting is configured
        If ($Setting1.Type -eq "(NotFound)") {
            If ($Setting2.Value -in $SettingValue -and $Setting2.Type -eq $RegistryType) {
                # Setting is configured
                $CompliantSetting.Value = $Setting2Value
                $CompliantSetting.Type = $Setting2.Type
            }
            Else {
                # Setting is not configured
                $Compliant = $false
            }
        }
        ElseIf ($Setting1.Value -in $SettingValue -and $Setting1.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting1Value
            $CompliantSetting.Type = $Setting1.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }

        Switch ($Compliant) {
            $true {
                $Status = "NotAFinding"
            }
            $false {
                $Status = "Open"
            }
        }

        $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
        $FindingDetails += "" | Out-String
        If ($CompliantSetting.Value) {
            $FindingDetails += "Compliant setting found:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
            $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
        }
        Else {
            $FindingDetails += "No compliant setting found:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
            $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
            $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V241993 {
    <#
    .DESCRIPTION
        Vuln ID    : V-241993
        STIG ID    : WNFWA-000005
        Rule ID    : SV-241993r922936_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Windows Defender Firewall with Advanced Security must allow outbound connections, unless a rule explicitly blocks the connection when connected to a domain.
        DiscussMD5 : 572F0DABD7D2DBC07692ACD94D1F77DD
        CheckMD5   : FB09C2A1876162DF7095D18C9D18447A
        FixMD5     : C87F983DF57C793B8DC7F5CB31FB5FC8
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"  # Registry path identified in STIG
    $SettingValueName = "DefaultOutboundAction"  # Value name identified in STIG
    $SettingValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Domain Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    If ((Get-CimInstance Win32_ComputerSystem).DomainRole -notin @(1, 3, 4, 5)) {
        $Status = "Not_Applicable"
        $FindingDetails += "System is not a member of a domain so this requirement is NA." | Out-String
    }
    Else {
        $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
        $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

        # Format the DWORD values
        If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
            $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $Setting1Value = $Setting1.Value
        }

        If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
            $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $Setting2Value = $Setting2.Value
        }

        # Check if profile is enabled
        If (Confirm-FWProfileEnabled -Profile Domain) {
            $ProfileEnabled = "Enabled"
        }
        Else {
            $ProfileEnabled = "Disabled (Finding)"
            $Compliant = $false
        }

        # Check if setting is configured
        If ($Setting1.Type -eq "(NotFound)") {
            If ($Setting2.Value -in $SettingValue -and $Setting2.Type -eq $RegistryType) {
                # Setting is configured
                $CompliantSetting.Value = $Setting2Value
                $CompliantSetting.Type = $Setting2.Type
            }
            Else {
                # Setting is not configured
                $Compliant = $false
            }
        }
        ElseIf ($Setting1.Value -in $SettingValue -and $Setting1.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting1Value
            $CompliantSetting.Type = $Setting1.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }

        Switch ($Compliant) {
            $true {
                $Status = "NotAFinding"
            }
            $false {
                $Status = "Open"
            }
        }

        $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
        $FindingDetails += "" | Out-String
        If ($CompliantSetting.Value) {
            $FindingDetails += "Compliant setting found:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
            $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
        }
        Else {
            $FindingDetails += "No compliant setting found:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
            $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
            $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V241994 {
    <#
    .DESCRIPTION
        Vuln ID    : V-241994
        STIG ID    : WNFWA-000009
        Rule ID    : SV-241994r922938_rule
        CCI ID     : CCI-000140
        Rule Name  : SRG-OS-000327-GPOS-00127
        Rule Title : Windows Defender Firewall with Advanced Security log size must be configured for domain connections.
        DiscussMD5 : C47980FA173FB79680784CF0E8DA4B8D
        CheckMD5   : E280D26633D61A392C90F39EA0831C16
        FixMD5     : 0ABCB3B45FF8971BA14090030E10E8EF
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging"  # Registry path identified in STIG
    $SettingValueName = "LogFileSize"  # Value name identified in STIG
    $SettingValue = "16384"  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Domain Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    If ((Get-CimInstance Win32_ComputerSystem).DomainRole -notin @(1, 3, 4, 5)) {
        $Status = "Not_Applicable"
        $FindingDetails += "System is not a member of a domain so this requirement is NA." | Out-String
    }
    Else {
        $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
        $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

        # Format the DWORD values
        If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
            $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $Setting1Value = $Setting1.Value
        }

        If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
            $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $Setting2Value = $Setting2.Value
        }

        # Check if profile is enabled
        If (Confirm-FWProfileEnabled -Profile Domain) {
            $ProfileEnabled = "Enabled"
        }
        Else {
            $ProfileEnabled = "Disabled (Finding)"
            $Compliant = $false
        }

        # Check if setting is configured
        If ($Setting1.Type -eq "(NotFound)") {
            If ($Setting2.Value -ge $SettingValue -and $Setting2.Type -eq $RegistryType) {
                # Setting is configured
                $CompliantSetting.Value = $Setting2Value
                $CompliantSetting.Type = $Setting2.Type
            }
            Else {
                # Setting is not configured
                $Compliant = $false
            }
        }
        ElseIf ($Setting1.Value -ge $SettingValue -and $Setting1.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting1Value
            $CompliantSetting.Type = $Setting1.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }

        Switch ($Compliant) {
            $true {
                $Status = "NotAFinding"
            }
            $false {
                $Status = "Open"
            }
        }

        $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
        $FindingDetails += "" | Out-String
        If ($CompliantSetting.Value) {
            $FindingDetails += "Compliant setting found:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
            $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
        }
        Else {
            $FindingDetails += "No compliant setting found:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
            $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
            $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V241995 {
    <#
    .DESCRIPTION
        Vuln ID    : V-241995
        STIG ID    : WNFWA-000010
        Rule ID    : SV-241995r922940_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000327-GPOS-00127
        Rule Title : Windows Defender Firewall with Advanced Security must log dropped packets when connected to a domain.
        DiscussMD5 : 7662DF28CBC859EC0E3C65877C6351DA
        CheckMD5   : 47BD982BAD7A845704ECE38D62E6C7C4
        FixMD5     : 732F8C0F1EE1F79BB908F7C3FF6FFC97
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging"  # Registry path identified in STIG
    $SettingValueName = "LogDroppedPackets"  # Value name identified in STIG
    $SettingValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Domain Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    If ((Get-CimInstance Win32_ComputerSystem).DomainRole -notin @(1, 3, 4, 5)) {
        $Status = "Not_Applicable"
        $FindingDetails += "System is not a member of a domain so this requirement is NA." | Out-String
    }
    Else {
        $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
        $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

        # Format the DWORD values
        If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
            $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $Setting1Value = $Setting1.Value
        }

        If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
            $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $Setting2Value = $Setting2.Value
        }

        # Check if profile is enabled
        If (Confirm-FWProfileEnabled -Profile Domain) {
            $ProfileEnabled = "Enabled"
        }
        Else {
            $ProfileEnabled = "Disabled (Finding)"
            $Compliant = $false
        }

        # Check if setting is configured
        If ($Setting1.Type -eq "(NotFound)") {
            If ($Setting2.Value -in $SettingValue -and $Setting2.Type -eq $RegistryType) {
                # Setting is configured
                $CompliantSetting.Value = $Setting2Value
                $CompliantSetting.Type = $Setting2.Type
            }
            Else {
                # Setting is not configured
                $Compliant = $false
            }
        }
        ElseIf ($Setting1.Value -in $SettingValue -and $Setting1.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting1Value
            $CompliantSetting.Type = $Setting1.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }

        Switch ($Compliant) {
            $true {
                $Status = "NotAFinding"
            }
            $false {
                $Status = "Open"
            }
        }

        $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
        $FindingDetails += "" | Out-String
        If ($CompliantSetting.Value) {
            $FindingDetails += "Compliant setting found:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
            $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
        }
        Else {
            $FindingDetails += "No compliant setting found:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
            $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
            $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V241996 {
    <#
    .DESCRIPTION
        Vuln ID    : V-241996
        STIG ID    : WNFWA-000011
        Rule ID    : SV-241996r922942_rule
        CCI ID     : CCI-001462
        Rule Name  : SRG-OS-000327-GPOS-00127
        Rule Title : Windows Defender Firewall with Advanced Security must log successful connections when connected to a domain.
        DiscussMD5 : E8550F6B36DF5457CE263582E6306F80
        CheckMD5   : FCF37F873FD4DDDEFD7F1B1CC89C448A
        FixMD5     : 1B49E48AEB84D5E7F32EFCFB767A7072
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging"  # Registry path identified in STIG
    $SettingValueName = "LogSuccessfulConnections"  # Value name identified in STIG
    $SettingValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Domain Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    If ((Get-CimInstance Win32_ComputerSystem).DomainRole -notin @(1, 3, 4, 5)) {
        $Status = "Not_Applicable"
        $FindingDetails += "System is not a member of a domain so this requirement is NA." | Out-String
    }
    Else {
        $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
        $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

        # Format the DWORD values
        If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
            $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $Setting1Value = $Setting1.Value
        }

        If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
            $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $Setting2Value = $Setting2.Value
        }

        # Check if profile is enabled
        If (Confirm-FWProfileEnabled -Profile Domain) {
            $ProfileEnabled = "Enabled"
        }
        Else {
            $ProfileEnabled = "Disabled (Finding)"
            $Compliant = $false
        }

        # Check if setting is configured
        If ($Setting1.Type -eq "(NotFound)") {
            If ($Setting2.Value -in $SettingValue -and $Setting2.Type -eq $RegistryType) {
                # Setting is configured
                $CompliantSetting.Value = $Setting2Value
                $CompliantSetting.Type = $Setting2.Type
            }
            Else {
                # Setting is not configured
                $Compliant = $false
            }
        }
        ElseIf ($Setting1.Value -in $SettingValue -and $Setting1.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting1Value
            $CompliantSetting.Type = $Setting1.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }

        Switch ($Compliant) {
            $true {
                $Status = "NotAFinding"
            }
            $false {
                $Status = "Open"
            }
        }

        $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
        $FindingDetails += "" | Out-String
        If ($CompliantSetting.Value) {
            $FindingDetails += "Compliant setting found:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
            $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
        }
        Else {
            $FindingDetails += "No compliant setting found:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
            $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
            $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V241997 {
    <#
    .DESCRIPTION
        Vuln ID    : V-241997
        STIG ID    : WNFWA-000012
        Rule ID    : SV-241997r922944_rule
        CCI ID     : CCI-000382
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Windows Defender Firewall with Advanced Security must block unsolicited inbound connections when connected to a private network.
        DiscussMD5 : 3EA3C2EFB7A6C91C46C2D05C76363A75
        CheckMD5   : 4FC96F625BC12E6209F38C44A3CA623A
        FixMD5     : 59E3792088D0648ACC62A80E3FDC59F8
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"  # Registry path identified in STIG
    $SettingValueName = "DefaultInboundAction"  # Value name identified in STIG
    $SettingValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Private Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
    $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

    # Format the DWORD values
    If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and fomat to 0x00000000
    }
    Else {
        $Setting1Value = $Setting1.Value
    }

    If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and fomat to 0x00000000
    }
    Else {
        $Setting2Value = $Setting2.Value
    }

    # Check if profile is enabled
    If (Confirm-FWProfileEnabled -Profile Private) {
        $ProfileEnabled = "Enabled"
    }
    Else {
        $ProfileEnabled = "Disabled (Finding)"
        $Compliant = $false
    }

    # Check if setting is configured
    If ($Setting1.Type -eq "(NotFound)") {
        If ($Setting2.Value -in $SettingValue -and $Setting2.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting2Value
            $CompliantSetting.Type = $Setting2.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }
    }
    ElseIf ($Setting1.Value -in $SettingValue -and $Setting1.Type -eq $RegistryType) {
        # Setting is configured
        $CompliantSetting.Value = $Setting1Value
        $CompliantSetting.Type = $Setting1.Type
    }
    Else {
        # Setting is not configured
        $Compliant = $false
    }

    Switch ($Compliant) {
        $true {
            $Status = "NotAFinding"
        }
        $false {
            $Status = "Open"
        }
    }

    $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
    $FindingDetails += "" | Out-String
    If ($CompliantSetting.Value) {
        $FindingDetails += "Compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
        $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
    }
    Else {
        $FindingDetails += "No compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V241998 {
    <#
    .DESCRIPTION
        Vuln ID    : V-241998
        STIG ID    : WNFWA-000013
        Rule ID    : SV-241998r922946_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Windows Defender Firewall with Advanced Security must allow outbound connections, unless a rule explicitly blocks the connection when connected to a private network.
        DiscussMD5 : B171C848CEE8EEA7A36B3239EF53F200
        CheckMD5   : ACE85394F5279D16B1FA41C661184A82
        FixMD5     : DF281FD83607CE6C47E8D2A0F7BCA304
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"  # Registry path identified in STIG
    $SettingValueName = "DefaultOutboundAction"  # Value name identified in STIG
    $SettingValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Private Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
    $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

    # Format the DWORD values
    If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and fomat to 0x00000000
    }
    Else {
        $Setting1Value = $Setting1.Value
    }

    If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and fomat to 0x00000000
    }
    Else {
        $Setting2Value = $Setting2.Value
    }

    # Check if profile is enabled
    If (Confirm-FWProfileEnabled -Profile Private) {
        $ProfileEnabled = "Enabled"
    }
    Else {
        $ProfileEnabled = "Disabled (Finding)"
        $Compliant = $false
    }

    # Check if setting is configured
    If ($Setting1.Type -eq "(NotFound)") {
        If ($Setting2.Value -in $SettingValue -and $Setting2.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting2Value
            $CompliantSetting.Type = $Setting2.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }
    }
    ElseIf ($Setting1.Value -in $SettingValue -and $Setting1.Type -eq $RegistryType) {
        # Setting is configured
        $CompliantSetting.Value = $Setting1Value
        $CompliantSetting.Type = $Setting1.Type
    }
    Else {
        # Setting is not configured
        $Compliant = $false
    }

    Switch ($Compliant) {
        $true {
            $Status = "NotAFinding"
        }
        $false {
            $Status = "Open"
        }
    }

    $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
    $FindingDetails += "" | Out-String
    If ($CompliantSetting.Value) {
        $FindingDetails += "Compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
        $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
    }
    Else {
        $FindingDetails += "No compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V241999 {
    <#
    .DESCRIPTION
        Vuln ID    : V-241999
        STIG ID    : WNFWA-000017
        Rule ID    : SV-241999r922948_rule
        CCI ID     : CCI-000140
        Rule Name  : SRG-OS-000327-GPOS-00127
        Rule Title : Windows Defender Firewall with Advanced Security log size must be configured for private network connections.
        DiscussMD5 : 5DC729495B7B2F2EC12CBF22459171F6
        CheckMD5   : 22D3D72F3BD55C07BA8766881A536732
        FixMD5     : FA91E351AD877180706D977F74ADC5E0
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging"  # Registry path identified in STIG
    $SettingValueName = "LogFileSize"  # Value name identified in STIG
    $SettingValue = "16384"  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Private Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
    $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

    # Format the DWORD values
    If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and fomat to 0x00000000
    }
    Else {
        $Setting1Value = $Setting1.Value
    }

    If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and fomat to 0x00000000
    }
    Else {
        $Setting2Value = $Setting2.Value
    }

    # Check if profile is enabled
    If (Confirm-FWProfileEnabled -Profile Private) {
        $ProfileEnabled = "Enabled"
    }
    Else {
        $ProfileEnabled = "Disabled (Finding)"
        $Compliant = $false
    }

    # Check if setting is configured
    If ($Setting1.Type -eq "(NotFound)") {
        If ($Setting2.Value -ge $SettingValue -and $Setting2.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting2Value
            $CompliantSetting.Type = $Setting2.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }
    }
    ElseIf ($Setting1.Value -ge $SettingValue -and $Setting1.Type -eq $RegistryType) {
        # Setting is configured
        $CompliantSetting.Value = $Setting1Value
        $CompliantSetting.Type = $Setting1.Type
    }
    Else {
        # Setting is not configured
        $Compliant = $false
    }

    Switch ($Compliant) {
        $true {
            $Status = "NotAFinding"
        }
        $false {
            $Status = "Open"
        }
    }

    $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
    $FindingDetails += "" | Out-String
    If ($CompliantSetting.Value) {
        $FindingDetails += "Compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
        $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
    }
    Else {
        $FindingDetails += "No compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V242000 {
    <#
    .DESCRIPTION
        Vuln ID    : V-242000
        STIG ID    : WNFWA-000018
        Rule ID    : SV-242000r922950_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000327-GPOS-00127
        Rule Title : Windows Defender Firewall with Advanced Security must log dropped packets when connected to a private network.
        DiscussMD5 : 3FEA37CB0CADBB95A13D707E09B533B4
        CheckMD5   : 4B6E6C4BCEE91C6001DB698F29BA107C
        FixMD5     : 8D7D6978317471E9B3830144CEC855C7
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging"  # Registry path identified in STIG
    $SettingValueName = "LogDroppedPackets"  # Value name identified in STIG
    $SettingValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Private Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
    $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

    # Format the DWORD values
    If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and fomat to 0x00000000
    }
    Else {
        $Setting1Value = $Setting1.Value
    }

    If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and fomat to 0x00000000
    }
    Else {
        $Setting2Value = $Setting2.Value
    }

    # Check if profile is enabled
    If (Confirm-FWProfileEnabled -Profile Private) {
        $ProfileEnabled = "Enabled"
    }
    Else {
        $ProfileEnabled = "Disabled (Finding)"
        $Compliant = $false
    }

    # Check if setting is configured
    If ($Setting1.Type -eq "(NotFound)") {
        If ($Setting2.Value -in $SettingValue -and $Setting2.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting2Value
            $CompliantSetting.Type = $Setting2.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }
    }
    ElseIf ($Setting1.Value -in $SettingValue -and $Setting1.Type -eq $RegistryType) {
        # Setting is configured
        $CompliantSetting.Value = $Setting1Value
        $CompliantSetting.Type = $Setting1.Type
    }
    Else {
        # Setting is not configured
        $Compliant = $false
    }

    Switch ($Compliant) {
        $true {
            $Status = "NotAFinding"
        }
        $false {
            $Status = "Open"
        }
    }

    $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
    $FindingDetails += "" | Out-String
    If ($CompliantSetting.Value) {
        $FindingDetails += "Compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
        $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
    }
    Else {
        $FindingDetails += "No compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V242001 {
    <#
    .DESCRIPTION
        Vuln ID    : V-242001
        STIG ID    : WNFWA-000019
        Rule ID    : SV-242001r922952_rule
        CCI ID     : CCI-001462
        Rule Name  : SRG-OS-000327-GPOS-00127
        Rule Title : Windows Defender Firewall with Advanced Security must log successful connections when connected to a private network.
        DiscussMD5 : 7050FE88BB96947D547DD7B11CBA042E
        CheckMD5   : 4A776279E6709C1D598211B67A9A47EF
        FixMD5     : C91ACF5A8DB437CB0155388FBFAC8FBA
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\Logging"  # Registry path identified in STIG
    $SettingValueName = "LogSuccessfulConnections"  # Value name identified in STIG
    $SettingValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Private Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
    $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

    # Format the DWORD values
    If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and fomat to 0x00000000
    }
    Else {
        $Setting1Value = $Setting1.Value
    }

    If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and fomat to 0x00000000
    }
    Else {
        $Setting2Value = $Setting2.Value
    }

    # Check if profile is enabled
    If (Confirm-FWProfileEnabled -Profile Private) {
        $ProfileEnabled = "Enabled"
    }
    Else {
        $ProfileEnabled = "Disabled (Finding)"
        $Compliant = $false
    }

    # Check if setting is configured
    If ($Setting1.Type -eq "(NotFound)") {
        If ($Setting2.Value -in $SettingValue -and $Setting2.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting2Value
            $CompliantSetting.Type = $Setting2.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }
    }
    ElseIf ($Setting1.Value -in $SettingValue -and $Setting1.Type -eq $RegistryType) {
        # Setting is configured
        $CompliantSetting.Value = $Setting1Value
        $CompliantSetting.Type = $Setting1.Type
    }
    Else {
        # Setting is not configured
        $Compliant = $false
    }

    Switch ($Compliant) {
        $true {
            $Status = "NotAFinding"
        }
        $false {
            $Status = "Open"
        }
    }

    $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
    $FindingDetails += "" | Out-String
    If ($CompliantSetting.Value) {
        $FindingDetails += "Compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
        $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
    }
    Else {
        $FindingDetails += "No compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V242002 {
    <#
    .DESCRIPTION
        Vuln ID    : V-242002
        STIG ID    : WNFWA-000020
        Rule ID    : SV-242002r922954_rule
        CCI ID     : CCI-000382
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Windows Defender Firewall with Advanced Security must block unsolicited inbound connections when connected to a public network.
        DiscussMD5 : DA7ABC450121558E89A0D92509F38CF1
        CheckMD5   : 8ACC8A6E764371BD01102E3B9942951F
        FixMD5     : 016D1FD83EC859DEADEC20C1F08F94FA
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"  # Registry path identified in STIG
    $SettingValueName = "DefaultInboundAction"  # Value name identified in STIG
    $SettingValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Public Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
    $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

    # Format the DWORD values
    If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and fomat to 0x00000000
    }
    Else {
        $Setting1Value = $Setting1.Value
    }

    If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and fomat to 0x00000000
    }
    Else {
        $Setting2Value = $Setting2.Value
    }

    # Check if profile is enabled
    If (Confirm-FWProfileEnabled -Profile Public) {
        $ProfileEnabled = "Enabled"
    }
    Else {
        $ProfileEnabled = "Disabled (Finding)"
        $Compliant = $false
    }

    # Check if setting is configured
    If ($Setting1.Type -eq "(NotFound)") {
        If ($Setting2.Value -in $SettingValue -and $Setting2.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting2Value
            $CompliantSetting.Type = $Setting2.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }
    }
    ElseIf ($Setting1.Value -in $SettingValue -and $Setting1.Type -eq $RegistryType) {
        # Setting is configured
        $CompliantSetting.Value = $Setting1Value
        $CompliantSetting.Type = $Setting1.Type
    }
    Else {
        # Setting is not configured
        $Compliant = $false
    }

    Switch ($Compliant) {
        $true {
            $Status = "NotAFinding"
        }
        $false {
            $Status = "Open"
        }
    }

    $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
    $FindingDetails += "" | Out-String
    If ($CompliantSetting.Value) {
        $FindingDetails += "Compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
        $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
    }
    Else {
        $FindingDetails += "No compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V242003 {
    <#
    .DESCRIPTION
        Vuln ID    : V-242003
        STIG ID    : WNFWA-000021
        Rule ID    : SV-242003r922956_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Windows Defender Firewall with Advanced Security must allow outbound connections, unless a rule explicitly blocks the connection when connected to a public network.
        DiscussMD5 : 7CC73625792370833CB7828E217B460A
        CheckMD5   : 472CCD7428370B21CC6D7B4DC40D2B6B
        FixMD5     : BEB501E73E44B0F625D4A0A5546228E3
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"  # Registry path identified in STIG
    $SettingValueName = "DefaultOutboundAction"  # Value name identified in STIG
    $SettingValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Public Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
    $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

    # Format the DWORD values
    If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and fomat to 0x00000000
    }
    Else {
        $Setting1Value = $Setting1.Value
    }

    If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and fomat to 0x00000000
    }
    Else {
        $Setting2Value = $Setting2.Value
    }

    # Check if profile is enabled
    If (Confirm-FWProfileEnabled -Profile Public) {
        $ProfileEnabled = "Enabled"
    }
    Else {
        $ProfileEnabled = "Disabled (Finding)"
        $Compliant = $false
    }

    # Check if setting is configured
    If ($Setting1.Type -eq "(NotFound)") {
        If ($Setting2.Value -in $SettingValue -and $Setting2.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting2Value
            $CompliantSetting.Type = $Setting2.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }
    }
    ElseIf ($Setting1.Value -in $SettingValue -and $Setting1.Type -eq $RegistryType) {
        # Setting is configured
        $CompliantSetting.Value = $Setting1Value
        $CompliantSetting.Type = $Setting1.Type
    }
    Else {
        # Setting is not configured
        $Compliant = $false
    }

    Switch ($Compliant) {
        $true {
            $Status = "NotAFinding"
        }
        $false {
            $Status = "Open"
        }
    }

    $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
    $FindingDetails += "" | Out-String
    If ($CompliantSetting.Value) {
        $FindingDetails += "Compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
        $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
    }
    Else {
        $FindingDetails += "No compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V242004 {
    <#
    .DESCRIPTION
        Vuln ID    : V-242004
        STIG ID    : WNFWA-000024
        Rule ID    : SV-242004r922958_rule
        CCI ID     : CCI-001190
        Rule Name  : SRG-OS-000327-GPOS-00127
        Rule Title : Windows Defender Firewall with Advanced Security local firewall rules must not be merged with Group Policy settings when connected to a public network.
        DiscussMD5 : E955C0FC0562CD2B44F23C4894BD421B
        CheckMD5   : 07A496F9464D559FCBDE8E9F76DBD646
        FixMD5     : 5DFE45A303B379D3AFE12746E480DC3A
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"  # Registry path identified in STIG
    $SettingValueName = "AllowLocalPolicyMerge"  # Value name identified in STIG
    $SettingValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Public Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    If ((Get-CimInstance Win32_ComputerSystem).DomainRole -notin @(1, 3, 4, 5)) {
        $Status = "Not_Applicable"
        $FindingDetails += "System is not a member of a domain so this requirement is NA." | Out-String
    }
    Else {
        $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName

        # Format the DWORD values
        If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
            $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $Setting1Value = $Setting1.Value
        }

        # Check if profile is enabled
        If (Confirm-FWProfileEnabled -Profile Public) {
            $ProfileEnabled = "Enabled"
        }
        Else {
            $ProfileEnabled = "Disabled (Finding)"
            $Compliant = $false
        }

        # Check if setting is configured
        If ($Setting1.Value -in $SettingValue -and $Setting1.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting1Value
            $CompliantSetting.Type = $Setting1.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }

        Switch ($Compliant) {
            $true {
                $Status = "NotAFinding"
            }
            $false {
                $Status = "Open"
            }
        }

        $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
        $FindingDetails += "" | Out-String
        If ($CompliantSetting.Value) {
            $FindingDetails += "Compliant setting found:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
            $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
        }
        Else {
            $FindingDetails += "No compliant setting found:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
            $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
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

Function Get-V242005 {
    <#
    .DESCRIPTION
        Vuln ID    : V-242005
        STIG ID    : WNFWA-000025
        Rule ID    : SV-242005r922960_rule
        CCI ID     : CCI-001190
        Rule Name  : SRG-OS-000327-GPOS-00127
        Rule Title : Windows Defender Firewall with Advanced Security local connection rules must not be merged with Group Policy settings when connected to a public network.
        DiscussMD5 : D9A51000B1877ACE4793DF72F441C40F
        CheckMD5   : DE26931B2A1CFF4F78E829A47E7F0F33
        FixMD5     : 2B1864873A6C42B6B86F919DC238B5A2
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"  # Registry path identified in STIG
    $SettingValueName = "AllowLocalIPsecPolicyMerge"  # Value name identified in STIG
    $SettingValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Public Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    If ((Get-CimInstance Win32_ComputerSystem).DomainRole -notin @(1, 3, 4, 5)) {
        $Status = "Not_Applicable"
        $FindingDetails += "System is not a member of a domain so this requirement is NA." | Out-String
    }
    Else {
        $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName

        # Format the DWORD values
        If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
            $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and fomat to 0x00000000
        }
        Else {
            $Setting1Value = $Setting1.Value
        }

        # Check if profile is enabled
        If (Confirm-FWProfileEnabled -Profile Public) {
            $ProfileEnabled = "Enabled"
        }
        Else {
            $ProfileEnabled = "Disabled (Finding)"
            $Compliant = $false
        }

        # Check if setting is configured
        If ($Setting1.Value -in $SettingValue -and $Setting1.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting1Value
            $CompliantSetting.Type = $Setting1.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }

        Switch ($Compliant) {
            $true {
                $Status = "NotAFinding"
            }
            $false {
                $Status = "Open"
            }
        }

        $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
        $FindingDetails += "" | Out-String
        If ($CompliantSetting.Value) {
            $FindingDetails += "Compliant setting found:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
            $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
        }
        Else {
            $FindingDetails += "No compliant setting found:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
            $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
            $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
            $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
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

Function Get-V242006 {
    <#
    .DESCRIPTION
        Vuln ID    : V-242006
        STIG ID    : WNFWA-000027
        Rule ID    : SV-242006r922962_rule
        CCI ID     : CCI-000140
        Rule Name  : SRG-OS-000327-GPOS-00127
        Rule Title : Windows Defender Firewall with Advanced Security log size must be configured for public network connections.
        DiscussMD5 : EBEB5FE59955705C4F268594EC0075C0
        CheckMD5   : 1A1F045408B0FD5C5FA12EB8DDDC2794
        FixMD5     : 073728ACB3A80A243DA3DB3A482C6512
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging"  # Registry path identified in STIG
    $SettingValueName = "LogFileSize"  # Value name identified in STIG
    $SettingValue = "16384"  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Public Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
    $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

    # Format the DWORD values
    If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and fomat to 0x00000000
    }
    Else {
        $Setting1Value = $Setting1.Value
    }

    If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and fomat to 0x00000000
    }
    Else {
        $Setting2Value = $Setting2.Value
    }

    # Check if profile is enabled
    If (Confirm-FWProfileEnabled -Profile Public) {
        $ProfileEnabled = "Enabled"
    }
    Else {
        $ProfileEnabled = "Disabled (Finding)"
        $Compliant = $false
    }

    # Check if setting is configured
    If ($Setting1.Type -eq "(NotFound)") {
        If ($Setting2.Value -ge $SettingValue -and $Setting2.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting2Value
            $CompliantSetting.Type = $Setting2.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }
    }
    ElseIf ($Setting1.Value -ge $SettingValue -and $Setting1.Type -eq $RegistryType) {
        # Setting is configured
        $CompliantSetting.Value = $Setting1Value
        $CompliantSetting.Type = $Setting1.Type
    }
    Else {
        # Setting is not configured
        $Compliant = $false
    }

    Switch ($Compliant) {
        $true {
            $Status = "NotAFinding"
        }
        $false {
            $Status = "Open"
        }
    }

    $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
    $FindingDetails += "" | Out-String
    If ($CompliantSetting.Value) {
        $FindingDetails += "Compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
        $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
    }
    Else {
        $FindingDetails += "No compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V242007 {
    <#
    .DESCRIPTION
        Vuln ID    : V-242007
        STIG ID    : WNFWA-000028
        Rule ID    : SV-242007r922964_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000327-GPOS-00127
        Rule Title : Windows Defender Firewall with Advanced Security must log dropped packets when connected to a public network.
        DiscussMD5 : 2496E9CDF47038B892ADDBC0E37599E0
        CheckMD5   : 9FD41687C34A3BC292EE6C6EB20ACCDF
        FixMD5     : B76434F2539A697A351D38121F1B0D26
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging"  # Registry path identified in STIG
    $SettingValueName = "LogDroppedPackets"  # Value name identified in STIG
    $SettingValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Public Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
    $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

    # Format the DWORD values
    If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and fomat to 0x00000000
    }
    Else {
        $Setting1Value = $Setting1.Value
    }

    If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and fomat to 0x00000000
    }
    Else {
        $Setting2Value = $Setting2.Value
    }

    # Check if profile is enabled
    If (Confirm-FWProfileEnabled -Profile Public) {
        $ProfileEnabled = "Enabled"
    }
    Else {
        $ProfileEnabled = "Disabled (Finding)"
        $Compliant = $false
    }

    # Check if setting is configured
    If ($Setting1.Type -eq "(NotFound)") {
        If ($Setting2.Value -in $SettingValue -and $Setting2.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting2Value
            $CompliantSetting.Type = $Setting2.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }
    }
    ElseIf ($Setting1.Value -in $SettingValue -and $Setting1.Type -eq $RegistryType) {
        # Setting is configured
        $CompliantSetting.Value = $Setting1Value
        $CompliantSetting.Type = $Setting1.Type
    }
    Else {
        # Setting is not configured
        $Compliant = $false
    }

    Switch ($Compliant) {
        $true {
            $Status = "NotAFinding"
        }
        $false {
            $Status = "Open"
        }
    }

    $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
    $FindingDetails += "" | Out-String
    If ($CompliantSetting.Value) {
        $FindingDetails += "Compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
        $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
    }
    Else {
        $FindingDetails += "No compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V242008 {
    <#
    .DESCRIPTION
        Vuln ID    : V-242008
        STIG ID    : WNFWA-000029
        Rule ID    : SV-242008r922966_rule
        CCI ID     : CCI-001462
        Rule Name  : SRG-OS-000327-GPOS-00127
        Rule Title : Windows Defender Firewall with Advanced Security must log successful connections when connected to a public network.
        DiscussMD5 : 790CA7E9D853E1F31178773CE4D39A94
        CheckMD5   : 124A093F444858A272CED388AEF86B47
        FixMD5     : E767E0DC9FCEF8D6BCDFAEA9923085F6
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $RegistryPath1 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"  # Registry path identified in STIG
    $RegistryPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging"  # Registry path identified in STIG
    $SettingValueName = "LogSuccessfulConnections"  # Value name identified in STIG
    $SettingValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $ProfileName = "Public Profile"
    $Compliant = $true
    $CompliantSetting = @{ }

    $Setting1 = Get-RegistryResult -Path $RegistryPath1 -ValueName $SettingValueName
    $Setting2 = Get-RegistryResult -Path $RegistryPath2 -ValueName $SettingValueName

    # Format the DWORD values
    If ($Setting1.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting1Value = "0x{0:x8}" -f $Setting1.Value + " ($($Setting1.Value))" # Convert to hex and fomat to 0x00000000
    }
    Else {
        $Setting1Value = $Setting1.Value
    }

    If ($Setting2.Type -in @("REG_DWORD", "REG_QWORD")) {
        $Setting2Value = "0x{0:x8}" -f $Setting2.Value + " ($($Setting2.Value))" # Convert to hex and fomat to 0x00000000
    }
    Else {
        $Setting2Value = $Setting2.Value
    }

    # Check if profile is enabled
    If (Confirm-FWProfileEnabled -Profile Public) {
        $ProfileEnabled = "Enabled"
    }
    Else {
        $ProfileEnabled = "Disabled (Finding)"
        $Compliant = $false
    }

    # Check if setting is configured
    If ($Setting1.Type -eq "(NotFound)") {
        If ($Setting2.Value -in $SettingValue -and $Setting2.Type -eq $RegistryType) {
            # Setting is configured
            $CompliantSetting.Value = $Setting2Value
            $CompliantSetting.Type = $Setting2.Type
        }
        Else {
            # Setting is not configured
            $Compliant = $false
        }
    }
    ElseIf ($Setting1.Value -in $SettingValue -and $Setting1.Type -eq $RegistryType) {
        # Setting is configured
        $CompliantSetting.Value = $Setting1Value
        $CompliantSetting.Type = $Setting1.Type
    }
    Else {
        # Setting is not configured
        $Compliant = $false
    }

    Switch ($Compliant) {
        $true {
            $Status = "NotAFinding"
        }
        $false {
            $Status = "Open"
        }
    }

    $FindingDetails += "$ProfileName is $ProfileEnabled" | Out-String
    $FindingDetails += "" | Out-String
    If ($CompliantSetting.Value) {
        $FindingDetails += "Compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($CompliantSetting.Value)" | Out-String
        $FindingDetails += "Type:`t`t$($CompliantSetting.Type)" | Out-String
    }
    Else {
        $FindingDetails += "No compliant setting found:" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath1" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting1Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting1.Type)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath2" | Out-String
        $FindingDetails += "Value Name:`t$SettingValueName" | Out-String
        $FindingDetails += "Value:`t`t$($Setting2Value)" | Out-String
        $FindingDetails += "Type:`t`t$($Setting2.Type)" | Out-String
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

Function Get-V242009 {
    <#
    .DESCRIPTION
        Vuln ID    : V-242009
        STIG ID    : WNFWA-000100
        Rule ID    : SV-242009r922967_rule
        CCI ID     : CCI-000067
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Inbound exceptions to the firewall on domain workstations must only allow authorized remote management hosts.
        DiscussMD5 : 3BC4674C024C4F71C1D5F33E175C22E3
        CheckMD5   : 36940C7CC32E94F37900BBFE291F90AB
        FixMD5     : B9D1B968178A95A3F915E7425528A0F2
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
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
    $DomainRole = (Get-CimInstance Win32_ComputerSystem).DomainRole
    If ($DomainRole -in @(0, 2, 3, 4, 5)) {
        $Status = "Not_Applicable"
        Switch ($DomainRole) {
            "0" {
                $RoleText = "Standalone Workstation"
            }
            "2" {
                $RoleText = "Standalone Server"
            }
            "3" {
                $RoleText = "Member Server"
            }
            "4" {
                $RoleText = "Backup Domain Controller"
            }
            "5" {
                $RoleText = "Primary Domain Controller"
            }
        }
        $FindingDetails += "System is a $RoleText so this requirement is NA." | Out-String
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBOnum300iHpQ23
# GWRy7j16Pdx9evXIKpeIcV8mwksx8qCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCMAPxdmvHHPzF68aOqbAEaWLKovhjw
# 4Wmy91mx0tKvizANBgkqhkiG9w0BAQEFAASCAQCrJylEWaoigmavYgussDhXAvBW
# 72/NVc2lJWE20sCxOY/vcxUgawOgf8EiRXzj2myr5hgWIYyYMPooPxIa8d8ZcnsR
# q2DHZGEKN8W4/UMYHhE5zL0ytrvy7fBMWrBzudiD/iYbOe7ZdWtvwH25aqvehVd6
# LO7XVCsooVWzjdTJXfM8zD9MoYLqsufnK5qSx4TXK24KlaLHzINpgP+gJdIE7t4H
# keXzUkwxz5y/V8D4eIU0HtELPtBbUAEfUgwYfwtmUyewcWtYzQdpxaLQPSuH3sSy
# /Z3BemF2k1B5/ihNFUJDo8GcQKr2a5XcDW/yh1e10ESRkwLSJRHBITRuPCwt
# SIG # End signature block
