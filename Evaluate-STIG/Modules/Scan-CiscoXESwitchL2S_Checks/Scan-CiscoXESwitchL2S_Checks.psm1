##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Cisco IOS XE Switch L2S
# Version:  V2R5
# Class:    UNCLASSIFIED
# Updated:  5/13/2024
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V220649 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220649
        STIG ID    : CISC-L2-000020
        Rule ID    : SV-220649r863283_rule
        CCI ID     : CCI-000778, CCI-001958
        Rule Name  : SRG-NET-000148-L2S-000015
        Rule Title : The Cisco switch must uniquely identify and authenticate all network-connected endpoint devices before establishing any connection.
        DiscussMD5 : F8510CA83F388038C74BF5CBCCB63E0C
        CheckMD5   : DDB343463008CCC67D5D81DD5FCC03B9
        FixMD5     : B01C9E2DE307BE04E7EA44A232AF1EF3
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
    $OpenFinding = $False
    $CompliantInt = @()
    $NonCompliantInt = @()
    $ActiveAccessSwitchPorts = @()
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*" -AND $_ -notlike "*AppGigabitEthernet*"}
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "shutdown") -AND ($InterfaceConfig -contains "switchport mode access")) {
            $ActiveAccessSwitchPorts += $Interface
        }
    }

    IF ($ActiveAccessSwitchPorts) {
        #This section checks Step 2 of STIG check
        $Radius = $ShowRunningConfig | Select-String -Pattern "^aaa group server radius .*"
        $FindingDetails += "Radius Server Group" | Out-String
        $FindingDetails += "--------------------------" | Out-String
        IF ($Radius) {
            $RadiusServer = ($Radius | Out-String).Trim().Split([char[]]"")[4]
        }
        Else {
            $OpenFinding = $True
            $RadiusServer = "Not Configured"
        }
        $FindingDetails += "$RadiusServer" | Out-String
        $FindingDetails += "" | Out-String

        $dot1xAuthentication = $ShowRunningConfig | Select-String -Pattern "^aaa authentication dot1x default group"
        IF ($dot1xAuthentication) {
            $dot1xAuthenticationServer = ($dot1xAuthentication | Out-String).Trim().Split([char[]]"")[5]
        }
        Else {
            $OpenFinding = $True
            $dot1xAuthenticationServer = "Not Configured"
        }
        $FindingDetails += "802.1x default group" | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += "$dot1xAuthenticationServer" | Out-String
        $FindingDetails += "" | Out-String

        $dot1xSysAuthCtrl = $ShowRunningConfig | Select-String -Pattern "^dot1x system-auth-control"
        IF (!$dot1xSysAuthCtrl) {
            $OpenFinding = $True
            $dot1xSysAuthCtrl = "Not Configured"
        }
        $FindingDetails += "dot1x system-auth-control" | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += "$dot1xSysAuthCtrl" | Out-String
        $FindingDetails += "" | Out-String

        IF (!($RadiusServer -eq $dot1xAuthenticationServer)) {
            $OpenFinding = $True
        }

        #This section checks Step 1
        ForEach ($Interface in $ActiveAccessSwitchPorts) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF ($InterfaceConfig -contains "dot1x pae authenticator" -or $InterfaceConfig -like "mab*" -AND ($InterfaceConfig | Where-Object {$_ -like "authentication host-mode*"} | Out-String).Trim().Split([char[]]"")[2] -ne "multi-host") {
                $CompliantInt += ($Interface | Out-String).Trim()
                IF ($InterfaceConfig -like "description*") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -like "mab*") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "mab*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -contains "switchport mode access") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport mode access"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -like "switchport access vlan*") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport access vlan*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -contains "dot1x pae authenticator") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "dot1x pae authenticator"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -like "authentication port-control*") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "authentication port-control*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -like "authentication host-mode*") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "authentication host-mode*"} | Out-String).Trim()
                }
                $CompliantInt += " "
            }
            Else {
                $OpenFinding = $True
                $NonCompliantInt += ($Interface | Out-String).Trim()
                IF ($InterfaceConfig -like "description*") {
                    $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -like "mab*") {
                    $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "mab*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -contains "switchport mode access") {
                    $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport mode access"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -like "switchport access vlan*") {
                    $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport access vlan*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -contains "dot1x pae authenticator") {
                    $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "dot1x pae authenticator"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -like "authentication port-control*") {
                    $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "authentication port-control*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -like "authentication host-mode*") {
                    $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "authentication host-mode*"} | Out-String).Trim()
                }
                $NonCompliantInt += ""
            }
        }

        IF ($CompliantInt) {
            $FindingDetails += "Compliant Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $CompliantInt | Out-String
            $FindingDetails += "" | Out-String
        }

        IF ($NonCompliantInt) {
            $FindingDetails += "Review switch configuration below." | Out-String
            $FindingDetails += "If 802.1x authentication or MAB is not configured on all access switch ports connecting to LAN outlets or devices not located in the telecom room, wiring closets, or equipment rooms, this is a finding." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Non-Compliant Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $NonCompliantInt | Out-String
            $FindingDetails += "" | Out-String
        }

        IF (!($OpenFinding)) {
            $Status = "NotAFinding"
        }
        Elseif ($OpenFinding) {
            $Status = "Open"
        }
    }
    Else {
        $FindingDetails += "There are no active access switchports configured on this switch" | Out-String
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

Function Get-V220655 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220655
        STIG ID    : CISC-L2-000090
        Rule ID    : SV-220655r917683_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-L2S-000021
        Rule Title : The Cisco switch must have Root Guard enabled on all switch ports connecting to access layer switches.
        DiscussMD5 : 919F25DECAC50CC844E5F32293AA2CD3
        CheckMD5   : 2BFB928840AC292F87F3B9665DE1936C
        FixMD5     : CFA2817C5768CA96D97F3F81DC7A17BB
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
    $OpenFinding = $False
    $CompliantInt = @()
    $NonCompliantInt = @()
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "shutdown") -AND $InterfaceConfig -like "switchport*") {
            IF ($InterfaceConfig -contains "spanning-tree guard root") {
                $CompliantInt += ($Interface | Out-String).Trim()
                IF ($InterfaceConfig -like "description*") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -like "switchport*") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -contains "spanning-tree guard root") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "spanning-tree guard root"} | Out-String).Trim()
                }
                $CompliantInt += " "
            }
            Else {
                $OpenFinding = $True
                $NonCompliantInt += ($Interface | Out-String).Trim()
                $NonCompliantInt += ($InterfaceConfig | Out-String).Trim()
                $NonCompliantInt += "spanning-tree guard root is not configured"
                $NonCompliantInt += ""
            }
        }
    }

    IF ($CompliantInt) {
        $FindingDetails += "Compliant Interfaces" | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $CompliantInt | Out-String
        $FindingDetails += "" | Out-String
    }

    IF ($NonCompliantInt) {
        $FindingDetails += "Review the switch topology as well as the switch configuration below to verify that Root Guard is enabled on all switch ports connecting to access layer switches." | Out-String
        $FindingDetails += "Interfaces without spanning-tree guard root configured" | Out-String
        $FindingDetails += "-------------------------------------------------------" | Out-String
        $FindingDetails += $NonCompliantInt | Out-String
        $FindingDetails += "" | Out-String
    }

    IF (!$OpenFinding) {
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

Function Get-V220656 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220656
        STIG ID    : CISC-L2-000100
        Rule ID    : SV-220656r856278_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-L2S-000022
        Rule Title : The Cisco switch must have BPDU Guard enabled on all user-facing or untrusted access switch ports.
        DiscussMD5 : 94230130CD0AE05E3249EC678D069733
        CheckMD5   : 66D0BC7EF09FB7A6742A5154DAEEBC0D
        FixMD5     : 3043178CCBE2ACDC6E2F469DF0D05BC0
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
    $OpenFinding = $False
    $CompliantInt = @()
    $NonCompliantInt = @()
    $ActiveAccessSwitchPorts = @()
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "shutdown") -AND $InterfaceConfig -match "switchport (mode)?\s?access") {
            $ActiveAccessSwitchPorts += $Interface
        }
    }

    IF ($ActiveAccessSwitchPorts) {
        ForEach ($Interface in $ActiveAccessSwitchPorts) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF ($InterfaceConfig -contains "spanning-tree bpduguard enable") {
                $CompliantInt += ($Interface | Out-String).Trim()
                IF ($InterfaceConfig -like "description*") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -contains "spanning-tree bpduguard enable") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "spanning-tree bpduguard enable"} | Out-String).Trim()
                }
                $CompliantInt += " "
            }
            Else {
                $OpenFinding = $True
                $NonCompliantInt += ($Interface | Out-String).Trim()
                $NonCompliantInt += ($InterfaceConfig | Out-String).Trim()
                $NonCompliantInt += "spanning-tree bpduguard enable is not configured"
                $NonCompliantInt += ""
            }
        }

        IF ($CompliantInt) {
            $FindingDetails += "Compliant Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $CompliantInt | Out-String
            $FindingDetails += "" | Out-String
        }

        IF ($NonCompliantInt) {
            $FindingDetails += "Review the switch configuration to verify that BPDU Guard is enabled on all user-facing or untrusted access switch ports:" | Out-String
            $FindingDetails += "Interfaces without BDPU guard enabled" | Out-String
            $FindingDetails += "-------------------------------------------" | Out-String
            $FindingDetails += $NonCompliantInt | Out-String
            $FindingDetails += "" | Out-String
        }

        IF (!($OpenFinding)) {
            $Status = "NotAFinding"
        }
    }
    Else {
        $FindingDetails += "There are no active access switchports configured on this switch" | Out-String
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

Function Get-V220657 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220657
        STIG ID    : CISC-L2-000110
        Rule ID    : SV-220657r856279_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-L2S-000023
        Rule Title : The Cisco switch must have STP Loop Guard enabled.
        DiscussMD5 : EEFE508FFEDFDF8955D91E4127265557
        CheckMD5   : 1FA851858FFE7C4A7DF77097657DC7BB
        FixMD5     : 3EE4773F0F7238F3BFDF4857EC0D2289
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
    $LoopGuard = $ShowRunningConfig | Select-String -Pattern "^spanning-tree loopguard default"
    $FindingDetails += "Spanning-tree loopguard" | Out-String
    $FindingDetails += "-----------------------------" | Out-String
    IF ($LoopGuard) {
        $FindingDetails += ($LoopGuard | Out-String).Trim()
        $Status = "NotAFinding"
    }
    Else {
        $FindingDetails += "spanning-tree loopguard not enabled" | Out-String
        $Status = "Open"
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

Function Get-V220658 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220658
        STIG ID    : CISC-L2-000120
        Rule ID    : SV-220658r856280_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-L2S-000024
        Rule Title : The Cisco switch must have Unknown Unicast Flood Blocking (UUFB) enabled.
        DiscussMD5 : 5AF49A78E3E971FF676BF9515E287A64
        CheckMD5   : BA90B6897D05E3562F404AC62DAD74BF
        FixMD5     : 38B6FB7665948A84EED2EA954824003B
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
    $OpenFinding = $False
    $CompliantInt = @()
    $NonCompliantInt = @()
    $ActiveAccessSwitchPorts = @()
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "shutdown") -AND $InterfaceConfig -match "switchport (mode)?\s?access") {
            $ActiveAccessSwitchPorts += $Interface
        }
    }

    IF ($ActiveAccessSwitchPorts) {
        ForEach ($Interface in $ActiveAccessSwitchPorts) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF ($InterfaceConfig -contains "switchport block unicast") {
                $CompliantInt += ($Interface | Out-String).Trim()
                IF ($InterfaceConfig -like "description*") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                }
                IF ($InterfaceConfig -contains "switchport block unicast") {
                    $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport block unicast"} | Out-String).Trim()
                }
                $CompliantInt += " "
            }
            Else {
                $OpenFinding = $True
                $NonCompliantInt += ($Interface | Out-String).Trim()
                $NonCompliantInt += ($InterfaceConfig | Out-String).Trim()
                $NonCompliantInt += "switchport block unicast is not configured"
                $NonCompliantInt += ""
            }
        }

        IF ($CompliantInt) {
            $FindingDetails += "Compliant Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $CompliantInt | Out-String
            $FindingDetails += "" | Out-String
        }

        IF ($NonCompliantInt) {
            $FindingDetails += "Non-Compliant Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $NonCompliantInt | Out-String
            $FindingDetails += "" | Out-String
        }

        IF ($OpenFinding) {
            $Status = "Open"
        }
        Else {
            $Status = "NotAFinding"
        }
    }
    Else {
        $FindingDetails += "There are no active access switchports configured on this switch" | Out-String
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

Function Get-V220659 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220659
        STIG ID    : CISC-L2-000130
        Rule ID    : SV-220659r928999_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-L2S-000025
        Rule Title : The Cisco switch must have DHCP snooping for all user VLANs to validate DHCP messages from untrusted sources.
        DiscussMD5 : 52AD90E48CDE65A4672D118864101A67
        CheckMD5   : 686D38193215026556C1898AD3D4B233
        FixMD5     : F5DA9C7FA27C75DDC0AEA3520FC5F716
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
    $ActiveAccessSwitchPorts = @() # Inventory of active switch ports
    $ActiveVLANs = @() # Inventory of VLANs assigned to active switchports
    $SnoopingVLANS = @() # Inventory of VLANs covered by DHCP snooping
    $ActiveNoSnooping = @() # Inventory of active VLANs without DHCP snooping enabled

    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*" -AND $_ -notlike "*AppGigabitEthernet*"}
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        If (-Not($InterfaceConfig -contains "shutdown") -AND ($InterfaceConfig -contains "switchport mode access")) {
            # Add active interface to inventory
            $ActiveAccessSwitchPorts += $Interface
            If ($InterfaceConfig -like "switchport access vlan*") {
                $AccessVLAN = ($InterfaceConfig -like "switchport access vlan*" | Out-String).Trim().Split([char[]]"")[3]
                If ($AccessVLAN -notin $ActiveVLANs) {
                    # Add active VLAN to inventory
                    $ActiveVLANs += [int]$AccessVLAN
                }
            }
            Else {
                If ("1" -notin $ActiveVLANs) {
                    # Add default VLAN to inventory
                    $ActiveVLANs += [int]1
                }
            }
        }
    }

    $Compliant = $true
    If ($ActiveAccessSwitchPorts) {
        $DHCPSnoopingLine = ($ShowRunningConfig | Select-String -Pattern "^ip dhcp snooping`$" | Out-String).Trim()
        If ($DHCPSnoopingLine) {
            $FindingDetails += "Found:`t`t`t`t`t'$($DHCPSnoopingLine)'" | Out-String
            $DHCPSnoopingVLANLine = ($ShowRunningConfig | Select-String -Pattern "^ip dhcp snooping vlan .*" | Out-String).Trim()
            $DHCPSnoopingVLANs = ($DHCPSnoopingVLANLine).Split([char[]]"").Split(",") | Select-Object -Skip 4
            If ($DHCPSnoopingVLANs) {
                $FindingDetails += "Found:`t`t`t`t`t'$($DHCPSnoopingVLANLine)'" | Out-String
                # Get list of VLANs with DHCP Snooping
                ForEach ($Vlan in $DHCPSnoopingVLANs) {
                    If ($Vlan -like "*-*") {
                        $DashIndex = $Vlan.IndexOf("-")
                        $StartInt = $Vlan.Substring(0, $DashIndex)
                        $EndInt = $Vlan.Substring($DashIndex + 1)
                        $SnoopingVLANS += [int]$StartInt..[int]$EndInt
                    }
                    Else {
                        $SnoopingVLANS += [int]$Vlan
                    }
                }
                # Check each active VLAN against VLANs with DHCP Snooping
                ForEach ($ActiveVLAN in $ActiveVLANs) {
                    If ($ActiveVLAN -notin $SnoopingVLANS) {
                        $Compliant = $false
                        $ActiveNoSnooping += [int]$ActiveVLAN
                    }
                }
                $FindingDetails += "Active Access VLANs in use:`t$(($ActiveVLANs | Select-Object -Unique | Sort-Object) -join ', ')" | Out-String
                $FindingDetails += "DHCP Snooping VLANs:`t`t$(($SnoopingVLANS | Select-Object -Unique | Sort-Object) -join ', ')" | Out-String
                If ($ActiveNoSnooping) {
                    $Compliant = $false
                    $VLANsToVerify = [int]$ActiveNoSnooping
                }
            }
            Else {
                $Compliant = $false
                $VLANsToVerify = $ActiveVLANs
                $FindingDetails += "NOT Found:`t`t`t`t'ip dhcp snooping vlan <user-vlans>'" | Out-String
            }
        }
        Else {
            $Compliant = $false
            $VLANsToVerify = $ActiveVLANs
            $FindingDetails += "NOT Found:`t`t`t`t'ip dhcp snooping'" | Out-String
        }

        If ($Compliant -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "" | Out-String
            $FindingDetails += "All active access VLANs have DHCP Snooping enabled." | Out-String
        }
        Else {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Verify if any of the below are user VLANs and make finding determinitation based on STIG check guidance:" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "VLANs without Snooping:`t$(($VLANsToVerify | Select-Object -Unique | Sort-Object) -join ', ')" | Out-String
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "There are no active access switchports configured on this switch" | Out-String
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

Function Get-V220660 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220660
        STIG ID    : CISC-L2-000140
        Rule ID    : SV-220660r929001_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-L2S-000026
        Rule Title : The Cisco switch must have IP Source Guard enabled on all user-facing or untrusted access switch ports.
        DiscussMD5 : 355BEC1413E67C2234943A0C25DBF547
        CheckMD5   : 75ABABCC10D5354B107F20485240BCA9
        FixMD5     : ECD33A14A8CE655D0565017250543FA8
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
    $ActiveAccessSwitchPorts = @() # Inventory of active switch ports
    $BadSwitchPorts = [System.Collections.Generic.List[System.Object]]::new() # Inventory of non-compliant switch ports

    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*" -AND $_ -notlike "*AppGigabitEthernet*"}
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        If (-Not($InterfaceConfig -contains "shutdown") -AND ($InterfaceConfig -contains "switchport mode access")) {
            # Add active interface to inventory
            $ActiveAccessSwitchPorts += $Interface
            If (-Not($InterfaceConfig | Where-Object {$_ -like "ip verify source"})) {
                # Add non-compliant interface to inventory
                $NewObj = [PSCustomObject]@{
                    Interface   = ($Interface | Out-String).Trim()
                    Description = ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                    Vlan        = ($InterfaceConfig -like "switchport access vlan*" | Out-String).Trim()
                    Mode        = ($InterfaceConfig -like "switchport mode access*" | Out-String).Trim()
                }
                $BadSwitchPorts.Add($NewObj)
            }
        }
    }

    $Compliant = $true
    If ($ActiveAccessSwitchPorts) {
        If ($BadSwitchPorts) {
            $Compliant = $false
            $FindingDetails += "The below active interfaces do not have 'ip verify source' configured.  Verify if any are user-facing or untrusted and make finding determinitation based on STIG check guidance:" | Out-String
            ForEach ($Item in $BadSwitchPorts) {
                $FindingDetails += "" | Out-String
                $FindingDetails += $Item.Interface | Out-String
                If ($Item.Description) {
                    $FindingDetails += " $($Item.Description)" | Out-String
                }
                If ($Item.Vlan) {
                    $FindingDetails += " $($Item.Vlan)" | Out-String
                }
                If ($Item.Mode) {
                    $FindingDetails += " $($Item.Mode)" | Out-String
                }
            }
        }
        Else {
            $FindingDetails += "All active interfaces have 'ip verify source'." | Out-String
        }
    }
    Else {
        $FindingDetails += "There are no active access switchports configured on this switch" | Out-String
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

Function Get-V220661 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220661
        STIG ID    : CISC-L2-000150
        Rule ID    : SV-220661r929003_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-NET-000362-L2S-000027
        Rule Title : The Cisco switch must have Dynamic Address Resolution Protocol (ARP) Inspection (DAI) enabled on all user VLANs.
        DiscussMD5 : ADCCF2024DB567605E03B203F42CC4F7
        CheckMD5   : 733A12EBC16F3F5DD5FB9137BDB1BE9E
        FixMD5     : 2FAAC2499CE2CF9CC522D2033FABDB89
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
    $ActiveAccessSwitchPorts = @() # Inventory of active switch ports
    $ActiveVLANs = @() # Inventory of VLANs assigned to active switchports
    $SnoopingVLANS = @() # Inventory of VLANs covered by DHCP snooping
    $ArpInspectVLANS = @() # Inventory of VLANs covered by ARP inspection
    $ActiveNoArpInspect = @() # Inventory of active VLANs without ARP inspection enabled
    $ArpInspectNoSnoop = @() # Inventory of ARP inspect VLANs not in DHCP snooping
    $CiscoCmdFound = "" # Cisco commands per STIG

    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*" -AND $_ -notlike "*AppGigabitEthernet*"}
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        If (-Not($InterfaceConfig -contains "shutdown") -AND ($InterfaceConfig -contains "switchport mode access")) {
            # Add active interface to inventory
            $ActiveAccessSwitchPorts += $Interface
            If ($InterfaceConfig -like "switchport access vlan*") {
                $AccessVLAN = ($InterfaceConfig -like "switchport access vlan*" | Out-String).Trim().Split([char[]]"")[3]
                If ($AccessVLAN -notin $ActiveVLANs) {
                    # Add active VLAN to inventory
                    $ActiveVLANs += [int]$AccessVLAN
                }
            }
            Else {
                If ("1" -notin $ActiveVLANs) {
                    # Add default VLAN to inventory
                    $ActiveVLANs += [int]1
                }
            }
        }
    }

    $Compliant = $true
    If ($ActiveAccessSwitchPorts) {
        $DHCPSnoopingLine = ($ShowRunningConfig | Select-String -Pattern "^ip dhcp snooping`$" | Out-String).Trim()
        If ($DHCPSnoopingLine) {
            $CiscoCmdFound += "Found:`t`t`t`t`t'$($DHCPSnoopingLine)'" | Out-String
            $DHCPSnoopingVLANLine = ($ShowRunningConfig | Select-String -Pattern "^ip dhcp snooping vlan .*" | Out-String).Trim()
            $DHCPSnoopingVLANs = ($DHCPSnoopingVLANLine).Split([char[]]"").Split(",") | Select-Object -Skip 4
            If ($DHCPSnoopingVLANs) {
                $CiscoCmdFound += "Found:`t`t`t`t`t'$($DHCPSnoopingVLANLine)'" | Out-String
                # Get list of VLANs with DHCP Snooping
                ForEach ($Vlan in $DHCPSnoopingVLANs) {
                    If ($Vlan -like "*-*") {
                        $DashIndex = $Vlan.IndexOf("-")
                        $StartInt = $Vlan.Substring(0, $DashIndex)
                        $EndInt = $Vlan.Substring($DashIndex + 1)
                        $SnoopingVLANS += [int]$StartInt..[int]$EndInt
                    }
                    Else {
                        $SnoopingVLANS += [int]$Vlan
                    }
                }
            }
            Else {
                $Compliant = $false
                $CiscoCmdFound += "NOT Found:`t`t`t`t'ip dhcp snooping vlan <user-vlans>'" | Out-String
            }
        }
        Else {
            $Compliant = $false
            $CiscoCmdFound += "NOT Found:`t`t`t`t'ip dhcp snooping'" | Out-String
        }

        $ARPInspectionLine = ($ShowRunningConfig | Select-String -Pattern "^ip arp inspection vlan" | Out-String).Trim()
        If ($ARPInspectionLine) {
            $CiscoCmdFound += "Found:`t`t`t`t`t'$($ARPInspectionLine)'" | Out-String
            $ARPInspectionVLANs = ($ARPInspectionLine).Split([char[]]"").Split(",") | Select-Object -Skip 4
            If ($ARPInspectionVLANs) {
                # Get list of VLANs with DHCP Snooping
                ForEach ($Vlan in $ARPInspectionVLANs) {
                    If ($Vlan -like "*-*") {
                        $DashIndex = $Vlan.IndexOf("-")
                        $StartInt = $Vlan.Substring(0, $DashIndex)
                        $EndInt = $Vlan.Substring($DashIndex + 1)
                        $ArpInspectVLANS += [int]$StartInt..[int]$EndInt
                    }
                    Else {
                        $ArpInspectVLANS += [int]$Vlan
                    }
                }
                # Check each ARP inspection VLAN against VLANs with DHCP snooping
                ForEach ($ArpVlan in $ArpInspectVLANS) {
                    If ($ArpVlan -notin $SnoopingVLANS) {
                        $Compliant = $false
                        $ArpInspectNoSnoop += [int]$ArpVlan
                    }
                }
                If ($ArpInspectNoSnoop) {
                    $Compliant = $false
                }

                # Check each active VLAN against VLANs with ARP inspection
                ForEach ($ActiveVLAN in $ActiveVLANs) {
                    If ($ActiveVLAN -notin $ArpInspectVLANS) {
                        $Compliant = $false
                        $ActiveNoArpInspect += [int]$ActiveVLAN
                    }
                }
                If ($ActiveNoArpInspect) {
                    $Compliant = $false
                }
            }
            Else {
                $Compliant = $false
                $ActiveNoArpInspect = $ActiveVLANs
                $CiscoCmdFound += "NOT Found:`t`t`t`t'ip arp inspection vlan <user-vlans>'" | Out-String
            }
        }
        Else {
            $Compliant = $false
            $ActiveNoArpInspect = $ActiveVLANs
            $CiscoCmdFound += "NOT Found:`t`t`t`t'ip arp inspection vlan <user-vlans>'" | Out-String
        }

        $FindingDetails += $CiscoCmdFound
        If ($Compliant -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "Active Access VLANs in use:`t$(($ActiveVLANs | Select-Object -Unique | Sort-Object) -join ', ')" | Out-String
            $FindingDetails += "DHCP Snooping VLANs:`t`t$(($SnoopingVLANS | Select-Object -Unique | Sort-Object) -join ', ')" | Out-String
            $FindingDetails += "ARP Inspection VLANs:`t`t$(($ArpInspectVLANS | Select-Object -Unique | Sort-Object) -join ', ')" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "All active access VLANs have DAI enabled." | Out-String
        }
        Else {
            $FindingDetails += "Active Access VLANs in use:`t$(($ActiveVLANs | Select-Object -Unique | Sort-Object) -join ', ')" | Out-String
            $FindingDetails += "DHCP Snooping VLANs:`t`t$(($SnoopingVLANS | Select-Object -Unique | Sort-Object) -join ', ')" | Out-String
            $FindingDetails += "ARP Inspection VLANs:`t`t$(($ArpInspectVLANS | Select-Object -Unique | Sort-Object) -join ', ')" | Out-String
            If ($ArpInspectNoSnoop) {
                $Status = "Open"
                $FindingDetails += "" | Out-String
                $FindingDetails += "The following VLANs have DAI configured but not DHCP snooping which is a dependency [finding]:" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "DAI without Snooping:`t$(($ArpInspectNoSnoop | Select-Object -Unique | Sort-Object) -join ', ')" | Out-String
            }
            If ($ActiveNoArpInspect) {
                $FindingDetails += "" | Out-String
                $FindingDetails += "Verify if any of the below are user VLANs and make finding determinitation based on STIG check guidance:" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "VLANs without DAI:`t$(($ActiveNoArpInspect | Select-Object -Unique | Sort-Object) -join ', ')" | Out-String
            }
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "There are no active access switchports configured on this switch" | Out-String
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

Function Get-V220662 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220662
        STIG ID    : CISC-L2-000160
        Rule ID    : SV-220662r648766_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000001
        Rule Title : The Cisco switch must have Storm Control configured on all host-facing switchports.
        DiscussMD5 : 08F946B5EDD028D508AF047F74E132CA
        CheckMD5   : 62DD8E608E587959AFF8BA237046833E
        FixMD5     : F140B20E1D21E60A9359652A9A203DE3
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
    $OpenFinding = $False
    $CompliantInt = @()
    $NonCompliantInt = @()
    $GigabitRange = 10..1000 #<----------------------Range is in Megabits
    $TenGigabitRange = 10..10000 #<----------------------Range is in Megabits

    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}

    ForEach ($Interface in $Interfaces) {
        IF ($Interface -like "*Gigabit*" -or $Interface -like "*tengigabitethernet") {
            IF ($Interface -like "*Gigabit*") {
                $Range = $GigabitRange
            }
            Else {
                $Range = $TenGigabitRange
            }
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF (!($InterfaceConfig -contains "shutdown")) {
                IF ($InterfaceConfig -like "storm-control unicast level bps*" -and $InterfaceConfig -like "storm-control broadcast level bps*") {
                    $StormCtrlUnicast = ($InterfaceConfig | Where-Object {$_ -like "storm-control unicast level bps*"} | Out-String).Trim().Split([char[]]"")[4]
                    $StormCtrlbroadcast = ($InterfaceConfig | Where-Object {$_ -like "storm-control broadcast level bps*"} | Out-String).Trim().Split([char[]]"")[4]

                    IF ($StormCtrlUnicast -is [INT]) {
                        $StormCtrlUnicast = $StormCtrlUnicast / 1000000
                    }
                    IF ($StormCtrlUnicast -like "*k") {
                        $StormCtrlUnicast = $StormCtrlUnicast.Replace("k", "") / 1000
                    }
                    IF ($StormCtrlUnicast -like "*m") {
                        $StormCtrlUnicast = $StormCtrlUnicast.Replace("m", "")
                    }
                    IF ($StormCtrlUnicast -like "*g") {
                        $StormCtrlUnicast = [DOUBLE]$StormCtrlUnicast.Replace("g", "") * 1000
                    }

                    IF ($StormCtrlbroadcast -is [INT]) {
                        $StormCtrlbroadcast = $StormCtrlbroadcast / 1000000
                    }
                    IF ($StormCtrlbroadcast -like "*k") {
                        $StormCtrlbroadcast = $StormCtrlbroadcast.Replace("k", "") / 1000
                    }
                    IF ($StormCtrlbroadcast -like "*m") {
                        $StormCtrlbroadcast = $StormCtrlbroadcast.Replace("m", "")
                    }
                    IF ($StormCtrlbroadcast -like "*g") {
                        $StormCtrlbroadcast = [DOUBLE]$StormCtrlbroadcast.Replace("g", "") * 1000
                    }

                    IF ($StormCtrlUnicast -in $Range) {
                        $CompliantInt += ($Interface | Out-String).Trim()
                        IF ($InterfaceConfig -like "description*") {
                            $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                        }
                        $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "storm-control unicast level bps*"} | Out-String).Trim()
                        $CompliantInt += ""
                    }
                    Else {
                        $OpenFinding = $True
                        $NonCompliantInt += ($Interface | Out-String).Trim()
                        IF ($InterfaceConfig -like "description*") {
                            $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                        }
                        $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "storm-control unicast level bps*"} | Out-String).Trim() + " - NON-COMPLIANT"
                        $NonCompliantInt += ""
                    }

                    IF ($StormCtrlbroadcast -in $Range) {
                        $CompliantInt += ($Interface | Out-String).Trim()
                        IF ($InterfaceConfig -like "description*") {
                            $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                        }
                        $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "storm-control broadcast level bps*"} | Out-String).Trim()
                        $FindingDetails += "" | Out-String
                        $CompliantInt += ""
                    }
                    Else {
                        $OpenFinding = $True
                        $NonCompliantInt += ($Interface | Out-String).Trim()
                        IF ($InterfaceConfig -like "description*") {
                            $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                        }
                        $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "storm-control broadcast level bps*"} | Out-String).Trim() + " - NON-COMPLIANT"
                        $NonCompliantInt += ""
                    }
                }
                Else {
                    $OpenFinding = $True
                    $NonCompliantInt += ($Interface | Out-String).Trim()
                    IF ($InterfaceConfig -like "description*") {
                        $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                    }
                    $StormCtrlUnicast = ($InterfaceConfig | Where-Object {$_ -like "storm-control unicast level bps*"} | Out-String).Trim().Split([char[]]"")[4]
                    $StormCtrlbroadcast = ($InterfaceConfig | Where-Object {$_ -like "storm-control broadcast level bps*"} | Out-String).Trim().Split([char[]]"")[4]

                    IF ($StormCtrlUnicast) {
                        IF ($StormCtrlUnicast -eq "62000000" -or $StormCtrlUnicast -eq "62000k" -or $StormCtrlUnicast -eq "62m" -or $StormCtrlUnicast -eq "0.062g") {
                            $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "storm-control unicast level bps*"} | Out-String).Trim()
                        }
                        Else {
                            $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "storm-control unicast level bps*"} | Out-String).Trim() + " - NON-COMPLIANT"
                        }
                    }
                    Else {
                        $NonCompliantInt += "storm-control unicast level NOT CONFIGURED"
                    }

                    IF ($StormCtrlbroadcast) {
                        IF ($StormCtrlbroadcast -eq "20000000" -or $StormCtrlbroadcast -eq "20000k" -or $StormCtrlbroadcast -eq "20m" -or $StormCtrlbroadcast -eq "0.02g") {
                            $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "storm-control broadcast level bps*"} | Out-String).Trim()
                            $NonCompliantInt += ""
                        }
                        Else {
                            $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "storm-control broadcast level bps*"} | Out-String).Trim() + " - NON-COMPLIANT"
                            $NonCompliantInt += ""
                        }
                    }
                    Else {
                        $NonCompliantInt += "storm-control broadcast level NOT CONFIGURED"
                        $NonCompliantInt += ""
                    }
                }
            }
        }
        Else {
            $OpenFinding = $True
            $NonCompliantInt += ($Interface | Out-String).Trim()
            IF ($InterfaceConfig -like "description*") {
                $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
            }
            $NonCompliantInt += "Interface is not supported"
            $NonCompliantInt += ""
        }
    }

    IF ($CompliantInt) {
        $FindingDetails += "Compliant Interfaces" | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $CompliantInt -join "`n" | Out-String
        $FindingDetails += "" | Out-String
    }

    IF ($NonCompliantInt) {
        $FindingDetails += "Review the switch configuration below and verify that interfaces are not host facing, make finding determinitation based on STIG check guidance:" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Interfaces" | Out-String
        $FindingDetails += "---------------" | Out-String
        $FindingDetails += $NonCompliantInt -join "`n" | Out-String
    }

    IF (!($OpenFinding)) {
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

Function Get-V220663 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220663
        STIG ID    : CISC-L2-000170
        Rule ID    : SV-220663r929005_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000002
        Rule Title : The Cisco switch must have IGMP or MLD Snooping configured on all VLANs.
        DiscussMD5 : 12C9D548B2EC855884201C0650FF9D12
        CheckMD5   : 4E9F5CD5F98E951B5D07A1C0015E5C17
        FixMD5     : CB857F07BD0E760BDE2A85091FAE00AE
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
    $ActiveAccessSwitchPorts = @() # Inventory of active switch ports
    $ActiveVLANs = @() # Inventory of VLANs assigned to active switchports
    $CiscoCmdFound = "" # Cisco commands per STIG

    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*" -AND $_ -notlike "*AppGigabitEthernet*"}
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        If (-Not($InterfaceConfig -contains "shutdown") -AND ($InterfaceConfig -contains "switchport mode access")) {
            # Add active interface to inventory
            $ActiveAccessSwitchPorts += $Interface
            If ($InterfaceConfig -like "switchport access vlan*") {
                $AccessVLAN = ($InterfaceConfig -like "switchport access vlan*" | Out-String).Trim().Split([char[]]"")[3]
                If ($AccessVLAN -notin $ActiveVLANs) {
                    # Add active VLAN to inventory
                    $ActiveVLANs += [int]$AccessVLAN
                }
            }
            Else {
                If ("1" -notin $ActiveVLANs) {
                    # Add default VLAN to inventory
                    $ActiveVLANs += [int]1
                }
            }
        }
    }

    $Compliant = $true
    $NoIpIgmpSnoopLine = ($ShowRunningConfig | Select-String -Pattern "^no ip igmp snooping`$" | Out-String).Trim()
    If ($NoIpIgmpSnoopLine) {
        $Compliant = $false
        $CiscoCmdFound += "Found:`t`t`t`t`t'$($NoIpIgmpSnoopLine)' [finding]" | Out-String
    }
    Else {
        $CiscoCmdFound += "NOT Found:`t`t`t`t'no ip igmp snooping'" | Out-String
    }

    $NoIpIgmpSnoopVlanLine = ($ShowRunningConfig | Select-String -Pattern "^no ip igmp snooping vlan .*" | Out-String).Trim()
    If ($NoIpIgmpSnoopVlanLine) {
        $Compliant = $false
        $CiscoCmdFound += "Found:`t`t`t`t`t'$($NoIpIgmpSnoopVlanLine)' [finding]" | Out-String
    }
    Else {
        $CiscoCmdFound += "NOT Found:`t`t`t`t'no ip igmp snooping vlan <vlan>'" | Out-String
    }

    $FindingDetails += $CiscoCmdFound
    If ($Compliant -eq $true) {
        $Status = "NotAFinding"
        $FindingDetails += "Active Access VLANs in use:`t$(($ActiveVLANs | Select-Object -Unique | Sort-Object) -join ', ')" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "IGMP snooping is enabled on all VLANs" | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "Active Access VLANs in use:`t$(($ActiveVLANs | Select-Object -Unique | Sort-Object) -join ', ')" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "IGMP snooping is NOT enabled for all VLANs" | Out-String
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

Function Get-V220664 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220664
        STIG ID    : CISC-L2-000180
        Rule ID    : SV-220664r539671_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000003
        Rule Title : The Cisco switch must implement Rapid STP where VLANs span multiple switches with redundant links.
        DiscussMD5 : 1E6A4E97F703C160564E7473275F90CC
        CheckMD5   : 491211EE657C6DB1E5E2A652574F6192
        FixMD5     : B8123D454A8726521B83B298A32E1E0B
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
    $FindingDetails += "Spanning Tree Protocol" | Out-String
    $FindingDetails += "-----------------------" | Out-String
    $SpanningTreeMode = $ShowRunningConfig | Select-String -Pattern "^spanning-tree mode (?:rapid-pvst|mst)"
    IF ($SpanningTreeMode) {
        $FindingDetails += ($SpanningTreeMode | Out-String).Trim()
        $Status = "NotAFinding"
    }
    Else {
        $FindingDetails += "Spanning Tree Protocol not configured" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Review switch configuration to determine if STP is required and make finding determination based on STIG check guidance." | Out-String
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

Function Get-V220665 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220665
        STIG ID    : CISC-L2-000190
        Rule ID    : SV-220665r539671_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000004
        Rule Title : The Cisco switch must enable Unidirectional Link Detection (UDLD) to protect against one-way connections.
        DiscussMD5 : D229039FB1EDE59283095AED5157DDBC
        CheckMD5   : E5EBFB1C441E34FB2EAE3350E10E2621
        FixMD5     : 486CD48786EFF8078D850A6111757A39
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
    $OpenFinding = $False
    $GlobalUDLD = $ShowRunningConfig | Select-String -Pattern "^udld enable"
    IF ($GlobalUDLD) {
        $FindingDetails += "Unidirection Link Detection (UDLD)" | Out-String
        $FindingDetails += "----------------------------------" | Out-String
        $FindingDetails += "$GlobalUDLD" | Out-String
        $Status = "NotAFinding"
    }
    Else {
        $CompliantInt = @()
        $NonCompliantInt = @()
        $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}
        ForEach ($Interface in $Interfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF (!($InterfaceConfig -contains "shutdown")) {
                IF ($InterfaceConfig -like "udld port*") {
                    $CompliantInt += ($Interface | Out-String).Trim()
                    IF ($InterfaceConfig -like "description*") {
                        $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                    }
                    IF ($InterfaceConfig -like "udld port*") {
                        $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "udld port*"} | Out-String).Trim()
                    }
                    $CompliantInt += " "
                }
                Else {
                    $OpenFinding = $True
                    $NonCompliantInt += ($Interface | Out-String).Trim()
                    $NonCompliantInt += ($InterfaceConfig | Out-String).Trim()
                    $NonCompliantInt += " Unidirectional Link Detection is not configured"
                    $NonCompliantInt += ""
                }
            }
        }

        IF ($CompliantInt) {
            $FindingDetails += "Compliant Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $CompliantInt | Out-String
            $FindingDetails += "" | Out-String
        }

        IF ($NonCompliantInt) {
            $FindingDetails += "Review interfaces below and ensure that none of the interfaces have fiber optic interconnections with neighbors; make finding determination based on STIG check guidance." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "UDLD Disabled Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $NonCompliantInt | Out-String
            $FindingDetails += "" | Out-String
        }

        IF (!($OpenFinding)) {
            $Status = "NotAFinding"
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

Function Get-V220666 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220666
        STIG ID    : CISC-L2-000200
        Rule ID    : SV-220666r539671_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000005
        Rule Title : The Cisco switch must have all trunk links enabled statically.
        DiscussMD5 : 11BF6C81F04B646088CDA0E1FA8C1CDB
        CheckMD5   : 09A7B52A41D46E11EED4B2C0E9A33A09
        FixMD5     : 39035E61FFFA04CD741AB6A8B374CF0C
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
    $OpenFinding = $False
    $CompliantInt = @()
    $NonCompliantInt = @()
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}
    $ActiveTrunkSwitchPorts = @()

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "shutdown") -AND $InterfaceConfig -match "switchport mode trunk") {
            $ActiveTrunkSwitchPorts += $Interface
        }
    }

    IF ($ActiveTrunkSwitchPorts) {
        ForEach ($Interface in $ActiveTrunkSwitchPorts) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF ($InterfaceConfig -contains "switchport nonegotiate") {
                $CompliantInt += ($Interface | Out-String).Trim()
                $CompliantInt += " " + ($InterfaceConfig | Select-String -Pattern "^switchport mode trunk" | Out-String).Trim()
                $CompliantInt += " " + ($InterfaceConfig | Select-String -Pattern "^switchport nonegotiate" | Out-String).Trim()
                $CompliantInt += ""
            }
            Else {
                $OpenFinding = $True
                $NonCompliantInt += ($Interface | Out-String).Trim()
                $NonCompliantInt += ($InterfaceConfig | Out-String).Trim()
                $NonCompliantInt += ""
            }
        }

        IF ($CompliantInt) {
            $FindingDetails += "Compliant Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $CompliantInt | Out-String
            $FindingDetails += "" | Out-String
        }

        IF ($NonCompliantInt) {
            $FindingDetails += "Non-Compliant Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $NonCompliantInt | Out-String
            $FindingDetails += "" | Out-String
        }

        IF ($OpenFinding) {
            $Status = "Open"
        }
        Else {
            $Status = "NotAFinding"
        }
    }
    Else {
        $FindingDetails += "There are no active trunk switchports configured on this switch" | Out-String
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

Function Get-V220667 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220667
        STIG ID    : CISC-L2-000210
        Rule ID    : SV-220667r539671_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000007
        Rule Title : The Cisco switch must have all disabled switch ports assigned to an unused VLAN.
        DiscussMD5 : 225620DA2F853DE034CA2A8DB3D8CDAB
        CheckMD5   : 2B1DAF048AA48F82E574669D3D2FFDB8
        FixMD5     : B43F9760182ECCF6A2980FE16084CFAD
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
    $OpenFinding = $False
    $Non8021xInterfaces = @()
    $NAInterfaces = @()
    $AllTrunkVLANs = @()
    $InterfaceResults = @()
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}
    $VlanStartString = "^VLAN\s+Name\s+Status\s+Ports"
    $VlanEndString = "^VLAN\s+Type\s+SAID\s+MTU\s+Parent RingNo\s+BridgeNo\s+Stp\s+BrdgMode\s+Trans1\s+Trans2"
    $VlanStartIndex = ($ShowTech | Select-String $VlanStartString).LineNumber
    $VlanEndIndex = ($ShowTech | Select-String $VlanEndString).LineNumber
    $ShowVlan = $ShowTech | Select-Object -Index (($VlanStartIndex + 1)..($VlanEndIndex - 3))
    $ShowVlanPSO = New-Object System.Collections.Generic.List[System.Object]
    $TrunkstartSTR = "^Port\s+Vlans\sallowed\son\strunk"
    $TrunkstartIndex = ($ShowTech | Select-String $TrunkstartSTR).LineNumber
    IF ($TrunkstartIndex) {
        $TrunkEndIndex = $TrunkstartIndex
        DO {
            $TrunkEndIndex++
        }Until($ShowTech[$TrunkEndIndex] -match "")
        $ShowInterfacesTrunk = $ShowTech | Select-Object -Index (($TrunkstartIndex - 1)..($TrunkEndIndex))

        ForEach ($Trunk in ($ShowInterfacesTrunk | Select-Object -Skip 1)) {
            if ($Trunk) {
                $Interface = (-split $Trunk)[0]
                $TrunkVlans = (-split $Trunk)[1].Split(",")

                ForEach ($TVlan in $TrunkVlans) {
                    IF ($TVlan -like "*-*") {
                        $DashIndex = $TVlan.IndexOf("-")
                        $StartInt = $TVlan.Substring(0, $DashIndex)
                        $EndInt = $TVlan.Substring($DashIndex + 1)
                        $AllTrunkVLANs += $StartInt..$EndInt
                    }
                    Else {
                        $AllTrunkVLANs += $TVlan
                    }
                }
            }

        }
    }

    ForEach ($Vlan in $ShowVLan) {
        IF (!(($Vlan -split '\s{2,}')[0])) {
            $Ports = $ShowVlanPSO[$ShowVlanPSO.Count - 1].Ports
            $AdditionalPorts = ($Vlan -split '\s{2,}')[1]
            $UpdatedPorts = $Ports + $AdditionalPorts
            $ShowVlanPSO[$ShowVlanPSO.Count - 1].Ports = $UpdatedPorts
        }
        Else {
            $NewVlanObj = [PSCustomObject]@{
                VLAN   = ($Vlan -split '\s+')[0]
                Name   = (($Vlan -split '\s+', 2)[1] -split '(?:act/lshut|sus/lshut|act/ishut|sus/ishut|active|suspend|act/unsup)')[0].Trim()
                Status = (($Vlan | Select-String '(?:act/lshut|sus/lshut|act/ishut|sus/ishut|active|suspend|act/unsup)').Matches).Value
                Ports  = ($Vlan -split '(?:act/lshut|sus/lshut|act/ishut|sus/ishut|active|suspend|act/unsup)')[1].Trim()
            }
            $ShowVlanPSO.Add($NewVlanObj)
        }
    }

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF ($InterfaceConfig -contains "shutdown" -AND $InterfaceConfig -match "switchport (mode)?\s?access" -AND !($InterfaceConfig -contains "dot1x pae authenticator")) {
            $Non8021xInterfaces += $Interface
        }

        IF ($InterfaceConfig -contains "shutdown" -AND $InterfaceConfig -match "switchport (mode)?\s?access" -AND $InterfaceConfig -contains "dot1x pae authenticator") {
            $NAInterfaces += ($Interface | Out-String).Trim()
            IF ($InterfaceConfig -like "description*") {
                $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
            }
            IF ($InterfaceConfig -contains "switchport mode access") {
                $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport mode access"} | Out-String).Trim()
            }
            IF ($InterfaceConfig -like "switchport access vlan*") {
                $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport access vlan*"} | Out-String).Trim()
            }
            IF ($InterfaceConfig -contains "dot1x pae authenticator") {
                $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "dot1x pae authenticator"})
            }
            IF ($InterfaceConfig -like "shutdown*") {
                $NAInterfaces += " " + ($InterfaceConfig | Where-Object {$_ -like "shutdown*"} | Out-String).Trim()
            }
            $NAInterfaces += ""
        }
    }

    IF ($Non8021xInterfaces) {
        ForEach ($Interface in $Non8021xInterfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            $InterfaceResults += ($Interface | Out-String).Trim()
            $InterfaceResults += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
            $VLAN = ( -split ($InterfaceConfig | Select-String -Pattern "^switchport access vlan.*" ))[3]
            IF (($ShowVlanPSO | Where-Object {$_.Vlan -eq $Vlan}).status -eq "act/lshut" -AND $Vlan -notin $AllTrunkVLANs) {
                $InterfaceResults += " " + ($InterfaceConfig | Select-String -Pattern "^switchport access vlan.*" | Out-String).Trim()
            }
            Else {
                $OpenFinding = $True
                $InterfaceResults += " " + ($InterfaceConfig | Select-String -Pattern "^switchport access vlan.*" | Out-String).Trim()
                IF (!(($ShowVlanPSO | Where-Object {$_.Vlan -eq $Vlan}).status -eq "act/lshut")) {
                    $InterfaceResults += "  VLAN Status For VLAN " + $VLAN + ": " + ($ShowVlanPSO | Where-Object {$_.Vlan -eq $Vlan}).status + " - NON-COMPLIANT"
                }
                IF ($Vlan -in $AllTrunkVLANs) {
                    $InterfaceResults += "  VLAN $VLAN is allowed on trunk links"
                }
            }
            $InterfaceResults += " " + ($InterfaceConfig | Select-String -patter "^shutdown$" | Out-String).Trim()
            $InterfaceResults += ""
        }

        $FindingDetails += "Inactive VLANs:" | Out-String
        $FindingDetails += ($ShowVlanPSO | Where-Object {$_.Status -ne "active"} | Select-Object VLAN, Name, STATUS | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += "Trunk Ports:" | Out-String
        $FindingDetails += IF ($ShowInterfacesTrunk) {
($ShowInterfacesTrunk | Out-String)
        }
        Else {
("Trunk ports not configured" | Out-String).Trim()
        }
        $FindingDetails += "" | Out-String
        $FindingDetails += "Shutdown Interfaces (without 802.1x)" | Out-String
        $FindingDetails += "-------------------------------------" | Out-String
        $FindingDetails += ($InterfaceResults | Out-String).Trim()
        IF ($OpenFinding) {
            $Status = "Open"
        }
        Else {
            $Status = "NotAFinding"
        }
    }
    Else {
        $FindingDetails += "All shutdown switchport mode access VLANs are managed by 802.1x" | Out-String
        $FindingDetails += "Switch ports configured for 802.1x are exempt from this requirement." | Out-String
        $FindingDetails += "" | Out-String
        if ($NAInterfaces) {
            $FindingDetails += "Interfaces" | Out-String
            $FindingDetails += "-----------" | Out-String
            $FindingDetails += $NAInterfaces -join "`n" | Out-String
        }
        $Status = "Not_Applicable"
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

Function Get-V220668 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220668
        STIG ID    : CISC-L2-000220
        Rule ID    : SV-220668r539671_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000008
        Rule Title : The Cisco switch must not have the default VLAN assigned to any host-facing switch ports.
        DiscussMD5 : CC13E41763978069BFB299C68B65A154
        CheckMD5   : F476375DE9FDA75252B696D5703DB207
        FixMD5     : D2950AF027B4A536392116BB95AE6A72
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
    $OpenFinding = $False
    $CompliantInt = @()
    $NonCompliantInt = @()
    $ActiveAccessSwitchPorts = @()
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "shutdown") -AND $InterfaceConfig -match "switchport (mode)?\s?access") {
            $ActiveAccessSwitchPorts += $Interface
        }
    }

    IF ($ActiveAccessSwitchPorts) {
        ForEach ($Interface in $ActiveAccessSwitchPorts) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            $SwitchPortVLAN = $InterfaceConfig | Select-String -Pattern "^switchport access .*"
            IF ($SwitchPortVLAN) {
                IF (($SwitchPortVLAN | Out-String).Trim().Split([char[]]"")[3] -eq "1") {
                    $OpenFinding = $True
                    $NonCompliantInt += ($Interface | Out-String).Trim()
                    IF ($InterfaceConfig -like "description*") {
                        $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                    }
                    $NonCompliantInt += " " + ($SwitchPortVLAN | Out-String).Trim()
                    $NonCompliantInt += ""
                }
                Else {
                    $CompliantInt += ($Interface | Out-String).Trim()
                    IF ($InterfaceConfig -like "description*") {
                        $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                    }
                    $CompliantInt += " " + ($SwitchPortVLAN | Out-String).Trim()
                    $CompliantInt += ""
                }
            }
            Else {
                $OpenFinding = $True
                $NonCompliantInt += ($Interface | Out-String).Trim()
                IF ($InterfaceConfig -like "description*") {
                    $NonCompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                }
                $NonCompliantInt += "switch port access vlan not configured, switchport will default to VLAN 1"
                $NonCompliantInt += ""
            }
        }

        IF ($CompliantInt) {
            $FindingDetails += "Compliant Interfaces " | Out-String
            $FindingDetails += "---------------------" | Out-String
            $FindingDetails += $CompliantInt | Out-String
        }

        IF ($NonCompliantInt) {
            $FindingDetails += "Non-Compliant Interfaces " | Out-String
            $FindingDetails += "---------------------------" | Out-String
            $FindingDetails += $NonCompliantInt | Out-String
        }

        IF ($OpenFinding) {
            $Status = "Open"
        }
        Else {
            $Status = "NotAFinding"
        }
    }
    Else {
        $FindingDetails += "There are no active access switchports configured on this switch" | Out-String
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

Function Get-V220669 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220669
        STIG ID    : CISC-L2-000230
        Rule ID    : SV-220669r539671_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000009
        Rule Title : The Cisco switch must have the default VLAN pruned from all trunk ports that do not require it.
        DiscussMD5 : 338F8B6991B345E3A5A323147021041A
        CheckMD5   : C2F2F0BC729950111E64707DCB1CF0F2
        FixMD5     : 557326D03F6FC5762202F76A1EB7A126
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
    $OpenFinding = $False
    $CompliantInt = @()
    $NonCompliantInt = @()
    $startSTR = "Port\s+Vlans\s+allowed\s+on\s+trunk"
    $startIndex = ($ShowTech | Select-String $startSTR).LineNumber
    if ($startIndex) {
        $EndIndex = $startIndex
        DO {
            $EndIndex++
        }Until($ShowTech[$EndIndex] -match "")
        $ShowInterfacesTrunk = $ShowTech | Select-Object -Index ($startIndex..($EndIndex))
        ForEach ($Trunk in $ShowInterfacesTrunk) {
            if ($Trunk) {
                $Interface = (-split $Trunk)[0]
                $TrunkVlans = (-split $Trunk)[1].Split(",")
                $VLANs = @()
                ForEach ($Vlan in $TrunkVlans) {
                    IF ($Vlan -like "*-*") {
                        $DashIndex = $Vlan.IndexOf("-")
                        $StartInt = $Vlan.Substring(0, $DashIndex)
                        $EndInt = $Vlan.Substring($DashIndex + 1)
                        $VLANs += $StartInt..$EndInt
                    }
                    Else {
                        $VLANs += $Vlan
                    }
                }
                IF ($VLANs -contains "1") {
                    $OpenFinding = $True
                    $NonCompliantInt += $Trunk
                }
                Else {
                    $CompliantInt += $Trunk
                }
            }
        }
    }
    Else {
        $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}

        ForEach ($Interface in $Interfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF (!($InterfaceConfig -contains "shutdown") -AND $InterfaceConfig -match "switchport trunk allowed vlan.*") {
                $Trunk = ( -Split ($InterfaceConfig | Select-String -Pattern "^switchport trunk allowed vlan.*"))[4]
                if ($Trunk) {
                    $TrunkVlans = $Trunk.Split(",")
                    $VLANs = @()
                    ForEach ($Vlan in $TrunkVlans) {
                        IF ($Vlan -like "*-*") {
                            $DashIndex = $Vlan.IndexOf("-")
                            $StartInt = $Vlan.Substring(0, $DashIndex)
                            $EndInt = $Vlan.Substring($DashIndex + 1)
                            $VLANs += $StartInt..$EndInt
                        }
                        Else {
                            $VLANs += $Vlan
                        }
                    }
                    IF ($VLANs -contains "1") {
                        $OpenFinding = $True
                        $NonCompliantInt += ($Interface | Out-String).Trim()
                        $NonCompliantInt += ($InterfaceConfig | Select-String -Pattern "^switchport trunk allowed vlan.*" | Out-String).Trim()
                        $NonCompliantInt += ("" | Out-String).Trim()
                    }
                    Else {
                        $CompliantInt += ($Interface | Out-String).Trim()
                        $CompliantInt += ($InterfaceConfig | Select-String -Pattern "^switchport trunk allowed vlan.*" | Out-String).Trim()
                        $CompliantInt += ("" | Out-String).Trim()
                    }
                }


            }
        }
    }

    IF ($CompliantInt) {
        $FindingDetails += "Compliant Trunk Interfaces" | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $CompliantInt | Out-String
        $FindingDetails += "" | Out-String
    }

    IF ($NonCompliantInt) {
        $FindingDetails += "Non-Compliant Trunk Interfaces" | Out-String
        $FindingDetails += "--------------------------" | Out-String
        $FindingDetails += $NonCompliantInt | Out-String
        $FindingDetails += "" | Out-String
    }

    IF ($OpenFinding) {
        $Status = "Open"
    }
    Else {
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

Function Get-V220670 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220670
        STIG ID    : CISC-L2-000240
        Rule ID    : SV-220670r539671_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000010
        Rule Title : The Cisco switch must not use the default VLAN for management traffic.
        DiscussMD5 : 8C62CF7A41941A44EFC29FDDA49EFD40
        CheckMD5   : D90FDB909EABE1A307BDAB48F5B04BEA
        FixMD5     : 9DD1285EDD75AAC6CF95B1146D17EB13
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
    $Vlan1 = ($ShowRunningConfig | Select-String -Pattern "^Interface vlan1$" | Out-String).Trim()
    $DefaultVLan = Get-Section $ShowRunningConfig "$vlan1"
    IF ($DefaultVLan -contains "shutdown" -AND $DefaultVLan -contains "no ip address") {
        $FindingDetails += $Vlan1 | Out-String
        $FindingDetails += $DefaultVLan | Out-String
        $Status = "NotAFinding"
    }
    Else {
        $FindingDetails += "Review the switch configuration below and verify that the default VLAN is not used to access the switch for management." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += $Vlan1 | Out-String
        $FindingDetails += $DefaultVLan | Out-String
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

Function Get-V220671 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220671
        STIG ID    : CISC-L2-000250
        Rule ID    : SV-220671r539671_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000011
        Rule Title : The Cisco switch must have all user-facing or untrusted ports configured as access switch ports.
        DiscussMD5 : 6F8F274B359BEF8A81A9ACBBDEEC588F
        CheckMD5   : E61E77F6FBB329C07A7837AB2EFAA48C
        FixMD5     : 68D38CA681E1501831A7110FB42D8C1F
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
    $TrunkInterfaces = @()
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "shutdown")) {
            IF ($InterfaceConfig -contains "switchport mode trunk") {
                $TrunkInterfaces += ($Interface | Out-String).Trim()
                $TrunkInterfaces += ($InterfaceConfig | Out-String).Trim()
                $TrunkInterfaces += ""
            }
        }
    }

    IF ($TrunkInterfaces) {
        $FindingDetails += "Review switch configuration below and determine if any interfaces are user-facing or untrusted switchports." | Out-String
        $FindingDetails += "Make finding determination based on STIG check guidance" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Trunk Interfaces" | Out-String
        $FindingDetails += "------------------------" | Out-String
        $FindingDetails += $TrunkInterfaces | Out-String
    }
    Else {
        $FindingDetails += "There are no trunk interfaces on this switch" | Out-String
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

Function Get-V220672 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220672
        STIG ID    : CISC-L2-000260
        Rule ID    : SV-220672r539671_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000012
        Rule Title : The Cisco switch must have the native VLAN assigned to an ID other than the default VLAN for all 802.1q trunk links.
        DiscussMD5 : 5C7174907755B77D7ECA1434D7B54A6D
        CheckMD5   : B45514755376BB74865CC68F2DDCA053
        FixMD5     : 772A2610F5A5891DFB4A343FA0F55CBE
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
    $OpenFinding = $False
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}
    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "shutdown")) {
            IF ($InterfaceConfig -contains "switchport trunk encapsulation dot1q") {
                IF ($InterfaceConfig | Where-Object {$_ -like "switchport trunk native vlan*"}) {
                    IF (($InterfaceConfig | Where-Object {$_ -like "switchport trunk native vlan*"} | Out-String).Trim().Split([char[]]"")[4] -eq "1") {
                        $OpenFinding = $True
                    }
                    IF (!$FindingDetails) {
                        $FindingDetails += "Trunk Interfaces" | Out-String
                        $FindingDetails += "------------------" | Out-String
                        $FindingDetails += "" | Out-String
                    }
                    $FindingDetails += ($Interface | Out-String).Trim()
                    $FindingDetails += " " + ($InterfaceConfig | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                }
                Else {
                    $OpenFinding = $True
                    IF (!$FindingDetails) {
                        $FindingDetails += "Trunk Interfaces" | Out-String
                        $FindingDetails += "------------------" | Out-String
                        $FindingDetails += "" | Out-String
                    }
                    $FindingDetails += ($Interface | Out-String).Trim()
                    $FindingDetails += " " + ($InterfaceConfig | Out-String).Trim()
                    $FindingDetails += "Swithport Native VLAN is not configured" | Out-String
                    $FindingDetails += "" | Out-String
                }
            }
        }
    }

    IF ($FindingDetails) {
        IF ($OpenFinding) {
            $Status = "Open"
        }
        Else {
            $Status = "NotAFinding"
        }
    }
    Else {
        $FINDINGDETAILS += "No 802.1q trunk links are configured" | Out-String
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

Function Get-V220673 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220673
        STIG ID    : CISC-L2-000270
        Rule ID    : SV-220673r539671_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-NET-000512-L2S-000013
        Rule Title : The Cisco switch must not have any switchports assigned to the native VLAN.
        DiscussMD5 : AC50A426EC1059E53A9F11F6E08EBE66
        CheckMD5   : 25595046E054827DCCCEFF79DBF12CF0
        FixMD5     : B83768DE527DF9D987AC617125B2DB48
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
    $NativeVLANs = @()
    $ActiveAccessSwitchPorts = @()
    $CompliantInt = @()
    $NonCompliantInt = @()
    $NativeVLanstartSTR = "^Port\s+Mode\s+Encapsulation\s+Status\s+Native\s+vlan"
    $NativeVLANstartIndex = ($ShowTech | Select-String $NativeVLanstartSTR).LineNumber
    if ($NativeVLANstartIndex) {
        $NativeVLANEndIndex = $NativeVLANstartIndex
        DO {
            $NativeVLANEndIndex++
        }Until($ShowTech[$NativeVLANEndIndex] -match "")
        $ShowInterfacesTrunk = $ShowTech | Select-Object -Index (($NativeVLANstartIndex - 1)..($NativeVLANEndIndex))
    }
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*"}

    ForEach ($Interface in $Interfaces) {
        $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
        IF (!($InterfaceConfig -contains "shutdown") -AND $InterfaceConfig -match "switchport (mode)?\s?access") {
            $ActiveAccessSwitchPorts += $Interface
        }
    }

    IF ($ActiveAccessSwitchPorts) {
        if ($ShowInterfacesTrunk) {
            ForEach ($Trunk in ($ShowInterfacesTrunk | Select-Object -Skip 1)) {
                IF ((-split $Trunk)[4] -notin $NativeVLANs) {
                    $NativeVLANs += (-split $Trunk)[4]
                }
            }
        }
        else {
            $NativeVLANs += $ShowRunningConfig | Select-String -Pattern "switchport trunk native vlan.*" | ForEach-Object {(-Split $_)[4]} | Get-Unique
        }
        ForEach ($Interface in $ActiveAccessSwitchPorts) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF ($InterfaceConfig -like "switchport access vlan*") {
                IF (($InterfaceConfig -like "switchport access vlan*" | Out-String).Trim().Split([char[]]"")[3] -in $NativeVLANs) {
                    $OpenFinding = $True
                    $NonCompliantInt += ($Interface | Out-String).Trim()
                    $NonCompliantInt += ($InterfaceConfig | Out-String).Trim()
                    $NonCompliantInt += ""
                }
                Else {
                    $CompliantInt += ($Interface | Out-String).Trim()
                    IF ($InterfaceConfig -like "description*") {
                        $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "description*"} | Out-String).Trim()
                    }
                    IF ($InterfaceConfig -contains "switchport mode access") {
                        $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport mode access"} | Out-String).Trim()
                    }
                    IF ($InterfaceConfig -like "switchport access vlan*") {
                        $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "switchport access vlan*"} | Out-String).Trim()
                    }
                    IF ($InterfaceConfig -contains "dot1x pae authenticator") {
                        $CompliantInt += " " + ($InterfaceConfig | Where-Object {$_ -like "dot1x pae authenticat"})
                    }
                    $CompliantInt += ""
                }
            }
            Else {
                $OpenFinding = $True
                $NonCompliantInt += ($Interface | Out-String).Trim()
                $NonCompliantInt += ($InterfaceConfig | Out-String).Trim()
                $NonCompliantInt += ""
                $NonCompliantInt += "switchport access vlan not configured"
                $NonCompliantInt += "$Interface will default to VLAN 1"
            }
        }

        if ($ShowInterfacesTrunk) {
            $FindingDetails += $ShowInterfacesTrunk.Trim() | Out-String
            $FindingDetails += "" | Out-String
        }
        else {
            $FindingDetails += "Native VLANs" | Out-String
            $FindingDetails += "---------------" | Out-String
            $FindingDetails += $NativeVLANs.Trim() | Out-String
            $FindingDetails += "" | Out-String
        }

        IF ($CompliantInt) {
            $FindingDetails += "Compliant Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $CompliantInt.Trim() | Out-String
            $FindingDetails += "" | Out-String
        }

        IF ($NonCompliantInt) {
            $FindingDetails += "Non-Compliant Interfaces" | Out-String
            $FindingDetails += "--------------------------" | Out-String
            $FindingDetails += $NonCompliantInt.Trim() | Out-String
            $FindingDetails += "" | Out-String
        }


        IF ($OpenFinding) {
            $Status = "Open"
        }
        Else {
            $Status = "NotAFinding"
        }
    }
    Else {
        $FindingDetails += "There are no active access switchports configured on this switch" | Out-String
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

# SIG # Begin signature block
# MIIL+QYJKoZIhvcNAQcCoIIL6jCCC+YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAz5BRpHQ1RjpQA
# yRF3G0mh+u/gdejRpGoQ9F77T+mn46CCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCzOxfPL4t1wYBWNULxlhViXbu8KcBT
# JvZizx1NHwzZGDANBgkqhkiG9w0BAQEFAASCAQCksBVSsmH88tr4Q/1a3vOzYfvX
# 1mOO74PcvtQGo55HGfMf1nQVly/IH6FmC8b3kIojH+CNCZDCkux6CbvchvAXykh4
# 7/x1xcfUIbKvz/eOWa5cEOFdc0YvcwSlN+xIqnGZYZny7v/8mnIaSNfYr4GjcO/S
# EGbXQvtRhoZAXH/2DOjAY+Dv7B/OkIRnSUlzEuVBzjmppkPMl83VPne/eoSvE4Lf
# Q5fdmrKSoUSKjh4MLpB/4Y3gS+g5yQLmMw3pXtLebhqSe23wgnhVpZgmyxx0XxOv
# LuPQtNg2Nn4fCh4LkXG3DHMovouMoUF+bYeyaxwtUM4uaKzy+cY3paddS1y9
# SIG # End signature block
