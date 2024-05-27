##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Microsoft Internet Explorer 11
# Version:  V2R5
# Class:    UNCLASSIFIED
# Updated:  5/13/2024
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V223015 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223015
        STIG ID    : DTBI015-IE11
        Rule ID    : SV-223015r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : The Internet Explorer warning about certificate address mismatch must be enforced.
        DiscussMD5 : C225005BABFB04C331AD96164225DFF1
        CheckMD5   : C06CCA52904EA15F6E6DE82D6804337A
        FixMD5     : A6F948F78D5A9CB10ACACE39918C9059
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"  # Registry path identified in STIG
    $RegistryValueName = "WarnOnBadCertRecving"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Turn on certificate address mismatch warning"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223016 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223016
        STIG ID    : DTBI018-IE11
        Rule ID    : SV-223016r879612_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-APP-000175
        Rule Title : Check for publishers certificate revocation must be enforced.
        DiscussMD5 : 8C86DCA271CFC47601D092C0549E4462
        CheckMD5   : 2D8E17A47F4FFCC61CFBB55CB5ABD69F
        FixMD5     : 5CFF53F5A3323ED223260BE6D59C3F51
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
    If ($ScanType -in @("Classified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA." | Out-String
    }
    Else {
        $TempUserHivePath = "Registry::HKU\Evaluate-STIG_UserHive\SOFTWARE\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing"  # User's loaded hive to perform check
        $RegistryPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing"  # Registry path identified in STIG
        $RegistryValueName = "State"  # Value name identified in STIG
        $RegistryValue = @("23C00")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Check for publisher's certificate revocation"  # GPO setting name identified in STIG
        $SettingState = "Enabled"  # GPO configured state identified in STIG.
        $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

        If ($TempUserHivePath) {
            $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
            $FindingDetails += "" | Out-String
            $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
        }
        Else {
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
        }

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            If ($SettingNotConfiguredAllowed -eq $true) {
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
                }
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

Function Get-V223017 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223017
        STIG ID    : DTBI022-IE11
        Rule ID    : SV-223017r879629_rule
        CCI ID     : CCI-001169
        Rule Name  : SRG-APP-000209
        Rule Title : The Download signed ActiveX controls property must be disallowed (Internet zone).
        DiscussMD5 : 885A750F997BA953A139BCBA23987E64
        CheckMD5   : CE55083C22493C4456C54EC730F59391
        FixMD5     : 974CB71245B82A4A4DEAE9A09632BC0D
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "1001"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Download signed ActiveX controls"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223018 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223018
        STIG ID    : DTBI023-IE11
        Rule ID    : SV-223018r879629_rule
        CCI ID     : CCI-001169
        Rule Name  : SRG-APP-000209
        Rule Title : The Download unsigned ActiveX controls property must be disallowed (Internet zone).
        DiscussMD5 : EAD0F4790C63E053E4C8ABD7193D7F9E
        CheckMD5   : 0C6F7FCC71F17EF1EBD21C4F8E3655EC
        FixMD5     : 5723B488C43A94F1F3594446528EF33C
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "1004"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Download unsigned ActiveX controls"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223019 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223019
        STIG ID    : DTBI024-IE11
        Rule ID    : SV-223019r879630_rule
        CCI ID     : CCI-001170
        Rule Name  : SRG-APP-000210
        Rule Title : The Initialize and script ActiveX controls not marked as safe property must be disallowed (Internet zone).
        DiscussMD5 : 9DF2CF07333C00021E2BF4BBF2F266F3
        CheckMD5   : 3D07BF0D602B27BC5E4E250A2558482B
        FixMD5     : 1755A8EA57EC6C6272878BB7705D3EA1
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "1201"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Initialize and script ActiveX controls not marked as safe"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223020 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223020
        STIG ID    : DTBI031-IE11
        Rule ID    : SV-223020r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : The Java permissions must be disallowed (Internet zone).
        DiscussMD5 : 5AFEC2B164909DA5BA0D2E0E871FCB56
        CheckMD5   : 7E4AB5816BF35BF05169777CB521A7B5
        FixMD5     : 8AF1B70EC7FBD14F2486B762951472E8
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "1C00"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Java permissions"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable Java)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223021 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223021
        STIG ID    : DTBI032-IE11
        Rule ID    : SV-223021r879534_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-APP-000039
        Rule Title : Accessing data sources across domains must be disallowed (Internet zone).
        DiscussMD5 : FF1DEB29C49DEC4BC7B8A132DF87A624
        CheckMD5   : FB01752E2C09FF08EA3926ED1DE700CD
        FixMD5     : F90484E6040F9D1396AD9F2E90C4BB7B
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "1406"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Access data sources across domains"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223022 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223022
        STIG ID    : DTBI036-IE11
        Rule ID    : SV-223022r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Functionality to drag and drop or copy and paste files must be disallowed (Internet zone).
        DiscussMD5 : AEBC5B4CF163E68D3E5EC009F5AA2FBF
        CheckMD5   : 2510315335F907E9FB3D3FB8FDA12CD5
        FixMD5     : 8111FD452ADA717B11AD4A2FFBA10B05
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "1802"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Allow drag and drop or copy and paste files"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223023 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223023
        STIG ID    : DTBI038-IE11
        Rule ID    : SV-223023r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Launching programs and files in IFRAME must be disallowed (Internet zone).
        DiscussMD5 : 257E2755F4B4A2FE1AC1A3555347D227
        CheckMD5   : 22E93C22A84DDFC1F43E2F1410D89CAC
        FixMD5     : 0E228C2E26D7FF071A0506A49CC8AD41
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "1804"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Launching applications and files in an IFRAME"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223024 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223024
        STIG ID    : DTBI039-IE11
        Rule ID    : SV-223024r879534_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-APP-000039
        Rule Title : Navigating windows and frames across different domains must be disallowed (Internet zone).
        DiscussMD5 : E4995D67E0DD9A2BE46CEF9D56C50F1B
        CheckMD5   : AC7BE3569D757C91FE5F7AB1F725087D
        FixMD5     : 637EF05D196003B61FD70313505ABD32
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "1607"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Navigate windows and frames across different domains"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223025 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223025
        STIG ID    : DTBI042-IE11
        Rule ID    : SV-223025r879642_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231
        Rule Title : Userdata persistence must be disallowed (Internet zone).
        DiscussMD5 : 6CF422F22672F65C6100D5A482A7A9A7
        CheckMD5   : 5A3419AB18369676139B65F253A56985
        FixMD5     : 04969B742925E0787698ED74F5AD68F5
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "1606"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Userdata persistence"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223026 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223026
        STIG ID    : DTBI044-IE11
        Rule ID    : SV-223026r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Clipboard operations via script must be disallowed (Internet zone).
        DiscussMD5 : FCE9C3836A685378DA408D7A9CB0DDCD
        CheckMD5   : 61F62AEA7203BE92313D00EA01806B85
        FixMD5     : C655BBCCF8CC43298C4E16936A55C3BF
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "1407"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Allow cut, copy or paste operations from the clipboard via script"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223027 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223027
        STIG ID    : DTBI046-IE11
        Rule ID    : SV-223027r879636_rule
        CCI ID     : CCI-001184
        Rule Name  : SRG-APP-000219
        Rule Title : Logon options must be configured to prompt (Internet zone).
        DiscussMD5 : 4D6A790D8E30B016DB0A3546A75A0E6A
        CheckMD5   : 2A70318C564E2E9AAB25FC48B8667BD3
        FixMD5     : CB67AFDBFC9B40A3BC8D45D289DEE81B
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "1A00"  # Value name identified in STIG
    $RegistryValue = @("10000")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Logon options"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Prompt for user name and password)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223028 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223028
        STIG ID    : DTBI061-IE11
        Rule ID    : SV-223028r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Java permissions must be configured with High Safety (Intranet zone).
        DiscussMD5 : 6C70B017C0E2959EC955D6D4D20CF6BD
        CheckMD5   : C6D4B9680F1DEAD715788173DAFBE913
        FixMD5     : 003B06787EBBE0E3646C9AC9FA78B320
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1"  # Registry path identified in STIG
    $RegistryValueName = "1C00"  # Value name identified in STIG
    $RegistryValue = @("10000")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Java permissions"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (High Safety)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223029 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223029
        STIG ID    : DTBI062-IE11
        Rule ID    : SV-223029r879628_rule
        CCI ID     : CCI-001662
        Rule Name  : SRG-APP-000207
        Rule Title : Anti-Malware programs against ActiveX controls must be run for the Intranet zone.
        DiscussMD5 : 7DE8EB0968354C09D8B06C9210895D83
        CheckMD5   : C326BE92F84E25C4B12744620EA92EAB
        FixMD5     : 101DDD7139E88592FA1DB9FF58B4AD27
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1"  # Registry path identified in STIG
    $RegistryValueName = "270C"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Don't run antimalware programs against ActiveX controls"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223030 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223030
        STIG ID    : DTBI091-IE11
        Rule ID    : SV-223030r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Java permissions must be configured with High Safety (Trusted Sites zone).
        DiscussMD5 : 670D30EA13EB9189FEF527AB4DEC011A
        CheckMD5   : 5B75CB38FE68A5E31585E4B405CC750F
        FixMD5     : DE685374EC8E560384A8DD12FC655FF9
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2"  # Registry path identified in STIG
    $RegistryValueName = "1C00"  # Value name identified in STIG
    $RegistryValue = @("10000")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Java permissions"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (High Safety)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223031 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223031
        STIG ID    : DTBI092-IE11
        Rule ID    : SV-223031r879628_rule
        CCI ID     : CCI-001662
        Rule Name  : SRG-APP-000207
        Rule Title : Anti-Malware programs against ActiveX controls must be run for the Trusted Sites zone.
        DiscussMD5 : 7DE8EB0968354C09D8B06C9210895D83
        CheckMD5   : F693DD6C2CD626AFC3BB7CFD55FAC382
        FixMD5     : 3D344BB2290D54E7B462252566F0210D
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2"  # Registry path identified in STIG
    $RegistryValueName = "270C"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Don't run antimalware programs against ActiveX controls"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223032 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223032
        STIG ID    : DTBI1000-IE11
        Rule ID    : SV-223032r879534_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-APP-000039
        Rule Title : Dragging of content from different domains within a window must be disallowed (Internet zone).
        DiscussMD5 : 01AF3A3C7246EAEDBED2E6C52CC4483C
        CheckMD5   : 5DEB028EF8AD4859C746D3651A590CDC
        FixMD5     : EFA8B459C43478EEB1F9EC344B7B6E13
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "2708"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Enable dragging of content from different domains within a window"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223033 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223033
        STIG ID    : DTBI1005-IE11
        Rule ID    : SV-223033r879534_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-APP-000039
        Rule Title : Dragging of content from different domains across windows must be disallowed (Restricted Sites zone).
        DiscussMD5 : 68AFC748C033FBE8792C37E2717B722C
        CheckMD5   : 26E1C9A05237616CE335665E4C1E8298
        FixMD5     : 15389D31632E6A9EE80DBD0590CC742F
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "2709"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Enable dragging of content from different domains across windows"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223034 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223034
        STIG ID    : DTBI1010-IE11
        Rule ID    : SV-223034r879573_rule
        CCI ID     : CCI-001695
        Rule Name  : SRG-APP-000112
        Rule Title : Internet Explorer Processes Restrict ActiveX Install must be enforced (Explorer).
        DiscussMD5 : 2A517D94495C15710DA633865E76C2D7
        CheckMD5   : E4B7A3D06088DD038F20698713CED8D0
        FixMD5     : E9F06444994CE9F3B73654B4FC6128B9
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL"  # Registry path identified in STIG
    $RegistryValueName = "explorer.exe"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Internet Explorer Processes"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223035 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223035
        STIG ID    : DTBI1020-IE11
        Rule ID    : SV-223035r879573_rule
        CCI ID     : CCI-001695
        Rule Name  : SRG-APP-000112
        Rule Title : Internet Explorer Processes Restrict ActiveX Install must be enforced (iexplore).
        DiscussMD5 : 2A517D94495C15710DA633865E76C2D7
        CheckMD5   : 46E1F4C8BB2E1DA8A593F4E068BE3147
        FixMD5     : E9F06444994CE9F3B73654B4FC6128B9
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL"  # Registry path identified in STIG
    $RegistryValueName = "iexplore.exe"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Internet Explorer Processes"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223036 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223036
        STIG ID    : DTBI1025-IE11
        Rule ID    : SV-223036r879534_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-APP-000039
        Rule Title : Dragging of content from different domains within a window must be disallowed (Restricted Sites zone).
        DiscussMD5 : 01AF3A3C7246EAEDBED2E6C52CC4483C
        CheckMD5   : CB468AFAF0A3726B9F5A008C2A64150E
        FixMD5     : AF9E7188DE5C9A74D09C0927F57B0694
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "2708"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Enable dragging of content from different domains within a window"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223037 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223037
        STIG ID    : DTBI1046-IE11
        Rule ID    : SV-223037r879628_rule
        CCI ID     : CCI-001662
        Rule Name  : SRG-APP-000207
        Rule Title : Anti-Malware programs against ActiveX controls must be run for the Internet zone.
        DiscussMD5 : E7ED8D8345C6D3F2D33BD0E4B2437D74
        CheckMD5   : E60C6B15A1E6BA69096FAB5F5AFA2569
        FixMD5     : FB206A73418AF6B6D343917B23C9962E
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "270C"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Don't run antimalware programs against ActiveX controls"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223038 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223038
        STIG ID    : DTBI1051-IE11
        Rule ID    : SV-223038r879628_rule
        CCI ID     : CCI-001662
        Rule Name  : SRG-APP-000207
        Rule Title : Anti-Malware programs against ActiveX controls must be run for the Restricted Sites zone.
        DiscussMD5 : E7ED8D8345C6D3F2D33BD0E4B2437D74
        CheckMD5   : 5F30D0AF4ECDFCABB388ABF8FDCC186E
        FixMD5     : 1463366E5465EF8FB5F1BE3D1D8CB9D9
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "270C"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Don't run antimalware programs against ActiveX controls"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223039 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223039
        STIG ID    : DTBI1060-IE11
        Rule ID    : SV-223039r879664_rule
        CCI ID     : CCI-001242
        Rule Name  : SRG-APP-000278
        Rule Title : Prevent bypassing SmartScreen Filter warnings must be enabled.
        DiscussMD5 : 7E233CA1962972607AD49D791EE054FA
        CheckMD5   : 567E5E3614A513FC24D7CDDDD17B4A46
        FixMD5     : 6CAC24986177AC147B60170BB6ECD616
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
    If ($ScanType -in @("Classified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA." | Out-String
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter"  # Registry path identified in STIG
        $RegistryValueName = "PreventOverride"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Prevent bypassing SmartScreen Filter warnings"  # GPO setting name identified in STIG
        $SettingState = "Enabled"  # GPO configured state identified in STIG.
        $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

        If ($TempUserHivePath) {
            $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
            $FindingDetails += "" | Out-String
            $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
        }
        Else {
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
        }

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            If ($SettingNotConfiguredAllowed -eq $true) {
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
                }
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

Function Get-V223040 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223040
        STIG ID    : DTBI1065-IE11
        Rule ID    : SV-223040r879629_rule
        CCI ID     : CCI-001169
        Rule Name  : SRG-APP-000209
        Rule Title : Prevent bypassing SmartScreen Filter warnings about files that are not commonly downloaded from the internet must be enabled.
        DiscussMD5 : 86696910AFACC0F3B7E30C057EB39EA0
        CheckMD5   : 5BF4C620D08BA32613922C1964B892A8
        FixMD5     : EC0CD156572ACEF51A175D3FA4DA1D66
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
    If ($ScanType -in @("Classified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA." | Out-String
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter"  # Registry path identified in STIG
        $RegistryValueName = "PreventOverrideAppRepUnknown"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Prevent bypassing SmartScreen Filter warnings about files that are not commonly downloaded from the internet"  # GPO setting name identified in STIG
        $SettingState = "Enabled"  # GPO configured state identified in STIG.
        $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

        If ($TempUserHivePath) {
            $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
            $FindingDetails += "" | Out-String
            $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
        }
        Else {
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
        }

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            If ($SettingNotConfiguredAllowed -eq $true) {
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
                }
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

Function Get-V223041 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223041
        STIG ID    : DTBI1070-IE11
        Rule ID    : SV-223041r879630_rule
        CCI ID     : CCI-001170
        Rule Name  : SRG-APP-000210
        Rule Title : Prevent per-user installation of ActiveX controls must be enabled.
        DiscussMD5 : 784703E3D2E45AF6E2579CF61F16156D
        CheckMD5   : CACA45DD1323BE4129C011B8F164887D
        FixMD5     : 5EF8FD903A6EEAD1AB5B5A38B6F5C065
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Security\ActiveX"  # Registry path identified in STIG
    $RegistryValueName = "BlockNonAdminActiveXInstall"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Prevent per-user installation of ActiveX controls"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223042 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223042
        STIG ID    : DTBI1075-IE11
        Rule ID    : SV-223042r942482_rule
        CCI ID     : CCI-001954
        Rule Name  : SRG-APP-000427
        Rule Title : Prevent ignoring certificate errors option must be enabled.
        DiscussMD5 : 9074318E3F5F5937DB7194965E0B2CAD
        CheckMD5   : CE96A4F04E02DFE456BE3F98FA6853F7
        FixMD5     : 10FF70B6E1B2C3DB2E33C32429DA34E2
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"  # Registry path identified in STIG
    $RegistryValueName = "PreventIgnoreCertErrors"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Prevent ignoring certificate errors"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223043 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223043
        STIG ID    : DTBI1080-IE11
        Rule ID    : SV-223043r879664_rule
        CCI ID     : CCI-001242
        Rule Name  : SRG-APP-000278
        Rule Title : Turn on SmartScreen Filter scan option for the Internet Zone must be enabled.
        DiscussMD5 : 7E76CC6B3768559ED021FBCCB89AEE36
        CheckMD5   : 226CCCA59066D4E9C7E705E4B51A449A
        FixMD5     : 5C12975148F9EC5425D71D78889BB9E2
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "2301"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Turn on SmartScreen Filter scan"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Enable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223044 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223044
        STIG ID    : DTBI1085-IE11
        Rule ID    : SV-223044r879664_rule
        CCI ID     : CCI-001242
        Rule Name  : SRG-APP-000278
        Rule Title : Turn on SmartScreen Filter scan option for the Restricted Sites Zone must be enabled.
        DiscussMD5 : 7E76CC6B3768559ED021FBCCB89AEE36
        CheckMD5   : DB68FABCD7F259C052A2C76DF5216800
        FixMD5     : 52C48A935B7424EE73B8DE87BA424979
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "2301"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Turn on SmartScreen Filter scan"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Enable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223045 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223045
        STIG ID    : DTBI1090-IE11
        Rule ID    : SV-223045r879630_rule
        CCI ID     : CCI-001170
        Rule Name  : SRG-APP-000210
        Rule Title : The Initialize and script ActiveX controls not marked as safe must be disallowed (Intranet Zone).
        DiscussMD5 : 9DF2CF07333C00021E2BF4BBF2F266F3
        CheckMD5   : 85CD947585FADC526E9BFFD03DCD126C
        FixMD5     : 593C115F6651E8DF724783C284EB9567
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1"  # Registry path identified in STIG
    $RegistryValueName = "1201"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Initialize and script ActiveX controls not marked as safe"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223046 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223046
        STIG ID    : DTBI1095-IE11
        Rule ID    : SV-223046r879630_rule
        CCI ID     : CCI-001170
        Rule Name  : SRG-APP-000210
        Rule Title : The Initialize and script ActiveX controls not marked as safe must be disallowed (Trusted Sites Zone).
        DiscussMD5 : 9DF2CF07333C00021E2BF4BBF2F266F3
        CheckMD5   : 6F7AE43E1425E61D9E1F793541410E1C
        FixMD5     : 7D40FD2BD57611CF91D258B89EF03367
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2"  # Registry path identified in STIG
    $RegistryValueName = "1201"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Initialize and script ActiveX controls not marked as safe"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223048 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223048
        STIG ID    : DTBI1105-IE11
        Rule ID    : SV-223048r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Run once selection for running outdated ActiveX controls must be disabled.
        DiscussMD5 : B1A914799F59CFEEB7E954A0F75CAC8E
        CheckMD5   : BB41ED7844CEDF0A42B4ED52F8427350
        FixMD5     : EF2D016E324C9DD2159B44D5C9B50CF7
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Ext"  # Registry path identified in STIG
    $RegistryValueName = "RunThisTimeEnabled"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Remove the Run this time button for outdated ActiveX controls in IE"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223049 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223049
        STIG ID    : DTBI1110-IE11
        Rule ID    : SV-223049r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Enabling outdated ActiveX controls for Internet Explorer must be blocked.
        DiscussMD5 : B1A914799F59CFEEB7E954A0F75CAC8E
        CheckMD5   : 09E1A529520FB303D9B65737255EDC09
        FixMD5     : F62BE7936A201CD6059CF3510F8B222E
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Ext"  # Registry path identified in STIG
    $RegistryValueName = "VersionCheckEnabled"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Turn off blocking of outdated ActiveX controls for Internet Explorer"  # GPO setting name identified in STIG
    $SettingState = "Disabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223050 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223050
        STIG ID    : DTBI1115-IE11
        Rule ID    : SV-223050r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Use of the Tabular Data Control (TDC) ActiveX control must be disabled for the Internet Zone.
        DiscussMD5 : 93CEDAFBFA654A35330596F0EF046325
        CheckMD5   : 26EC0A8BE80446E1AE1F7BF40FD16800
        FixMD5     : 21AB06207C2E409153D767944C4EA52D
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "120c"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Allow only approved domains to use the TDC ActiveX control"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Only allow approved domains to use the TDC ActiveX control)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223051 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223051
        STIG ID    : DTBI112-IE11
        Rule ID    : SV-223051r879629_rule
        CCI ID     : CCI-001169
        Rule Name  : SRG-APP-000209
        Rule Title : The Download signed ActiveX controls property must be disallowed (Restricted Sites zone).
        DiscussMD5 : 3DD4EB521D80E55EE321AC7A2554CA07
        CheckMD5   : 8BC5AE714A06DDBA6A91A5B1B748560B
        FixMD5     : B88E4DC08A0B603D385523B7D89F98B5
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "1001"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Download signed ActiveX controls"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223052 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223052
        STIG ID    : DTBI1120-IE11
        Rule ID    : SV-223052r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Use of the Tabular Data Control (TDC) ActiveX control must be disabled for the Restricted Sites Zone.
        DiscussMD5 : 6D8EE4FA5B4E34416C21DAAC95229F09
        CheckMD5   : 3C1EB1A98E8B9A03127E322E2AC32CA4
        FixMD5     : 036E6477C3A229CC9E3D0CB1755D8C75
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "120c"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Allow only approved domains to use the TDC ActiveX control"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Only allow approved domains to use the TDC ActiveX control)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223053 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223053
        STIG ID    : DTBI1125-IE11
        Rule ID    : SV-223053r879629_rule
        CCI ID     : CCI-001169
        Rule Name  : SRG-APP-000209
        Rule Title : VBScript must not be allowed to run in Internet Explorer (Internet zone).
        DiscussMD5 : F80EC998B5D80ECD567A85C504723D81
        CheckMD5   : 373433CC5A7697A1A43655A84C663272
        FixMD5     : 33DFEBDB36A046811E7A69EE39EF822A
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "140C"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Allow VBScript to run in Internet Explorer"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223054 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223054
        STIG ID    : DTBI113-IE11
        Rule ID    : SV-223054r879629_rule
        CCI ID     : CCI-001169
        Rule Name  : SRG-APP-000209
        Rule Title : The Download unsigned ActiveX controls property must be disallowed (Restricted Sites zone).
        DiscussMD5 : DA96EC536EFA101364F4C6884CD0F1B0
        CheckMD5   : FB127ADB94A71C988BF7B0005D7BC3E0
        FixMD5     : 875789E8D42E90EE8C817705471F7221
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "1004"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Download unsigned ActiveX controls"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223055 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223055
        STIG ID    : DTBI1130-IE11
        Rule ID    : SV-223055r879629_rule
        CCI ID     : CCI-001169
        Rule Name  : SRG-APP-000209
        Rule Title : VBScript must not be allowed to run in Internet Explorer (Restricted Sites zone).
        DiscussMD5 : F80EC998B5D80ECD567A85C504723D81
        CheckMD5   : 553CCD083143DB48AB6962D314B0B303
        FixMD5     : C70C9502621A3189C2B41ACD5DB6C592
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "140C"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Allow VBScript to run in Internet Explorer"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223056 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223056
        STIG ID    : DTBI1135-IE11
        Rule ID    : SV-223056r879655_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266
        Rule Title : Internet Explorer Development Tools Must Be Disabled.
        DiscussMD5 : A109345DD581EC64760D779013A26BEE
        CheckMD5   : EF9AE0D85435E1624E122DB7D56A897B
        FixMD5     : AC243B2438BC25E31DA35288A627A99D
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\IEDevTools"  # Registry path identified in STIG
    $RegistryValueName = "Disabled"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Turn off Developer Tools"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223057 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223057
        STIG ID    : DTBI114-IE11
        Rule ID    : SV-223057r879630_rule
        CCI ID     : CCI-001170
        Rule Name  : SRG-APP-000210
        Rule Title : The Initialize and script ActiveX controls not marked as safe property must be disallowed (Restricted Sites zone).
        DiscussMD5 : 7E38A3488652C513DA29266F9F58DC19
        CheckMD5   : 40780FA170ABC669F2ACB1F7CED0BE89
        FixMD5     : 38B24D0C71F5CD53A1563CC6C20F9F6C
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "1201"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Initialize and script ActiveX controls not marked as safe"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223058 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223058
        STIG ID    : DTBI115-IE11
        Rule ID    : SV-223058r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : ActiveX controls and plug-ins must be disallowed (Restricted Sites zone).
        DiscussMD5 : 8DBD4D05E0E277AA27819AB7F57AEE5B
        CheckMD5   : 733F5710093EBFCA09778A80F3606E41
        FixMD5     : C52AF13C540E2D8532CD078D7D29BFBC
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "1200"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Run ActiveX controls and plugins"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223059 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223059
        STIG ID    : DTBI116-IE11
        Rule ID    : SV-223059r879630_rule
        CCI ID     : CCI-001170
        Rule Name  : SRG-APP-000210
        Rule Title : ActiveX controls marked safe for scripting must be disallowed (Restricted Sites zone).
        DiscussMD5 : 347900D0C2DDB1A6668CD3254D28AACE
        CheckMD5   : D221CCECEB8B8DAA66B0EA7478D2A618
        FixMD5     : 8E19AA86AB54546A14A7E34E55A228B7
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "1405"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Script ActiveX controls marked safe for scripting"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223060 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223060
        STIG ID    : DTBI119-IE11
        Rule ID    : SV-223060r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : File downloads must be disallowed (Restricted Sites zone).
        DiscussMD5 : 8B35FC8CE2D5DBB062B698012888DAE1
        CheckMD5   : C8DC3EDE95E7015D0965432AE03F09AE
        FixMD5     : 433129111EFE039BD9DB77392902B836
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "1803"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Allow file downloads"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223061 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223061
        STIG ID    : DTBI121-IE11
        Rule ID    : SV-223061r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Java permissions must be disallowed (Restricted Sites zone).
        DiscussMD5 : 5AFEC2B164909DA5BA0D2E0E871FCB56
        CheckMD5   : 3F3298A4C2C605E01727D8C6D1AA05F8
        FixMD5     : FEDB58B9309513922571E5F44218F984
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "1C00"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Java permissions"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable Java)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223062 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223062
        STIG ID    : DTBI122-IE11
        Rule ID    : SV-223062r879534_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-APP-000039
        Rule Title : Accessing data sources across domains must be disallowed (Restricted Sites zone).
        DiscussMD5 : 0BA3B8B5D6E6B12E9BF5680F987A4B03
        CheckMD5   : EBBA02E863A4DFF6608173B4A2D55FB0
        FixMD5     : 3A65A5320BBAE15C1AEF3657B1426FDD
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "1406"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Access data sources across domains"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223063 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223063
        STIG ID    : DTBI123-IE11
        Rule ID    : SV-223063r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : The Allow META REFRESH property must be disallowed (Restricted Sites zone).
        DiscussMD5 : 24BA4DFAF249DB8F0CD246CA072E25E9
        CheckMD5   : 37C4AAE90D4F4398C1B4E1E026E2EFA6
        FixMD5     : E6DBCC67B0A61F0077B8AE1D8AE3A412
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "1608"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Allow META REFRESH"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223064 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223064
        STIG ID    : DTBI126-IE11
        Rule ID    : SV-223064r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Functionality to drag and drop or copy and paste files must be disallowed (Restricted Sites zone).
        DiscussMD5 : FD0B4FEC7EB467B075786C3606AEF12E
        CheckMD5   : 9A05B03C299895EC88D2C06399630F1B
        FixMD5     : E71E03457737A12BB9F8B25A3A352466
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "1802"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Allow drag and drop or copy and paste files"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223065 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223065
        STIG ID    : DTBI128-IE11
        Rule ID    : SV-223065r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Launching programs and files in IFRAME must be disallowed (Restricted Sites zone).
        DiscussMD5 : 257E2755F4B4A2FE1AC1A3555347D227
        CheckMD5   : 5B69022DDC93812808E06DD8A835E434
        FixMD5     : 485A3A55DB01D3BDBD9BB9365CC1FC1F
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "1804"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Launching applications and files in an IFRAME"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223066 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223066
        STIG ID    : DTBI129-IE11
        Rule ID    : SV-223066r879534_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-APP-000039
        Rule Title : Navigating windows and frames across different domains must be disallowed (Restricted Sites zone).
        DiscussMD5 : 5AF988A801CF1E85DA1E4444D2CA0D7F
        CheckMD5   : 1BD6609BC333F5E7BF78996E1D9EE7EF
        FixMD5     : A83EF5986732331B593001E3D92C3FD3
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "1607"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Navigate windows and frames across different domains"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223067 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223067
        STIG ID    : DTBI132-IE11
        Rule ID    : SV-223067r879642_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231
        Rule Title : Userdata persistence must be disallowed (Restricted Sites zone).
        DiscussMD5 : B7275503FF782F925B772573E3464E85
        CheckMD5   : 77C12DDAB75627D44655A78926501B38
        FixMD5     : 5974672C7C8448A45094B2518762223B
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "1606"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Userdata persistence"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223068 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223068
        STIG ID    : DTBI133-IE11
        Rule ID    : SV-223068r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Active scripting must be disallowed (Restricted Sites Zone).
        DiscussMD5 : 866CF03B0C412904074D69FF98D79817
        CheckMD5   : 922B7C9205390B76CEFD1431A2E87510
        FixMD5     : 5E83F2E92CAE3D0663B121CC47111C1C
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "1400"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Allow active scripting"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223069 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223069
        STIG ID    : DTBI134-IE11
        Rule ID    : SV-223069r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Clipboard operations via script must be disallowed (Restricted Sites zone).
        DiscussMD5 : FCE9C3836A685378DA408D7A9CB0DDCD
        CheckMD5   : B508512214626AC6437CCBFA1B69EC11
        FixMD5     : EE1C9C18FC9BB1E443FAF5CC80196F6D
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "1407"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Allow cut, copy or paste operations from the clipboard via script"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223070 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223070
        STIG ID    : DTBI136-IE11
        Rule ID    : SV-223070r879636_rule
        CCI ID     : CCI-001184
        Rule Name  : SRG-APP-000219
        Rule Title : Logon options must be configured and enforced (Restricted Sites zone).
        DiscussMD5 : 39D80FF52216B44DCE9D0CBFD9BFB28F
        CheckMD5   : B00457CD601EC5FFE3DCBB63F4D69B6D
        FixMD5     : 3D29CA508FA5D8C6E2290CB41AF37D65
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "1A00"  # Value name identified in STIG
    $RegistryValue = @("30000")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Logon options"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Anonymous logon)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223071 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223071
        STIG ID    : DTBI300-IE11
        Rule ID    : SV-223071r879559_rule
        CCI ID     : CCI-000169
        Rule Name  : SRG-APP-000089
        Rule Title : Configuring History setting must be set to 40 days.
        DiscussMD5 : 097747D4D580E7A928A1BE0097FD13D8
        CheckMD5   : 45B82CD94A602D21EDBF43047AE59CE4
        FixMD5     : 236A267666F1AF35F2F9BA1AD9C7EF66
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Url History"  # Registry path identified in STIG
    $RegistryValueName = "DaysToKeep"  # Value name identified in STIG
    $RegistryValue = @("28")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Disable Configuring History"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (40 Days)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223072 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223072
        STIG ID    : DTBI318-IE11
        Rule ID    : SV-223072r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Internet Explorer must be set to disallow users to add/delete sites.
        DiscussMD5 : 9290086C6640E1E99B331843B825FC0E
        CheckMD5   : 4945E0D47FB4D01CFEADA6D2B811CFA0
        FixMD5     : 112EB9C260F31A59F60E948E4B022BF3
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"  # Registry path identified in STIG
    $RegistryValueName = "Security_zones_map_edit"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Security Zones: Do not allow users to add/delete sites"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223073 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223073
        STIG ID    : DTBI319-IE11
        Rule ID    : SV-223073r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : Internet Explorer must be configured to disallow users to change policies.
        DiscussMD5 : 3B14C76A3CC84CCDF07377D36ACD4175
        CheckMD5   : C7CC4EDB22D962F847B11404EF7076DD
        FixMD5     : 889D24F5E09A0B954C01A90385D74322
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"  # Registry path identified in STIG
    $RegistryValueName = "Security_options_edit"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Security Zones: Do not allow users to change policies"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223074 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223074
        STIG ID    : DTBI320-IE11
        Rule ID    : SV-223074r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : Internet Explorer must be configured to use machine settings.
        DiscussMD5 : C9EB80AC1DFD26745B00F50B8ABF41A4
        CheckMD5   : 8FF3DD38DC691F3BD593F1E0AF0DE01C
        FixMD5     : 0D96D08D43B349917A3F6972EFCE183C
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"  # Registry path identified in STIG
    $RegistryValueName = "Security_HKLM_only"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Security Zones: Use only machine settings"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223075 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223075
        STIG ID    : DTBI325-IE11
        Rule ID    : SV-223075r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : Security checking features must be enforced.
        DiscussMD5 : 8DF5A1B052FE47348D395616CE60FEB3
        CheckMD5   : 79102A4CA16CB36A256B1735CE460093
        FixMD5     : 399D92BBF55F569DA51F3873D6A1E20C
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Security"  # Registry path identified in STIG
    $RegistryValueName = "DisableSecuritySettingsCheck"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Turn off the Security Settings Check feature"  # GPO setting name identified in STIG
    $SettingState = "Disabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223076 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223076
        STIG ID    : DTBI350-IE11
        Rule ID    : SV-223076r879630_rule
        CCI ID     : CCI-001170
        Rule Name  : SRG-APP-000210
        Rule Title : Software must be disallowed to run or install with invalid signatures.
        DiscussMD5 : 790BA68CC4E1781CD3B16E4A72DFEF3E
        CheckMD5   : 94CD746A28F3854F91036F6AC602987B
        FixMD5     : 92FE25E409CF519588954E0F19A61BC6
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Download"  # Registry path identified in STIG
    $RegistryValueName = "RunInvalidSignatures"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Allow software to run or install even if the signature is invalid"  # GPO setting name identified in STIG
    $SettingState = "Disabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223077 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223077
        STIG ID    : DTBI356-IE11
        Rule ID    : SV-223077r879643_rule
        CCI ID     : CCI-001084
        Rule Name  : SRG-APP-000233
        Rule Title : The 64-bit tab processes, when running in Enhanced Protected Mode on 64-bit versions of Windows, must be turned on.
        DiscussMD5 : DABAADA611161F9E8DBC0D36A41F22FA
        CheckMD5   : E73C9A5857CDAEEC3EF3CD51949295C7
        FixMD5     : FCC33FF8B6B4CECCDD9F11AC17398D0A
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"  # Registry path identified in STIG
    $RegistryValueName = "Isolation64Bit"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Turn on 64-bit tab processes when running in Enhanced Protected Mode on 64-bit versions of Windows"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223078 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223078
        STIG ID    : DTBI365-IE11
        Rule ID    : SV-223078r879612_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-APP-000175
        Rule Title : Checking for server certificate revocation must be enforced.
        DiscussMD5 : E77DCF7549CEED644B74771DBD45520E
        CheckMD5   : FFA4FC6E8A402564EF61A9E1093D1CF0
        FixMD5     : B97A2FB898B204004C0B7E62D9C8A1EB
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"  # Registry path identified in STIG
    $RegistryValueName = "CertificateRevocation"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Check for server certificate revocation"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223079 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223079
        STIG ID    : DTBI370-IE11
        Rule ID    : SV-223079r942483_rule
        CCI ID     : CCI-001749
        Rule Name  : SRG-APP-000131
        Rule Title : Checking for signatures on downloaded programs must be enforced.
        DiscussMD5 : 707FB8E7858C4A41D122C0340328C823
        CheckMD5   : FA0F4883E61314F21FE493CA6A250D37
        FixMD5     : 5926889D05A598FE756B3C3CA756C1A0
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Download"  # Registry path identified in STIG
    $RegistryValueName = "CheckExeSignatures"  # Value name identified in STIG
    $RegistryValue = @("yes")  # Value(s) expected in STIG
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Check for signatures on downloaded programs"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223080 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223080
        STIG ID    : DTBI375-IE11
        Rule ID    : SV-223080r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : All network paths (UNCs) for Intranet sites must be disallowed.
        DiscussMD5 : B2C7DBE524823BA834C1B15580181E20
        CheckMD5   : AF62A68FC82336019EDFB5210B5996E8
        FixMD5     : A70852DDA1DCD900B1B539FC96E7A385
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap"  # Registry path identified in STIG
    $RegistryValueName = "UNCAsIntranet"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Intranet Sites: Include all network paths (UNCs)"  # GPO setting name identified in STIG
    $SettingState = "Disabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223081 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223081
        STIG ID    : DTBI385-IE11
        Rule ID    : SV-223081r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Script-initiated windows without size or position constraints must be disallowed (Internet zone).
        DiscussMD5 : 7931C2D0C1211043D9E111AF157643C6
        CheckMD5   : E8B44B0DEB14D0F7F749E3E5235B11AC
        FixMD5     : B43A63C92C6F0493D98C19A0B77DB0A4
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "2102"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Allow script-initiated windows without size or position constraints"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223082 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223082
        STIG ID    : DTBI390-IE11
        Rule ID    : SV-223082r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Script-initiated windows without size or position constraints must be disallowed (Restricted Sites zone).
        DiscussMD5 : 7931C2D0C1211043D9E111AF157643C6
        CheckMD5   : D50D7C5FF7C666BE36987EB8FEE5BB90
        FixMD5     : 3BFC69826EA2B2E8FDEF7037C34786EE
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "2102"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Allow script-initiated windows without size or position constraints"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223083 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223083
        STIG ID    : DTBI395-IE11
        Rule ID    : SV-223083r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Scriptlets must be disallowed (Internet zone).
        DiscussMD5 : 55057DB1E1341F8B48ECEE81388D379C
        CheckMD5   : 659FAF5C65BB5ABAA46BFAA3CC9EA3B0
        FixMD5     : F70B0DBCA9C09CBF631724B2CFFC420F
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "1209"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Allow Scriptlets"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223084 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223084
        STIG ID    : DTBI415-IE11
        Rule ID    : SV-223084r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Automatic prompting for file downloads must be disallowed (Internet zone).
        DiscussMD5 : 2A2DE0A3A061FEE5E4F1B34B5D17B225
        CheckMD5   : 1A72DA321AA91CD11B0C876A0EF01711
        FixMD5     : 2F9B53FC9AD6B3A9AADFCB42B8C5916F
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "2200"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Automatic prompting for file downloads"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223085 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223085
        STIG ID    : DTBI425-IE11
        Rule ID    : SV-223085r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Java permissions must be disallowed (Local Machine zone).
        DiscussMD5 : C7C5F24928C71C127D026DE1EE6AF0B6
        CheckMD5   : 625CB1C7BD25F45CE4496CE996F0350D
        FixMD5     : 3BAC67B4E470CADE2DE1E72A86460561
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0"  # Registry path identified in STIG
    $RegistryValueName = "1C00"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Java permissions"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable Java)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223086 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223086
        STIG ID    : DTBI426-IE11
        Rule ID    : SV-223086r879628_rule
        CCI ID     : CCI-001662
        Rule Name  : SRG-APP-000207
        Rule Title : Anti-Malware programs against ActiveX controls must be run for the Local Machine zone.
        DiscussMD5 : 7DE8EB0968354C09D8B06C9210895D83
        CheckMD5   : 95F4DBFA10ED856A97105613553D41F8
        FixMD5     : A6E0A89057059E7106B4FA275D6EAD34
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0"  # Registry path identified in STIG
    $RegistryValueName = "270C"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Don't run antimalware programs against ActiveX controls"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223087 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223087
        STIG ID    : DTBI430-IE11
        Rule ID    : SV-223087r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Java permissions must be disallowed (Locked Down Local Machine zone).
        DiscussMD5 : 6C70B017C0E2959EC955D6D4D20CF6BD
        CheckMD5   : C500DB5096EF56DB17A823690F169D5D
        FixMD5     : 9848D6E836D2D8981D52B5A74A6C2F76
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0"  # Registry path identified in STIG
    $RegistryValueName = "1C00"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Java permissions"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable Java)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223088 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223088
        STIG ID    : DTBI435-IE11
        Rule ID    : SV-223088r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Java permissions must be disallowed (Locked Down Intranet zone).
        DiscussMD5 : 6C70B017C0E2959EC955D6D4D20CF6BD
        CheckMD5   : BA66544C782E7A725AFF73CE4F43A665
        FixMD5     : ADF1AF2AD57F4AEB51C0406B76C678F5
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1"  # Registry path identified in STIG
    $RegistryValueName = "1C00"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Java permissions"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable Java)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223089 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223089
        STIG ID    : DTBI440-IE11
        Rule ID    : SV-223089r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Java permissions must be disallowed (Locked Down Trusted Sites zone).
        DiscussMD5 : DE761D8708A4F698F3C8CA062BF19F43
        CheckMD5   : 12A636EAC20CABAE6BD035D6DF07E022
        FixMD5     : 947D3F79BEE8444C3ECB61E65FFDD9CE
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2"  # Registry path identified in STIG
    $RegistryValueName = "1C00"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Java permissions"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable Java)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223090 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223090
        STIG ID    : DTBI450-IE11
        Rule ID    : SV-223090r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Java permissions must be disallowed (Locked Down Restricted Sites zone).
        DiscussMD5 : 18DE0BD786B3D3D283387C495610F962
        CheckMD5   : 84D4EE0CE91E7FC70F51060832485482
        FixMD5     : D168ACFB9A40D5C991E60DE153F6B26E
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "1C00"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Java permissions"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable Java)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223091 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223091
        STIG ID    : DTBI455-IE11
        Rule ID    : SV-223091r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : XAML files must be disallowed (Internet zone).
        DiscussMD5 : BBA8F7D4AFE3175647CD8A28B476BBC4
        CheckMD5   : 7B5F27B80495D5F9064B5AB6DB1E4D42
        FixMD5     : CAAA2AC899A8D111EC53E9D74285602F
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "2402"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Allow loading of XAML files"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223092 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223092
        STIG ID    : DTBI460-IE11
        Rule ID    : SV-223092r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : XAML files must be disallowed (Restricted Sites zone).
        DiscussMD5 : BBA8F7D4AFE3175647CD8A28B476BBC4
        CheckMD5   : 0F002984F6A4DBE6E7723C5FC3B9400A
        FixMD5     : A90BF24C6012E3FA951C6C7FBAB81B2D
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "2402"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Allow loading of XAML files"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223093 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223093
        STIG ID    : DTBI485-IE11
        Rule ID    : SV-223093r879643_rule
        CCI ID     : CCI-001084
        Rule Name  : SRG-APP-000233
        Rule Title : Protected Mode must be enforced (Internet zone).
        DiscussMD5 : FE106AC6E7F289E7D994FD03978F8498
        CheckMD5   : 50F2369178510D362C39D87B59D6184F
        FixMD5     : 6ED67FA9586E5E9D0FA8719D087EF1EA
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "2500"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Turn on Protected Mode"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Enable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223094 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223094
        STIG ID    : DTBI490-IE11
        Rule ID    : SV-223094r879643_rule
        CCI ID     : CCI-001084
        Rule Name  : SRG-APP-000233
        Rule Title : Protected Mode must be enforced (Restricted Sites zone).
        DiscussMD5 : FE106AC6E7F289E7D994FD03978F8498
        CheckMD5   : 11A5807D59EA861892AF2F32D23AAFB6
        FixMD5     : 95441403538AF70B2C579C8FA407FE50
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "2500"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Turn on Protected Mode"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Enable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223095 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223095
        STIG ID    : DTBI495-IE11
        Rule ID    : SV-223095r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Pop-up Blocker must be enforced (Internet zone).
        DiscussMD5 : DF3A3ACF92B5286EAFA543CC4D526727
        CheckMD5   : 51F237737836E03DAAF739DE6716E978
        FixMD5     : 0FC5A849C58379DCEBA19788DAC52D03
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "1809"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Use Pop-up Blocker"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Enable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223096 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223096
        STIG ID    : DTBI500-IE11
        Rule ID    : SV-223096r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Pop-up Blocker must be enforced (Restricted Sites zone).
        DiscussMD5 : DF3A3ACF92B5286EAFA543CC4D526727
        CheckMD5   : 797113F5360438C20689B9AB3E82DEBA
        FixMD5     : 5B52153EDDFB6C7B4D0D202C5B82C518
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "1809"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Use Pop-up Blocker"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Enable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223097 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223097
        STIG ID    : DTBI515-IE11
        Rule ID    : SV-223097r879534_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-APP-000039
        Rule Title : Websites in less privileged web content zones must be prevented from navigating into the Internet zone.
        DiscussMD5 : F39A08E63B64A71EEC7E76E8291F8A79
        CheckMD5   : 7B6CD612461ECA1EE2C8FBD6A548EE93
        FixMD5     : 046E87DD7CCD4F5508D52949DBFDB27D
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "2101"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Web sites in less privileged Web content zones can navigate into this zone"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223098 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223098
        STIG ID    : DTBI520-IE11
        Rule ID    : SV-223098r879534_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-APP-000039
        Rule Title : Websites in less privileged web content zones must be prevented from navigating into the Restricted Sites zone.
        DiscussMD5 : CBD962270986CCD9FB9A6DBB4A4CF247
        CheckMD5   : C1548A54FA8D7B0607382997022919B2
        FixMD5     : 4020E7B4C507748D0B61562B660BFFD2
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "2101"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Web sites in less privileged Web content zones can navigate into this zone"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223099 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223099
        STIG ID    : DTBI575-IE11
        Rule ID    : SV-223099r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Allow binary and script behaviors must be disallowed (Restricted Sites zone).
        DiscussMD5 : 268F71C450F671A1298E225B8AE4EEB2
        CheckMD5   : A7E67C4272440C117A045BD1862EFA7A
        FixMD5     : E47F770871EEB0C24190C712B8F57FE9
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "2000"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Allow binary and script behaviors"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223100 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223100
        STIG ID    : DTBI580-IE11
        Rule ID    : SV-223100r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Automatic prompting for file downloads must be disallowed (Restricted Sites zone).
        DiscussMD5 : 2A2DE0A3A061FEE5E4F1B34B5D17B225
        CheckMD5   : 702A4360415D4E6E8223FC163CA5098F
        FixMD5     : 93E474B4FCA2B5C87CB363A6A84C6249
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "2200"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Automatic prompting for file downloads"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223101 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223101
        STIG ID    : DTBI590-IE11
        Rule ID    : SV-223101r879627_rule
        CCI ID     : CCI-001166
        Rule Name  : SRG-APP-000206
        Rule Title : Internet Explorer Processes for MIME handling must be enforced. (Reserved)
        DiscussMD5 : 6EDBBE4CFD28D86AA7564170FE24C189
        CheckMD5   : 77577D657A322EF7CA8596B97DD77F06
        FixMD5     : 574DCF4195B30923DCD87B9F00F63A67
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING"  # Registry path identified in STIG
    $RegistryValueName = "(Reserved)"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Internet Explorer Processes"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223102 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223102
        STIG ID    : DTBI592-IE11
        Rule ID    : SV-223102r879627_rule
        CCI ID     : CCI-001166
        Rule Name  : SRG-APP-000206
        Rule Title : Internet Explorer Processes for MIME handling must be enforced (Explorer).
        DiscussMD5 : 97F63A237E9427B4157E76A5B05064BE
        CheckMD5   : E1FF9E49A9646320710BDADA5232B77F
        FixMD5     : 62267603CCD838B116EBD958A956EE56
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING"  # Registry path identified in STIG
    $RegistryValueName = "explorer.exe"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Internet Explorer Processes"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223103 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223103
        STIG ID    : DTBI594-IE11
        Rule ID    : SV-223103r879627_rule
        CCI ID     : CCI-001166
        Rule Name  : SRG-APP-000206
        Rule Title : Internet Explorer Processes for MIME handling must be enforced (iexplore).
        DiscussMD5 : 080289631EF395E0AED6297B02CF9E12
        CheckMD5   : 102D1A1C2350737CD296873340F5A992
        FixMD5     : 62267603CCD838B116EBD958A956EE56
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING"  # Registry path identified in STIG
    $RegistryValueName = "iexplore.exe"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Internet Explorer Processes"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223104 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223104
        STIG ID    : DTBI595-IE11
        Rule ID    : SV-223104r879627_rule
        CCI ID     : CCI-001166
        Rule Name  : SRG-APP-000206
        Rule Title : Internet Explorer Processes for MIME sniffing must be enforced (Reserved).
        DiscussMD5 : 75B2A39B8D821F52E875B017BDA20624
        CheckMD5   : 1D6A879AC11E58111301EDB70763603E
        FixMD5     : 83FEF0F77628DB316803BB76A8355864
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING"  # Registry path identified in STIG
    $RegistryValueName = "(Reserved)"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Internet Explorer Processes"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223105 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223105
        STIG ID    : DTBI596-IE11
        Rule ID    : SV-223105r879627_rule
        CCI ID     : CCI-001166
        Rule Name  : SRG-APP-000206
        Rule Title : Internet Explorer Processes for MIME sniffing must be enforced (Explorer).
        DiscussMD5 : 4CB92B9C282A11CA22F522AE3C74B5A6
        CheckMD5   : 93DD98BB3CDF427E25BD5C6795797481
        FixMD5     : AA278C4C378CE4FC2BF83F223292F302
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING"  # Registry path identified in STIG
    $RegistryValueName = "explorer.exe"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Internet Explorer Processes"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223106 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223106
        STIG ID    : DTBI597-IE11
        Rule ID    : SV-223106r879627_rule
        CCI ID     : CCI-001166
        Rule Name  : SRG-APP-000206
        Rule Title : Internet Explorer Processes for MIME sniffing must be enforced (iexplore).
        DiscussMD5 : 4CB92B9C282A11CA22F522AE3C74B5A6
        CheckMD5   : 6F4B06ABFA2D48163573F1003C3A11BF
        FixMD5     : 83FEF0F77628DB316803BB76A8355864
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING"  # Registry path identified in STIG
    $RegistryValueName = "iexplore.exe"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Internet Explorer Processes"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223107 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223107
        STIG ID    : DTBI599-IE11
        Rule ID    : SV-223107r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Internet Explorer Processes for MK protocol must be enforced (Reserved).
        DiscussMD5 : 4D436D6BCA8E013A05D274D48DB92D82
        CheckMD5   : E31A0363BC878320986F050F6C33E08B
        FixMD5     : A1E646D36F9BE8946672663E0AA1FDA8
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL"  # Registry path identified in STIG
    $RegistryValueName = "(Reserved)"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Internet Explorer Processes"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223108 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223108
        STIG ID    : DTBI600-IE11
        Rule ID    : SV-223108r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Internet Explorer Processes for MK protocol must be enforced (Explorer).
        DiscussMD5 : E64C3E372CDB9B4C56C87116AEBEF7C7
        CheckMD5   : 8CAA96513831B3B253D63C272045E916
        FixMD5     : A1E646D36F9BE8946672663E0AA1FDA8
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL"  # Registry path identified in STIG
    $RegistryValueName = "explorer.exe"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Internet Explorer Processes"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223109 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223109
        STIG ID    : DTBI605-IE11
        Rule ID    : SV-223109r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Internet Explorer Processes for MK protocol must be enforced (iexplore).
        DiscussMD5 : CD9C94A9913E6D247528AA8A919C1DFB
        CheckMD5   : B61082044F8CF7CEA744F7A579CEF334
        FixMD5     : AD5AEFC9E3D8E54D895ADDFF8D718F07
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL"  # Registry path identified in STIG
    $RegistryValueName = "iexplore.exe"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Internet Explorer Processes"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223110 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223110
        STIG ID    : DTBI610-IE11
        Rule ID    : SV-223110r879643_rule
        CCI ID     : CCI-001084
        Rule Name  : SRG-APP-000233
        Rule Title : Internet Explorer Processes for Zone Elevation must be enforced (Reserved).
        DiscussMD5 : FFBE29F8E9A59C9E554344AD567BE2BE
        CheckMD5   : 8F69328296A9DAD55CA0F1BDBDC73E62
        FixMD5     : 4CC4FED9108E7AC90314747A0C9BB751
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION"  # Registry path identified in STIG
    $RegistryValueName = "(Reserved)"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Internet Explorer Processes"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223111 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223111
        STIG ID    : DTBI612-IE11
        Rule ID    : SV-223111r879643_rule
        CCI ID     : CCI-001084
        Rule Name  : SRG-APP-000233
        Rule Title : Internet Explorer Processes for Zone Elevation must be enforced (Explorer).
        DiscussMD5 : 7DDA5DD4A194615B65948507BDA7528E
        CheckMD5   : 923D13C42A41E7C0FB179C0263CAFC5A
        FixMD5     : 4CC4FED9108E7AC90314747A0C9BB751
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION"  # Registry path identified in STIG
    $RegistryValueName = "explorer.exe"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Internet Explorer Processes"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223112 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223112
        STIG ID    : DTBI614-IE11
        Rule ID    : SV-223112r879643_rule
        CCI ID     : CCI-001084
        Rule Name  : SRG-APP-000233
        Rule Title : Internet Explorer Processes for Zone Elevation must be enforced (iexplore).
        DiscussMD5 : FFBE29F8E9A59C9E554344AD567BE2BE
        CheckMD5   : 312CF688A898DD585D32D69B17506C74
        FixMD5     : 4CC4FED9108E7AC90314747A0C9BB751
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION"  # Registry path identified in STIG
    $RegistryValueName = "iexplore.exe"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Internet Explorer Processes"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223113 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223113
        STIG ID    : DTBI630-IE11
        Rule ID    : SV-223113r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Internet Explorer Processes for Restrict File Download must be enforced (Reserved).
        DiscussMD5 : 4496C570653D33E8E1848D664AA237E1
        CheckMD5   : D7AC1065C12D164D208D0379B6F28152
        FixMD5     : A0D3CE8EF03A84F3D48B831D5A9BFE89
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD"  # Registry path identified in STIG
    $RegistryValueName = "(Reserved)"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Internet Explorer Processes"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223114 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223114
        STIG ID    : DTBI635-IE11
        Rule ID    : SV-223114r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Internet Explorer Processes for Restrict File Download must be enforced (Explorer).
        DiscussMD5 : 4496C570653D33E8E1848D664AA237E1
        CheckMD5   : DF1A0293FC8F8E48EC9F21287EEE8287
        FixMD5     : 5A37950937AEEDBA2D5F166BE841A852
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD"  # Registry path identified in STIG
    $RegistryValueName = "explorer.exe"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Internet Explorer Processes"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223115 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223115
        STIG ID    : DTBI640-IE11
        Rule ID    : SV-223115r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Internet Explorer Processes for Restrict File Download must be enforced (iexplore).
        DiscussMD5 : 4496C570653D33E8E1848D664AA237E1
        CheckMD5   : ED27BAB43200FEB35636E415193FCE67
        FixMD5     : A0D3CE8EF03A84F3D48B831D5A9BFE89
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD"  # Registry path identified in STIG
    $RegistryValueName = "iexplore.exe"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Internet Explorer Processes"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223116 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223116
        STIG ID    : DTBI645-IE11
        Rule ID    : SV-223116r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Internet Explorer Processes for restricting pop-up windows must be enforced (Reserved).
        DiscussMD5 : 35317BF4E0A9E9F92D421EBC65438428
        CheckMD5   : 0CAAF4803E893D198F17C5ACCEE79323
        FixMD5     : 8158C5A314CF0DF60282CF0AFD6F8B6D
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS"  # Registry path identified in STIG
    $RegistryValueName = "(Reserved)"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Internet Explorer Processes"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223117 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223117
        STIG ID    : DTBI647-IE11
        Rule ID    : SV-223117r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Internet Explorer Processes for restricting pop-up windows must be enforced (Explorer).
        DiscussMD5 : 13070067091257CA8F6DD484517E6F35
        CheckMD5   : 5864593CEDD9BB8A08F4902603E2BBBF
        FixMD5     : 36CC16A2BA56781AB766B629CFFC25C3
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS"  # Registry path identified in STIG
    $RegistryValueName = "explorer.exe"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Internet Explorer Processes"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223118 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223118
        STIG ID    : DTBI649-IE11
        Rule ID    : SV-223118r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Internet Explorer Processes for restricting pop-up windows must be enforced (iexplore).
        DiscussMD5 : 13070067091257CA8F6DD484517E6F35
        CheckMD5   : A07BAF78EA2562DDB18C95FAA14D99EB
        FixMD5     : 38BBADC0E4C7A7F59BB17113A81D503D
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS"  # Registry path identified in STIG
    $RegistryValueName = "iexplore.exe"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Internet Explorer Processes"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223119 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223119
        STIG ID    : DTBI650-IE11
        Rule ID    : SV-223119r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : .NET Framework-reliant components not signed with Authenticode must be disallowed to run (Restricted Sites Zone).
        DiscussMD5 : C8FF3A7A778F38D060CC87CA6CD70B4B
        CheckMD5   : DE39C0D53450EFA8558C2897BBA1144D
        FixMD5     : 403E920A609F54ECC642E096D0962913
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "2004"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Run .NET Framework-reliant components not signed with Authenticode"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223120 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223120
        STIG ID    : DTBI655-IE11
        Rule ID    : SV-223120r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : .NET Framework-reliant components signed with Authenticode must be disallowed to run (Restricted Sites Zone).
        DiscussMD5 : 90474E3297BB55F785064FB48A6CD632
        CheckMD5   : 91C74FAC974CC6FB13A7D1F2C9EFE59A
        FixMD5     : 4DB280A0438C14A97B1F11A2D9B0D3F8
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "2001"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Run .NET Framework-reliant components signed with Authenticode"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223121 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223121
        STIG ID    : DTBI670-IE11
        Rule ID    : SV-223121r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Scripting of Java applets must be disallowed (Restricted Sites zone).
        DiscussMD5 : 294088ED9A7F0EF583C0C98EDC4B6300
        CheckMD5   : D1CA0CDACE3FE93C97FE61C216EFC0D7
        FixMD5     : CA4B1C7CAE9ECBBBEE96675A3FD429A6
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "1402"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Scripting of Java applets"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223122 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223122
        STIG ID    : DTBI690-IE11
        Rule ID    : SV-223122r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : AutoComplete feature for forms must be disallowed.
        DiscussMD5 : 943C61EF8749A5B15940986104FF33FE
        CheckMD5   : 586349581814AE8558B5615A07DD4CC7
        FixMD5     : 50A423E893047A695875CE4B88B26649
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
    $TempUserHivePath = "Registry::HKU\Evaluate-STIG_UserHive\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"  # User's loaded hive to perform check
    $RegistryPath = "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"  # Registry path identified in STIG
    $RegistryValueName = "Use FormSuggest"  # Value name identified in STIG
    $RegistryValue = @("no")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Disable AutoComplete for forms"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223123 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223123
        STIG ID    : DTBI715-IE11
        Rule ID    : SV-223123r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Crash Detection management must be enforced.
        DiscussMD5 : F81593B92C4B9629E1AA27597D75888A
        CheckMD5   : E57B17F07B82489B3BCC6E77256583D3
        FixMD5     : 0D416DB4D0C6BE50D451F61DC8390AD7
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Restrictions"  # Registry path identified in STIG
    $RegistryValueName = "NoCrashDetection"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Turn off Crash Detection"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223124 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223124
        STIG ID    : DTBI725-IE11
        Rule ID    : SV-223124r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Turn on the auto-complete feature for user names and passwords on forms must be disabled.
        DiscussMD5 : 9CFBAF988156338EB91F77409F0EAD9A
        CheckMD5   : 476631763B317C8F1547A7ACD8B35932
        FixMD5     : 41C6CFE684ED76279248C95A7432C176
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
    $TempUserHivePath = "Registry::HKU\Evaluate-STIG_UserHive\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"  # User's loaded hive to perform check
    $RegistryPath = "HKCU:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"  # Registry path identified in STIG
    $RegistryValueName1 = "FormSuggest Passwords"  # Value name identified in STIG
    $RegistryValueName2 = "FormSuggest PW Ask"  # Value name identified in STIG
    $RegistryValue = @("no")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Turn on the auto-complete feature for user names and passwords on forms"  # GPO setting name identified in STIG
    $SettingState = "Disabled"  # GPO configured state identified in STIG.

    $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
    $FindingDetails += "" | Out-String
    $RegistryResult1 = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName1
    $RegistryResult2 = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName2

    If ($RegistryResult1.Type -eq "(NotFound)" -or $RegistryResult2.Type -eq "(NotFound)") {
        $Status = "Open"
        $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
    }
    Else {
        If (($RegistryResult1.Value -in $RegistryValue -and $RegistryResult1.Type -eq $RegistryType) -and ($RegistryResult2.Value -in $RegistryValue -and $RegistryResult2.Type -eq $RegistryType)) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
        }
    }

    $FindingDetails += "" | Out-String
    $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
    $FindingDetails += "Value Name:`t$RegistryValueName1" | Out-String
    $FindingDetails += "Value:`t`t$($RegistryResult1.Value)" | Out-String
    $FindingDetails += "Type:`t`t$($RegistryResult1.Type)" | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
    $FindingDetails += "Value Name:`t$RegistryValueName2" | Out-String
    $FindingDetails += "Value:`t`t$($RegistryResult2.Value)" | Out-String
    $FindingDetails += "Type:`t`t$($RegistryResult2.Type)" | Out-String
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

Function Get-V223125 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223125
        STIG ID    : DTBI740-IE11
        Rule ID    : SV-223125r879627_rule
        CCI ID     : CCI-001166
        Rule Name  : SRG-APP-000206
        Rule Title : Managing SmartScreen Filter use must be enforced.
        DiscussMD5 : BBD7A46B8C9F8ED4F928F8784C1FCFFC
        CheckMD5   : 37C270EDC755008710567A81C1588C6F
        FixMD5     : F06F9B8E8195BFA57F38D688B3246C75
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
    If ($ScanType -in @("Classified")) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA." | Out-String
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter"  # Registry path identified in STIG
        $RegistryValueName = "EnabledV9"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Prevent Managing SmartScreen Filter"  # GPO setting name identified in STIG
        $SettingState = "Enabled: (On)"  # GPO configured state identified in STIG.
        $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

        If ($TempUserHivePath) {
            $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
            $FindingDetails += "" | Out-String
            $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
        }
        Else {
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
        }

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            If ($SettingNotConfiguredAllowed -eq $true) {
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
                }
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

Function Get-V223126 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223126
        STIG ID    : DTBI760-IE11
        Rule ID    : SV-223126r879559_rule
        CCI ID     : CCI-000169
        Rule Name  : SRG-APP-000089
        Rule Title : Browser must retain history on exit.
        DiscussMD5 : D37CC26B7C09CFDD1187B9B17AFEAA6F
        CheckMD5   : BDE526C8185D4298FAC9222B88C1E25C
        FixMD5     : BFB97FADF06358C68383DD0CA86EF3B8
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Privacy"  # Registry path identified in STIG
    $RegistryValueName = "ClearBrowsingHistoryOnExit"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Allow deleting browsing history on exit"  # GPO setting name identified in STIG
    $SettingState = "Disabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223127 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223127
        STIG ID    : DTBI770-IE11
        Rule ID    : SV-223127r879559_rule
        CCI ID     : CCI-000169
        Rule Name  : SRG-APP-000089
        Rule Title : Deleting websites that the user has visited must be disallowed.
        DiscussMD5 : E15DEF051E84916D0055FF757308FB03
        CheckMD5   : 1FE9D1E824A812F91FC98256698BA292
        FixMD5     : A33541CA6179BC63D6040E7F03A8D3EF
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Privacy"  # Registry path identified in STIG
    $RegistryValueName = "CleanHistory"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Prevent Deleting Web sites that the User has Visited"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223128 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223128
        STIG ID    : DTBI780-IE11
        Rule ID    : SV-223128r879554_rule
        CCI ID     : CCI-000166
        Rule Name  : SRG-APP-000080
        Rule Title : InPrivate Browsing must be disallowed.
        DiscussMD5 : 644BA1D8E68E05742534AD6D8F9B06D7
        CheckMD5   : 00FD2FEE8415988D675D463E32ED1E58
        FixMD5     : DC97676C2A73CF66117FD2D476D82018
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Privacy"  # Registry path identified in STIG
    $RegistryValueName = "EnableInPrivateBrowsing"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Turn off InPrivate Browsing"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223129 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223129
        STIG ID    : DTBI800-IE11
        Rule ID    : SV-223129r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Scripting of Internet Explorer WebBrowser control property must be disallowed (Internet zone).
        DiscussMD5 : 3DB8F6442837F0A5DDE68CCA90F11FBF
        CheckMD5   : E0BA3FE781B5B555523BA166773123DF
        FixMD5     : 66E664743DF81A46E1053493C8E03EBD
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "1206"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Allow scripting of Internet Explorer WebBrowser controls"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223130 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223130
        STIG ID    : DTBI810-IE11
        Rule ID    : SV-223130r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : When uploading files to a server, the local directory path must be excluded (Internet zone).
        DiscussMD5 : 227999B66752A6E4FB299F64B90B8F67
        CheckMD5   : FEA52934F7EDCB127250482AAADDB5E2
        FixMD5     : 531B3FFF53D13AD1D30DD15E8A4BA70C
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "160A"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Include local path when user is uploading files to a server"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223131 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223131
        STIG ID    : DTBI815-IE11
        Rule ID    : SV-223131r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Internet Explorer Processes for Notification Bars must be enforced (Reserved).
        DiscussMD5 : 57BAE6C325B309EC8900885E45E6D657
        CheckMD5   : 3485DDBF186BF30304A18C52E3EAA3D4
        FixMD5     : 1A0C53B4EEE4655253B8848ED6686450
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND"  # Registry path identified in STIG
    $RegistryValueName = "(Reserved)"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Internet Explorer Processes"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223132 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223132
        STIG ID    : DTBI820-IE11
        Rule ID    : SV-223132r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : Security Warning for unsafe files must be set to prompt (Internet zone).
        DiscussMD5 : B7B19F56CCF5332B36E250962F20BE1D
        CheckMD5   : 0340AE5DD3B19E6E544C2E827382D121
        FixMD5     : 7F712DCD45C6F23957D51E3D1988A00E
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "1806"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Show security warning for potentially unsafe files"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Prompt)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223133 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223133
        STIG ID    : DTBI825-IE11
        Rule ID    : SV-223133r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Internet Explorer Processes for Notification Bars must be enforced (Explorer).
        DiscussMD5 : 57BAE6C325B309EC8900885E45E6D657
        CheckMD5   : D43D0B7B39B36ECFE9E005E38A88E836
        FixMD5     : 92ADE689E05D4D55123AA854904F0241
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND"  # Registry path identified in STIG
    $RegistryValueName = "explorer.exe"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Internet Explorer Processes"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223134 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223134
        STIG ID    : DTBI830-IE11
        Rule ID    : SV-223134r879630_rule
        CCI ID     : CCI-001170
        Rule Name  : SRG-APP-000210
        Rule Title : ActiveX controls without prompt property must be used in approved domains only (Internet zone).
        DiscussMD5 : FC95090EF50B0582D8498D5DD8A882F1
        CheckMD5   : F056610F4A69EFC22BA7AEE56B78CED4
        FixMD5     : 3715F3D5E855C2E9D7C9ECB93115F45E
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "120b"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Allow only approved domains to use ActiveX controls without prompt"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Enable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223135 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223135
        STIG ID    : DTBI835-IE11
        Rule ID    : SV-223135r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Internet Explorer Processes for Notification Bars must be enforced (iexplore).
        DiscussMD5 : 57BAE6C325B309EC8900885E45E6D657
        CheckMD5   : 931FD36105E7B392CCD12D0EEB38AF92
        FixMD5     : 1A0C53B4EEE4655253B8848ED6686450
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND"  # Registry path identified in STIG
    $RegistryValueName = "iexplore.exe"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Internet Explorer Processes"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223136 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223136
        STIG ID    : DTBI840-IE11
        Rule ID    : SV-223136r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Cross-Site Scripting Filter must be enforced (Internet zone).
        DiscussMD5 : 48FCE046F6EEDF5F813BA6D4CA788EA5
        CheckMD5   : DF6EB8BF0E1F2C0890A9F3DC82A1055E
        FixMD5     : C2840FA4FDB8E51F465074DA8690AD8F
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "1409"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Turn on Cross-Site Scripting Filter"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Enable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223137 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223137
        STIG ID    : DTBI850-IE11
        Rule ID    : SV-223137r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Scripting of Internet Explorer WebBrowser Control must be disallowed (Restricted Sites zone).
        DiscussMD5 : 0A744EE863E2AC2CA8F065E8F0C8036C
        CheckMD5   : 523AF2182E13C12E53CB6BAAA56866B6
        FixMD5     : ABA0CA9631F67C2C2D1739E1DCBA314B
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "1206"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Allow scripting of Internet Explorer WebBrowser controls"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223138 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223138
        STIG ID    : DTBI860-IE11
        Rule ID    : SV-223138r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : When uploading files to a server, the local directory path must be excluded (Restricted Sites zone).
        DiscussMD5 : 227999B66752A6E4FB299F64B90B8F67
        CheckMD5   : 6506B111D6AAF68D19A9B10481CFC880
        FixMD5     : 3A0B1C756BDE22D7D9BAF34ACD6371D2
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "160A"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Include local path when user is uploading files to a server"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223139 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223139
        STIG ID    : DTBI870-IE11
        Rule ID    : SV-223139r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : Security Warning for unsafe files must be disallowed (Restricted Sites zone).
        DiscussMD5 : DFA50C27746C7AA0CA450B36B86E9005
        CheckMD5   : 41D31C2D2F159774FEF01997C2BD5275
        FixMD5     : A5EABC97DFD1E45BD2DAEE2134591C38
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "1806"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Show security warning for potentially unsafe files"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223140 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223140
        STIG ID    : DTBI880-IE11
        Rule ID    : SV-223140r879630_rule
        CCI ID     : CCI-001170
        Rule Name  : SRG-APP-000210
        Rule Title : ActiveX controls without prompt property must be used in approved domains only (Restricted Sites zone).
        DiscussMD5 : FC95090EF50B0582D8498D5DD8A882F1
        CheckMD5   : 3E5C3305E857262F03D5E4491A5849BC
        FixMD5     : DB2C8E11767B8E8198A3A91388DB8852
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "120b"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Allow only approved domains to use ActiveX controls without prompt"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Enable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223141 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223141
        STIG ID    : DTBI890-IE11
        Rule ID    : SV-223141r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Cross-Site Scripting Filter property must be enforced (Restricted Sites zone).
        DiscussMD5 : 48FCE046F6EEDF5F813BA6D4CA788EA5
        CheckMD5   : 425A3F076B902673B90E8A476DCCCC58
        FixMD5     : CC1E6D802AF2A76FB5C1029397FFE5A8
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "1409"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Turn on Cross-Site Scripting Filter"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Enable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223142 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223142
        STIG ID    : DTBI900-IE11
        Rule ID    : SV-223142r879573_rule
        CCI ID     : CCI-001695
        Rule Name  : SRG-APP-000112
        Rule Title : Internet Explorer Processes Restrict ActiveX Install must be enforced (Reserved).
        DiscussMD5 : 2A517D94495C15710DA633865E76C2D7
        CheckMD5   : E041F2453AD470B466DF98D9E7B46B03
        FixMD5     : E9F06444994CE9F3B73654B4FC6128B9
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL"  # Registry path identified in STIG
    $RegistryValueName = "(Reserved)"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_SZ"  # Value type expected in STIG
    $SettingName = "Internet Explorer Processes"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223143 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223143
        STIG ID    : DTBI910-IE11
        Rule ID    : SV-223143r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Status bar updates via script must be disallowed (Internet zone).
        DiscussMD5 : 94E79A0D515754D934E7D9B65EE23072
        CheckMD5   : 6B3CAD79D1E53D4B0988B1C173042F67
        FixMD5     : B01463F7B7E564307E69FC5DC6CB3174
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "2103"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Allow updates to status bar via script"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223144 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223144
        STIG ID    : DTBI920-IE11
        Rule ID    : SV-223144r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : .NET Framework-reliant components not signed with Authenticode must be disallowed to run (Internet zone).
        DiscussMD5 : 01E028B906D2C9060F316101C00BD6C0
        CheckMD5   : 8806084201A922672ECD7E50B9186EAB
        FixMD5     : 728AF0EE05EDC087A260D3EDDC87C4AB
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "2004"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Run .NET Framework-reliant components not signed with Authenticode"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223145 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223145
        STIG ID    : DTBI930-IE11
        Rule ID    : SV-223145r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : .NET Framework-reliant components signed with Authenticode must be disallowed to run (Internet zone).
        DiscussMD5 : A2C754AD185142E546A44991EEE8C35A
        CheckMD5   : C168E47259874EEFE42DEE2A805B4D4A
        FixMD5     : 56E721C1AE6B27C42536787A73F4345C
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "2001"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Run .NET Framework-reliant components signed with Authenticode"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223146 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223146
        STIG ID    : DTBI940-IE11
        Rule ID    : SV-223146r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Scriptlets must be disallowed (Restricted Sites zone).
        DiscussMD5 : 55057DB1E1341F8B48ECEE81388D379C
        CheckMD5   : 3E7C5CC860479B057B245B17BC73961A
        FixMD5     : 3EF8A13F0E28365419B8D70E1F684847
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "1209"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Allow Scriptlets"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223147 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223147
        STIG ID    : DTBI950-IE11
        Rule ID    : SV-223147r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Status bar updates via script must be disallowed (Restricted Sites zone).
        DiscussMD5 : CA7276C09694440FD66BDFAE0F012D81
        CheckMD5   : EC0E577E6420E7D94FE89F6A68B03CA1
        FixMD5     : ADB0B271B92BD457AE21DED879D060C4
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4"  # Registry path identified in STIG
    $RegistryValueName = "2103"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Allow updates to status bar via script"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223148 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223148
        STIG ID    : DTBI985-IE11
        Rule ID    : SV-223148r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : When Enhanced Protected Mode is enabled, ActiveX controls must be disallowed to run in Protected Mode.
        DiscussMD5 : E58AEC7794909537E45BD4347083AC52
        CheckMD5   : DE34E4822B5FB9B255DD7E727BBAA874
        FixMD5     : 07E61D14A2B0F8751C789EC5D7267DAF
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"  # Registry path identified in STIG
    $RegistryValueName = "DisableEPMCompat"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Do not allow ActiveX controls to run in Protected Mode when Enhanced Protected Mode is enabled"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V223149 {
    <#
    .DESCRIPTION
        Vuln ID    : V-223149
        STIG ID    : DTBI990-IE11
        Rule ID    : SV-223149r879534_rule
        CCI ID     : CCI-001414
        Rule Name  : SRG-APP-000039
        Rule Title : Dragging of content from different domains across windows must be disallowed (Internet zone).
        DiscussMD5 : 132D35434F3FFF8BD92C82B6B2F07103
        CheckMD5   : 56011ED10EADA22EB8EF3F02CD6F7AEB
        FixMD5     : B7D80C2124B0C374CA2B23BAC20EFC09
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3"  # Registry path identified in STIG
    $RegistryValueName = "2709"  # Value name identified in STIG
    $RegistryValue = @("3")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Enable dragging of content from different domains across windows"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Disable)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V250540 {
    <#
    .DESCRIPTION
        Vuln ID    : V-250540
        STIG ID    : DTBI014-IE11
        Rule ID    : SV-250540r942484_rule
        CCI ID     : CCI-002450
        Rule Name  : SRG-APP-000416
        Rule Title : Turn off Encryption Support must be enabled.
        DiscussMD5 : 6D3EE950FAAD7324F65BC50282A51036
        CheckMD5   : 456750BA400B2F4805360F1E0675C952
        FixMD5     : 8CD83999F6BA3ACC654226B2D85938DD
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"  # Registry path identified in STIG
    $RegistryValueName = "SecureProtocols"  # Value name identified in STIG
    $RegistryValue = @("800")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Turn off Encryption Support"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (Use TLS1.1, Use TLS 1.2)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V250541 {
    <#
    .DESCRIPTION
        Vuln ID    : V-250541
        STIG ID    : DTBI1100-IE11
        Rule ID    : SV-250541r942485_rule
        CCI ID     : CCI-002450
        Rule Name  : SRG-APP-000416
        Rule Title : Allow Fallback to SSL 3.0 (Internet Explorer) must be disabled.
        DiscussMD5 : 08532F0EF58772FA032FB3A44604D17A
        CheckMD5   : EF22D8EA6AF55E05F86BA58BEA63F3DF
        FixMD5     : FA07A8D6718C24D6C5DC600B373AB355
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"  # Registry path identified in STIG
    $RegistryValueName = "EnableSSL3Fallback"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value(s) expected in STIG
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Allow fallback to SSL 3.0 (Internet Explorer)"  # GPO setting name identified in STIG
    $SettingState = "Enabled: (No Sites)"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        If ($SettingNotConfiguredAllowed -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V252910 {
    <#
    .DESCRIPTION
        Vuln ID    : V-252910
        STIG ID    : DTBI999-IE11
        Rule ID    : SV-252910r942486_rule
        CCI ID     : CCI-002605
        Rule Name  : SRG-APP-000456
        Rule Title : The version of Internet Explorer running on the system must be a supported version.
        DiscussMD5 : D7DD5A52E6F1FCCDF41665453B71B349
        CheckMD5   : 6EAFB9F8F75EEF503A1FAF7C37927E6A
        FixMD5     : 27F2032A834C06161802263869842A17
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
    # Check for unsupported operating systems
    # https://docs.microsoft.com/en-us/lifecycle/faq/internet-explorer-microsoft-edge
    # Note, this check includes Windows 11 GPO check to match SCAP.  From DISA Request Item RITM0045851:
    # Good afternoon and thank you for contacting DISA STIG support. At the time during development for disabling IE, it was decided to include it on both Windows 10 and Windows 11 since the local security policy existed to ensure IE was disabled.
    $SupportedOS = $false
    $OSCaption = (Get-CimInstance Win32_OperatingSystem).Caption
    Switch -Wildcard ($OSCaption) {
        "*Windows*Enterprise*" {
            # Only Windows Workstation Enterprise LTSB/LTSC is still supported
            If ((Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows NT\Currentversion" -Name ProductName) -match "LTSB|LTSC") {
                $SupportedOS = $true
                $OSCaption = (Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows NT\Currentversion" -Name ProductName)
            }
        }
        "*Windows*Server*" {
            $SupportedOS = $true
        }
    }

    If ($SupportedOS -ne $true) {
        $FindingDetails += "Per the STIG, Internet Explorer 11 must be removed or disabled on $($OSCaption)." | Out-String
        $FindingDetails += "" | Out-String

        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main"  # Registry path identified in STIG
        $RegistryValueName = "NotifyDisableIEOptions"  # Value name identified in STIG
        $RegistryValue = @("0","2")  # Value(s) expected in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Disable Internet Explorer 11 as a standalone browser"  # GPO setting name identified in STIG
        $SettingState = "Enabled: ('Never [0]' or 'Once per user [2]')"  # GPO configured state identified in STIG.
        $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

        If ($TempUserHivePath) {
            $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
            $FindingDetails += "" | Out-String
            $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
        }
        Else {
            $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
        }

        If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
            $RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            If ($SettingNotConfiguredAllowed -eq $true) {
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in group policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
                }
            }
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "Internet Explorer is supported on $OSCaption" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Reference: https://docs.microsoft.com/en-us/lifecycle/faq/internet-explorer-microsoft-edge" | Out-String
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCSJ9pFJlbnaikl
# L7SH4otVkOuHA3KQ/ms09ZS4wzNAb6CCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCyodZBTM2X5WBZ4qzE/aGa5cxMjIyh
# 8X5GilzoIMUgOzANBgkqhkiG9w0BAQEFAASCAQBqhuLFuPjaxcvSgJ2mmUoAsz/6
# Wo/1dqg17xYD1+xWW7fVbTIQ5fdDAAXMmX0s51sMdk+Jc509mwvik6XDs+yOOyBE
# OUmHbHjh36JKVD17KBeSCWuUH4y/VDvU8zBdLQctDMbkFIPN+ZcT1J0cFrbOh6PZ
# wZ1eYA3z6cSUyzd7M6Aa5bTnpz6L9T7lsTDyuWie3ir4p4fgMyXwEso0H+dRECF6
# sb8T8jtvF8GvUDuJ4MhFjJSik4q2jwgjcAwo7GaL7N3agYFBA1EYzp5ae4pcq6OD
# lpFWhP1I/U4tCQy+jVbqUvol310kqBo8+FgHQt/KAMsMHdQguGORBFyrDRxz
# SIG # End signature block
