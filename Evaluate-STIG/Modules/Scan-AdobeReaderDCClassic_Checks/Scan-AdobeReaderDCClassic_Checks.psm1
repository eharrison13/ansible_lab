##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Adobe Acrobat Reader DC Classic Track
# Version:  V2R1
# Class:    UNCLASSIFIED
# Updated:  5/13/2024
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V213141 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213141
        STIG ID    : ARDC-CL-000005
        Rule ID    : SV-213141r557349_rule
        CCI ID     : CCI-001166, CCI-001169, CCI-001170, CCI-001662, CCI-001695
        Rule Name  : SRG-APP-000112
        Rule Title : Adobe Reader DC must enable Enhanced Security in a Standalone Application.
        DiscussMD5 : 551929ADB802EFBAF3B5D2245054DE19
        CheckMD5   : B8EE5271A7070A55E754A7EE633DD163
        FixMD5     : 24CE52A773D11020DF31B8CE1343D83F
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Reader*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Reader Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\FeatureLockDown"  # Registry path identified in STIG
        $RegistryValueName = "bEnhancedSecurityStandalone"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Enable Enhanced Security Standalone"  # GPO setting name identified in STIG
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
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
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

Function Get-V213142 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213142
        STIG ID    : ARDC-CL-000010
        Rule ID    : SV-213142r557349_rule
        CCI ID     : CCI-001166, CCI-001169, CCI-001170, CCI-001662, CCI-001695
        Rule Name  : SRG-APP-000112
        Rule Title : Adobe Reader DC must enable Enhanced Security in a Browser.
        DiscussMD5 : BE40CBBAC1B1A1DD5C0A56CC86C9354B
        CheckMD5   : D2BD0F9648A0DBE1FCE5C4AFEE75EF45
        FixMD5     : 25CD4793A32E6B493EB682E2EC468C72
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Reader*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Reader Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\FeatureLockDown"  # Registry path identified in STIG
        $RegistryValueName = "bEnhancedSecurityInBrowser"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Enable Enhanced Security In Browser"  # GPO setting name identified in STIG
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
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
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

Function Get-V213143 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213143
        STIG ID    : ARDC-CL-000015
        Rule ID    : SV-213143r557349_rule
        CCI ID     : CCI-001166, CCI-001169, CCI-001170, CCI-001662, CCI-001695
        Rule Name  : SRG-APP-000112
        Rule Title : Adobe Reader DC must enable Protected Mode.
        DiscussMD5 : 087AA2D8DA9528851C0B37FE0C19B3D6
        CheckMD5   : 309CFD8AAC1852006DEF8FDF6B776841
        FixMD5     : DE4102DF5F780A099C22D004E9A6A0FE
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Reader*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Reader Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\FeatureLockDown"  # Registry path identified in STIG
        $RegistryValueName = "bProtectedMode"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Protected Mode"  # GPO setting name identified in STIG
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
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
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

Function Get-V213144 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213144
        STIG ID    : ARDC-CL-000020
        Rule ID    : SV-213144r557349_rule
        CCI ID     : CCI-001166, CCI-001169, CCI-001170, CCI-001662, CCI-001695
        Rule Name  : SRG-APP-000112
        Rule Title : Adobe Reader DC must enable Protected View.
        DiscussMD5 : A3C25940DA9769F098931C63A1DE60B0
        CheckMD5   : 395A7465008EE4D538A8B0E2B27B5FFC
        FixMD5     : 9571F647748818246420CCCA0A56C0FA
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Reader*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Reader Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\FeatureLockDown"  # Registry path identified in STIG
        $RegistryValueName = "iProtectedView"  # Value name identified in STIG
        $RegistryValue = @("2")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Protected View"  # GPO setting name identified in STIG
        $SettingState = "Enabled with 'All files'"  # GPO configured state identified in STIG.
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
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
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

Function Get-V213145 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213145
        STIG ID    : ARDC-CL-000025
        Rule ID    : SV-213145r557349_rule
        CCI ID     : CCI-001166, CCI-001169, CCI-001170, CCI-001662, CCI-001695
        Rule Name  : SRG-APP-000112
        Rule Title : Adobe Reader DC must Block Websites.
        DiscussMD5 : B471C02F41E190AE786AFE8324B5FF0E
        CheckMD5   : 984B93D0BFEEFF5E873BAE7AF7C60A3B
        FixMD5     : 6157C21F69213C0A258B4CD9BFF8B4D8
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Reader*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Reader Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\FeatureLockDown\cDefaultLaunchURLPerms"  # Registry path identified in STIG
        $RegistryValueName = "iURLPerms"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Access to websites"  # GPO setting name identified in STIG
        $SettingState = "Enabled with Block PDF files access to all web sites"  # GPO configured state identified in STIG.
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
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
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

Function Get-V213146 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213146
        STIG ID    : ARDC-CL-000030
        Rule ID    : SV-213146r557349_rule
        CCI ID     : CCI-001166, CCI-001169, CCI-001170, CCI-001662, CCI-001695
        Rule Name  : SRG-APP-000112
        Rule Title : Adobe Reader DC must block access to Unknown Websites.
        DiscussMD5 : A787EB328EB4681CFE2FEE9C7CF875D4
        CheckMD5   : 8899BB813CB597FC772CA7C6E6D7748C
        FixMD5     : EA80648D6090331CC8A2590274F6B740
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Reader*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Reader Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\FeatureLockDown\cDefaultLaunchURLPerms"  # Registry path identified in STIG
        $RegistryValueName = "iUnknownURLPerms"  # Value name identified in STIG
        $RegistryValue = @("3")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Access to unknown websites"  # GPO setting name identified in STIG
        $SettingState = "Enabled with Block access"  # GPO configured state identified in STIG.
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
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
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

Function Get-V213147 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213147
        STIG ID    : ARDC-CL-000035
        Rule ID    : SV-213147r557349_rule
        CCI ID     : CCI-001166, CCI-001169, CCI-001170, CCI-001662, CCI-001695
        Rule Name  : SRG-APP-000112
        Rule Title : Adobe Reader DC must prevent opening files other than PDF or FDF.
        DiscussMD5 : D98D218CCC27A477FC53FA2BEC69121B
        CheckMD5   : B3AA72685B584B29DECD7A8E87579BC1
        FixMD5     : C31D75D4E1561718017BAA338C29EB9C
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Reader*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Reader Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\FeatureLockDown"  # Registry path identified in STIG
        $RegistryValueName = "iFileAttachmentPerms"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Allow opening of non-PDF file attachments with external applications"  # GPO setting name identified in STIG
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
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
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

Function Get-V213148 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213148
        STIG ID    : ARDC-CL-000045
        Rule ID    : SV-213148r557349_rule
        CCI ID     : CCI-001166, CCI-001169, CCI-001170, CCI-001662, CCI-001695
        Rule Name  : SRG-APP-000112
        Rule Title : Adobe Reader DC must block Flash Content.
        DiscussMD5 : D49046506BA844ECCA3F697DD3A37B38
        CheckMD5   : 5FE36E0E13B192B96D8ED4B32E4B532B
        FixMD5     : F3F969D3A38AED7B733D5C5BEF8974B1
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Reader*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Reader Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\FeatureLockDown"  # Registry path identified in STIG
        $RegistryValueName = "bEnableFlash"  # Value name identified in STIG
        $RegistryValue = @("0")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Enable Flash"  # GPO setting name identified in STIG
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
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
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

Function Get-V213149 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213149
        STIG ID    : ARDC-CL-000050
        Rule ID    : SV-213149r557349_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133
        Rule Title : Adobe Reader DC must disable the ability to change the Default Handler.
        DiscussMD5 : 593A52B3195998E80B9B88F4D3074C15
        CheckMD5   : B8A4ACBE86923BADC4E1275805BAB4B6
        FixMD5     : 2E2ABC27F0BEEB6B965838C8E8B5F43E
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Reader*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Reader Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\FeatureLockDown"  # Registry path identified in STIG
        $RegistryValueName = "bDisablePDFHandlerSwitching"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Disable PDF handler switching"  # GPO setting name identified in STIG
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
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
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

Function Get-V213150 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213150
        STIG ID    : ARDC-CL-000055
        Rule ID    : SV-213150r557349_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Adobe Reader DC must disable the Adobe Send and Track plugin for Outlook.
        DiscussMD5 : 603DE60C6EF0AC2EF5EFEE288D893CE4
        CheckMD5   : 1695DB578B868331A917B328B26FB302
        FixMD5     : 3D12A6676F8A52722CC9723AF816F2E3
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Reader*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Reader Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\FeatureLockDown\cCloud"  # Registry path identified in STIG
        $RegistryValueName = "bAdobeSendPluginToggle"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Send and Track plugin"  # GPO setting name identified in STIG
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
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
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

Function Get-V213151 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213151
        STIG ID    : ARDC-CL-000060
        Rule ID    : SV-213151r557349_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Adobe Reader DC must disable all service access to Document Cloud Services.
        DiscussMD5 : 1F8E96A9319CBEF4DECD04E06E8DBED3
        CheckMD5   : F54CC88C57720B562856F036DAB1D8BF
        FixMD5     : C47A68A6CABD1015ABC9789A19FCE630
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Reader*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Reader Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\FeatureLockDown\cServices"  # Registry path identified in STIG
        $RegistryValueName = "bToggleAdobeDocumentServices"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Service access to Document Cloud Services"  # GPO setting name identified in STIG
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
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
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

Function Get-V213152 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213152
        STIG ID    : ARDC-CL-000065
        Rule ID    : SV-213152r557349_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Adobe Reader DC must disable Cloud Synchronization.
        DiscussMD5 : 2C1675CFC132762793B0E84F5718AAC3
        CheckMD5   : 5A85C88DF846D3EBFCD8772FBDEFAA92
        FixMD5     : C7171E26C731A19838840C14993A4961
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Reader*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Reader Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\FeatureLockDown\cServices"  # Registry path identified in STIG
        $RegistryValueName = "bTogglePrefsSync"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Cloud Synchronization"  # GPO setting name identified in STIG
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
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
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

Function Get-V213153 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213153
        STIG ID    : ARDC-CL-000070
        Rule ID    : SV-213153r557349_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Adobe Reader DC must disable the Adobe Repair Installation.
        DiscussMD5 : 12E3B802E5542293B5916A9A35EE74CC
        CheckMD5   : 97A77FF53C008B85121A1FB976F7D776
        FixMD5     : AF6CE481E19ED67FB7BFC0F290D7AE84
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Reader*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Reader Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPathArr = @("HKLM:\SOFTWARE\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\Installer", "HKLM:\SOFTWARE\Wow6432Node\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\Installer")  # Registry path identified in STIG
        $RegistryValueName = "DisableMaintenance"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value(s) expected in STIG
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

        ForEach ($RegistryPath in $RegistryPathArr) {
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
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                    $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
                }
                Else {
                    $Status = "Open"
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                    $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
                }
            }
            Else {
                If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                    $Status = "NotAFinding"
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                    $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    $Status = "Open"
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

Function Get-V213154 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213154
        STIG ID    : ARDC-CL-000075
        Rule ID    : SV-213154r557349_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Adobe Reader DC must disable 3rd Party Web Connectors.
        DiscussMD5 : 755CD02D2A67D62B4DEFA4F621430CD6
        CheckMD5   : BCE02F35BEF31F3E8A7FA0BB2AEBFCA7
        FixMD5     : 1F026DCFFB7707276929023B8D47F44B
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Reader*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Reader Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\FeatureLockDown\cServices"  # Registry path identified in STIG
        $RegistryValueName = "bToggleWebConnectors"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Third-party web connectors"  # GPO setting name identified in STIG
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
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
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

Function Get-V213155 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213155
        STIG ID    : ARDC-CL-000080
        Rule ID    : SV-213155r557349_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Adobe Reader DC must disable Acrobat Upsell.
        DiscussMD5 : C9AA8EB413F3F53685D1D1D0AD3B8725
        CheckMD5   : DBF6C47E23FB34E754FDAC7CBE020C5E
        FixMD5     : 61FAF54E200DB869A53172A5915DE246
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Reader*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Reader Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\FeatureLockDown"  # Registry path identified in STIG
        $RegistryValueName = "bAcroSuppressUpsell"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Acrobat Upsell"  # GPO setting name identified in STIG
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
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
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

Function Get-V213156 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213156
        STIG ID    : ARDC-CL-000085
        Rule ID    : SV-213156r557349_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Adobe Reader DC must disable Adobe Send for Signature.
        DiscussMD5 : A9751B8453D4D995383A93B5B2CB41C8
        CheckMD5   : DB3C604AF94CD35E1D16AE1E46CC1D92
        FixMD5     : 1231F79F1EF35B022DF56F431752510D
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Reader*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Reader Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\FeatureLockDown\cServices"  # Registry path identified in STIG
        $RegistryValueName = "bToggleAdobeSign"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Adobe Send for Signature"  # GPO setting name identified in STIG
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
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
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

Function Get-V213157 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213157
        STIG ID    : ARDC-CL-000090
        Rule ID    : SV-213157r557349_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Adobe Reader DC must disable access to Webmail.
        DiscussMD5 : CC3A6595F72B9BACB0F79399BAFC3E7E
        CheckMD5   : 9469D642A247F9506620524DA5B5FE06
        FixMD5     : 3C42DED622F21D5AFB4E2CA9B0742FCD
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Reader*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Reader Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\FeatureLockDown\cWebmailProfiles"  # Registry path identified in STIG
        $RegistryValueName = "bDisableWebmail"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "WebMail"  # GPO setting name identified in STIG
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
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
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

Function Get-V213158 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213158
        STIG ID    : ARDC-CL-000100
        Rule ID    : SV-213158r557349_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Adobe Reader DC must disable Online SharePoint Access.
        DiscussMD5 : 68CF6CEC082565F726D92200CB7D45F4
        CheckMD5   : 2246E1CD125B1D05E1DEF3206FB48823
        FixMD5     : E1FCAB64DC36A7A0953B073681D8BFD5
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Reader*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Reader Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\FeatureLockDown\cSharePoint"  # Registry path identified in STIG
        $RegistryValueName = "bDisableSharePointFeatures"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Online SharePoint Access"  # GPO setting name identified in STIG
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
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
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

Function Get-V213159 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213159
        STIG ID    : ARDC-CL-000115
        Rule ID    : SV-213159r557349_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Adobe Reader DC must disable the Adobe Welcome Screen.
        DiscussMD5 : 4C42F437C1FBC1DEEB5F3B4DA672FE48
        CheckMD5   : 9B66126C7C315F84636010CBAAEC282B
        FixMD5     : 94F76E5E909A9A64DCA0E8C76B458ADC
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Reader*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Reader Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\FeatureLockDown\cWelcomeScreen"  # Registry path identified in STIG
        $RegistryValueName = "bShowWelcomeScreen"  # Value name identified in STIG
        $RegistryValue = @("0")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Welcome Screen"  # GPO setting name identified in STIG
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
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
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

Function Get-V213160 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213160
        STIG ID    : ARDC-CL-000120
        Rule ID    : SV-213160r557349_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Adobe Reader DC must disable Service Upgrades.
        DiscussMD5 : D259A9A620AB143A9CF341ACDCA69682
        CheckMD5   : 1AE1FAE498E06D6166B8F4F72F347AB7
        FixMD5     : 64572AAFC28796BAE9FEB1E57752A652
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Reader*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Reader Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\FeatureLockDown\cServices"  # Registry path identified in STIG
        $RegistryValueName = "bUpdater"  # Value name identified in STIG
        $RegistryValue = @("0")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Service Upgrades"  # GPO setting name identified in STIG
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
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
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

Function Get-V213161 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213161
        STIG ID    : ARDC-CL-000315
        Rule ID    : SV-213161r557349_rule
        CCI ID     : CCI-001813
        Rule Name  : SRG-APP-000380
        Rule Title : Adobe Reader DC must disable the ability to add Trusted Files and Folders.
        DiscussMD5 : 91009D6047A2D8050D34899FF8BE9AC0
        CheckMD5   : 5A753173BD80C60119DC44D079CBE047
        FixMD5     : D5C9232DCE9EB276092EB9421CCC380D
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Reader*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Reader Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\FeatureLockDown"  # Registry path identified in STIG
        $RegistryValueName = "bDisableTrustedFolders"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Privileged folder locations"  # GPO setting name identified in STIG
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
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
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

Function Get-V213162 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213162
        STIG ID    : ARDC-CL-000320
        Rule ID    : SV-213162r557349_rule
        CCI ID     : CCI-001813
        Rule Name  : SRG-APP-000380
        Rule Title : Adobe Reader DC must disable the ability to specify Host-Based Privileged Locations.
        DiscussMD5 : 3C2F21E4F667E3FE3C29C8AC2194DBE9
        CheckMD5   : 882DB5F0E5B2B7DA31277E4DF0E36DFF
        FixMD5     : D030EF2F088FB341668070A6CED2258D
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Reader*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Reader Classic version."
    }
    Else {
        $TempUserHivePath = ""  # User's loaded hive to perform check
        $RegistryPath = "HKLM:\Software\Policies\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\FeatureLockDown"  # Registry path identified in STIG
        $RegistryValueName = "bDisableTrustedSites"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Privileged host locations"  # GPO setting name identified in STIG
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
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
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

Function Get-V213163 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213163
        STIG ID    : ARDC-CL-000330
        Rule ID    : SV-213163r557349_rule
        CCI ID     : CCI-002470
        Rule Name  : SRG-APP-000427
        Rule Title : Adobe Reader DC must disable periodical uploading of European certificates.
        DiscussMD5 : AD2EF3E9E51959A052658907F48856AE
        CheckMD5   : 24585736FBA97C3DCCDF34E953EE70D3
        FixMD5     : 9B45B76A74D60D8B7C97582BB4245359
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Reader*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Reader Classic version."
    }
    Else {
        $TempUserHivePath = "Registry::HKU\Evaluate-STIG_UserHive\SOFTWARE\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\Security\cDigSig\cEUTLDownload"  # User's loaded hive to perform check
        $RegistryPath = "HKCU:\Software\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\Security\cDigSig\cEUTLDownload"  # Registry path identified in STIG
        $RegistryValueName = "bLoadSettingsFromURL"  # Value name identified in STIG
        $RegistryValue = @("0")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Load trusted certificates from an Adobe EUTL server"  # GPO setting name identified in STIG
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
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
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

Function Get-V213164 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213164
        STIG ID    : ARDC-CL-000335
        Rule ID    : SV-213164r557349_rule
        CCI ID     : CCI-002470
        Rule Name  : SRG-APP-000427
        Rule Title : Adobe Reader DC must disable periodical uploading of Adobe certificates.
        DiscussMD5 : 29A042D6242D5182F50E8314C8AFF070
        CheckMD5   : 8E9B6E90C07C0BFA77ACDB6D24BD9D04
        FixMD5     : AA321CED7511187AADA6877A48898B9F
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Reader*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Reader Classic version."
    }
    Else {
        $TempUserHivePath = "Registry::HKU\Evaluate-STIG_UserHive\SOFTWARE\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\Security\cDigSig\cAdobeDownload"  # User's loaded hive to perform check
        $RegistryPath = "HKCU:\Software\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\Security\cDigSig\cAdobeDownload"  # Registry path identified in STIG
        $RegistryValueName = "bLoadSettingsFromURL"  # Value name identified in STIG
        $RegistryValue = @("0")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Load trusted certificates from an Adobe AATL server"  # GPO setting name identified in STIG
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
            $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and format to 0x00000000
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
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

Function Get-V213165 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213165
        STIG ID    : ARDC-CL-000340
        Rule ID    : SV-213165r557349_rule
        CCI ID     : CCI-002605
        Rule Name  : SRG-APP-000456
        Rule Title : Unsupported version of Adobe Acrobat Reader DC Classic must be uninstalled.
        DiscussMD5 : B53615A757C4214F9F0BE82AF0FD868A
        CheckMD5   : 5358E8336A774E9204FCE86E761DC283
        FixMD5     : 68B338DBE91EBB5490375D3E8C6F48BD
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
    $Compliant = $true
    $ClassicVersions = @("2015","2017","2020")
    $EoSDates = New-Object System.Collections.Generic.List[System.Object]
    ForEach ($Version in $ClassicVersions) {
        Switch ($Version) {
            "2015" {
                $NewObj = [PSCustomObject]@{
                    Version = $Version
                    EoS     = (Get-Date -Date 7/7/2020)
                }
            }
            "2017" {
                $NewObj = [PSCustomObject]@{
                    Version = $Version
                    EoS     = (Get-Date -Date 6/6/2022)
                }
            }
            "2020" {
                $NewObj = [PSCustomObject]@{
                    Version = $Version
                    EoS     = (Get-Date -Date 6/1/2025)
                }
            }
        }
        $EoSDates.Add($NewObj)
    }

    $Installs = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Reader*" -and $_.Track -eq "Classic"}
    $FindingDetails += "Refer to https://helpx.adobe.com/support/programs/eol-matrix.html for Adobe support periods." | Out-String
    $FindingDetails += "" | Out-String
    ForEach ($Item in $Installs) {
        If ((Get-Date) -gt ($EoSDates | Where-Object Version -EQ $Item.Version).EoS) {
            $Compliant = $false
            $EoSMsg = "Support ended on $(Get-Date ($EoSDates | Where-Object Version -EQ $Item.Version).EoS -Format MM/dd/yyyy)"
        }
        Else {
            $EoSMsg = "Support will end on $(Get-Date ($EoSDates | Where-Object Version -EQ $Item.Version).EoS -Format MM/dd/yyyy)"
        }
        $FindingDetails += "Name:`t`t`t$($Item.Name)" | Out-String
        $FindingDetails += "Version:`t`t`t$($Item.Version)" | Out-String
        $FindingDetails += "Track:`t`t`t$($Item.Track)" | Out-String
        $FindingDetails += "DisplayVersion:`t$($Item.DisplayVersion)" | Out-String
        $FindingDetails += "Architecture:`t`t$($Item.Architecture)" | Out-String
        $FindingDetails += "Support:`t`t`t$($EoSMsg)" | Out-String
        $FindingDetails += "" | Out-String
    }

    If ($Compliant -eq $true) {
        $Status = "NotAFinding"
    }
    Else {
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

Function Get-V213166 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213166
        STIG ID    : ARDC-CL-000345
        Rule ID    : SV-213166r557349_rule
        CCI ID     : CCI-002450
        Rule Name  : SRG-APP-000514
        Rule Title : Adobe Reader DC must enable FIPS mode.
        DiscussMD5 : D656DB55D410337BD6161348B00F118A
        CheckMD5   : 3F70E2D6B534891F6D420FDD2B4EBABF
        FixMD5     : 0931C26D66C0A384C37E3FE0E983F33A
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
    $ClassicVersion = Get-AdobeReaderProInstalls | Where-Object {$_.Name -like "Adobe Reader*" -and $_.Track -eq "Classic"}
    If (-Not($ClassicVersion)) {
        Throw "Unable to detect Adobe Reader Classic version."
    }
    Else {
        $TempUserHivePath = "Registry::HKU\Evaluate-STIG_UserHive\SOFTWARE\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\AVGeneral"  # User's loaded hive to perform check
        $RegistryPath = "HKCU:\Software\Adobe\Acrobat Reader\$($ClassicVersion[0].Version)\AVGeneral"  # Registry path identified in STIG
        $RegistryValueName = "bFIPSMode"  # Value name identified in STIG
        $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
        $RegistryType = "REG_DWORD"  # Value type expected in STIG
        $SettingName = "Enable FIPS"  # GPO setting name identified in STIG
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
        }
        Else {
            $RegistryResultValue = $RegistryResult.Value
        }

        If ($RegistryResult.Type -eq "(NotFound)") {
            #If the registry value does not exist
            If ($SettingNotConfiguredAllowed -eq $true) {
                #And it is allowed to be not configured set to notAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
            Else {
                #Or, if it must be configured, set this to Open
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
            }
        }
        Else {
            #If the registry value is found...
            If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
                #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
                $Status = "NotAFinding"
                $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
                $Status = "Open"
                $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
                $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
                If ($RegistryResult.Value -in $RegistryValue) {
                    #If the registry result matches the expected value
                    $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
                }
                Else {
                    #If the result value and expected value are different, print what the value is set to and what it should be.
                    $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
                }
                If ($RegistryResult.Type -eq $RegistryType) {
                    #If the result type is the same as expected
                    $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
                }
                Else {
                    #If the result type is different from what is expected, print both.
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

# SIG # Begin signature block
# MIIL+QYJKoZIhvcNAQcCoIIL6jCCC+YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAOKsWE0uxO+iJW
# S+kVVWXAIjj0FH42J33cH9AFV2iXWqCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDY+lPFXsOUtt/Fz+nsMprZB78XMXUC
# 8qQrMgp3FsxVeTANBgkqhkiG9w0BAQEFAASCAQDLi1mD64ntvqnBr6hI9h5guNH6
# BnM5d5G6Ip8TT/UPU6tC4wR1ASYaTAJeNU12jCySJGU1MhPJCBiLrnd+CW5Clryj
# YiSQLq4DnrMqJ4W6ojMI6bZsOaO4bXQ5u2syu2IM03BzhyBqrLDAUux4ee7EcTZc
# CynqGxfLXAWIHPxZH3sWR9c+OkVOOZecqGnmFs5e0TuANIRnLW85FbFggs3kbIQd
# ZIZjIG35EaYAZ0Jud7NPe/dU8KNxUG7vdWb/WUkFg2la0ni2GVxpnwgz0JoyDZRO
# Ok7BhTaT0CCr0q8XBz0wQCv3TRPxaCe69DGZEuHeOTSA5ym8qEB+3JdAk/0h
# SIG # End signature block
