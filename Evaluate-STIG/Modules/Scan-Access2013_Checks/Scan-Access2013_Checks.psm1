##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Microsoft Access 2013
# Version:  V1R6
# Class:    UNCLASSIFIED
# Updated:  5/13/2024
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V17173 {
    <#
    .DESCRIPTION
        Vuln ID    : V-17173
        STIG ID    : DTOO104
        Rule ID    : SV-52759r1_rule
        CCI ID     : CCI-001170
        Rule Name  : DTOO104 - Disable user name and password
        Rule Title : Disabling of user name and password syntax from being used in URLs must be enforced.
        DiscussMD5 : 3D6711BE1CFDD6B115C9BFBAD658484E
        CheckMD5   : 7B3C8D24CFA178F3CCB1789220FCACB0
        FixMD5     : 3F84A90E0E7984021F64AA6C261EF8BE
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_HTTP_USERNAME_PASSWORD_DISABLE"  # Registry path identified in STIG
    $RegistryValueName = "msaccess.exe"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Disable user name and password"  # GPO setting name identified in STIG
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

Function Get-V17174 {
    <#
    .DESCRIPTION
        Vuln ID    : V-17174
        STIG ID    : DTOO111
        Rule ID    : SV-52761r1_rule
        CCI ID     : CCI-001695
        Rule Name  : DTOO111 - Enable IE Bind to Object
        Rule Title : Enabling IE Bind to Object functionality must be present.
        DiscussMD5 : B3E005C2E3985AD36F5939898631F2BC
        CheckMD5   : 2B18C9F903EB34FB19AF0AA94E990038
        FixMD5     : FEC43CF5C89DBEA7EC6C4B79C13E3F3B
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SAFE_BINDTOOBJECT"  # Registry path identified in STIG
    $RegistryValueName = "msaccess.exe"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Bind to Object"  # GPO setting name identified in STIG
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

Function Get-V17175 {
    <#
    .DESCRIPTION
        Vuln ID    : V-17175
        STIG ID    : DTOO117
        Rule ID    : SV-52762r1_rule
        CCI ID     : CCI-001170
        Rule Name  : DTOO117 - Saved from URL
        Rule Title : Saved from URL mark to assure Internet zone processing must be enforced.
        DiscussMD5 : 0738E8004F2E65D6826D7F9265E83BEA
        CheckMD5   : 174A93C46706BC12FDE2A296346CBD82
        FixMD5     : 50BFDDC5CF6119D52097A4FAAA786CA9
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_UNC_SAVEDFILECHECK"  # Registry path identified in STIG
    $RegistryValueName = "msaccess.exe"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Saved from URL"  # GPO setting name identified in STIG
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

Function Get-V17183 {
    <#
    .DESCRIPTION
        Vuln ID    : V-17183
        STIG ID    : DTOO123
        Rule ID    : SV-52763r1_rule
        CCI ID     : CCI-001170
        Rule Name  : DTOO123-Block Navigation to URL from Office
        Rule Title : Navigation to URLs embedded in Office products must be blocked.
        DiscussMD5 : 15A059C11FCE317B8DD12BF6ACFF5061
        CheckMD5   : 6D06A2EE02427EAF7E0A2C34845BC997
        FixMD5     : 457340587DB490E4EA24B1FE6A51A282
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_VALIDATE_NAVIGATE_URL"  # Registry path identified in STIG
    $RegistryValueName = "msaccess.exe"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Navigate URL"  # GPO setting name identified in STIG
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

Function Get-V17184 {
    <#
    .DESCRIPTION
        Vuln ID    : V-17184
        STIG ID    : DTOO129
        Rule ID    : SV-52767r1_rule
        CCI ID     : CCI-001662
        Rule Name  : DTOO129 - Block Pop-Ups
        Rule Title : Links that invoke instances of Internet Explorer from within an Office product must be blocked.
        DiscussMD5 : EFB63DF9F2D8A6B2C21E8924A2533510
        CheckMD5   : 0F54D17A3C58AFDC1F9C2D408D4FBD57
        FixMD5     : 0C2B43C4E30178755C24E79AF1142855
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WEBOC_POPUPMANAGEMENT"  # Registry path identified in STIG
    $RegistryValueName = "msaccess.exe"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Block popups"  # GPO setting name identified in STIG
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

Function Get-V17187 {
    <#
    .DESCRIPTION
        Vuln ID    : V-17187
        STIG ID    : DTOO131
        Rule ID    : SV-52769r1_rule
        CCI ID     : CCI-001749
        Rule Name  : DTOO131 - Trust Bar Notifications
        Rule Title : Trust Bar Notifications for unsigned application add-ins must be blocked.
        DiscussMD5 : 3E957B8CC3C2E19123445FA649DC9A56
        CheckMD5   : 5A884536CE4566339BD5F24AF5FABF6B
        FixMD5     : 1C1709BB5C80E290D671C7C818C1630C
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
    $TempUserHivePath = "Registry::HKU\Evaluate-STIG_UserHive\SOFTWARE\Policies\Microsoft\Office\15.0\access\security"  # User's loaded hive to perform check
    $RegistryPath = "HKCU:\Software\Policies\Microsoft\Office\15.0\access\security"  # Registry path identified in STIG
    $RegistryValueName = "NoTBPromptUnsignedAddin"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Disable Trust Bar Notification for unsigned application add-ins and block them"  # GPO setting name identified in STIG
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

Function Get-V17545 {
    <#
    .DESCRIPTION
        Vuln ID    : V-17545
        STIG ID    : DTOO304
        Rule ID    : SV-52776r1_rule
        CCI ID     : CCI-000381
        Rule Name  : DTOO304 - VBA Macro Warning settings
        Rule Title : Trust access for VBA must be disallowed.
        DiscussMD5 : F5B38D20002FA01AB5BE9FA1F83124A2
        CheckMD5   : 3A2FEC0DF357D134B07D77AC628F98BE
        FixMD5     : C40AF0064BECD11C3F816E7F2007D753
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
    $TempUserHivePath = "Registry::HKU\Evaluate-STIG_UserHive\SOFTWARE\policies\Microsoft\office\15.0\access\security"  # User's loaded hive to perform check
    $RegistryPath = "HKCU:\software\policies\Microsoft\office\15.0\access\security"  # Registry path identified in STIG
    $RegistryValueName = "vbawarnings"  # Value name identified in STIG
    $RegistryValue = @("2")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "VBA macro Notification Settings"  # GPO setting name identified in STIG
    $SettingState = "Enabled: Disable all with notification"  # GPO configured state identified in STIG.
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

Function Get-V17584 {
    <#
    .DESCRIPTION
        Vuln ID    : V-17584
        STIG ID    : DTOO136
        Rule ID    : SV-52772r1_rule
        CCI ID     : CCI-000381
        Rule Name  : DTOO136 - Default file format
        Rule Title : The Save commands default file format must be configured.
        DiscussMD5 : 54B572B3ADCD69ED1DF341FDF524FF8C
        CheckMD5   : 2CAF6BB8B8B039FD9011BFED66392BE6
        FixMD5     : C1F0AD18FC920E3989372D21B5F7DB05
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
    $TempUserHivePath = "Registry::HKU\Evaluate-STIG_UserHive\SOFTWARE\Policies\Microsoft\Office\15.0\access\settings"  # User's loaded hive to perform check
    $RegistryPath = "HKCU:\Software\Policies\Microsoft\Office\15.0\access\settings"  # Registry path identified in STIG
    $RegistryValueName = "Default File Format"  # Value name identified in STIG
    $RegistryValue = @("12")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Default File Format"  # GPO setting name identified in STIG
    $SettingState = "Enabled (Access 2007)"  # GPO configured state identified in STIG.
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

Function Get-V17603 {
    <#
    .DESCRIPTION
        Vuln ID    : V-17603
        STIG ID    : DTOO137
        Rule ID    : SV-52773r1_rule
        CCI ID     : CCI-000366
        Rule Name  : DTOO137 - Prompt / Convert Older Databases
        Rule Title : Prompts to convert older databases must be enforced.
        DiscussMD5 : 52F4EBE7C7B86628AFBB66DE3E5E4CCF
        CheckMD5   : 729CF5D4226A0412EC2D69D689115718
        FixMD5     : A5EE44E7A7C12F59CFAF18EE6E86C82E
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
    $TempUserHivePath = "Registry::HKU\Evaluate-STIG_UserHive\SOFTWARE\Policies\Microsoft\Office\15.0\access\settings"  # User's loaded hive to perform check
    $RegistryPath = "HKCU:\Software\Policies\Microsoft\Office\15.0\access\settings"  # Registry path identified in STIG
    $RegistryValueName = "NoConvertDialog"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Do not prompt to convert older databases"  # GPO setting name identified in STIG
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

Function Get-V17757 {
    <#
    .DESCRIPTION
        Vuln ID    : V-17757
        STIG ID    : DTOO135
        Rule ID    : SV-52771r1_rule
        CCI ID     : CCI-000381
        Rule Name  : DTOO135 - Modal Trust Decision Only
        Rule Title : Database functionality configurations must be displayed to the user.
        DiscussMD5 : D2290CE070969DB0969D7E3678A5C389
        CheckMD5   : 0C9BA0DE4A6BC19669CD85A99ACA3EF2
        FixMD5     : 5108DE6A00F08B68A3DC79A2E3862555
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
    $TempUserHivePath = "Registry::HKU\Evaluate-STIG_UserHive\SOFTWARE\Policies\Microsoft\Office\15.0\access\security"  # User's loaded hive to perform check
    $RegistryPath = "HKCU:\Software\Policies\Microsoft\Office\15.0\access\security"  # Registry path identified in STIG
    $RegistryValueName = "ModalTrustDecisionOnly"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Modal Trust Decision Only"  # GPO setting name identified in STIG
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

Function Get-V17810 {
    <#
    .DESCRIPTION
        Vuln ID    : V-17810
        STIG ID    : DTOO130
        Rule ID    : SV-52768r1_rule
        CCI ID     : CCI-002460
        Rule Name  : DTOO130 - Underline hyperlinks
        Rule Title : The configuration for enabling of hyperlinks must be enforced.
        DiscussMD5 : 5322FCDFE3B2B198D885BA4621884C00
        CheckMD5   : C1C04669D15897F353F5E949EA49150E
        FixMD5     : 8D2E068D2442B5B033B5640DDAC3D660
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
    $TempUserHivePath = "Registry::HKU\Evaluate-STIG_UserHive\SOFTWARE\Policies\Microsoft\Office\15.0\access\internet"  # User's loaded hive to perform check
    $RegistryPath = "HKCU:\Software\Policies\Microsoft\Office\15.0\access\internet"  # Registry path identified in STIG
    $RegistryValueName = "DoNotUnderlineHyperlinks"  # Value name identified in STIG
    $RegistryValue = @("0")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Underline Hyperlinks"  # GPO setting name identified in STIG
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

Function Get-V26584 {
    <#
    .DESCRIPTION
        Vuln ID    : V-26584
        STIG ID    : DTOO126
        Rule ID    : SV-52765r1_rule
        CCI ID     : CCI-001662
        Rule Name  : DTOO126 - Add-on Management
        Rule Title : Add-on Management functionality must be allowed.
        DiscussMD5 : 7C4EE06C4D10F3407490E1B72E452A97
        CheckMD5   : 13C613633DFCC0F86806F1B26879DBE0
        FixMD5     : C8D9037766541D241C9B9E8CFC66B1E1
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ADDON_MANAGEMENT"  # Registry path identified in STIG
    $RegistryValueName = "msaccess.exe"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Add-on Management"  # GPO setting name identified in STIG
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

Function Get-V26585 {
    <#
    .DESCRIPTION
        Vuln ID    : V-26585
        STIG ID    : DTOO209
        Rule ID    : SV-52774r1_rule
        CCI ID     : CCI-001695
        Rule Name  : DTOO209 - Zone Elevation Protection
        Rule Title : Protection from zone elevation must be enforced.
        DiscussMD5 : 52D56D491DB43FA83C289436F8E31C32
        CheckMD5   : E1C99F424A6B064DAC480153D8A030B3
        FixMD5     : BB26FFB397EB5647A9010FB9D387A5A6
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION"  # Registry path identified in STIG
    $RegistryValueName = "msaccess.exe"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Protection From Zone Elevation"  # GPO setting name identified in STIG
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

Function Get-V26586 {
    <#
    .DESCRIPTION
        Vuln ID    : V-26586
        STIG ID    : DTOO211
        Rule ID    : SV-52775r1_rule
        CCI ID     : CCI-002460
        Rule Name  : DTOO211 - Restrict ActiveX Install
        Rule Title : ActiveX Installs must be configured for proper restriction.
        DiscussMD5 : 6E1A29A00F314CE8B1F1D28CC95B68D2
        CheckMD5   : 74E98DA21762C44791E6FD5796691E27
        FixMD5     : A74C040A6008C968A64AAA135A0ED7C1
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL"  # Registry path identified in STIG
    $RegistryValueName = "msaccess.exe"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Restrict ActiveX Install"  # GPO setting name identified in STIG
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

Function Get-V26587 {
    <#
    .DESCRIPTION
        Vuln ID    : V-26587
        STIG ID    : DTOO132
        Rule ID    : SV-52770r1_rule
        CCI ID     : CCI-001169
        Rule Name  : DTOO132 - Restrict File Download
        Rule Title : File Downloads must be configured for proper restrictions.
        DiscussMD5 : E04E00346214A645A69EE2C7F7FF3B93
        CheckMD5   : A02961B1B8F9CBD316A0342DF031C5E5
        FixMD5     : A9AFA380BA4962360C14CF97921865A6
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD"  # Registry path identified in STIG
    $RegistryValueName = "msaccess.exe"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Restrict File Download"  # GPO setting name identified in STIG
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

Function Get-V26588 {
    <#
    .DESCRIPTION
        Vuln ID    : V-26588
        STIG ID    : DTOO124
        Rule ID    : SV-52764r1_rule
        CCI ID     : CCI-001695
        Rule Name  : DTOO124 - Scripted Window Security
        Rule Title : Scripted Window Security must be enforced.
        DiscussMD5 : 5B15E95EFB4F43B2E61DD1BDFC47FBA9
        CheckMD5   : 3E4996384E2F49EB99A88FDB620EB430
        FixMD5     : 9BD6D941A273A6CB90894C47253F418B
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS"  # Registry path identified in STIG
    $RegistryValueName = "msaccess.exe"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Scripted Window Security Restrictions"  # GPO setting name identified in STIG
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

Function Get-V26589 {
    <#
    .DESCRIPTION
        Vuln ID    : V-26589
        STIG ID    : DTOO127
        Rule ID    : SV-52766r1_rule
        CCI ID     : CCI-001749
        Rule Name  : DTOO127 - Add-ins are signed by Trusted Publisher
        Rule Title : Add-ins to Office applications must be signed by a Trusted Publisher.
        DiscussMD5 : F5A9165C8E9C77CB888772ED9DCBE8FB
        CheckMD5   : 77EE310DE9B5DDDA47B32ADDB7E51E16
        FixMD5     : 3DACA1AAFE6959F50C0233E2D9204B14
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
    $TempUserHivePath = "Registry::HKU\Evaluate-STIG_UserHive\SOFTWARE\Policies\Microsoft\Office\15.0\access\security"  # User's loaded hive to perform check
    $RegistryPath = "HKCU:\Software\Policies\Microsoft\Office\15.0\access\security"  # Registry path identified in STIG
    $RegistryValueName = "RequireAddinSig"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "Require that application add-ins are signed by Trusted Publisher"  # GPO setting name identified in STIG
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCTvICDFRQOAYw5
# P9i/VjNa79wo9ns6Y/RBwbwjOTNEdKCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCD9E3egG48RZ6nbompt8z6dYCoj7XzJ
# rZdG0xl0q5CUwjANBgkqhkiG9w0BAQEFAASCAQBQvEw5zzAP2fmkGR1GWaxUdvcN
# O+JohmWpOE/dc5ku27Fm70jkpN/LQZrtr5YjasYuEs03SE60M/1Z595LIFohLY8Z
# 4rwQhLbC/3Su8EE4kgWgpBd+lsayMkPQ9xoQmBMM5A/k+tUlPNi6pRzTI+TJJbtV
# Ps9CNsVzC4f++a5Iua6aWRb9+CC5xa1MwKKQbL159kPZdOOErXBKkYQQjopZVE63
# 8aV0XKPP0nvAyY4UxRMl6UcU1buNCURk24bD2hu25kRZY87mutX1AXPwrtxbJPrk
# PwH1kVRb2V4FG8x2MKAT6vqpSVofv4E5SqINHZYxEXtcw2XgzmENublwgl88
# SIG # End signature block
