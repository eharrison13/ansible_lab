##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Apache Server 2.4 Windows Server
# Version:  V2R3
# Class:    UNCLASSIFIED
# Updated:  5/13/2024
# Author:   U.S. Army Communications-Electronics Command, Software Engineering Center (CECOM SEC)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V214306 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214306
        STIG ID    : AS24-W1-000010
        Rule ID    : SV-214306r879511_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-WSR-000001
        Rule Title : The Apache web server must limit the number of allowed simultaneous session requests.
        DiscussMD5 : 438F141F1363E3C82AFB70470908BE15
        CheckMD5   : BF6EE9583C894493C41FC7B970923BA8
        FixMD5     : 877FE136432834B33B78B3C6A94633EA
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
    $ErrorCount = 0
    $DirectiveName = "MaxKeepAliveRequests"
    $ExpectedValue = "100 or greater"
    $DirectivesFound = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName

    $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $DirectivesFound
    $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $DirectivesFound

    $FindingDetails = Get-ApacheFormattedOutput -FoundValues $DirectivesFound -ExpectedValue $ExpectedValue -IsInGlobalConfig $IsInGlobalConfig -IsInAllVirtualHosts $IsInAllVirtualHosts

    if ($IsInGlobalConfig -or $IsInAllVirtualHosts) {
        # Check all of the directives like a normal check.
        foreach ($directive in $DirectivesFound) {
            if ($directive.Status -eq "Not Found") {
                continue
            }
            $KeepAlive = ($directive.ConfigFileLine.ToString() -split '\s+')[1] -as [int]
            if ($KeepAlive -lt "100") {
                $ErrorCount++
                break
            }
        }
    }
    else {
        $ErrorCount++
    }

    if ($ErrorCount -eq 0) {
        $Status = "NotAFinding"
    }
    else {
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

Function Get-V214307 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214307
        STIG ID    : AS24-W1-000020
        Rule ID    : SV-214307r879511_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-WSR-000002
        Rule Title : The Apache web server must perform server-side session management.
        DiscussMD5 : 227DDE10A7985058476F3326DDCF7666
        CheckMD5   : 6210341C2BC84F20C91F536543237E51
        FixMD5     : DE5C64B9F3F60379006A750F2FF96F72
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
    $ErrorCount = 0
    $ApacheModules = @("session_module", "usertrack_module")
    $ExpectedState = "Enabled"

    foreach ($ApacheModule in $ApacheModules) {
        $ModuleStatus = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $ApacheModule
        $FindingDetails += Get-ApacheFormattedOutput -FoundValues $ModuleStatus -ExpectedValue $ExpectedState

        if ($ModuleStatus.Status -eq "Disabled") {
            $ErrorCount++
        }
    }

    if ($ErrorCount -ge 1) {
        $Status = "Open"
    }
    else {
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

Function Get-V214308 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214308
        STIG ID    : AS24-W1-000030
        Rule ID    : SV-214308r879519_rule
        CCI ID     : CCI-000068, CCI-000213, CCI-000803, CCI-001453, CCI-002418, CCI-002422
        Rule Name  : SRG-APP-000014-WSR-000006
        Rule Title : The Apache web server must use encryption strength in accordance with the categorization of data hosted by the Apache web server when remote connections are provided.
        DiscussMD5 : 713FF0C3A97B36C4DBAA5D731AB71363
        CheckMD5   : 531E67184F2D45DF8192E72B3B3B68D9
        FixMD5     : FB98B69BA0835A22F79B32F68466A514
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
    $ErrorCount = 0
    $ApacheModuleName = "ssl_module"
    $ExpectedState = "Enabled"
    $ModuleStatus = Get-ApacheModule -ApacheInstance $Global:ApacheInstance -ModuleName $ApacheModuleName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $ModuleStatus -ExpectedValue $ExpectedState

    $ApacheDirectiveName = "SSLProtocol"
    $DirectiveExpectedValue = "-ALL +TLSv1.2 -SSLv2 -SSLv3"
    $DirectiveResult = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $ApacheDirectiveName
    $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $DirectiveResult
    $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $DirectiveResult
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResult -ExpectedValue $DirectiveExpectedValue -IsInGlobalConfig $IsInGlobalConfig -IsInAllVirtualHosts $IsInAllVirtualHosts

    if ($ModuleStatus.Status -eq "Disabled") {
        $ErrorCount++
    }
    else {
        if ( -not ($IsInGlobalConfig) -and -not ($IsInAllVirtualHosts)) {
            $ErrorCount++
        }
        else {
            foreach ($directive in $DirectiveResult) {
                if ($directive.Status -eq "Not Found") {
                    continue
                }

                $MustAppear = "-ALL"
                foreach ($test in $MustAppear) {
                    $result = $directive.ConfigFileLine | Select-String -Pattern $test
                    if ($null -eq $result -or $result -eq "") {
                        $ErrorCount++
                        break
                    }
                }

                $ShouldCount = 0
                $ShouldAppear = "\+TLSv1.2", "\+TLSv1.3"
                foreach ($test in $ShouldAppear) {
                    $result = $directive.ConfigFileLine | Select-String -Pattern $test
                    if ($null -ne $result -and $result -ne "") {
                        $ShouldCount++
                        break
                    }
                }
                if ($ShouldCount -eq 0) {
                    $ErrorCount++
                    break
                }

                $ShouldNotAppear = "\+TLSv1\s", "\+TLSv1$", "\+TLSv1.1", "\+SSL"
                foreach ($test in $ShouldNotAppear) {
                    $result = $directive.ConfigFileLine | Select-String -Pattern $test
                    if ($null -ne $result -and $result -ne "") {
                        $ErrorCount++
                        break
                    }
                }
            }
        }
    }

    if ($ErrorCount -eq 0) {
        $Status = "NotAFinding"
    }
    else {
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

Function Get-V214309 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214309
        STIG ID    : AS24-W1-000065
        Rule ID    : SV-214309r881525_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : System logging must be enabled.
        DiscussMD5 : D5A491463105C41B0A54615E3A9D1FF5
        CheckMD5   : EF6545257323F68739B795FA52433BCF
        FixMD5     : 5C13CCFA06CF7D00C54310DD6038BDBA
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
    $ErrorCount = 0
    $ApacheDirectiveName = "CustomLog"
    $ExpectedValue = "`"<log file path>`" <audit configs>"
    $ExpectedPattern = "(.+)\/(.+)"
    $ApacheFoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $ApacheDirectiveName

    $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $ApacheFoundValues
    $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $ApacheFoundValues

    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $ApacheFoundValues -ExpectedValue $ExpectedValue -IsInGlobalConfig $IsInGlobalConfig -IsInAllVirtualHosts $IsInAllVirtualHosts

    if ($IsInGlobalConfig -or $IsInAllVirtualHosts) {
        foreach ($line in $ApacheFoundValues) {
            if ($line.Status -eq "Not Found") {
                continue
            }

            $ConfigLine = $line.ConfigFileLine.Trim()
            $DetectedValue = $ConfigLine.Substring($ConfigLine.IndexOf(' ')).Trim()
            if ($DetectedValue | Select-String -Pattern $ExpectedPattern -Quiet) {
                continue
            }
            $ErrorCount++
            break
        }
    }
    else {
        $ErrorCount++
    }

    if ($ErrorCount -eq 0) {
        $Status = "NotAFinding"
    }
    else {
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

Function Get-V214310 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214310
        STIG ID    : AS24-W1-000070
        Rule ID    : SV-214310r879559_rule
        CCI ID     : CCI-000169, CCI-001464
        Rule Name  : SRG-APP-000089-WSR-000047
        Rule Title : The Apache web server must generate, at a minimum, log records for system startup and shutdown, system access, and system authentication events.
        DiscussMD5 : 957A337CC2EDC4B4CB680F252666584D
        CheckMD5   : 4E099912E17331CEFA3740B880EACF16
        FixMD5     : 1B5BDC6868E902A0313C98A22E0B2A0B
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
    $ApacheModuleName = "log_config_module"
    $ExpectedValue = "Enabled"

    $ModuleObject = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $ApacheModuleName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $ModuleObject -ExpectedValue $ExpectedValue

    if ($ModuleObject.Status -eq "Disabled") {
        $Status = "Open"
    }
    else {
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

Function Get-V214311 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214311
        STIG ID    : AS24-W1-000090
        Rule ID    : SV-214311r879563_rule
        CCI ID     : CCI-000130, CCI-000131, CCI-000132, CCI-000133, CCI-000134, CCI-001487
        Rule Name  : SRG-APP-000095-WSR-000056
        Rule Title : The Apache web server must produce log records containing sufficient information to establish what type of events occurred.
        DiscussMD5 : 2AB61D34549A9469B24E02E58BF14700
        CheckMD5   : 3EC265107B6E9EE8358A4D2EF7D740C8
        FixMD5     : B78BD3BCBB917D9325F23BD6C8AC6F8C
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
    $FoundValueCount = 0
    $DirectiveName = "LogFormat"
    $ExpectedValue = '"%a %A %h %H %l %m %s %t %u %U"'
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails = Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue

    foreach ($directiveLine in $FoundValues) {
        if ($directiveLine.Status -eq "Not Found") {
            continue
        }
        $FoundValueCount++
    }

    if ($FoundValueCount -le 0) {
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

Function Get-V214314 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214314
        STIG ID    : AS24-W1-000180
        Rule ID    : SV-214314r879576_rule
        CCI ID     : CCI-000162
        Rule Name  : SRG-APP-000118-WSR-000068
        Rule Title : The Apache web server log files must only be accessible by privileged users.
        DiscussMD5 : 8FC11A6A2BBC37631668E9C7F7EA791F
        CheckMD5   : 4C05C6AD76CB3A3830DD313F87BC268A
        FixMD5     : 5BE831318AE815946A0BBDD87E33D553
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
    $LogDirs = [System.Collections.ArrayList]@(Get-ApacheLogDirs -ApacheInstance $ApacheInstance)
    foreach ($LogDir in $LogDirs) {
        if ([string]::IsNullOrEmpty($LogDir)) {
            continue
        }

        $CombinedPath = Join-Path -Path $LogDir -ChildPath "*"
        $Acls = (icacls $CombinedPath) | Out-String
        $Acls = [Regex]::Replace( $Acls, "Successfully.*$", "").Trim()
        $Acls = [Regex]::Replace( $Acls, "(\(OI\)|\(CI\)|\(IO\)|\(NP\)|\(I\))", "")
        $Acls = [Regex]::Replace( $Acls, "\(N\)", "(No Access)")
        $Acls = [Regex]::Replace( $Acls, "\(F\)", "(Full)")
        $Acls = [Regex]::Replace( $Acls, "\(M\)", "(Modify)")
        $Acls = [Regex]::Replace( $Acls, "\(RX\)", "(Read & Execute)")
        $Acls = [Regex]::Replace( $Acls, "\(R\)", "(Read)")
        $Acls = [Regex]::Replace( $Acls, "\(W\)", "(Write)")
        $Acls = [Regex]::Replace( $Acls, "\(D\)", "(Delete)")

        $FindingDetails += "$Acls" | Out-String
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

Function Get-V214315 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214315
        STIG ID    : AS24-W1-000200
        Rule ID    : SV-214315r879578_rule
        CCI ID     : CCI-000163, CCI-000164
        Rule Name  : SRG-APP-000120-WSR-000070
        Rule Title : The log information from the Apache web server must be protected from unauthorized deletion and modification.
        DiscussMD5 : 37A67AEEDE5EB928748F7E79B2CB7B73
        CheckMD5   : CA5482DAFD7EF310B7B572E8102CD059
        FixMD5     : B6C351550EE5D7027236621B151D396E
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
    $LogDirs = [System.Collections.ArrayList]@(Get-ApacheLogDirs -ApacheInstance $ApacheInstance)
    foreach ($LogDir in $LogDirs) {
        if ([string]::IsNullOrEmpty($LogDir)) {
            continue
        }

        $CombinedPath = Join-Path -Path $LogDir -ChildPath "*"
        $Acls = (icacls $CombinedPath) | Out-String
        $Acls = [Regex]::Replace( $Acls, "Successfully.*$", "").Trim()
        $Acls = [Regex]::Replace( $Acls, "(\(OI\)|\(CI\)|\(IO\)|\(NP\)|\(I\))", "")
        $Acls = [Regex]::Replace( $Acls, "\(N\)", "(No Access)")
        $Acls = [Regex]::Replace( $Acls, "\(F\)", "(Full)")
        $Acls = [Regex]::Replace( $Acls, "\(M\)", "(Modify)")
        $Acls = [Regex]::Replace( $Acls, "\(RX\)", "(Read & Execute)")
        $Acls = [Regex]::Replace( $Acls, "\(R\)", "(Read)")
        $Acls = [Regex]::Replace( $Acls, "\(W\)", "(Write)")
        $Acls = [Regex]::Replace( $Acls, "\(D\)", "(Delete)")

        $FindingDetails += "$Acls" | Out-String
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

Function Get-V214319 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214319
        STIG ID    : AS24-W1-000250
        Rule ID    : SV-214319r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000075
        Rule Title : The Apache web server must only contain services and functions necessary for operation.
        DiscussMD5 : B5C1B6D042AB37DB8AB103660F2B7AA5
        CheckMD5   : F7BF90B5FDF82DBD8BFE72696350A187
        FixMD5     : 00E73B184792B2554DCE5FCD48AE94DD
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
    $ErrorCount = 0
    $pathsChecked = [System.Collections.ArrayList]@()
    $DefaultIndexHTMLCode = @('(?i)test page for apache installation', '(?i)this page is used to test the proper operation of the apache')

    $DirectiveName = "DocumentRoot"
    $SRVROOT = '${SRVROOT}'
    $DocumentRoots = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName

    $Found = $false
    foreach ($documentRoot in $DocumentRoots) {
        if ($documentRoot.Status -eq "Not Found") {
            continue
        }

        $DirectoryPath = (($documentRoot.ConfigFileLine -replace $DirectiveName, '').Trim() -replace '"', '').Replace($SRVROOT, $ApacheInstance.HttpdRootPath)
        $DirectoryPath = $DirectoryPath -replace '\/', '\'
        $DirectoryPath = $DirectoryPath -replace '/', '\'
        $DirectoryPath = $DirectoryPath -replace '\\\\', '\'
        # Did all of that to normalize the path.

        # Ignore if path does not exist.
        if (-not (Test-Path -Path $DirectoryPath)) {
            continue
        }

        # Recurse through each directory and subdirectory and ignore if we don't find any subdirectories.
        $SubDirectories = Get-ChildItem -Path $DirectoryPath -Recurse -Force -Directory
        if ($null -eq $SubDirectories) {
            continue
        }

        foreach ($subDirectory in $SubDirectories) {
            $defaultHtmlFiles = Get-ChildItem -Path $subDirectory.FullName | Where-Object {$_.Name -eq 'index.htm' -or $_.Name -eq 'index.html' -or $_.Name -eq 'welcome.html'}
            if ($null -eq $defaultHtmlFiles) {
                continue
            }

            foreach ($defaultHtmlFile in $defaultHtmlFiles) {
                $filePath = Join-Path -Path $subDirectory.FullName -ChildPath $defaultHtmlFile.Name
                if ($pathsChecked -contains $filePath) {
                    continue
                }

                [void]$pathsChecked.add($filePath)

                foreach ($lineOfcode in $DefaultIndexHTMLCode) {
                    $testPage = Select-String -Path $filePath -Pattern $lineOfcode | Select-String -Pattern '^\s{0,}#' -NotMatch -Quiet
                    if ($testPage -eq $False) {
                        continue
                    }

                    if (-not ($Found)) {
                        $FindingDetails += "Default Apache Page Check:" | Out-String
                        $FindingDetails += "" | Out-String
                        $Found = $true
                    }

                    $FindingDetails += "`t`tPage Found: $($filePath)" | Out-String
                    $FindingDetails += "" | Out-String
                    $ErrorCount++
                    break
                }
            }
        }
    }

    if ($Found -eq $true) {
        $FindingDetails += "" | Out-String
    }

    $Found = $false

    # Recurse through each directory and subdirectory
    $SubDirectories = Get-ChildItem -Path $ApacheInstance.HttpdRootPath -Recurse -Force -Directory
    if ($null -ne $SubDirectories) {
        foreach ($subDirectory in $SubDirectories) {
            if ($subDirectory -notmatch "manual") {
                continue
            }

            $htmlFiles = Get-ChildItem -Path $subDirectory.FullName | Where-Object {$_.Name -Match '.htm'}
            if ($null -eq $htmlFiles) {
                continue
            }

            if (-not ($Found)) {
                $FindingDetails += "Apache User Manual Check:" | Out-String
                $FindingDetails += "" | Out-String
                $Found = $true
            }

            $UserManualOutput = "`t`tUser Manual Content Directory Found: " + $($subDirectory.FullName)
            $FindingDetails += $UserManualOutput | Out-String
            $FindingDetails += "" | Out-String
            $ErrorCount++
        }
    }

    if ($Found) {
        $FindingDetails += "" | Out-String
    }

    $DirectiveName = "Include\s+httpd-manual.conf"
    $ExpectedValue = "[Disabled] Include httpd-manual.conf"

    $DirectiveResults = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    foreach ($directive in $DirectiveResults) {
        $directive.Name = $directive.Name -replace "[\\b\\s+]", " " -replace "\s+", " "
    }
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResults -ExpectedValue $ExpectedValue

    foreach ($foundDirective in $DirectiveResults) {
        if ($foundDirective.Status -eq "Not Found") {
            continue
        }

        $ErrorCount++
        break
    }

    $startBlock = "LocationMatch" # Directives identified in STIG
    $endBlock = "LocationMatch" # Directives identified in STIG
    $DirectiveCheck = 'ErrorDocument\s+403\b'
    $ExpectedValue = "[Disabled] ErrorDocument 403 /error/noindex.html"

    $DirectiveResults = Get-ApacheDirectiveFromBlock -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -BlockStart $startBlock -BlockEnd $endBlock -DirectivePattern $DirectiveCheck
    foreach ($directive in $DirectiveResults) {
        $directive.Name = $directive.Name -replace "[\\b\\s+]", " " -replace "\s+", " "
    }
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResults -ExpectedValue $ExpectedValue

    foreach ($foundDirective in $DirectiveResults) {
        if ($foundDirective.Status -eq "Not Found") {
            continue
        }

        $ErrorCount++
        break
    }

    $DirectiveCheck = 'SetHandler'
    $ExpectedValue = "Disabled or Not Found"
    $startBlock = "Location" # Directives identified in STIG
    $endBlock = "Location" # Directives identified in STIG

    $DirectiveResults = Get-ApacheDirectiveFromBlock -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -BlockStart $startBlock -BlockEnd $endBlock -DirectivePattern $DirectiveCheck
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResults -ExpectedValue $ExpectedValue

    foreach ($foundDirective in $DirectiveResults) {

        if ($foundDirective.Status -eq "Not Found") {
            continue
        }

        $ErrorCount++
        break
    }

    if ($ErrorCount -ge 1) {
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

Function Get-V214320 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214320
        STIG ID    : AS24-W1-000260
        Rule ID    : SV-214320r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000076
        Rule Title : The Apache web server must not be a proxy server.
        DiscussMD5 : 6C97689C8D38013BEB245DB852A6C150
        CheckMD5   : 67061CB8E129485C5E673EF05434E581
        FixMD5     : D6F20275B999F90E918A6AD7B2E78621
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
    $Modules = @('proxy_module', 'proxy_ajp_module', 'proxy_balancer_module', 'proxy_ftp_module', 'proxy_http_module', 'proxy_connect_module')
    $ExpectedState = "Disabled"
    $ErrorCount = 0

    foreach ($modulefound in $Modules) {
        $ModuleStatus = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $modulefound
        $FindingDetails += Get-ApacheFormattedOutput -FoundValues $ModuleStatus -ExpectedValue $ExpectedState
        if ($ModuleStatus.Status -ne "Disabled") {
            $ErrorCount++
        }
    }

    If ($ErrorCount -eq 0) {
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

Function Get-V214322 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214322
        STIG ID    : AS24-W1-000280
        Rule ID    : SV-214322r879587_rule
        CCI ID     : CCI-000381, CCI-001082, CCI-001813
        Rule Name  : SRG-APP-000141-WSR-000078
        Rule Title : Apache web server application directories, libraries, and configuration files must only be accessible to privileged users.
        DiscussMD5 : 18DD9185E1F369EF5C9125D4B0EDDF8B
        CheckMD5   : 60D4BEE78A830F9CE79F6A93174A4581
        FixMD5     : 7C63A5703AE0EE6FBF5BCD856A090CC6
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
    $ErrorActionPreference = "Stop"
    try {
        $FindingDetails += Get-LocalGroupMember -Name Administrators | Select-Object @{Name = "Administrators"; Expression = {$_.Name}} | Out-String | ForEach-Object {$_.Trim()} -ea stop
        $FindingDetails += "" | Out-String
        $FindingDetails += Get-LocalGroupMember -Name Users | Select-Object @{Name = "Users"; Expression = {$_.Name}} | Out-String | ForEach-Object {$_.Trim()} -ea stop
    }
    Catch {
        # Error handling
        # These powershell commands have issues running on some systems that have been removed from domains. Instead we will use native Windows commands which run on all systems.
        $UsersGroup = net localgroup administrators | Where-Object {($_ -ne "") -and ($_ -NotMatch "----*") -and ($_ -NotMatch "The command completed")} | Select-String -Pattern "Members" -NotMatch | Select-String -Pattern "Comment" -NotMatch | Select-String -Pattern "The command completed successfully." -NotMatch | Out-String | ForEach-Object {$_.Trim()}
        $UsersGroup += "" | Out-String
        $UsersGroup += net localgroup users | Where-Object {($_ -ne "") -and ($_ -NotMatch "----*") -and ($_ -NotMatch "The command completed")} | Select-String -Pattern "Members" -NotMatch | Select-String -Pattern "Comment" -NotMatch | Select-String -Pattern "The command completed successfully." -NotMatch | Out-String | ForEach-Object {$_.Trim()}
        $UsersGroup = $usersGroup.replace('Alias name', 'User Type:')
        $FindingDetails += $UsersGroup
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

Function Get-V214323 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214323
        STIG ID    : AS24-W1-000300
        Rule ID    : SV-214323r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000081
        Rule Title : The Apache web server must have resource mappings set to disable the serving of certain file types.
        DiscussMD5 : 893943AF1C9E2E2EA4C50059E1C66C7D
        CheckMD5   : 2CEB9ECEAEFC7996F199926D449B9EE4
        FixMD5     : 724AB0C86F27B0B3B230437C1FC6A189
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
    $HasFoundDirectives = $false
    $Directives = @("AddHandler", "Action") # Directives identified in STIG
    $ExpectedValue = "Directive does not contain '.exe' '.dll' '.com' '.bat' or '.csh' MIME types."

    foreach ($directive in $Directives) {
        $DirectiveResults = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $directive
        $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $DirectiveResults
        $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $DirectiveResults
        $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResults -ExpectedValue $ExpectedValue -IsInGlobalConfig $IsInGlobalConfig -IsInAllVirtualHosts $IsInAllVirtualHosts
        foreach ($foundDirective in $DirectiveResults) {
            if ($foundDirective.Status -eq "Not Found") {
                continue
            }

            $HasFoundDirectives = $true
            break
        }
    }

    # We haven't found anything so no need to mark this check as Not_Reviewed
    if ($HasFoundDirectives -eq $false) {
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

Function Get-V214324 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214324
        STIG ID    : AS24-W1-000310
        Rule ID    : SV-214324r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000082
        Rule Title : The Apache web server must allow the mappings to unused and vulnerable scripts to be removed.
        DiscussMD5 : 5111E74263E14CCB3C3C18D532AC1C9C
        CheckMD5   : B5C0B3199B9CF68ED4A14787FA59FDB2
        FixMD5     : 6E3E20157591228B02B9AB931AB684EE
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
    $NeedsChecking = 0
    $DirectiveNames = @('Script', 'ScriptAlias', 'ScriptAliasMatch', 'ScriptInterpreterSource')
    $ExpectedState = "Not present unless required for operational use."

    foreach ($directiveName in $DirectiveNames) {
        $DirectiveStatus = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $directiveName
        $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveStatus -ExpectedValue $ExpectedState
        foreach ($line in $DirectiveStatus) {
            if ($line.Status -ne "Not Found") {
                $NeedsChecking++
            }
        }
    }

    if ($NeedsChecking -eq 0) {
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

Function Get-V214325 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214325
        STIG ID    : AS24-W1-000330
        Rule ID    : SV-214325r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000085
        Rule Title : The Apache web server must have Web Distributed Authoring (WebDAV) disabled.
        DiscussMD5 : CC08D5167A170A1F23A4CB6B2B189ED7
        CheckMD5   : 75A4B0E088C700CCE721B4E82CC0CBAB
        FixMD5     : 7EA6D117359093394F7B5823DF56D63A
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
    $ErrorCount = 0
    $Modules = @('dav_module', 'dav_fs_module', 'dav_lock_module')
    $ExpectedValue = "Disabled"

    foreach ($modulefound in $Modules) {
        $ModuleResult = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $modulefound
        $FindingDetails += Get-ApacheFormattedOutput -FoundValue $ModuleResult -ExpectedValue $ExpectedValue

        if ($ModuleResult.Status -eq "Disabled") {
            continue
        }

        $ErrorCount++
    }

    if ($ErrorCount -gt 0) {
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

Function Get-V214326 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214326
        STIG ID    : AS24-W1-000360
        Rule ID    : SV-214326r879588_rule
        CCI ID     : CCI-000382
        Rule Name  : SRG-APP-000142-WSR-000089
        Rule Title : The Apache web server must be configured to use a specified IP address and port.
        DiscussMD5 : E9C9524A4E0D5B719E837C9BD3529168
        CheckMD5   : D313A3DA93D5D726FA7DB0B86FAC68B9
        FixMD5     : FB01F4361A0F2538EB6AA696EC15ED2D
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
    $ErrorFound = 0
    $Ipv6Pattern = '(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\]:\d{1,5}'
    $DirectiveName = "Listen"
    $BadPatterns = @('0.0.0.0:\d{1,5}', '\[::ffff:0.0.0.0\]:\d', '\[::\]:\d', '\[::0\]:\d')
    $GoodPatterns = @('\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}:\d{1,5}', $Ipv6Pattern)
    $ExpectedValue = "The Listen directive must be enabled and specify a valid IP address and port"
    $DirectiveResults = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName

    $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $DirectiveResults
    $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $DirectiveResults

    $FindingDetails = Get-ApacheFormattedOutput -FoundValues $DirectiveResults -ExpectedValue $ExpectedValue -IsInGlobalConfig $IsInGlobalConfig -IsInAllVirtualHosts $IsInAllVirtualHosts

    foreach ($line in $DirectiveResults) {
        $GoodOneFound = 0
        if ($line.Status -eq "Not Found") {
            continue
        }

        foreach ($regex in $BadPatterns) {
            $IsBadPattern = [bool]($line | Select-String -Pattern $regex -Quiet)
            if ($IsBadPattern -eq $false) {
                continue
            }

            $ErrorFound++
            break
        }

        if ($ErrorFound -ge 1) {
            # We Found something we weren't supposed to. Break the outter for-loop because there is no
            # point in continuing.
            break
        }

        foreach ($regex in $GoodPatterns) {
            $IsGoodPattern = [bool]($line | Select-String -Pattern $regex -Quiet)
            if ($IsGoodPattern -eq $false) {
                continue
            }

            $GoodOneFound++
            break
        }

        if ($GoodOneFound -eq 0) {
            $ErrorFound++
            break
        }
    }

    if ($ErrorFound -eq 0) {
        $Status = "NotAFinding"
    }
    else {
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

Function Get-V214327 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214327
        STIG ID    : AS24-W1-000370
        Rule ID    : SV-214327r879609_rule
        CCI ID     : CCI-000197
        Rule Name  : SRG-APP-000172-WSR-000104
        Rule Title : The Apache web server must encrypt passwords during transmission.
        DiscussMD5 : 570389E79BEA2895342AFCF8486DA1CB
        CheckMD5   : 267AC9A030610D17E51411820BE0D3F6
        FixMD5     : B8634D33565FCF8AE40BDADA25D08F6E
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
    $ErrorCount = 0
    $DirectiveName = "SSLVerifyClient"
    $ExpectedValue = "Must be set to `"require`""
    $GoodValue = "require\b"

    $DirectiveResults = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName

    $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $DirectiveResults
    $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $DirectiveResults

    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResults -ExpectedValue $ExpectedValue -IsInGlobalConfig $IsInGlobalConfig -IsInAllVirtualHosts $IsInAllVirtualHosts

    if ($IsInGlobalConfig -or $IsInAllVirtualHosts) {
        foreach ($directive in $DirectiveResults) {
            if ($directive.Status -eq "Not Found") {
                continue
            }

            $FoundValue = ($directive.ConfigFileLine.ToString() -split '\s+')[1]
            $IsMatch = [bool]($FoundValue | Select-String -Pattern $GoodValue -Quiet)

            if ($IsMatch -eq $true) {
                continue
            }

            $ErrorCount++
            break
        }
    }
    else {
        $ErrorCount++
    }

    if ($ErrorCount -ge 1) {
        $Status = "Open"
    }
    else {
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

Function Get-V214328 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214328
        STIG ID    : AS24-W1-000380
        Rule ID    : SV-214328r879612_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-APP-000175-WSR-000095
        Rule Title : The Apache web server must perform RFC 5280-compliant certification path validation.
        DiscussMD5 : 3570D71CF21A5B2EF7A8EDBDE42326F8
        CheckMD5   : 7F98A7BB59E3C4014ACA273221AA772E
        FixMD5     : 31FB60B9349E6493FC44360972AC5C7B
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
    $DirectiveName = "SSLCACertificateFile"
    $ExpectedValue = "Issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs)"
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails = Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue

    foreach ($line In $FoundValues ) {
        if ($line.Status -eq "Not Found") {
            continue
        }
        else {
            $caFilePath = $line.ConfigFileLine.ToString().Split('"')[1]
            if ($null -eq $caFilePath) {
                $caFilePath = $line.ConfigFileLine.ToString().Split()[1]
            }

            $FileFound = $false

            #check unaltered directive path
            $filePath = $caFilePath
            if (Test-Path -Path "$filePath") {
                $FileFound = $true
            }

            #check path ${SRVROOT} with HttpdRootPath substitution
            if ($FileFound -ne $true) {
                $filePath = $caFilePath.Replace('${SRVROOT}', $ApacheInstance.HttpdRootPath)
                if (Test-Path -Path "$filePath") {
                    $FileFound = $true
                }
            }

            #check relative path
            if ($FileFound -ne $true) {
                $filePath = Join-Path -Path $ApacheInstance.HttpdRootPath -ChildPath $caFilePath
                if (Test-Path -Path "$filePath") {
                    $FileFound = $true
                }
            }

            if ($FileFound -ne $true) {
                break
            }
            $opensslPath = $ApacheInstance.ExecutablePath.Replace("httpd.exe", "openssl.exe")
            if (Test-Path -Path "$opensslPath") {
                $opensslCommandOutput = & "$opensslPath" x509 -noout -text -purpose -in $filePath | Out-String
                $directiveIndex = $FindingDetails.IndexOf($caFilePath)
                if ($null -eq $ApacheInstance.VirtualHosts) {
                    $onLineIndex = $FindingDetails.IndexOf("Config Level", $directiveIndex)
                }
                else {
                    $onLineIndex = $FindingDetails.IndexOf("Site Name", $directiveIndex)
                }
                $insertIndex = $FindingDetails.IndexOf("`n", $onLineIndex)
                $FindingDetails = $FindingDetails.Insert($insertIndex, "`n`n$opensslCommandOutput") | Out-String
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

Function Get-V214329 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214329
        STIG ID    : AS24-W1-000430
        Rule ID    : SV-214329r879631_rule
        CCI ID     : CCI-001082
        Rule Name  : SRG-APP-000211-WSR-000030
        Rule Title : Apache web server accounts accessing the directory tree, the shell, or other operating system functions and utilities must only be administrative accounts.
        DiscussMD5 : 3D748CCAB39740BDC35EBEB9C37B7E58
        CheckMD5   : 444215D468B3A57F5AB0F82C1F624CA7
        FixMD5     : 05A7C92988853BF7E946A10A64B737EC
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
    $ErrorCount = 0
    $AllFiles = Get-ChildItem -Path $ApacheInstance.HttpdRootPath -Recurse -Force -ErrorAction SilentlyContinue
    $AllFolders = Get-ChildItem -Directory -Path $ApacheInstance.HttpdRootPath -Recurse -Force -ErrorAction SilentlyContinue

    $ApacheOwner = (Get-ItemProperty "HKLM:\system\CurrentControlSet\Services\Apache2.4").ObjectName
    $LocalSystemAliases = @('(?i).*NT AUTHORITY\\SYSTEM.*', '(?i)BUILTIN\\Administrators.*')

    if ($ApacheOwner -eq "LocalSystem") {
        # LocalSystem includes aliases listed above and will not show up in the ACL list as an Owner.
        $ApacheOwner = $LocalSystemAliases
    }

    $BadFiles = @{}
    foreach ($file in $AllFiles) {
        $IsCorrectOwner = $false
        $FileOwner = Get-Acl -Path $file.FullName
        foreach ($owner in $ApacheOwner) {
            if ($($FileOwner.Owner.ToString() | Select-String -Pattern $owner) -or $IsCorrectOwner -eq $true) {
                $IsCorrectOwner = $true
                continue
            }
        }

        if ($IsCorrectOwner -eq $true) {
            continue
        }

        if (-not ($BadFiles.ContainsKey($FileOwner.Owner))) {
            $BadFiles[$FileOwner.Owner] = [System.Collections.ArrayList]@()
        }

        $BadFiles[$FileOwner.Owner] += ($file.FullName)
        $ErrorCount++
    }

    $BadFolders = @{}
    foreach ($folder in $AllFolders) {
        $IsCorrectOwner = $false
        $FolderOwner = Get-Acl -Path $folder.FullName
        foreach ($owner in $ApacheOwner) {
            if ($($FolderOwner.Owner.ToString() | Select-String -Pattern $owner) -or $IsCorrectOwner -eq $true) {
                $IsCorrectOwner = $true
                continue
            }
        }

        if ($IsCorrectOwner -eq $true) {
            continue
        }

        if (-not ($BadFolders.ContainsKey($FolderOwner.Owner))) {
            $BadFolders[$FolderOwner.Owner] = [System.Collections.ArrayList]@()
        }

        $BadFolders[$FolderOwner.Owner] += ($folder.FullName)
        $ErrorCount++
    }

    $ApacheOwner = $ApacheOwner.Replace('(?i)', '').Replace('\\', '\').Replace('.*', '')
    $FindingDetails += "Apache User: $($ApacheOwner)" | Out-String
    $FindingDetails += "---------------------------------------------------------------" | Out-String
    $FindingDetails += "" | Out-String
    if ($BadFolders.Count -ge 1) {

        foreach ($owner in $BadFolders.Keys) {
            $FindingDetails += "Folder Owner:`t$($owner)" | Out-String
            foreach ($folder in $BadFolders[$owner]) {
                $FindingDetails += "Folder:`t`t`t$($folder)" | Out-String
            }
        }
    }
    else {
        $FindingDetails += "All folders are owned by the Apache User." | Out-String
        $FindingDetails += "" | Out-String
    }

    if ($BadFiles.Count -ge 1) {

        $FindingDetails += "---------------------------------------------------------------" | Out-String
        $FindingDetails += "" | Out-String

        foreach ($owner in $BadFiles.Keys) {
            $FindingDetails += "File Owner:`t$($owner)" | Out-String
            foreach ($file in $BadFiles[$owner]) {
                $FindingDetails += "File:`t`t`t$($file)" | Out-String
            }
        }
    }
    else {
        $FindingDetails += "All files are owned by the Apache User." | Out-String
        $FindingDetails += "" | Out-String
    }

    if ($ErrorCount -ge 1) {
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

Function Get-V214331 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214331
        STIG ID    : AS24-W1-000460
        Rule ID    : SV-214331r879637_rule
        CCI ID     : CCI-001185
        Rule Name  : SRG-APP-000220-WSR-000201
        Rule Title : The Apache web server must invalidate session identifiers upon hosted application user logout or other session termination.
        DiscussMD5 : 6A8419E9435BCECB032B98E0D87E4C0A
        CheckMD5   : 10F8A5660832F7C6F0AA73658CAAD542
        FixMD5     : 2B54F842461A6BF086801505536E685E
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
    $DirectiveName = "SessionMaxAge"
    $ExpectedValue = "600 or Less"
    $ErrorCount = 0
    $DirectiveResult = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName

    $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $DirectiveResult
    $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $DirectiveResult

    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResult -ExpectedValue $ExpectedValue -IsInGlobalConfig $IsInGlobalConfig -IsInAllVirtualHosts $IsInAllVirtualHosts

    if ($IsInGlobalConfig -or $IsInAllVirtualHosts) {
        # Check all of the directives like a normal check.
        foreach ($directive in $DirectiveResult) {
            if ($directive.Status -eq "Not Found") {
                continue
            }
            $MaxAge = $directive.ConfigFileLine.ToString().Split()[1] -as [int]
            if ($MaxAge -gt 600) {
                $ErrorCount++
                break
            }
        }
    }
    else {
        $ErrorCount++
    }

    if ($ErrorCount -eq 0) {
        $Status = "NotAFinding"
    }
    else {
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

Function Get-V214332 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214332
        STIG ID    : AS24-W1-000470
        Rule ID    : SV-214332r879638_rule
        CCI ID     : CCI-001664
        Rule Name  : SRG-APP-000223-WSR-000011
        Rule Title : Cookies exchanged between the Apache web server and client, such as session cookies, must have security settings that disallow cookie access outside the originating Apache web server and hosted application.
        DiscussMD5 : AD6B50F36EB3CBE0812431727E69EB13
        CheckMD5   : 4FA52450590C27A40A38D54FB9EA2B34
        FixMD5     : 93E88AF88799D5F6C884DBEB4A4646CA
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
    $ErrorCount = 0
    $DirectiveName = "Header*.*Set-Cookie"
    $ExpectedValue = "Must include 'httpOnly' and 'secure'"
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $Null -DirectiveName $DirectiveName

    $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $FoundValues
    $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $FoundValues

    foreach ($line in $FoundValues) {
        #Format Directive Name
        $line.Name = "Header"
    }

    $FindingDetails = Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue -IsInGlobalConfig $IsInGlobalConfig -IsInAllVirtualHosts $IsInAllVirtualHosts

    if ($IsInGlobalConfig -or $IsInAllVirtualHosts) {
        foreach ($line in $FoundValues) {
            if ($line.Status -eq "Not Found") {
                continue
            }

            $ContainsHttpOnlySecure = [bool] ($line | Select-String -Pattern "$($DirectiveName)\b\s.*\b(httponly.*secure|secure.*httponly)\b" -Quiet)
            if ($ContainsHttpOnlySecure -eq $true) {
                continue # Our Pattern Matches therefore directive is good end loop.
            }

            #Directive matches but expected value missing exit loop
            $ErrorCount++
            break
        }
    }

    if ($ErrorCount -ge 1) {
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

Function Get-V214333 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214333
        STIG ID    : AS24-W1-000480
        Rule ID    : SV-214333r879638_rule
        CCI ID     : CCI-001188, CCI-001664
        Rule Name  : SRG-APP-000223-WSR-000145
        Rule Title : The Apache web server must accept only system-generated session identifiers.
        DiscussMD5 : 7BE063AD95733A42724D19326CCD4F94
        CheckMD5   : ACE61EBF9443EFCE3DAA1CFB07C7E1DE
        FixMD5     : AC62F3C5A3D08F373180D2FE9663FAE1
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
    $ModUniqueId = "unique_id_module"
    $ExpectedValue = "Enable"
    $ModuleResult = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $ModUniqueId
    $FindingDetails += Get-ApacheFormattedOutput -FoundValue $ModuleResult -ExpectedValue $ExpectedValue
    If ($ModuleResult.Status -eq "Disabled") {
        $Status = "Open"
    }
    else {
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

Function Get-V214334 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214334
        STIG ID    : AS24-W1-000500
        Rule ID    : SV-214334r879639_rule
        CCI ID     : CCI-001188
        Rule Name  : SRG-APP-000224-WSR-000136
        Rule Title : The Apache web server must generate unique session identifiers that cannot be reliably reproduced.
        DiscussMD5 : CA342D89A873CAFD0DDA42052ECA6D5E
        CheckMD5   : 527DE1F28D8566EE5915936EBCA5A8B4
        FixMD5     : AC62F3C5A3D08F373180D2FE9663FAE1
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
    $ModUniqueId = "unique_id_module"
    $ExpectedValue = "Enable"
    $ModuleResult = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $ModUniqueId
    $FindingDetails = Get-ApacheFormattedOutput -FoundValue $ModuleResult -ExpectedValue $ExpectedValue

    If ($ModuleResult.Status -eq "Disabled") {
        $Status = "Open"
    }
    else {
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

Function Get-V214335 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214335
        STIG ID    : AS24-W1-000530
        Rule ID    : SV-214335r879639_rule
        CCI ID     : CCI-001188
        Rule Name  : SRG-APP-000224-WSR-000139
        Rule Title : The Apache web server must generate unique session identifiers with definable entropy.
        DiscussMD5 : A1517AEF8E0242DDCB7EBC58BDB4FE80
        CheckMD5   : A0AEA7F45C7351A19D1B35C980F759C5
        FixMD5     : AD8C7029F4D694FF124D2F60D60E4EF8
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
    $ErrorCount = 0

    $ApacheModuleName = "ssl_module"
    $ExpectedState = "Enabled"
    $ModuleStatus = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $ApacheModuleName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $ModuleStatus -ExpectedValue $ExpectedState

    $Directive = "SSLRandomSeed"
    $Patterns = @("\s+startup\s+builtin\b", "\s+connect\s+builtin\b")
    $ExpectedValue = "Directive values 'startup builtin' and 'connect builtin' are present in config."
    $DirectiveResults = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $Directive

    $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $DirectiveResults
    $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $DirectiveResults

    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResults -ExpectedValue $ExpectedValue -IsInGlobalConfig $IsInGlobalConfig -IsInAllVirtualHosts $IsInAllVirtualHosts

    $PatternCount = 0
    $patternsChecked = [System.Collections.ArrayList]@()

    if ($ModuleStatus.Status -eq "Disabled") {
        $ErrorCount++
    }
    else {
        # It's okay to have this if else structure here because we aren't adding anything to the FindingDetails
        # when we check the directives against the STIG.
        if ($IsInGlobalConfig -or $IsInAllVirtualHosts) {
            # Check all of the directives like a normal check.
            foreach ($directive in $DirectiveResults) {
                if ($directive.Status -eq "Not Found") {
                    continue
                }

                foreach ($pattern in $Patterns) {
                    $result = $directive.ConfigFileLine | Select-String -Pattern $pattern
                    if ($null -ne $result -and $result -ne "") {
                        if ($patternsChecked.Contains($result.ToString())) {
                            continue
                        }
                        [void]$patternsChecked.add($result.ToString())
                        $PatternCount++
                    }
                }
            }
        }
        else {
            $ErrorCount++
        }
    }

    if ($PatternCount -lt 2) {
        $ErrorCount++
    }

    if ($ErrorCount -eq 0) {
        $Status = "NotAFinding"
    }
    else {
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

Function Get-V214337 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214337
        STIG ID    : AS24-W1-000580
        Rule ID    : SV-214337r879643_rule
        CCI ID     : CCI-001084
        Rule Name  : SRG-APP-000233-WSR-000146
        Rule Title : The Apache web server document directory must be in a separate partition from the Apache web servers system files.
        DiscussMD5 : C1D7279387F1250507FA99D4F38BDA08
        CheckMD5   : E2EC099E6B6E077ACE36098752A82795
        FixMD5     : 4B0F6F59ADEC9D294683B1B92D3D50E9
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
    $UserSIDs = Get-LocalUser | Select-Object * | Select-Object SID
    $SMBShares = Get-SmbShare -IncludeHidden
    $Printers = Get-Printer
    $RemoteDrives = @()
    $ErrorCount = 0

    $NonDefaultSharedPrinters = @()
    $NonDefaultShares = @()

    foreach ($sid in $UserSIDs) {
        $RegistryPath = "REGISTRY::HKEY_USERS\$($sid.SID)\Network\*"  # Registry path identified in STIG
        $RegistryValueName = "RemotePath"
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        if ($RegistryResult.Value -ne "(NotFound)") {
            $RemoteDrives += $RegistryResult.Value
        }
    }

    foreach ($share in $SMBShares) {
        if ($share.Name -match '.*\$') {
            continue
        }
        $ErrorCount ++
        $NonDefaultShares += $share
    }

    $DefaultPrinters = @('(?i)Microsoft', '(?i)^fax', '(?i)OneNote', '(?i)PDF')
    foreach ($printer in $Printers) {
        $IgnorePrinter = $false
        foreach ($pattern in $DefaultPrinters) {
            if ($printer.Name -match $pattern -or $IgnorePrinter -eq $true) {
                $IgnorePrinter = $true
                continue
            }
            $ErrorCount ++
            $NonDefaultSharedPrinters += $printer
        }
    }

    if ($null -ne $RemoteDrives -and $RemoteDrives.Count -ge 1) {
        $ErrorCount ++
    }

    if ($ErrorCount -ge 1) {
        $FindingDetails += "Printers:" | Out-String
        if ($NonDefaultSharedPrinters.Count -le 0) {
            $FindingDetails += "No non-default printers found." | Out-String
        }
        else {
            foreach ($printer in $NonDefaultSharedPrinters) {
                $PrinterName = $printer.Name
                $FindingDetails += "Printer Name:`t$($PrinterName)" | Out-String
            }
        }
        $FindingDetails += "" | Out-String

        $FindingDetails += "Shares:" | Out-String
        if ($NonDefaultShares.Count -le 0) {
            $FindingDetails += "No non-default shares found." | Out-String
        }
        else {
            foreach ($share in $NonDefaultShares) {
                $ShareName = $share.Name
                $FindingDetails += "Share Name:`t$($ShareName)" | Out-String
            }
        }
        $FindingDetails += "" | Out-String

        $FindingDetails += "Remote Drives:" | Out-String
        if ($null -eq $RemoteDrives -or $RemoteDrives.Count -le 0) {
            $FindingDetails += "No remote drives found." | Out-String
        }
        else {
            foreach ($drive in $RemoteDrives) {
                $FindingDetails += "Remote Drive:`t$($drive)" | Out-String
            }
        }
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails += "No Printers, Shares, or Remote Drives Found to be shared with the Web Server."
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

Function Get-V214338 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214338
        STIG ID    : AS24-W1-000590
        Rule ID    : SV-214338r879650_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246-WSR-000149
        Rule Title : The Apache web server must restrict the ability of users to launch denial-of-service (DoS) attacks against other information systems or networks.
        DiscussMD5 : 071F435F263754841239069F7EFCDC99
        CheckMD5   : 36F30F987EB86452DCD425FDDC2C521A
        FixMD5     : 6C18AA586B30CD9AD90013D803AC6E14
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
    $ErrorCount = 0
    $DirectiveName = "Timeout"
    $ExpectedValue = "10 or Less"
    $DirectiveResult = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName

    $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $DirectiveResult
    $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $DirectiveResult
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResult -ExpectedValue $ExpectedValue -IsInGlobalConfig $IsInGlobalConfig -IsInAllVirtualHosts $IsInAllVirtualHosts

    if ($IsInGlobalConfig -or $IsInAllVirtualHosts) {
        # Check all of the directives like a normal check.
        foreach ($directive in $DirectiveResult) {
            if ($directive.Status -eq "Not Found") {
                continue
            }
            $MaxAge = ($directive.ConfigFileLine.ToString() -split '\s+')[1] -as [int]
            if ($MaxAge -gt 10) {
                $ErrorCount++
                break
            }
        }
    }
    else {
        $ErrorCount++
    }
    if ($ErrorCount -eq 0 ) {
        $Status = "NotAFinding"
    }
    else {
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

Function Get-V214339 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214339
        STIG ID    : AS24-W1-000620
        Rule ID    : SV-214339r879655_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266-WSR-000159
        Rule Title : Warning and error messages displayed to clients must be modified to minimize the identity of the Apache web server, patches, loaded modules, and directory paths.
        DiscussMD5 : 6596859F3E3CF18122C7B96CAFA87E7D
        CheckMD5   : 79FB22D1D26DBF59F29A16460DBDB489
        FixMD5     : DFAFBC3320EF7244AB649B630CA31FDE
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
    $DirectiveName = "ErrorDocument"
    $ExpectedValue = "Configured and the error messages must not be too descriptive."
    $DirectiveResult = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName

    $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $DirectiveResult
    $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $DirectiveResult

    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResult -ExpectedValue $ExpectedValue -IsInGlobalConfig $IsInGlobalConfig -IsInAllVirtualHosts $IsInAllVirtualHosts

    if (-not ($IsInGlobalConfig) -and -not ($IsInAllVirtualHosts)) {
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

Function Get-V214340 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214340
        STIG ID    : AS24-W1-000630
        Rule ID    : SV-214340r879655_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266-WSR-000160
        Rule Title : Debugging and trace information used to diagnose the Apache web server must be disabled.
        DiscussMD5 : 8CA9503CDF1BD3D942F5461A064C2B7C
        CheckMD5   : 837D8330DDB43ADD8D3A2EFA0EA48214
        FixMD5     : ABC5BAFBD826B2916CE028F06550AE3A
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
    $BadDirective = 0
    $DirectiveName = "TraceEnable"
    $ExpectedValue = "Off"

    $DirectiveResult = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $DirectiveResult
    $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $DirectiveResult
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResult -ExpectedValue $ExpectedValue -IsInGlobalConfig $IsInGlobalConfig -IsInAllVirtualHosts $IsInAllVirtualHosts

    if ($IsInGlobalConfig -or $IsInAllVirtualHosts) {
        # Check all of the directives like a normal check.
        foreach ($directive in $DirectiveResult) {
            if ($directive.Status -eq "Not Found") {
                continue
            }
            $FoundValue = ($directive.ConfigFileLine.ToString() -split '\s+')[1]
            $FoundValue = $FoundValue | Select-String -Pattern $ExpectedValue

            if ($null -eq $FoundValue) {
                $BadDirective++
            }
        }
    }
    else {
        $BadDirective++
    }
    if ($BadDirective -ge 1) {
        $Status = "Open"
    }
    else {
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

Function Get-V214341 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214341
        STIG ID    : AS24-W1-000640
        Rule ID    : SV-214341r879673_rule
        CCI ID     : CCI-002361
        Rule Name  : SRG-APP-000295-WSR-000012
        Rule Title : The Apache web server must set an absolute timeout for sessions.
        DiscussMD5 : 74EC392945EE049185D5B5D3217E4A1A
        CheckMD5   : 08B4D81CBF7A7113614D0F0D6787AF29
        FixMD5     : 669B788903DE3589C37F93D0EC1E04AD
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
    $DirectiveName = "SessionMaxAge"
    $ExpectedValue = "600 or Less"
    $ErrorCount = 0
    $DirectiveResult = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName

    $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $DirectiveResult
    $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $DirectiveResult

    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResult -ExpectedValue $ExpectedValue -IsInGlobalConfig $IsInGlobalConfig -IsInAllVirtualHosts $IsInAllVirtualHosts

    if ($IsInGlobalConfig -or $IsInAllVirtualHosts) {
        # Check all of the directives like a normal check.
        foreach ($directive in $DirectiveResult) {
            if ($directive.Status -eq "Not Found") {
                continue
            }
            $MaxAge = $directive.ConfigFileLine.ToString().Split()[1] -as [int]
            if ($MaxAge -gt 600) {
                $ErrorCount++
                break
            }
        }
    }
    else {
        $ErrorCount++
    }

    if ($ErrorCount -eq 0) {
        $Status = "NotAFinding"
    }
    else {
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

Function Get-V214342 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214342
        STIG ID    : AS24-W1-000650
        Rule ID    : SV-214342r879673_rule
        CCI ID     : CCI-002361
        Rule Name  : SRG-APP-000295-WSR-000134
        Rule Title : The Apache web server must set an inactive timeout for completing the TLS handshake
        DiscussMD5 : E3CBC0BA02735E05B176715DA2C42DCE
        CheckMD5   : 14314833FCDE6F53E40E3ECE99B444C2
        FixMD5     : 362D94109681884843A2DB851C17AABE
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
    $ApacheModuleName = "reqtimeout_module"
    $ExpectedState = "Enabled"
    $ModuleStatus = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $ApacheModuleName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $ModuleStatus -ExpectedValue $ExpectedState

    $DirectiveName = "RequestReadTimeout"
    $ExpectedValue = "Must be explicitly configured"
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName

    $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $FoundValues
    $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $FoundValues
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue -IsInGlobalConfig $IsInGlobalConfig -IsInAllVirtualHosts $IsInAllVirtualHosts

    if ($ModuleStatus.Status -eq "Disabled") {
        $Status = "Open"
    }
    else {
        if (-not ($IsInGlobalConfig) -and -not ($IsInAllVirtualHosts)) {
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

Function Get-V214343 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214343
        STIG ID    : AS24-W1-000670
        Rule ID    : SV-214343r879692_rule
        CCI ID     : CCI-002314
        Rule Name  : SRG-APP-000315-WSR-000004
        Rule Title : The Apache web server must restrict inbound connections from nonsecure zones.
        DiscussMD5 : DC6161D8D832C4A41CD92A09F884A0ED
        CheckMD5   : 08031A9FB10B5A07978A9859A42CBEB4
        FixMD5     : ADDAE87EA68E5CF4E498A652F7AC175D
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
    $startBlock = "RequireAll"
    $endBlock = "RequireAll"
    $DirectiveCheck = "Require"
    $ExpectedValue = "Restrict IPs from nonsecure zones."

    $DirectiveResult = Get-ApacheDirectiveFromBlock -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -BlockStart $startBlock -BlockEnd $endBlock -DirectivePattern $DirectiveCheck
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResult -ExpectedValue $ExpectedValue

    $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $DirectiveResult
    $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $DirectiveResult

    if (-not ($IsInGlobalConfig) -and -not ($IsInAllVirtualHosts)) {
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

Function Get-V214346 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214346
        STIG ID    : AS24-W1-000700
        Rule ID    : SV-214346r879729_rule
        CCI ID     : CCI-001844
        Rule Name  : SRG-APP-000356-WSR-000007
        Rule Title : An Apache web server that is part of a web server cluster must route all remote management through a centrally managed access control point.
        DiscussMD5 : 495D648DA5F19D67A179684899064225
        CheckMD5   : 2CFF5F33E86E6254E09417F4934B6639
        FixMD5     : 85F9E0CAC934EA9297083C10D2FC2A19
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
    $ApacheModuleName = "proxy_module"
    $ExpectedState = "Enabled"
    $ModuleStatus = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $ApacheModuleName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $ModuleStatus -ExpectedValue $ExpectedState

    $DirectiveName = "ProxyPass"
    $ExpectedValue = "Must be configured"
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName

    $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $FoundValues
    $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $FoundValues

    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue -IsInGlobalConfig $IsInGlobalConfig -IsInAllVirtualHosts $IsInAllVirtualHosts


    if ($ModuleStatus.Status -eq "Disabled") {
        $Status = "Open"
    }
    else {
        if ($IsInGlobalConfig -or $IsInAllVirtualHosts) {
            $Status = "NotAFinding"
        }
        else {
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

Function Get-V214351 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214351
        STIG ID    : AS24-W1-000760
        Rule ID    : SV-214351r879748_rule
        CCI ID     : CCI-001890
        Rule Name  : SRG-APP-000375-WSR-000171
        Rule Title : The Apache web server must generate log records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT) with a minimum granularity of one second.
        DiscussMD5 : 2C710E440A03F983C23FA7074E390E12
        CheckMD5   : 94B03B49C88C13D093CA400E67810849
        FixMD5     : 4B1D249D440DCDC1D4837DCFE2A7B5C2
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
    $ErrorCount = 0

    $LogConfigModule = "log_config_module"
    $ModuleExpectedState = "Enabled"
    $ModuleResult = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $LogConfigModule
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $ModuleResult -ExpectedValue $ModuleExpectedState

    $LogFormatDirective = "LogFormat"
    $DirectiveExpectedValue = "Contains `"%t`" setting"
    $DirectiveResult = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $LogFormatDirective

    $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $DirectiveResult
    $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $DirectiveResult

    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResult -ExpectedValue $DirectiveExpectedValue -IsInGlobalConfig $IsInGlobalConfig -IsInAllVirtualHosts $IsInAllVirtualHosts

    if ($ModuleResult.Status -eq "Disabled") {
        $ErrorCount++
    }
    else {
        $Pattern = '%t\b'
        if ($IsInGlobalConfig -or $IsInAllVirtualHosts) {
            # Check all of the directives like a normal check.
            foreach ($directive in $DirectiveResult) {
                if ($directive.Status -eq "Not Found") {
                    continue
                }

                $directive = $directive.ConfigFileLine
                $Test = $directive | Select-String -Pattern $Pattern -CaseSensitive
                if ($null -eq $Test -or $Test -eq "") {
                    $ErrorCount++
                    break
                }

                $CommentPattern = '(?<!#.*)%t\b' # Checking for in-line comment. Example: %r #%t
                $CommentTest = $directive | Select-String -Pattern $CommentPattern -NotMatch -CaseSensitive
                if ($null -ne $CommentTest -and $CommentTest -ne "") {
                    $ErrorCount++
                    break
                }
            }
        }
        else {
            $ErrorCount++
        }
    }

    if ($ErrorCount -ge 1) {
        $Status = "Open"
    }
    else {
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

Function Get-V214352 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214352
        STIG ID    : AS24-W1-000800
        Rule ID    : SV-214352r879798_rule
        CCI ID     : CCI-002470
        Rule Name  : SRG-APP-000427-WSR-000186
        Rule Title : The Apache web server must only accept client certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs).
        DiscussMD5 : C101CA7CAF345FE585935154F170949B
        CheckMD5   : D5056C8A973C4EB350097A4AD6EB1F5F
        FixMD5     : B88B695ED237517CBB64FEE238738E7B
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
    $DirectiveName = "SSLCACertificateFile"
    $ExpectedValue = "Issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs)"
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails = Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue

    foreach ($line In $FoundValues ) {
        if ($line.Status -eq "Not Found") {
            continue
        }
        else {
            $caFilePath = $line.ConfigFileLine.ToString().Split('"')[1]
            if ($null -eq $caFilePath) {
                $caFilePath = $line.ConfigFileLine.ToString().Split()[1]
            }

            $FileFound = $false

            #check unaltered directive path
            $filePath = $caFilePath
            if (Test-Path -Path "$filePath") {
                $FileFound = $true
            }

            #check path ${SRVROOT} with HttpdRootPath substitution
            if ($FileFound -ne $true) {
                $filePath = $caFilePath.Replace('${SRVROOT}', $ApacheInstance.HttpdRootPath)
                if (Test-Path -Path "$filePath") {
                    $FileFound = $true
                }
            }

            #check relative path
            if ($FileFound -ne $true) {
                $filePath = Join-Path -Path $ApacheInstance.HttpdRootPath -ChildPath $caFilePath
                if (Test-Path -Path "$filePath") {
                    $FileFound = $true
                }
            }

            if ($FileFound -ne $true) {
                break
            }
            $opensslPath = $ApacheInstance.ExecutablePath.Replace("httpd.exe", "openssl.exe")
            if (Test-Path -Path "$opensslPath") {
                $opensslCommandOutput = & "$opensslPath" x509 -noout -text -purpose -in $filePath | Out-String
                $directiveIndex = $FindingDetails.IndexOf($caFilePath)
                if ($null -eq $ApacheInstance.VirtualHosts) {
                    $onLineIndex = $FindingDetails.IndexOf("Config Level", $directiveIndex)
                }
                else {
                    $onLineIndex = $FindingDetails.IndexOf("Site Name", $directiveIndex)
                }
                $insertIndex = $FindingDetails.IndexOf("`n", $onLineIndex)
                $FindingDetails = $FindingDetails.Insert($insertIndex, "`n`n$opensslCommandOutput") | Out-String
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

Function Get-V214353 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214353
        STIG ID    : AS24-W1-000820
        Rule ID    : SV-214353r879806_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-APP-000435-WSR-000147
        Rule Title : The Apache web server must be protected from being stopped by a non-privileged user.
        DiscussMD5 : 6DE0061143728BFF192808CCDB855117
        CheckMD5   : 3EF6981D7226640C0A897B4885F670FF
        FixMD5     : B09A902B2107584CD3CD81C8718DD7EE
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
    $HttpdPermissions = (Get-Acl -Path $ApacheInstance.HttpdRootPath).Access
    $DetectedFullControl = $HttpdPermissions | Where-Object {$_.FileSystemRights -like 'FullControl' -and $_.AccessControlType -eq 'Allow'} | Select-Object IdentityReference
    $DetectedRead = $HttpdPermissions | Where-Object {$_.FileSystemRights -like 'Read*' -and $_.AccessControlType -eq 'Allow'} | Select-Object IdentityReference, FileSystemRights

    $FindingDetails += "FullControl privileges for httpd.exe" | Out-String
    if (($DetectedFullControl | Measure-Object).Count -le 0) {
        $FindingDetails += "No Accounts Detected"
    }
    else {
        foreach ($user in $DetectedFullControl) {
            $FindingDetails += "Account:`t$($user.IdentityReference)" | Out-String
        }
    }

    $FindingDetails += "" | Out-String
    $FindingDetails += "Read & Execute or Read privileges for httpd.exe" | Out-String
    if (($DetectedRead | Measure-Object).Count -le 0) {
        $FindingDetails += "No Accounts Detected"
    }
    else {
        foreach ($user in $DetectedRead) {
            $FindingDetails += "Account:`t$($user.IdentityReference)" | Out-String
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

Function Get-V214354 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214354
        STIG ID    : AS24-W1-000830
        Rule ID    : SV-214354r879806_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-APP-000435-WSR-000148
        Rule Title : The Apache web server must be tuned to handle the operational requirements of the hosted application.
        DiscussMD5 : 1831797E217355F7E18C2BCD701F0C1E
        CheckMD5   : C449F289B8D2965BBCEF15825E77AB2A
        FixMD5     : 0AFCDD311654AA247E824C1B10ACA205
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
    $ErrorCount = 0
    $DirectiveName = "Timeout"
    $ExpectedValue = "10 or Less"
    $DirectiveResult = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName

    $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $DirectiveResult
    $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $DirectiveResult
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResult -ExpectedValue $ExpectedValue -IsInGlobalConfig $IsInGlobalConfig -IsInAllVirtualHosts $IsInAllVirtualHosts

    if ($IsInGlobalConfig -or $IsInAllVirtualHosts) {
        # Check all of the directives like a normal check.
        foreach ($directive in $DirectiveResult) {
            if ($directive.Status -eq "Not Found") {
                continue
            }
            $MaxAge = ($directive.ConfigFileLine.ToString() -split '\s+')[1] -as [int]
            if ($MaxAge -gt 10) {
                $ErrorCount++
                break
            }
        }
    }
    else {
        $ErrorCount++
    }
    if ($ErrorCount -eq 0 ) {
        $Status = "NotAFinding"
    }
    else {
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

Function Get-V214355 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214355
        STIG ID    : AS24-W1-000860
        Rule ID    : SV-214355r879810_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000439-WSR-000153
        Rule Title : The Apache web server cookies, such as session cookies, sent to the client using SSL/TLS must not be compressed.
        DiscussMD5 : 37034EF4B47F643998F10638B40AC36D
        CheckMD5   : BFDAAB8DE5408000D27A4141E319EA85
        FixMD5     : 7086A457778B70FB01A026951A74BA3E
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
    $DirectiveName = "SSLCompression"
    $ExpectedValue = "If the directive is present, it must be set to off"
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails = Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue
    $ErrorCount = 0

    foreach ($line in $FoundValues) {
        if ($line.Status -eq "Not Found") {
            continue
        }
        if ($line.ConfigFileLine | Select-String -NotMatch "\s*\boff\b\s*") {
            $ErrorCount++
            break
        }
    }
    If ($ErrorCount -eq 0) {
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

Function Get-V214356 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214356
        STIG ID    : AS24-W1-000930
        Rule ID    : SV-214356r879827_rule
        CCI ID     : CCI-002605
        Rule Name  : SRG-APP-000456-WSR-000187
        Rule Title : The Apache web server must install security-relevant software updates within the configured time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).
        DiscussMD5 : D03EBD79C8CB6A1252B39AB79C661C61
        CheckMD5   : 0967C1941C59316A1D4B8FA8D2B8BE93
        FixMD5     : F62A5E86690CEA3CC6FD5B7785D556AE
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
    $Version = Get-ApacheVersionTable -ExecutablePath $ApacheInstance.ExecutablePath
    $ServerVersion = $Version | Select-String -Pattern 'Server version'
    $ServerBuilt = $Version | Select-String -Pattern 'Server built'

    $ServerVersion1 = $ServerVersion -replace ".*Server version:\s+"
    $ServerBuilt1 = $ServerBuilt -replace ".*Server built:\s+"

    $FindingDetails += "Server version:`t`t$($ServerVersion1)" | Out-String
    $FindingDetails += "Server built:`t`t$($ServerBuilt1)" | Out-String
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

Function Get-V214357 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214357
        STIG ID    : AS24-W1-000940
        Rule ID    : SV-214357r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000079
        Rule Title : All accounts installed with the Apache web server software and tools must have passwords assigned and default passwords changed.
        DiscussMD5 : C28EA026F50E85359DEDEC517ADDFA7C
        CheckMD5   : D22AD6100A43EFF74265415F411F9886
        FixMD5     : 36AD773F2D1AD93D747AF6EAF5193C0D
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
    $LocalUsers = Get-LocalUser | Select-Object "Name"
    $LocalUsers = $LocalUsers | Select-Object -Skip 4

    foreach ($user in $LocalUsers) {
        $userinfo = Get-LocalUser $user.Name | Select-Object *
        if ( ($null -ne $userinfo) -and ($userinfo.Enabled -eq "True") ) {
            $username = $userinfo.Name
            $FindingDetails += "Local User: " + $username | Out-String

            try {
                $sid = $userinfo.SID.Value
                $regpath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $sid
                $profilepath = Get-ItemProperty -Path $regpath -Name 'ProfileImagePath'

                $ct = Get-ItemProperty -Path $profilepath.ProfileImagePath | Select-Object -Property CreationTime
                if ( ($null -ne $ct) -and ($ct -ne "") ) {
                    $FindingDetails += "First Logon:  " + $ct.CreationTime | Out-String
                }
                else {
                    $FindingDetails += "First Logon: Never" | Out-String
                }
            }
            catch {
                $FindingDetails += "First Logon: Never" | Out-String
            }

            if (($null -ne $userinfo.PasswordLastSet) -and ($userinfo.PasswordLastSet -ne "")) {
                $FindingDetails += "Password Last Set: " + $userinfo.PasswordLastSet | Out-String
            }
            else {
                $FindingDetails += "Password Last Set: Never" | Out-String
            }

            if ($null -eq $userinfo.PasswordLastSet) {
                $FindingDetails += "*** DEFAULT PASSWORD DETECTED ***" | Out-String
            }
            elseif (($null -eq $ct.CreationTime) -or
                 ($userinfo.PasswordLastSet -lt $ct.CreationTime)) {
                $FindingDetails += "*** INITIAL PASSWORD DETECTED ***" | Out-String
            }

            $FindingDetails += "`n--------------------`n" | Out-String
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

Function Get-V214358 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214358
        STIG ID    : AS24-W1-000950
        Rule ID    : SV-214358r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The Apache web server must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.
        DiscussMD5 : 3CE58ADAA2D1094E21A4625C1F2EC57C
        CheckMD5   : F119BABBF3BE8D30BFC1D32C140253CB
        FixMD5     : CB304C9DE7E299EC14EC7D4FEEABB2B9
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
    $ErrorCount = 0
    $ExpectedValue = "Website utilizes IANA well-known ports for HTTP and HTTPS"
    $Patterns = ('\b80\b', '\b443\b', ':80\b', ':443\b')
    $Pattern = ".*:[0-9]{1,5}"
    $ServerName = "ServerName"
    $GlobalFoundValue = Get-ApacheDirectiveFromGlobalConfig -ApacheInstance $ApacheInstance -DirectiveName $ServerName

    foreach ($website in $GlobalFoundValue) {
        if ($website.Status -eq "Not Found") {
            continue
        }
        $FindingDetails += Get-ApacheFormattedOutput -FoundValues $GlobalFoundValue -ExpectedValue $ExpectedValue

        if ($null -eq ($website | Select-String -Pattern $Pattern | Select-String -Pattern $Patterns)) {
            $ErrorCount++
        }
    }

    $DirectiveName = "<\s*VirtualHost"
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName

    foreach ($website in $FoundValues) {
        if ($website.Name -eq "<\s*VirtualHost") {
            $website.Name = "VirtualHost"
        }
        if ($website.status -eq "Not Found" ) {
            continue
        }
        $FindingDetails += Get-ApacheFormattedOutput -FoundValues $website -ExpectedValue $ExpectedValue
        if ($null -eq ($website | Select-String -Pattern $Pattern | Select-String -Pattern $Patterns)) {
            $ErrorCount++
        }
    }

    if ($ErrorCount -eq 0) {
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

Function Get-V214359 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214359
        STIG ID    : AS24-W1-000960
        Rule ID    : SV-214359r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The Apache web server software must be a vendor-supported version.
        DiscussMD5 : 64F035EAD9B5D1E839C2CB526ADB7AD2
        CheckMD5   : D5A0A29F8E3B536CE9F60C447CE100EA
        FixMD5     : F62A5E86690CEA3CC6FD5B7785D556AE
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
    $Version = Get-ApacheVersionTable -ExecutablePath $ApacheInstance.ExecutablePath
    $ServerVersion = $Version | Select-String -Pattern 'Server version'
    $ServerBuilt = $Version | Select-String -Pattern 'Server built'

    $ServerBuilt1 = $ServerBuilt -replace ".*Server built:\s+" -replace "\d\d:\d\d:\d\d"
    $ServerVersion1 = $ServerVersion -replace ".*Server version:\s+Apache/"

    #This line splits on one or more spaces to prevent double spaces causing incorrect dates e.g. Dec"  "1 2020
    $MonthYearSplit = $ServerBuilt1 -split "\s+"
    $Year = $MonthYearSplit[2]
    $Bad2012 = '(?i)Jan.*2012'

    #this test ensures date is greater than 2011 to fix Y2K  type bug
    $testgt = $Year -gt 2011

    $IsValidBuiltMonthAndYear = $false
    if ($ServerBuilt1 -notmatch $Bad2012 -and $testgt -eq $true) {
        $IsValidBuiltMonthAndYear = $true
    }

    If ($ServerVersion -match 'Apache/[2-9]\.[4-9].*' -and $IsValidBuiltMonthAndYear -eq $true) {
        $Status = "NotAFinding"
        $FindingDetails += "Expected Version:`t`tApache 2.4 (or higher)" | Out-String
        $FindingDetails += "Detected Version:`t`t$($ServerVersion1)" | Out-String
        $FindingDetails += "Expected Built Date:`tFebruary 2012 (or Later)" | Out-String
        $FindingDetails += "Detected Built Date:`t$($ServerBuilt1)" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "Expected Version:`t`tApache 2.4 (or higher)" | Out-String
        $FindingDetails += "Detected Version:`t`t$($ServerVersion1)" | Out-String
        $FindingDetails += "Expected Built Date:`tFebruary 2012 (or Later)" | Out-String
        $FindingDetails += "Detected Built Date:`t$($ServerBuilt1)" | Out-String
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

# SIG # Begin signature block
# MIIL+QYJKoZIhvcNAQcCoIIL6jCCC+YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB65DfRJRmlE82g
# 7NwCoIeQEknUwLs5VlT3sIcg+/vHlaCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBhScu0gaHjorhc72+xjJejAf546quL
# Xf3aCkN3FTV5UzANBgkqhkiG9w0BAQEFAASCAQB9GolTPWReV/grj3F6cXfaBjyq
# GYMCONdhFJptNprkqeDzwFNT9PpHpXzI2L1O+FPelMMPwmaGah04PPnv/h280ket
# zkf2I5mJfnUoRg371l5JxaiyExGplzlWk+//32NivpNBhDK6GbLrbewE/c+HpbxT
# wGda5TboIRp34DOkMgjL8S4NFjanujLNQo1JxemdctLQhJfippb1JJa2Y5gMWtb+
# 7IvndiPAvXuXMumfmSTmHurd3IrMJeiPrAe6A//8nTbGNLtwh3A48PNld27BQAdh
# 8OrAhLJDgAnRlSK5W241auqQMlqDXQXxbDRvJsjkJJ+10xDV/uo1sdwonML4
# SIG # End signature block
