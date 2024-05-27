##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Apache Server 2.4 UNIX Server
# Version:  V2R7
# Class:    UNCLASSIFIED
# Updated:  5/13/2024
# Author:   U.S. Army Communications-Electronics Command, Software Engineering Center (CECOM SEC)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V214228 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214228
        STIG ID    : AS24-U1-000010
        Rule ID    : SV-214228r881404_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-WSR-000001
        Rule Title : The Apache web server must limit the number of allowed simultaneous session requests.
        DiscussMD5 : 2ECCA660E5E38A0FE5452A38789CD581
        CheckMD5   : 373716B717C62C831B676D20D67F5EF1
        FixMD5     : FEAC6F7F269A5ED525608102C2EC3C1D
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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
    $KeepAliveDirective = "KeepAlive"
    $ExpectedValue1 = "on"
    $KeepAliveFound = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $KeepAliveDirective
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $KeepAliveFound -ExpectedValue $ExpectedValue1
    $IsKAInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $KeepAliveFound
    $IsKAInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $KeepAliveFound

    if ($IsKAInGlobalConfig -or $IsKAInAllVirtualHosts) {
        # Check all of the directives like a normal check.
        foreach ($directive in $KeepAliveFound) {
            if ($directive.Status -eq "Not Found") {
                continue
            }
            $KeepAlive = $directive.ConfigFileLine.ToString().Split()[1]
            if ($KeepAlive -ne "On") {
                $ErrorCount++
                break
            }
        }
    }
    else {
        $ErrorCount++
    }

    $MaxKeepAlive = "MaxKeepAliveRequests"
    $ExpectedValue = "100 or greater"
    $MaxKAFound = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $MaxKeepAlive
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $MaxKAFound -ExpectedValue $ExpectedValue
    $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $MaxKAFound
    $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $MaxKAFound

    if ($IsInGlobalConfig -or $IsInAllVirtualHosts) {
        # Check all of the directives like a normal check.
        foreach ($directive in $MaxKAFound) {
            if ($directive.Status -eq "Not Found") {
                continue
            }
            $MaxKeepAlive = $directive.ConfigFileLine.ToString().Split()[1] -as [int]
            if ($MaxKeepAlive -lt "100") {
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

Function Get-V214229 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214229
        STIG ID    : AS24-U1-000020
        Rule ID    : SV-214229r881406_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-WSR-000002
        Rule Title : The Apache web server must perform server-side session management.
        DiscussMD5 : 2CE65186228483D9C44C7FCFB8CE2202
        CheckMD5   : 28C0D3223E208244EB1E43766C22F6EE
        FixMD5     : C37FFB2BD41E3F57C596B67173B41E00
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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

Function Get-V214230 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214230
        STIG ID    : AS24-U1-000030
        Rule ID    : SV-214230r881408_rule
        CCI ID     : CCI-000068, CCI-000197, CCI-000213, CCI-000803, CCI-001188, CCI-001453, CCI-002418, CCI-002422, CCI-002470
        Rule Name  : SRG-APP-000014-WSR-000006
        Rule Title : The Apache web server must use cryptography to protect the integrity of remote sessions.
        DiscussMD5 : 8E2E20B20472142B1005C6BC26A6D74F
        CheckMD5   : 068846DF45A3A0C352D5E00F06D66A4B
        FixMD5     : 33C312ECCD5EBAB5DDCD5B33369A68CB
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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

    $ApacheDirectiveName = "SSLProtocol"
    $DirectiveExpectedValue = "-ALL +TLSv1.2"
    $DirectiveResult = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $ApacheDirectiveName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResult -ExpectedValue $DirectiveExpectedValue

    $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $DirectiveResult
    $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $DirectiveResult

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

                $ShouldNotAppear = "\+TLSv1\s+", "\+TLSv1.1", "\+SSL"
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

Function Get-V214231 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214231
        STIG ID    : AS24-U1-000065
        Rule ID    : SV-214231r881410_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The Apache web server must have system logging enabled.
        DiscussMD5 : 5DD3AA73093FB7EBBDA74DA2359AA959
        CheckMD5   : 958778DAE4D7DFD63133D1D5C62D5EEC
        FixMD5     : 1B1E597FDB738EACE7CDC36132A8DD17
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$SiteName,

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
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $ApacheFoundValues -ExpectedValue $ExpectedValue

    $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $ApacheFoundValues
    $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $ApacheFoundValues

    if ($IsInGlobalConfig -or $IsInAllVirtualHosts) {
        foreach ($line in $ApacheFoundValues) {
            if ($line.Status -eq "Not Found") {
                continue
            }

            $ConfigLine = $line.configfileline.Trim()
            $DetectedValue = $ConfigLine.substring($ConfigLine.IndexOf(' ')).Trim()
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

Function Get-V214232 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214232
        STIG ID    : AS24-U1-000070
        Rule ID    : SV-214232r881413_rule
        CCI ID     : CCI-000130, CCI-000131, CCI-000132, CCI-000133, CCI-000134, CCI-000169, CCI-001464, CCI-001487
        Rule Name  : SRG-APP-000089-WSR-000047
        Rule Title : The Apache web server must generate, at a minimum, log records for system startup and shutdown, system access, and system authentication events.
        DiscussMD5 : 6476BB7216A8970FF8876B67F2DB0924
        CheckMD5   : 11F1DCB3942182AB730B7DB58034935F
        FixMD5     : 4FA3A80F062928484095760ABF5D68AD
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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
    $ApacheModuleName = "log_config_module"
    $ExpectedValue = "Enabled"

    $ModuleObject = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $ApacheModuleName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $ModuleObject -ExpectedValue $ExpectedValue
    if ($ModuleObject.Status -eq "Disabled") {
        $ErrorCount++
    }

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

    if ($FoundValueCount -le 0 -or $ErrorCount -ge 1) {
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

Function Get-V214235 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214235
        STIG ID    : AS24-U1-000180
        Rule ID    : SV-214235r881417_rule
        CCI ID     : CCI-000162
        Rule Name  : SRG-APP-000118-WSR-000068
        Rule Title : The Apache web server log files must only be accessible by privileged users.
        DiscussMD5 : 8FC11A6A2BBC37631668E9C7F7EA791F
        CheckMD5   : 1EDD81F0246E2098A69BB0FCBF5234A9
        FixMD5     : BB113745B8FA0C125A05C46139678B0E
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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
    $LogDirExists = 0
    $LogFilesExists = 0
    $NonLocalFileOwnership = 0
    $StandardUsers = @()
    $LogDirs = [System.Collections.ArrayList]@(Get-ApacheLogDirs -ApacheInstance $ApacheInstance)
    $LocalUsers = Get-Content /etc/passwd | Select-String -NotMatch "nologin" | ForEach-Object {$_.ToString().Split(":")[0]}
    $GetApacheUserLine = "$($ApacheInstance.ExecutablePath) -S"
    $ApacheUserLine = Invoke-Expression $GetApacheUserLine
    $ApacheServiceUser = ( $ApacheUserLine | grep "User:" | sed -e 's/^.*name=\"//' -e 's/\".*$//')

    foreach ( $user in $LocalUsers ) {
        if ( -Not ( "$user" -eq "$ApacheServiceUser" ) ) {
            $Priv = $(sudo -l -U $user)
            if ($null -eq $Priv) {
                continue
            }

            if ( $Priv.Contains("is not allowed to run sudo") ) {
                $StandardUsers += $user
            }
        }
    }

    foreach ($LogDir in $LogDirs) {

        If ( Test-Path "$LogDir" ) {
            $LogDirExists = 1
            $LogFiles = Get-ChildItem -Path $LogDir -Recurse -Attributes !Directory | Select-Object -ExpandProperty FullName

            if ( ($LogFiles | Measure-Object).Count -gt 0 ) {
                $LogFilesExists = 1

                foreach ( $user in $StandardUsers ) {
                    $firstLine = 1

                    foreach ( $file in $LogFiles ) {
                        $HasAccess = $(sudo -u $user test -r $file && echo true || echo false)
                        if ( $HasAccess.Contains("true" )) {
                            $ErrorCount++
                            If ( $firstLine -eq "1" ) {
                                $FindingDetails += "Standard user [$($user)] has read access to:" | Out-String
                                $FindingDetails += "`t$file" | Out-String
                                $firstLine = 0
                            }
                            else {
                                $FindingDetails += "`t$file" | Out-String
                            }
                        }
                    }

                    If ( $firstLine -eq "0" ) {
                        $FindingDetails += "" | Out-String
                    }
                }

                $AllUsers = Get-Content /etc/passwd | ForEach-Object {$_.ToString().Split(":")[0]}
                foreach ( $file in $LogFiles ) {
                    $UserFileAccess = $(stat -L -c "%U" $file)
                    if ( -not ($AllUsers.Contains($UserFileAccess)) ) {
                        $FindingDetails += "File [$file] owner [$($UserFileAccess)] is not a local user and has access" | Out-String
                        $FindingDetails += "" | Out-String
                        $NonLocalFileOwnership = 1
                    }

                    $AllGroups = Get-Content /etc/group | ForEach-Object {$_.ToString().Split(":")[0]}
                    $GroupFileAccess = $(stat -L -c "%G" $file)
                    if ( -not ($AllGroups.Contains($GroupFileAccess)) ) {
                        $FindingDetails += "File [$file] group [$($GroupFileAccess)] is not a local group and has access" | Out-String
                        $FindingDetails += "" | Out-String
                        $NonLocalFileOwnership = 1
                    }

                    $OtherFileAccess = $(stat -L -c "%A" $file | cut -c8-10)
                    if ( $OtherFileAccess -match "[rw]" ) {
                        $FindingDetails += "File [$file] access mode [$($OtherFileAccess)] grants Others access" | Out-String
                        $FindingDetails += "" | Out-String
                        $ErrorCount++
                    }
                }
            }
        }
        else {
            $FindingDetails += "Directory $($LogDir) does not exist" | Out-String
        }
    }

    if ($ErrorCount -eq 0) {
        if ( $NonLocalFileOwnership -eq 0 ) {
            if ( $LogDirExists -eq 1 ) {
                if ( $LogFilesExists -eq 1 ) {
                    $FindingDetails += "No users have access to files in $LogDir" | Out-String
                }
                else {
                    $FindingDetails += "No log files found in $LogDir" | Out-String
                }
            }
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

Function Get-V214236 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214236
        STIG ID    : AS24-U1-000190
        Rule ID    : SV-214236r881419_rule
        CCI ID     : CCI-000163, CCI-000164
        Rule Name  : SRG-APP-000119-WSR-000069
        Rule Title : The log information from the Apache web server must be protected from unauthorized modification or deletion.
        DiscussMD5 : 34E69415584CCE5B46CD6262C9748697
        CheckMD5   : 34A3D7C287B7E9A68B0CC7CC297F65CC
        FixMD5     : C0602D9ABB0D894637CA7B93F424C88E
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$SiteName,

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
    $PathsToLogs = [System.Collections.ArrayList]@(Get-ApacheLogDirs -ApacheInstance $ApacheInstance)
    $FileOwners = @()
    $FileList = @()
    foreach ($PathtoLogs in $PathsToLogs) {
        $FileOwners += (ls -Ll ${PathToLogs} | awk '{if(NR>1)print}' | awk '{print $3}')
        $FileList += (ls -Ll ${PathToLogs} | awk '{if(NR>1)print}' | awk '{print $9}')
    }

    #Gather the service account from the conf files
    $DirectiveName = "User"
    $DirectiveFiles = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    if ( ($DirectiveFiles | Measure-Object).Count -ge "1" ) {
        $ApacheUser = $DirectiveFiles[0].ConfigFileLine | awk '{print $2}'
    }
    else {
        $ApacheUser = "nouser"
    }

    if ( ($FileList | Measure-Object).Count -ge 1 ) {
        $LineNum = 0
        $BadFiles = 0
        while ( $LineNum -lt ($FileList | Measure-Object).Count ) {
            $FindingDetails += "File:`t`t`t`t${PathToLogs}/$($FileList[$LineNum])" | Out-String
            $FindingDetails += "Expected Owner:`t$ApacheUser" | Out-String
            $FindingDetails += "Detected Owner:`t$($FileOwners[$LineNum])" | Out-String
            $FindingDetails += "" | Out-String
            if ( "$($FileOwners[$LineNum])" -ne "$ApacheUser" ) {
                $BadFiles++
            }
            $LineNum++
        }
        if ( $BadFiles -ge 1 ) {
            $Status = "Open"
        }
    }
    else {
        $FindingDetails += "No log files found." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214238 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214238
        STIG ID    : AS24-U1-000230
        Rule ID    : SV-214238r879584_rule
        CCI ID     : CCI-001749
        Rule Name  : SRG-APP-000131-WSR-000073
        Rule Title : Expansion modules must be fully reviewed, tested, and signed before they can exist on a production Apache web server.
        DiscussMD5 : 0BF730F5451B904047348EB80160DC97
        CheckMD5   : EA7B6882A741E115AF006807A49D1699
        FixMD5     : 53C1D1CD3982DF16715FCEBD020E48C3
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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
    $FindingDetails += $ApacheInstance.modules | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214239 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214239
        STIG ID    : AS24-U1-000240
        Rule ID    : SV-214239r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000015
        Rule Title : The Apache web server must not perform user management for hosted applications.
        DiscussMD5 : 7ED3AC4931322A6F41D7772BC199A21F
        CheckMD5   : 8BCEC1A724CD3313731443FD0616BBA1
        FixMD5     : 000115376120ECE8A5ADED707E33F622
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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
    $DirectiveName = "AuthUserFile"
    $ExpectedValue = "Not Found"
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue

    foreach ($directiveLine in $FoundValues) {
        if ($directiveLine.Status -eq "Not Found") {
            continue
        }

        $ErrorCount++
        break
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

Function Get-V214241 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214241
        STIG ID    : AS24-U1-000260
        Rule ID    : SV-214241r953851_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000076
        Rule Title : The Apache web server must not be a proxy server.
        DiscussMD5 : 6C97689C8D38013BEB245DB852A6C150
        CheckMD5   : D8FB9376A75AD550EDA7461E0A8039C5
        FixMD5     : DE7A7577498583736F8A9CE692AB26FB
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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
    $BadModules = @('proxy_module', 'proxy_ajp_module', 'proxy_balancer_module', 'proxy_ftp_module', 'proxy_http_module', 'proxy_connect_module')
    $ExpectedValue = "Disabled"
    foreach ($ApacheModuleName in $BadModules) {
        $ModuleObject = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $ApacheModuleName
        $FindingDetails += Get-ApacheFormattedOutput -FoundValues $ModuleObject -ExpectedValue $ExpectedValue
        if ($ModuleObject.Status -ne "Disabled") {
            $ErrorCount++
        }
    }

    $DirectiveName = "ProxyRequest"
    $ExpectedValue = "Off"
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue

    foreach ($directive in $FoundValues) {
        if ($directive.Status -eq "Not Found") {
            continue
        }
        $ProxyRequest = $directive.ConfigFileLine.ToString().Split()[1]
        if ($ProxyRequest -eq "On") {
            $ErrorCount++
            break
        }
    }

    if ($ErrorCount -gt 0) {
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

Function Get-V214242 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214242
        STIG ID    : AS24-U1-000270
        Rule ID    : SV-214242r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000077
        Rule Title : The Apache web server must provide install options to exclude the installation of documentation, sample code, example applications, and tutorials.
        DiscussMD5 : DFD73606808EC3577136C6D3CDB39813
        CheckMD5   : C0D8BFC3D18E04B0EA9F8C8D9F9C0637
        FixMD5     : B4D80C96A30A254505F3B2BC9BCDF444
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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
        $directive.Name = $directive.Name -replace "[\\b\\s+]", " " | tr -s " "
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
        $directive.Name = $directive.Name -replace "[\\b\\s+]", " " | tr -s " "
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

Function Get-V214243 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214243
        STIG ID    : AS24-U1-000300
        Rule ID    : SV-214243r881424_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000081
        Rule Title : The Apache web server must have resource mappings set to disable the serving of certain file types.
        DiscussMD5 : 893943AF1C9E2E2EA4C50059E1C66C7D
        CheckMD5   : B48249249E6C6307B79C23148534B9A8
        FixMD5     : A74B09CA29D94E069BA47F59C31F69F5
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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

Function Get-V214244 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214244
        STIG ID    : AS24-U1-000310
        Rule ID    : SV-214244r881427_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000082
        Rule Title : The Apache web server must allow the mappings to unused and vulnerable scripts to be removed.
        DiscussMD5 : 5111E74263E14CCB3C3C18D532AC1C9C
        CheckMD5   : A4BBDEF4E379873A90B98B1093A86BBC
        FixMD5     : F68B690A71D00A6459C839B8A30097F5
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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
    $ScriptCount = 0
    $DirectiveNames = @("Script", "ScriptAlias", "ScriptAliasMatch", "ScriptInterpreterSource")
    $ExpectedValue = "Needed for application operation"
    $FoundValues = @()
    foreach ($DirectiveName in $DirectiveNames) {
        $FoundValues += Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    }
    foreach ($directive in $FoundValues) {
        if ($directive.Status -eq "Not Found") {
            continue
        }
        $FindingDetails += Get-ApacheFormattedOutput -FoundValues $directive -ExpectedValue $ExpectedValue
        $ScriptCount++
    }

    if ($ScriptCount -gt 0) {
        $Status = "Not_Reviewed"
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "No Script directives found." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214245 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214245
        STIG ID    : AS24-U1-000330
        Rule ID    : SV-214245r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000085
        Rule Title : The Apache web server must have Web Distributed Authoring (WebDAV) disabled.
        DiscussMD5 : 68D715EA4D1C5DAF57DBFCBB3325667D
        CheckMD5   : 916D74822663FFBDBEA83826B5DACCC5
        FixMD5     : B69BD67694493EDC3C012F7B642C1111
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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
    $BadModules = ('dav_module', 'dav_fs_module', 'dav_lock_module')
    $ExpectedValue = "Disabled"
    foreach ($ApacheModuleName in $BadModules) {
        $ModuleObject = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $ApacheModuleName
        $FindingDetails += Get-ApacheFormattedOutput -FoundValues $ModuleObject -ExpectedValue $ExpectedValue
        if ($ModuleObject.Status -ne "Disabled") {
            $ErrorCount++
        }
    }

    if ($ErrorCount -gt 0) {
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

Function Get-V214246 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214246
        STIG ID    : AS24-U1-000360
        Rule ID    : SV-214246r881430_rule
        CCI ID     : CCI-000186, CCI-000382
        Rule Name  : SRG-APP-000142-WSR-000089
        Rule Title : The Apache web server must be configured to use a specified IP address and port.
        DiscussMD5 : DC815BB797A1D40EF8A0CE3736FF27AB
        CheckMD5   : 1C2794C208F3798F108F89E4032B81F2
        FixMD5     : EF1B7DF8187AF24DECC005DEECE52148
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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

Function Get-V214247 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214247
        STIG ID    : AS24-U1-000430
        Rule ID    : SV-214247r879631_rule
        CCI ID     : CCI-001082
        Rule Name  : SRG-APP-000211-WSR-000030
        Rule Title : Apache web server accounts accessing the directory tree, the shell, or other operating system functions and utilities must only be administrative accounts.
        DiscussMD5 : 3D748CCAB39740BDC35EBEB9C37B7E58
        CheckMD5   : FC86ECF2638E01A7B46A484BA553F048
        FixMD5     : FC692446347A3CCA6DA99E314EC9ABC3
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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
    #Check for available shells
    $ShellsExist = Get-Content /etc/shells
    #Compare /etc/passwd against available shell types to create list of users with shell access
    $UsersWithShell = Get-Content /etc/passwd | Select-String -Pattern $ShellsExist | ForEach-Object {$_.ToString().Split(":")[0] + " "}
    #Print users with shell access to audit
    $FindingDetails += "Users with shell access:" | Out-String
    foreach ($User in $UsersWithShell) {
        $FindingDetails += $User | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214248 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214248
        STIG ID    : AS24-U1-000440
        Rule ID    : SV-214248r879631_rule
        CCI ID     : CCI-000381, CCI-001082, CCI-001813
        Rule Name  : SRG-APP-000211-WSR-000031
        Rule Title : Apache web server application directories, libraries, and configuration files must only be accessible to privileged users.
        DiscussMD5 : FD2F82C78AAFD328C4CE7CEC80D340C0
        CheckMD5   : 9E945BFA3FD87588BD0F85E0BB31F83B
        FixMD5     : 7C63A5703AE0EE6FBF5BCD856A090CC6
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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
    $ShellsExist = Get-Content /etc/shells
    $UsersWithShell = Get-Content /etc/passwd | Select-String -Pattern $ShellsExist | ForEach-Object {$_.ToString().Split(":")[0]}
    $UsersWithSudo = (getent -s files passwd | ForEach-Object {([String]$_).Split(":")[0]} | sudo xargs -L1 sudo -l -U | Out-String -Stream | Select-String -Pattern "may run" -NoEmphasis)
    $FindingDetails += "Users with sudo and shell access:" | Out-String

    Foreach ($User in $UsersWithSudo) {
        $SudoUserList += $User | ForEach-Object { $_.ToString().Trim("> ") -replace '^User ' -replace ' may run*.*' } | Out-String
    }

    $SudoUserList = $SudoUserList.Split()

    Foreach ($User in $UsersWithShell) {
        $TestMatch = [regex]::Match($SudoUserList, $User).Value
        $TestMatch = $TestMatch | Where-Object {$_ -ne ""}
        $FindingDetails += $TestMatch | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214250 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214250
        STIG ID    : AS24-U1-000460
        Rule ID    : SV-214250r881433_rule
        CCI ID     : CCI-001185, CCI-002361
        Rule Name  : SRG-APP-000220-WSR-000201
        Rule Title : The Apache web server must invalidate session identifiers upon hosted application user logout or other session termination.
        DiscussMD5 : CCFBB129F07BA51950457056B318377A
        CheckMD5   : D37F6764B1B871160B60CBE509C1A201
        FixMD5     : 2D6DAAEED252D5548DB7BACA67571F1C
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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
    $DirectiveName = "SessionMaxAge"
    $ExpectedValue = "600 or Less"

    $DirectiveResult = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResult -ExpectedValue $ExpectedValue

    $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $DirectiveResult
    $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $DirectiveResult

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

Function Get-V214251 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214251
        STIG ID    : AS24-U1-000470
        Rule ID    : SV-214251r879638_rule
        CCI ID     : CCI-001664
        Rule Name  : SRG-APP-000223-WSR-000011
        Rule Title : Cookies exchanged between the Apache web server and client, such as session cookies, must have security settings that disallow cookie access outside the originating Apache web server and hosted application.
        DiscussMD5 : AD6B50F36EB3CBE0812431727E69EB13
        CheckMD5   : 0A964409D58E7E52C60D5CDBB50AC016
        FixMD5     : C2DB24AE0A12483B2221149ACBAFBADC
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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
    $ApacheModule = "headers_module"
    $ExpectedState = "Enabled"

    $ModuleStatus = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $ApacheModule
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $ModuleStatus -ExpectedValue $ExpectedState

    if ($ModuleStatus.Status -eq "Disabled") {
        $ErrorCount++
    }

    $DirectiveName = "SessionCookieName"
    $ExpectedValue = "Must contain 'HttpOnly', 'Secure' and not 'Domain' settings"
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $Null -DirectiveName $DirectiveName
    $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $FoundValues
    $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $FoundValues
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue -IsInGlobalConfig $IsInGlobalConfig -IsInAllVirtualHosts $IsInAllVirtualHosts


    if ($IsInGlobalConfig -or $IsInAllVirtualHosts) {
        foreach ($line in $FoundValues) {
            if ($line.Status -eq "Not Found") {
                continue
            }

            if ($line | Select-String -Pattern "$($DirectiveName).*\bdomain=\b") {
                $ErrorCount++
                break
            }

            if ($line | Select-String -Pattern "$($DirectiveName)\b\s.*;\s*httponly\s*;") {
                if ($line | Select-String -Pattern "$($DirectiveName)\b\s.*;\s*secure\s*;") {
                    continue
                }
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
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214252 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214252
        STIG ID    : AS24-U1-000510
        Rule ID    : SV-214252r881435_rule
        CCI ID     : CCI-001188
        Rule Name  : SRG-APP-000224-WSR-000137
        Rule Title : The Apache web server must generate a session ID long enough that it cannot be guessed through brute force.
        DiscussMD5 : C133F96DC40C9561C636F6D1E9178BAD
        CheckMD5   : EE628E29AB23D8FE03E25346ED786D17
        FixMD5     : 28BFA5016BEE2FC73F407109D0283872
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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
    $SessionCryptoModule = "session_crypto_module"
    $ExpectedValue = "Enabled"
    $ModuleResult = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $SessionCryptoModule
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $ModuleResult -ExpectedValue $ExpectedValue

    if ($ModuleObject.Status -eq "Disabled") {
        $Status = "Open"
    }
    else {
        $DirectiveName = "SessionCryptoCipher"
        $ExpectedValue = "Set to `"aes256`""
        $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName

        $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $FoundValues
        $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $FoundValues

        $FindingDetails += Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue -IsInGlobalConfig $IsInGlobalConfig -IsInAllVirtualHosts $IsInAllVirtualHosts

        if ($IsInGlobalConfig -or $IsInAllVirtualHosts) {
            foreach ($directive in $FoundValues) {
                if ($directive.Status -eq "Not Found") {
                    continue
                }

                $TestValue = $directive.ConfigFileLine.ToString().Split()[1].Trim()
                if ($TestValue -notlike "aes256") {
                    $ErrorCount++
                    break
                }
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
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214253 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214253
        STIG ID    : AS24-U1-000520
        Rule ID    : SV-214253r881438_rule
        CCI ID     : CCI-001188, CCI-001664
        Rule Name  : SRG-APP-000224-WSR-000138
        Rule Title : The Apache web server must generate a session ID using as much of the character set as possible to reduce the risk of brute force.
        DiscussMD5 : ADEC248CF01A89D0AC21B60815013010
        CheckMD5   : F448D0EE7A022B33B3552F5EFD690098
        FixMD5     : 239F0EE976B3BCAE9E6B25068098301B
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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
    $UniqueidModule = "unique_id_module"
    $ExpectedValue = "Enabled"
    $ModuleResult = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $UniqueidModule
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

Function Get-V214255 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214255
        STIG ID    : AS24-U1-000590
        Rule ID    : SV-214255r881441_rule
        CCI ID     : CCI-001094, CCI-002385
        Rule Name  : SRG-APP-000246-WSR-000149
        Rule Title : The Apache web server must be tuned to handle the operational requirements of the hosted application.
        DiscussMD5 : 7B0CAADBDCA09017ABF326CFF4ED6215
        CheckMD5   : 380640C59ECC3D0D8D1693503AED2672
        FixMD5     : 99433AB3CD92530D5D02647BDAD0CB32
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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
    $DirectiveName = "Timeout"
    $ExpectedValue = "10 or Less"
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $BadDirective = 0
    $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $FoundValues
    $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $FoundValues
    $FindingDetails = Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue -IsInGlobalConfig $IsInGlobalConfig -IsInAllVirtualHosts $IsInAllVirtualHosts

    if ($IsInGlobalConfig -or $IsInAllVirtualHosts) {
        foreach ($directive in $FoundValues) {
            if ($directive.Status -eq "Not Found") {
                continue
            }
            $MaxTimeout = $directive.ConfigFileLine.ToString().Split()[1] -as [int]
            if ($MaxTimeout -gt 10) {
                $BadDirective++
                break
            }
        }
    }
    else {
        $BadDirective++
    }

    if ($BadDirective -eq 0) {
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

Function Get-V214256 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214256
        STIG ID    : AS24-U1-000620
        Rule ID    : SV-214256r944428_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266-WSR-000159
        Rule Title : Warning and error messages displayed to clients must be modified to minimize the identity of the Apache web server, patches, loaded modules, and directory paths.
        DiscussMD5 : 6596859F3E3CF18122C7B96CAFA87E7D
        CheckMD5   : 41CB362B820065FB243E34C309D94F42
        FixMD5     : 6E006F7510C8C618C45CE5FEE4ABD705
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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
    $DirectiveName = "ErrorDocument\s*[45]\d\d\b"
    $ExpectedValue = "ErrorDocument 4xx and 5xx are defined."
    $DirectiveResult = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName

    for ( $i = 0; $i -lt $DirectiveResult.Count; $i++) {
        $DirectiveResult[$i].Name = $DirectiveResult[$i].Name -replace "\\s\*\[45]\\d\\d\\b", " 4xx or 5xx"
    }

    $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $DirectiveResult
    $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $DirectiveResult

    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResult -ExpectedValue $ExpectedValue -IsInGlobalConfig $IsInGlobalConfig -IsInAllVirtualHosts $IsInAllVirtualHosts

    if ($IsInGlobalConfig -or $IsInAllVirtualHosts) {
        $Status = "Not_Reviewed"
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

Function Get-V214257 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214257
        STIG ID    : AS24-U1-000630
        Rule ID    : SV-214257r881447_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266-WSR-000160
        Rule Title : Debugging and trace information used to diagnose the Apache web server must be disabled.
        DiscussMD5 : 93DF3B357177B39BA5002711C40529C4
        CheckMD5   : 95101593D0F7899CC1E08044068FEFC5
        FixMD5     : 2DBBA80068964A429ECAC85A28BD4F6B
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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
    $DirectiveName = "TraceEnable"
    $ExpectedValue = "Off"
    $DirectiveBlockCaps = @("Directory", "Location")

    # Check the blocks first.
    foreach ($blockCap in $DirectiveBlockCaps) {
        $FoundCount = 0
        $FindingDetails += "$($blockCap) Directives" | Out-String
        $FindingDetails += "---------------------------------------------" | Out-String
        $DirectiveResult = Get-ApacheDirectiveFromBlock -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -BlockStart $blockCap -BlockEnd $blockCap -DirectivePattern $DirectiveName

        # Check the value of each.
        foreach ($directive in $DirectiveResult) {
            if ($directive.Status -eq "Not Found") {
                continue
            }

            $FoundValue = (($directive.ConfigFileLine.ToString() -split '\s+')[1]) | Select-String -Pattern $ExpectedValue -Quiet
            if ($FoundValue -eq $False) {
                # This means we found a TraceEnable Directive in a Directory or Location block and it's set to on.
                # We can ignore TraceEnable directives in Directory or Location blocks if they are set to off
                # because the stig says 'For any --> enabled <-- "TraceEnable" directives notnested in a Directory or Location directive'
                $ErrorCount++
                $FoundCount++
                $FindingDetails += Get-ApacheFormattedOutput -FoundValues $directive -ExpectedValue $ExpectedValue
            }
        }

        # If we haven't found anything worth reporting I guess it's best to leave the output brief?
        if ($FoundCount -le 0) {
            $FindingDetails += "No TraceEnable Directives set to `"On`" found in $($blockCap) Directives" | Out-String
            $FindingDetails += "" | Out-String
        }
    }

    $FindingDetails += "TraceEnable Global/Virtual Host Configs" | Out-String
    $FindingDetails += "---------------------------------------------" | Out-String

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

            $FoundValue = (($directive.ConfigFileLine.ToString() -split '\s+')[1]) | Select-String -Pattern $ExpectedValue
            if ($null -eq $FoundValue -or $FoundValue -eq "") {
                $ErrorCount++
            }
        }
    }
    else {
        $ErrorCount++
    }

    $FindingDetails += "LogLevel Global/Virtual Host Configs" | Out-String
    $FindingDetails += "---------------------------------------------" | Out-String

    $DirectiveName = "LogLevel"
    $ExpectedValue = "Must be used"
    $DirectiveResult = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $DirectiveResult
    $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $DirectiveResult
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResult -ExpectedValue $ExpectedValue -IsInGlobalConfig $IsInGlobalConfig -IsInAllVirtualHosts $IsInAllVirtualHosts

    if (-not ($IsInGlobalConfig) -and -not ($IsInAllVirtualHosts)) {
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

Function Get-V214258 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214258
        STIG ID    : AS24-U1-000650
        Rule ID    : SV-214258r881450_rule
        CCI ID     : CCI-002361
        Rule Name  : SRG-APP-000295-WSR-000134
        Rule Title : The Apache web server must set an inactive timeout for sessions.
        DiscussMD5 : B7C8175A30A5AE2F8F469920D93E425C
        CheckMD5   : D9D9604E24DE1B1D047E7803F102F514
        FixMD5     : CCD0811AFC8E8F40C4F90E14A959FB6F
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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
    $ErrorCount = 0

    if ($ModuleStatus.Status -eq "Disabled") {
        $ErrorCount++
    }
    else {
        if ($IsInGlobalConfig -or $IsInAllVirtualHosts) {
            foreach ($line in $FoundValues) {
                if ($line.Status -eq "Not Found") {
                    continue
                }
                if ($line | Select-String -Pattern $DirectiveName\b) {
                    continue
                }
                $ErrorCount++
                break
            }
        }
        else {
            $ErrorCount++
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

Function Get-V214259 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214259
        STIG ID    : AS24-U1-000670
        Rule ID    : SV-214259r881452_rule
        CCI ID     : CCI-002314
        Rule Name  : SRG-APP-000315-WSR-000004
        Rule Title : The Apache web server must restrict inbound connections from nonsecure zones.
        DiscussMD5 : 14B37B452C85E606D5106183023253F7
        CheckMD5   : 2CA4A0B9D18AC2E73B01B57B75F4EF67
        FixMD5     : 06A0B318F70BF2C1D4A53B9C9AE94849
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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
    $startBlock = "RequireAll"
    $endBlock = "RequireAll"
    $DirectiveCheck = "Require"
    $ExpectedValue = "Restrict IPs from nonsecure zones."

    $DirectiveResult = Get-ApacheDirectiveFromBlock -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -BlockStart $startBlock -BlockEnd $endBlock -DirectivePattern $DirectiveCheck
    $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $DirectiveResult
    $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $DirectiveResult
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResult -ExpectedValue $ExpectedValue -IsInGlobalConfig $IsInGlobalConfig -IsInAllVirtualHosts $IsInAllVirtualHosts

    if (-not ($IsInGlobalConfig) -and -not ($IsInAllVirtualHosts)) {
        $ErrorCount++
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

Function Get-V214265 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214265
        STIG ID    : AS24-U1-000750
        Rule ID    : SV-214265r881456_rule
        CCI ID     : CCI-001889, CCI-001890
        Rule Name  : SRG-APP-000374-WSR-000172
        Rule Title : The Apache web server must generate log records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT) which are stamped at a minimum granularity of one second.
        DiscussMD5 : 95705D9E007018B5878111B74BFA510C
        CheckMD5   : C85C4CC80E4B1FDFD552F1511DE25478
        FixMD5     : EB434B3A8C6453AC2353380A9AB9D8A9
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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
    $DirectiveExpectedValue = "Contains %t setting"
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

Function Get-V214266 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214266
        STIG ID    : AS24-U1-000780
        Rule ID    : SV-214266r879756_rule
        CCI ID     : CCI-001762
        Rule Name  : SRG-APP-000383-WSR-000175
        Rule Title : The Apache web server must prohibit or restrict the use of nonsecure or unnecessary ports, protocols, modules, and/or services.
        DiscussMD5 : 32C8F848D002E7F8709CD7B10B314D2F
        CheckMD5   : 288664DC438BBF961EE521F7C005EC13
        FixMD5     : 631512945C45913030FF2A8D6F88E3E0
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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

Function Get-V214267 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214267
        STIG ID    : AS24-U1-000820
        Rule ID    : SV-214267r881458_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-APP-000435-WSR-000147
        Rule Title : The Apache web server must be protected from being stopped by a non-privileged user.
        DiscussMD5 : 6DE0061143728BFF192808CCDB855117
        CheckMD5   : 89C78BC9B594A7DB88D5D8BE122267D5
        FixMD5     : E1CEDB5B5DC6778685434187968DEA31
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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
    $WarningCount = 0
    $Expression = "$($ApacheInstance.ExecutablePath) -S"
    $ApachePidFileLine = Invoke-Expression $Expression
    $ApachePidFile = ( $ApachePidFileLine | grep "PidFile:" | awk '{print $2}' | sed 's/\"//g')

    $Expression = "ls -laH $ApachePidFile"
    $PidFileListing = Invoke-Expression $Expression

    $ApachePidFileOwner = ($PidFileListing | awk '{print $3}')
    $ApachePidFileGroup = ($PidFileListing | awk '{print $4}')
    $Expression = "cat /etc/passwd"
    $LocalAccounts = Invoke-Expression $Expression
    $ApachePidFileOwnerShell = ($LocalAccounts | grep "^$($ApachePidFileOwner)" | awk -F: '{print $7}')
    $ApachePidFileGroupShell = ($LocalAccounts | grep "^$($ApachePidFileGroup)" | awk -F: '{print $7}')

    $FindingDetails += "PidFile:`t`t`t$($ApachePidFile)" | Out-String
    $FindingDetails += "Expected Owner:`troot or Administrative Service Account User" | Out-String
    $FindingDetails += "Detected Owner:`t$($ApachePidFileOwner)" | Out-String
    $FindingDetails += "Expected Group:`troot or Administrative Service Account Group" | Out-String
    $FindingDetails += "Detected Owner:`t$($ApachePidFileGroup)`n" | Out-String

    if ("$($ApachePidFileOwner)" -ne "root") {
        if ("$($ApachePidFileOwnerShell)" -like "*/nologin") {
            $WarningCount++
        }
        else {
            $ErrorCount++
        }
    }

    if ("$($ApachePidFileGroup)" -ne "root") {
        if ("$($ApachePidFileGroupShell)" -like "*/nologin") {
            $WarningCount++
        }
        else {
            $ErrorCount++
        }
    }

    $Expression = "bash -c 'type -P service'"
    $ServicePath = Invoke-Expression "$($Expression)"

    $Expression = "bash -c 'ls -laH $ServicePath'"
    $ServicePathListing = Invoke-Expression "$($Expression)"

    $ServiceOwner = ($ServicePathListing | awk '{print $3}')
    $ServiceGroup = ($ServicePathListing | awk '{print $4}')
    $ServiceOwnerShell = ($LocalAccounts | grep "^$($ServiceOwner)" | awk -F: '{print $7}')
    $ServiceGroupShell = ($LocalAccounts | grep "^$($ServiceGroup)" | awk -F: '{print $7}')

    $FindingDetails += "Service:`t`t`t$($ServicePath)" | Out-String
    $FindingDetails += "Expected Owner:`troot or Administrative Service Account User" | Out-String
    $FindingDetails += "Detected Owner:`t$($ServiceOwner)" | Out-String
    $FindingDetails += "Expected Group:`troot or Administrative Service Account Group" | Out-String
    $FindingDetails += "Detected Owner:`t$($ServiceGroup)`n" | Out-String

    if ("$($ServiceOwner)" -ne "root") {
        if ("$($ServiceOwnerShell)" -like "*/nologin") {
            $WarningCount++
        }
        else {
            $ErrorCount++
        }
    }

    if ("$($ServiceGroup)" -ne "root") {
        if ("$($ServiceGroupShell)" -like "*/nologin") {
            $WarningCount++
        }
        else {
            $ErrorCount++
        }
    }

    $Expression = "bash -c 'type -P apachectl'"
    $ApachectlPath = Invoke-Expression "$($Expression)"

    $Expression = "bash -c 'ls -laH $ApachectlPath'"
    $ApachectlPathListing = Invoke-Expression "$($Expression)"

    $ApachectlOwner = ($ApachectlPathListing | awk '{print $3}')
    $ApachectlGroup = ($ApachectlPathListing | awk '{print $4}')
    $ApachectlOwnerShell = ($LocalAccounts | grep "^$($ApachectlOwner)" | awk -F: '{print $7}')
    $ApachectlGroupShell = ($LocalAccounts | grep "^$($ApachectlGroup)" | awk -F: '{print $7}')

    $FindingDetails += "Apachectl:`t`t$($ApachectlPath)" | Out-String
    $FindingDetails += "Expected Owner:`troot or Administrative Service Account User" | Out-String
    $FindingDetails += "Detected Owner:`t$($ApachectlOwner)" | Out-String
    $FindingDetails += "Expected Group:`troot or Administrative Service Account Group" | Out-String
    $FindingDetails += "Detected Owner:`t$($ApachectlGroup)`n" | Out-String

    if ("$($ApachectlOwner)" -ne "root") {
        if ("$($ApachectlOwnerShell)" -like "*/nologin") {
            $WarningCount++
        }
        else {
            $ErrorCount++
        }
    }

    if ("$($ApachectlGroup)" -ne "root") {
        if ("$($ApachectlGroupShell)" -like "*/nologin") {
            $WarningCount++
        }
        else {
            $ErrorCount++
        }
    }

    if ($ErrorCount -le 0) {
        if ($WarningCount -le 0) {
            $Status = "NotAFinding"
        }
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

Function Get-V214268 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214268
        STIG ID    : AS24-U1-000870
        Rule ID    : SV-214268r881461_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000439-WSR-000154
        Rule Title : Cookies exchanged between the Apache web server and the client, such as session cookies, must have cookie properties set to prohibit client-side scripts from reading the cookie data.
        DiscussMD5 : 3158830024042F70F4D98FC4E0F2825C
        CheckMD5   : 7F275A821E923B5E5581E92B05E404B5
        FixMD5     : 7A4EF4C5CB08449CEC0CC7E1074B53BE
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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
    $ApacheModuleName = "session_cookie_module"
    $ExpectedState = "Enabled"
    $ModuleStatus = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $ApacheModuleName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $ModuleStatus -ExpectedValue $ExpectedState

    if ($ModuleStatus.Status -eq "Disabled") {
        $ErrorCount++
    }
    else {
        $SessionDirective = "Session"
        $SessionExpectedValue = "Must be set to 'on'"
        $SessionFoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $SessionDirective
        $SessionIsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $SessionFoundValues
        $SessionIsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $SessionFoundValues
        $FindingDetails += Get-ApacheFormattedOutput -FoundValues $SessionFoundValues -ExpectedValue $SessionExpectedValue -IsInGlobalConfig $SessionIsInGlobalConfig -IsInAllVirtualHosts $SessionIsInAllVirtualHosts

        if ($SessionIsInGlobalConfig -or $SessionIsInAllVirtualHosts) {
            foreach ($directive in $SessionFoundValues) {
                if ($directive.Status -eq "Not Found") {
                    continue
                }
                if (-not($directive | Select-String -Pattern "$SessionDirective\b\s.*\bon\b")) {
                    $ErrorCount++
                    break
                }
            }
        }
        else {
            $ErrorCount++
        }

        $CookieNameDirective = "SessionCookieName"
        $CookieExpectedValue = "Must contain 'httpOnly' and 'secure'"
        $CookieFoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $CookieNameDirective
        $CookieIsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $CookieFoundValues
        $CookieIsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $CookieFoundValues
        $FindingDetails += Get-ApacheFormattedOutput -FoundValues $CookieFoundValues -ExpectedValue $CookieExpectedValue -IsInGlobalConfig $CookieIsInGlobalConfig -IsInAllVirtualHosts $CookieIsInAllVirtualHosts

        if ($CookieIsInGlobalConfig -or $CookieIsInAllVirtualHosts) {
            foreach ($directive in $CookieFoundValues) {
                if ($directive.Status -eq "Not Found") {
                    continue
                }
                if (-not($directive | Select-String -Pattern "$CookieNameDirective\b\s.*\b(httponly.*secure|secure.*httponly)\b")) {
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
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214269 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214269
        STIG ID    : AS24-U1-000900
        Rule ID    : SV-214269r881463_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000439-WSR-000188
        Rule Title : The Apache web server must remove all export ciphers to protect the confidentiality and integrity of transmitted information.
        DiscussMD5 : 2CC9BE94A9C829099A98F3ED518BD245
        CheckMD5   : BE8E560F5E7B13CBCBEFDD3BFFDDA25F
        FixMD5     : A8AEA179B81FC0484B6BAFD64565055A
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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
    $DirectiveName = "SSLCipherSuite"
    $ExpectedValue = "Contains `"!EXP`" or `"!EXPORT`""
    $Pattern = "\!EXP|\!EXPORT"
    $DirectiveResult = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $DirectiveResult
    $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $DirectiveResult
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResult -ExpectedValue $ExpectedValue -IsInGlobalConfig $IsInGlobalConfig -IsInAllVirtualHosts $IsInAllVirtualHosts

    if ($IsInGlobalConfig -or $IsInAllVirtualHosts) {
        foreach ($directive in $DirectiveResult) {
            if ($directive.Status -eq "Not Found") {
                continue
            }

            $TestValue = (($directive.ConfigFileLine.ToString() -split "\s+")[1]) | Select-String -Pattern $Pattern
            if ($null -eq $TestValue -or $TestValue -eq "") {
                $ErrorCount++
                break
            }
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

Function Get-V214270 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214270
        STIG ID    : AS24-U1-000930
        Rule ID    : SV-214270r879827_rule
        CCI ID     : CCI-002605
        Rule Name  : SRG-APP-000456-WSR-000187
        Rule Title : The Apache web server must install security-relevant software updates within the configured time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).
        DiscussMD5 : D03EBD79C8CB6A1252B39AB79C661C61
        CheckMD5   : CA1DEE898200FB83962A1614176CEA94
        FixMD5     : F62A5E86690CEA3CC6FD5B7785D556AE
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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

Function Get-V214271 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214271
        STIG ID    : AS24-U1-000940
        Rule ID    : SV-214271r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000079
        Rule Title : The account used to run the Apache web server must not have a valid login shell and password defined.
        DiscussMD5 : C9F2E3AAAF8E074512A548D42EBD9AF6
        CheckMD5   : 16B8272FE638DE16762FDE713D182A0A
        FixMD5     : 192BDAE13D26B602DA91DAA769D5B947
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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
    $GoodPasswordPattern = "^!|^\*"
    $NoLogonShell = "/sbin/nologin"
    $ExpectedValue = "The account must not have BOTH a valid login shell AND a defined password."

    $Command = "ps -ef | grep -i $($ApacheInstance.ExecutablePath) | grep -v grep | awk '`$3 != 1' | awk '{print `$1}' | sort -u"
    $HttpdAccounts = @(Invoke-Expression -Command $Command)
    foreach ($httpdAccount in $HttpdAccounts) {
        $LoginShell = ((Select-String -Path "/etc/passwd" -Pattern $httpdAccount -Raw).Split(":")[6]).Trim()
        $Password = ((Select-String -Path "/etc/shadow" -Pattern $httpdAccount -Raw).Split(":")[1]).Trim()
        if ([string]::IsNullOrWhiteSpace($LoginShell) -or [string]::IsNullOrWhiteSpace($Password)) {
            continue
        }

        $FindingDetails += "Account:`t`t`t`t$($HttpdAccount)" | Out-String
        $FindingDetails += "Expected Value:`t`t$($ExpectedValue)" | Out-String

        $HasNoPassword = $Password | Select-String -Pattern $GoodPasswordPattern -Quiet
        if ($LoginShell -ne $NoLogonShell) {

            # This won't be something like '/sbin/nologin'
            $FindingDetails += "Valid Login Shell:`t`tYes" | Out-String

            if ($HasNoPassword -eq $true) {
                $FindingDetails += "Defined Password:`t`tNo" | Out-String
            }
            else {
                # Valid login Shall and password is defined.
                $FindingDetails += "Defined Password:`t`tYes" | Out-String
                $ErrorCount++
            }
        }
        else {
            # We don't care about this section in terms of incrementing the error count
            # since we already have an invalid login shell set.
            $FindingDetails += "Valid Login Shell:`t`tNo" | Out-String

            if ($HasNoPassword -eq $true) {
                $FindingDetails += "Defined Password:`t`tYes" | Out-String
            }
            else {
                $FindingDetails += "Defined Password:`t`tNo" | Out-String
            }
        }

        $FindingDetails += "" | Out-String
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

Function Get-V214272 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214272
        STIG ID    : AS24-U1-000950
        Rule ID    : SV-214272r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The Apache web server must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.
        DiscussMD5 : 5AB3E17F1F7A0B8231C21CC55EEF1C48
        CheckMD5   : A5FB4533F2EF48AC2980246A71E026C1
        FixMD5     : CB304C9DE7E299EC14EC7D4FEEABB2B9
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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

Function Get-V214273 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214273
        STIG ID    : AS24-U1-000960
        Rule ID    : SV-214273r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The Apache web server software must be a vendor-supported version.
        DiscussMD5 : 44E40A9B7DEF1D4DD7B92B7186334EA7
        CheckMD5   : 23C7CFFD25B17ABB72703B65E2370693
        FixMD5     : F62A5E86690CEA3CC6FD5B7785D556AE
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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

Function Get-V214274 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214274
        STIG ID    : AS24-U1-000970
        Rule ID    : SV-214274r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The Apache web server htpasswd files (if present) must reflect proper ownership and permissions.
        DiscussMD5 : 8BE2CF19E2C371976911D0ED658C1963
        CheckMD5   : 3E380EC9B2C241BFC0B99C8E757F5526
        FixMD5     : 3AFDC6EFAB77943BB9B2FE029A8E89A1
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $true)]
        [String]$SiteName,

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
    $ValidPerms = 550
    $ExpectedValue = "r-xr-x---(550) or less"

    $Command = "find / -mount -name htpasswd"
    $HtPasswdFiles = @(Invoke-Expression -Command $Command)

    foreach ($file in $HtPasswdFiles) {
        $Command = "stat -c `'%a`' $($file)"
        $Permissions = (Invoke-Expression -Command $Command) -as [int]

        $Command = "ls -l $($file) | awk `'{print `$3}`'"
        $FileOwner = (Invoke-Expression -Command $Command)

        $FindingDetails += "File Path:`t`t`t`t$($file)" | Out-String
        $FindingDetails += "Expected Permissions:`t$($ExpectedValue)" | Out-String
        $FindingDetails += "Permissions:`t`t`t$($Permissions)" | Out-String
        $FindingDetails += "Owner:`t`t`t`t$($FileOwner)" | Out-String

        if ($Permissions -gt $ValidPerms) {
            $ErrorCount++
        }
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

# SIG # Begin signature block
# MIIL+QYJKoZIhvcNAQcCoIIL6jCCC+YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCtzI3QMZfoOqnv
# THqnBI2GlPS0JWccdDRNHqFHiQNAcaCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCZujfPC3s0X0D2qTCsRog4LRw3iyYx
# P+x8n/4sx/kZgjANBgkqhkiG9w0BAQEFAASCAQBLjido8qhwPTIBXaXOYTGZoVFi
# ZVkeked+30A1zKelBEVkR09r32gKTCgDHN+P0bHVLiUNRAKV8RWN8b4LOyTt7ZXl
# 7KpGpVzze7PzYZjCdE6AZGIK8kO7LVc+EVeYUwrIa6kS2FZAPH7D8oD4VXsFxVcA
# 3kOFqN2hvoSxYSHyShkTqcFLDwiVUauZVhP9rbrb/JppPBN4+bS0Z1SjYUvwDShG
# umh2Pwb2kz0Cq0ptGeG+JKPeHSad1Yw1uYY5gu8qwbuRLFhb7ABxjEIu8BVI+5ne
# kUjhLIIDdYBkgHujBC9Y4WEGkWZRs4bZBHGGgp76racaeN4RRD4sXM3vP6Xw
# SIG # End signature block
