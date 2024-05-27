##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Microsoft IIS 8.5 Site
# Version:  V2R9
# Class:    UNCLASSIFIED
# Updated:  5/13/2024
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V214444 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214444
        STIG ID    : IISW-SI-000201
        Rule ID    : SV-214444r879511_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-WSR-000002
        Rule Title : The IIS 8.5 website session state must be enabled.
        DiscussMD5 : A8F85DD7644F18DE21EFF4E20BF1983A
        CheckMD5   : 3F61D28A2DF6F0F88885625BFCC9D200
        FixMD5     : D473A0C42FC49D17DB9F3972E2798C50
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $Mode = Get-WebConfigurationProperty "/system.web/sessionState" -PsPath "IIS:\Sites\$SiteName" -Name mode
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.web/sessionState' -PsPath 'IIS:\Sites\$SiteName' -Name mode}"
        $Mode = Invoke-Expression $PSCommand
    }

    If ($Mode -eq "InProc") {
        $Status = "NotAFinding"
    }
    Else {
        $Status = "Open"
    }

    $FindingDetails += "Mode is set to '$($Mode)'" | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214445 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214445
        STIG ID    : IISW-SI-000202
        Rule ID    : SV-214445r879511_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-WSR-000002
        Rule Title : The IIS 8.5 website session state cookie settings must be configured to Use Cookies mode.
        DiscussMD5 : BDB278C66CF558EFC338F203DE411E44
        CheckMD5   : 04EF5E8AF9EB7FA28990BDA04F378F3A
        FixMD5     : A2624C16A53A76C74A2CB94F62D290C7
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $Cookieless = Get-WebConfigurationProperty "/system.web/sessionState" -PsPath "IIS:\Sites\$SiteName" -Name cookieless
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.web/sessionState' -PsPath 'IIS:\Sites\$SiteName' -Name cookieless}"
        $Cookieless = Invoke-Expression $PSCommand
    }

    If ($Cookieless -eq "UseCookies") {
        $Status = "NotAFinding"
    }
    Else {
        $Status = "Open"
    }

    $FindingDetails += "Cookie Settings is set to '$($Cookieless)'" | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214446 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214446
        STIG ID    : IISW-SI-000203
        Rule ID    : SV-214446r903081_rule
        CCI ID     : CCI-000068
        Rule Name  : SRG-APP-000014-WSR-000006
        Rule Title : A private IIS 8.5 website must only accept Secure Socket Layer connections.
        DiscussMD5 : AB956EF9C261E12C7144487ECCA022E4
        CheckMD5   : CF2D004793FFC6363A994F005E9F3826
        FixMD5     : BBCA27C47BED9724E94174F88F0972DE
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
    If (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "WsusService") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting WSUS so this requirement is NA."
    }
    ElseIf (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    Else {
        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Import-Module WebAdministration
            $Access = Get-WebConfigurationProperty "/system.webServer/security/access" -PsPath "IIS:\Sites\$SiteName" -Name *
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/security/access' -PsPath 'IIS:\Sites\$SiteName' -Name *}"
            $Access = Invoke-Expression $PSCommand
        }
        $SslFlags = $Access.sslFlags -split ","

        If ("Ssl" -in $SslFlags) {
            $FindingDetails += "Require SSL is enabled"
        }
        Else {
            $FindingDetails += "Require SSL is NOT enabled" | Out-String
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

Function Get-V214447 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214447
        STIG ID    : IISW-SI-000204
        Rule ID    : SV-214447r903084_rule
        CCI ID     : CCI-000068
        Rule Name  : SRG-APP-000014-WSR-000006
        Rule Title : A public IIS 8.5 website must only accept Secure Socket Layer connections when authentication is required.
        DiscussMD5 : AB956EF9C261E12C7144487ECCA022E4
        CheckMD5   : 923A89C7A16E40F739070C5A48F8BB6C
        FixMD5     : BBCA27C47BED9724E94174F88F0972DE
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
    If (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "WsusService") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting WSUS so this requirement is NA."
    }
    ElseIf (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    Else {
        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Import-Module WebAdministration
            $Access = Get-WebConfigurationProperty "/system.webServer/security/access" -PsPath "IIS:\Sites\$SiteName" -Name *
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/security/access' -PsPath 'IIS:\Sites\$SiteName' -Name *}"
            $Access = Invoke-Expression $PSCommand
        }
        $SslFlags = $Access.sslFlags -split ","

        If ("Ssl" -in $SslFlags) {
            $FindingDetails += "Require SSL is enabled"
        }
        Else {
            $FindingDetails += "Require SSL is NOT enabled" | Out-String
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

Function Get-V214448 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214448
        STIG ID    : IISW-SI-000205
        Rule ID    : SV-214448r879562_rule
        CCI ID     : CCI-001462, CCI-001464
        Rule Name  : SRG-APP-000092-WSR-000055
        Rule Title : The enhanced logging for each IIS 8.5 website must be enabled and capture, record, and log all content related to a user session.
        DiscussMD5 : D9CEED897A1EC6037CC9638A89478B95
        CheckMD5   : 37459042EBCA46FEA46950FA6D8AF2F8
        FixMD5     : 62488BD13A60F1658B387FDF25FAEC64
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $WebSite = Get-WebSite -Name "$SiteName" | Select-Object *
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebSite -Name '$SiteName' | Select-Object *}"
        $WebSite = Invoke-Expression $PSCommand
    }
    $Compliant = $true
    $FlagsToCheck = ("Date", "Time", "ClientIP", "UserName", "Method", "URIQuery", "HttpStatus", "Referer")
    $MissingFlags = ""
    $LogFlags = $WebSite.logFile.logExtFileFlags -split ","

    If ($WebSite.logFile.logFormat -ne "W3C") {
        $Compliant = $false
    }

    Foreach ($Flag in $FlagsToCheck) {
        If ($Flag -notin $LogFlags) {
            $Compliant = $false
            $MissingFlags += $Flag | Out-String
        }
    }

    $FindingDetails += "Logging format is set to '$($WebSite.logFile.logFormat)'" | Out-String
    $FindingDetails += "" | Out-String
    If ($MissingFlags -eq "") {
        $FindingDetails += "Date, Time, Client IP Address, User Name, Method, URI Query, Protocol Status, and Referrer are all logged." | Out-String
    }
    Else {
        $FindingDetails += "The following minimum fields are not logged:" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += $MissingFlags | Out-String
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

Function Get-V214449 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214449
        STIG ID    : IISW-SI-000206
        Rule ID    : SV-214449r879562_rule
        CCI ID     : CCI-000139, CCI-001464
        Rule Name  : SRG-APP-000092-WSR-000055
        Rule Title : Both the log file and Event Tracing for Windows (ETW) for each IIS 8.5 website must be enabled.
        DiscussMD5 : F9D41435B95618BCF50CB880519AE58B
        CheckMD5   : 08481C2216B2AED0E5AB04B63705F5E9
        FixMD5     : B7BB79E70EA73A77DD5E48571D42CE6A
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $WebSite = Get-WebSite -Name "$SiteName" | Select-Object *
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebSite -Name '$SiteName' | Select-Object *}"
        $WebSite = Invoke-Expression $PSCommand
    }

    If ($WebSite.logFile.logTargetW3C -like "*ETW*" -and $WebSite.logFile.logTargetW3C -like "*File*") {
        $FindingDetails += "Both ETW and Log file logging are enabled." | Out-String
        $Status = "NotAFinding"
    }
    Else {
        $FindingDetails += "'$($WebSite.logFile.logTargetW3C)' is the only option selected." | Out-String
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

Function Get-V214451 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214451
        STIG ID    : IISW-SI-000209
        Rule ID    : SV-214451r879567_rule
        CCI ID     : CCI-000134
        Rule Name  : SRG-APP-000099-WSR-000061
        Rule Title : The IIS 8.5 website must produce log records that contain sufficient information to establish the outcome (success or failure) of IIS 8.5 website events.
        DiscussMD5 : 4CBE40B042FDA8A92BC8FCE2E5AFC138
        CheckMD5   : 45DE481BBBCCE84DE7FDB4D90EBD9590
        FixMD5     : 1DD2D496FAD8FDFE57795E92463DCFD6
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $WebSite = Get-WebSite -Name "$SiteName" | Select-Object *
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebSite -Name '$SiteName' | Select-Object *}"
        $WebSite = Invoke-Expression $PSCommand
    }

    $customField1_logged = $false # the custom "Connection" field we're looking for
    $customField2_logged = $false # the custom "Warning" field we're looking for

    If ($WebSite.logFile.logFormat -ne "W3C") {
        $Status = "Open"
        $FindingDetails += "Log format is '$($WebSite.logFile.logFormat)' [Expected 'W3C']" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $FindingDetails += "Log format is '$($WebSite.logFile.logFormat)'" | Out-String
        $FindingDetails += "" | Out-String
    }

    ForEach ($Item in $Website.logFile.customFields.Collection) {
        If ($Item.sourceType -eq "RequestHeader" -and $Item.sourceName -eq "Connection") {
            $customField1_logged = $true
        }
        ElseIf ($Item.sourceType -eq "RequestHeader" -and $Item.sourceName -eq "Warning") {
            $customField2_logged = $true
        }
    }

    If ($customField1_logged -eq $true) {
        $FindingDetails += "The 'Request Header >> Connection' custom field is configured." | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "The 'Request Header >> Connection' custom field is NOT configured." | Out-String
        $FindingDetails += "" | Out-String
    }

    If ($customField2_logged -eq $true) {
        $FindingDetails += "The 'Request Header >> Warning' custom field is configured." | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "The 'Request Header >> Warning' custom field is NOT configured." | Out-String
        $FindingDetails += "" | Out-String
    }

    If ($Status -ne "Open") {
        # if we never marked a site as failing, then we pass the whole check.
        $Status = 'NotAFinding'
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214452 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214452
        STIG ID    : IISW-SI-000210
        Rule ID    : SV-214452r879568_rule
        CCI ID     : CCI-001487
        Rule Name  : SRG-APP-000100-WSR-000064
        Rule Title : The IIS 8.5 website must produce log records containing sufficient information to establish the identity of any user/subject or process associated with an event.
        DiscussMD5 : EDA80E0B5A3CEB39B0D0A4342C615A1D
        CheckMD5   : F796594142B405D6C4D0904B766907AE
        FixMD5     : 1256D2548AC8DB13F70185CE974251E5
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $WebSite = Get-WebSite -Name "$SiteName" | Select-Object *
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebSite -Name '$SiteName' | Select-Object *}"
        $WebSite = Invoke-Expression $PSCommand
    }

    $LogFlags = $Website.logFile.logExtFileFlags -Split ","
    $FlagsToCheck = ("UserAgent", "UserName", "Referer")
    $MissingFlags = ""
    $customField1_logged = $false # the custom "Authorization" field we're looking for
    $customField2_logged = $false # the custom "Content-Type" field we're looking for

    If ($Website.logFile.logFormat -ne "W3C") {
        $Status = "Open"
        $FindingDetails += "Log format is '$($WebSite.logFile.logFormat)' [Expected 'W3C']" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $FindingDetails += "Log format is '$($WebSite.logFile.logFormat)'" | Out-String
        $FindingDetails += "" | Out-String

        # check the standard fields first
        Foreach ($Flag in $FlagsToCheck) {
            If ($Flag -notin $LogFlags) {
                $MissingFlags += $Flag | Out-String
            }
        }

        If ($MissingFlags) {
            $Status = "Open"
            $FindingDetails += "The following minimum fields are not logged:" | Out-String
            $FindingDetails += $MissingFlags | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $FindingDetails += "User Agent, User Name, and Referrer are all logged." | Out-String
            $FindingDetails += "" | Out-String
        }

        ForEach ($Item in $Website.logFile.customFields.Collection) {
            If ($Item.sourceType -eq "RequestHeader" -and $Item.sourceName -eq "Authorization") {
                $customField1_logged = $true
            }
            ElseIf ($Item.sourceType -eq "ResponseHeader" -and $Item.sourceName -eq "Content-Type") {
                $customField2_logged = $true
            }
        }

        If ($customField1_logged -eq $true) {
            $FindingDetails += "The 'Request Header >> Authorization' custom field is configured." | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "The 'Request Header >> Authorization' custom field is NOT configured." | Out-String
            $FindingDetails += "" | Out-String
        }

        If ($customField2_logged -eq $true) {
            $FindingDetails += "The 'Response Header >> Content-Type' custom field is configured." | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "The 'Response Header >> Content-Type' custom field is NOT configured." | Out-String
            $FindingDetails += "" | Out-String
        }
    }

    If ($Status -ne "Open") {
        # if we never marked a site as failing, then we pass the whole check.
        $Status = 'NotAFinding'
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214454 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214454
        STIG ID    : IISW-SI-000214
        Rule ID    : SV-214454r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000081
        Rule Title : The IIS 8.5 website must have Multipurpose Internet Mail Extensions (MIME) that invoke OS shell programs disabled.
        DiscussMD5 : 4EF5D5B840CA72C229912347349F475E
        CheckMD5   : B111975FE5BF75E790C3354A9E3A6001
        FixMD5     : 7F02AF40862919C3F3BA6068F6FD1B5A
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $Configuration = (Get-WebConfiguration '/system.webServer/staticContent' -PsPath "IIS:\Sites\$SiteName").Collection
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; (Get-WebConfiguration '/system.webServer/staticContent' -PsPath 'IIS:\Sites\$SiteName').Collection}"
        $Configuration = Invoke-Expression $PSCommand
    }

    $Compliant = $true
    $ExtensionFindings = ""
    $ExtensionsToCheck = @(".exe", ".dll", ".com", ".bat", ".csh")
    ForEach ($Extension in $ExtensionsToCheck) {
        If ($Configuration | Where-Object fileExtension -EQ $Extension) {
            $Compliant = $false
            $ExtensionFindings += $Extension | Out-String
        }
    }

    If ($Compliant -eq $true) {
        $Status = "NotAFinding"
        $FindingDetails += "No invalid MIME types for OS shell program extensions found."
    }
    Else {
        $Status = "Open"
        $FindingDetails += "The following invalid MIME types for OS shell program extensions are configured:" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += $ExtensionFindings | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214455 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214455
        STIG ID    : IISW-SI-000215
        Rule ID    : SV-214455r903087_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000082
        Rule Title : Mappings to unused and vulnerable scripts on the IIS 8.5 website must be removed.
        DiscussMD5 : F26CF3C0058C6961D8C0F95EBBC35D60
        CheckMD5   : 7D0C598420D9B2F4BCE67AED0C2529AF
        FixMD5     : 3EA04D5BB32BB7D8F1CA3AD390D53BD6
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
    If (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    Else {
        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Import-Module WebAdministration
            $FileExtensions = Get-WebConfigurationProperty "/system.webServer/security/requestFiltering" -PsPath "IIS:\Sites\$SiteName" -Name fileExtensions | Select-Object -ExpandProperty Collection
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/security/requestFiltering' -PsPath 'IIS:\Sites\$SiteName' -Name fileExtensions | Select-Object -expandproperty Collection}"
            $FileExtensions = Invoke-Expression $PSCommand
        }

        $FindingDetails += "Denied file extensions:" | Out-String
        $FindingDetails += "-----------------------------------" | Out-String
        If (($FileExtensions | Where-Object allowed -EQ $false | Measure-Object).Count -eq 0) {
            $FindingDetails += "None" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            ForEach ($Item in ($FileExtensions | Where-Object allowed -EQ $false)) {
                $FindingDetails += "FileExtension:`t$($Item.fileExtension)" | Out-String
                $FindingDetails += "Allowed:`t`t$($Item.allowed)" | Out-String
                $FindingDetails += "" | Out-String
            }
        }

        $FindingDetails += "Allowed file extensions:" | Out-String
        $FindingDetails += "-----------------------------------" | Out-String
        If (($FileExtensions | Where-Object allowed -EQ $true | Measure-Object).Count -eq 0) {
            $FindingDetails += "None" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            ForEach ($Item in ($FileExtensions | Where-Object allowed -EQ $true)) {
                $FindingDetails += "FileExtension:`t$($Item.fileExtension)" | Out-String
                $FindingDetails += "Allowed:`t`t$($Item.allowed)" | Out-String
                $FindingDetails += "" | Out-String
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

Function Get-V214456 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214456
        STIG ID    : IISW-SI-000216
        Rule ID    : SV-214456r903089_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000083
        Rule Title : The IIS 8.5 website must have resource mappings set to disable the serving of certain file types.
        DiscussMD5 : E660313F263E649FBA1907ED40DC063B
        CheckMD5   : D4901DF95EB98BE9B3338E58B0E4E6B4
        FixMD5     : 0E187225985B4ED7D58C7D994DC70BD8
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
    If (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    Else {
        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Import-Module WebAdministration
            $FileExtensions = Get-WebConfigurationProperty "/system.webServer/security/requestFiltering" -PsPath "IIS:\Sites\$SiteName" -Name fileExtensions | Select-Object -ExpandProperty Collection
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/security/requestFiltering' -PsPath 'IIS:\Sites\$SiteName' -Name fileExtensions | Select-Object -expandproperty Collection}"
            $FileExtensions = Invoke-Expression $PSCommand
        }

        $FindingDetails += "Denied file extensions:" | Out-String
        $FindingDetails += "-----------------------------------" | Out-String
        If (($FileExtensions | Where-Object allowed -EQ $false | Measure-Object).Count -eq 0) {
            $FindingDetails += "None" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            ForEach ($Item in ($FileExtensions | Where-Object allowed -EQ $false)) {
                $FindingDetails += "FileExtension:`t$($Item.fileExtension)" | Out-String
                $FindingDetails += "Allowed:`t`t$($Item.allowed)" | Out-String
                $FindingDetails += "" | Out-String
            }
        }

        $FindingDetails += "Allowed file extensions:" | Out-String
        $FindingDetails += "-----------------------------------" | Out-String
        If (($FileExtensions | Where-Object allowed -EQ $true | Measure-Object).Count -eq 0) {
            $FindingDetails += "None" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            ForEach ($Item in ($FileExtensions | Where-Object allowed -EQ $true)) {
                $FindingDetails += "FileExtension:`t$($Item.fileExtension)" | Out-String
                $FindingDetails += "Allowed:`t`t$($Item.allowed)" | Out-String
                $FindingDetails += "" | Out-String
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

Function Get-V214457 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214457
        STIG ID    : IISW-SI-000217
        Rule ID    : SV-214457r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000085
        Rule Title : The IIS 8.5 website must have Web Distributed Authoring and Versioning (WebDAV) disabled.
        DiscussMD5 : 755E1D5550A79779DF357F74323C8F0A
        CheckMD5   : E24123F2BB294E3DA807E34BE59E126C
        FixMD5     : A29B89C1E59E36B7370F2B67BFC3CFC9
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
    If ((Get-WindowsFeature -Name "Web-DAV-Publishing").Installed -eq $true) {
        $FindingDetails += "Web-DAV-Publishing is installed."
        $Status = "Open"
    }
    If ($Status -ne "Open") {
        $FindingDetails += "WebDAV is not installed."
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

Function Get-V214459 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214459
        STIG ID    : IISW-SI-000219
        Rule ID    : SV-214459r879588_rule
        CCI ID     : CCI-000382
        Rule Name  : SRG-APP-000142-WSR-000089
        Rule Title : Each IIS 8.5 website must be assigned a default host header.
        DiscussMD5 : 751E064D2115CE2827F49ACCB3532C98
        CheckMD5   : 11120F542E009E0D9AA3F4B1B4F584B3
        FixMD5     : B12C5412AFD090D8E5FB341EE0A94406
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
    If (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    Else {
        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Import-Module WebAdministration
            $WebSite = Get-WebSite -Name "$SiteName" | Select-Object *
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebSite -Name '$SiteName' | Select-Object *}"
            $WebSite = Invoke-Expression $PSCommand
        }

        $Compliant = $true
        $BindingInfo = $WebSite.bindings.collection.bindingInformation
        $SiteBound80or443 = $false

        ForEach ($Binding in $BindingInfo) {
            $SingleBinding = $Binding.Split(':') # bindings are written as "<ipAddress>:<port>:<hostheader>".
            If ($SingleBinding[1] -eq '443' -or $SingleBinding[1] -eq '80') {
                #if the site is on port 443 or 80 (the only ports the STIGs calls out needing a host header on).
                If ($SingleBinding[2] -ne '') {
                    #check if the site has been bound to a host header
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "The site is bound to $($SingleBinding[2]) on port $($SingleBinding[1])"
                    $siteBound80or443 = $true
                }
                Else {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "The site is NOT bound to a specific host header on port $($SingleBinding[1])"
                    $SiteBound80or443 = $true
                }
            }
        }

        If ($siteBound80or443 -eq $false) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "The site < $SiteName > is not using ports 80 or 443 and so this check is not applicable. There is no reason to turn on an unused port after all."
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

Function Get-V214460 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214460
        STIG ID    : IISW-SI-000220
        Rule ID    : SV-214460r903091_rule
        CCI ID     : CCI-000197, CCI-001188, CCI-002470
        Rule Name  : SRG-APP-000172-WSR-000104
        Rule Title : A private websites authentication mechanism must use client certificates to transmit session identifier to assure integrity.
        DiscussMD5 : B514D03781F80E807ED9A784C3FBFC5C
        CheckMD5   : 0CF4C0894290A3B337EECE170A87F256
        FixMD5     : B842CA2A8E1AF216B321999AE7F76C5D
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
    If (Get-Service MSExchangeServiceHost -ErrorAction SilentlyContinue) {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting Exchange so this requirement is NA."
    }
    If (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "WsusService") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting WSUS so this requirement is NA."
    }
    ElseIf (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    Else {
        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Import-Module WebAdministration
            $Access = Get-WebConfigurationProperty "/system.webServer/security/access" -PsPath "IIS:\Sites\$SiteName" -Name *
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/security/access' -PsPath 'IIS:\Sites\$SiteName' -Name *}"
            $Access = Invoke-Expression $PSCommand
        }

        $SslFlags = $Access.sslFlags -split ","
        If ("SslRequireCert" -in $SslFlags) {
            $Status = "NotAFinding"
            $FindingDetails += "Client Certificates is set to 'Require'" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "Client Certificates is NOT set to 'Require'" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Confirm if this this is a public server.  If so, mark this finding as Not Applicable."
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

Function Get-V214461 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214461
        STIG ID    : IISW-SI-000221
        Rule ID    : SV-214461r879631_rule
        CCI ID     : CCI-001082
        Rule Name  : SRG-APP-000211-WSR-000031
        Rule Title : Anonymous IIS 8.5 website access accounts must be restricted.
        DiscussMD5 : 925AE8C48167DBA4C44DF43FD26D9D2E
        CheckMD5   : 29C07EEA586D393EC48679C4AE64A63F
        FixMD5     : AE4AF08DCF7CE01B416F0570B348E68A
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $AnonymousAuth = Get-WebConfigurationProperty "/system.webServer/security/authentication/anonymousAuthentication" -PsPath "IIS:\Sites\$SiteName" -Name *
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/security/authentication/anonymousAuthentication' -PsPath 'IIS:\Sites\$SiteName' -Name *}"
        $AnonymousAuth = Invoke-Expression $PSCommand
    }

    $Server = ($env:COMPUTERNAME)
    $Computer = [ADSI]"WinNT://$Server,computer"
    $GroupsToCheck = ("/Administrators", "/Backup Operators", "/Certificate Service", "/Distributed COM Users", "/Event Log Readers", "/Network Configuration Operators", "/Performance Log Users", "/Performance Monitor Users", "/Power Users", "/Print Operators", "/Remote Desktop Users", "/Replicator")

    $group = $computer.psbase.children | Where-Object { $_.psbase.schemaClassname -eq 'group' } | Where-Object { $_.Path -like "*/Administrators*" }

    If ($AnonymousAuth.enabled -eq $true) {
        If (-Not($AnonymousAuth.userName) -or $AnonymousAuth.userName -eq "") {
            $Status = "NotAFinding"
            $FindingDetails += "Anonymous Authentication is Enabled but is configured for Application Pool Identity." | Out-String
        }
        Else {
            $FindingDetails += "Anonymous Authentication is Enabled and using the account '$($AnonymousAuth.userName)' for authentication." | Out-String
            $FindingDetails += "" | Out-String
            $PrivilegedMembership = ""
            ForEach ($Group in $GroupsToCheck) {
                $GroupInfo = $Computer.psbase.children | Where-Object { $_.psbase.schemaClassname -eq 'group' } | Where-Object { $_.Path -like "*$Group*" }
                $Members = $GroupInfo.psbase.Invoke("Members") | ForEach-Object { $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null) }
                $Members | ForEach-Object {
                    If ($_ -eq $AnonymousAuth.userName) {
                        $PrivilegedMembership += $GroupInfo.Name | Out-String
                    }
                }
            }
            If ($PrivilegedMembership -ne "") {
                $Status = "Open"
                $FindingDetails += "$($AnonymousAuth.userName) is a member of the following privileged groups:" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += $PrivilegedMembership
            }
            Else {
                $Status = "NotAFinding"
                $FindingDetails += "$($AnonymousAuth.userName) is not a member of any privileged groups." | Out-String
            }
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "Anonymous Authentication is Disabled" | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214462 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214462
        STIG ID    : IISW-SI-000223
        Rule ID    : SV-214462r879639_rule
        CCI ID     : CCI-001188
        Rule Name  : SRG-APP-000224-WSR-000136
        Rule Title : The IIS 8.5 website must generate unique session identifiers that cannot be reliably reproduced.
        DiscussMD5 : 1D12C16CECF4F8DB8E651531D8CDB1EF
        CheckMD5   : C104443D88B6CCFBFB4538A2253BC716
        FixMD5     : B7CC87655FA92037EEA2ED1E725AC99A
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $Mode = Get-WebConfigurationProperty "/system.web/sessionState" -PsPath "IIS:\Sites\$SiteName" -Name mode
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.web/sessionState' -PsPath 'IIS:\Sites\$SiteName' -Name mode}"
        $Mode = Invoke-Expression $PSCommand
    }

    If ($Mode -eq "InProc") {
        $Status = "NotAFinding"
    }
    Else {
        $Status = "Open"
    }

    $FindingDetails += "Mode is set to '$($Mode)'" | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214463 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214463
        STIG ID    : IISW-SI-000224
        Rule ID    : SV-214463r879643_rule
        CCI ID     : CCI-001084
        Rule Name  : SRG-APP-000233-WSR-000146
        Rule Title : The IIS 8.5 website document directory must be in a separate partition from the IIS 8.5 websites system files.
        DiscussMD5 : DFC3894D5ECFD3AAC781F7169AFB858B
        CheckMD5   : 79F4C4004BADA79E76B8C3DC754282A4
        FixMD5     : 20F8A42A296E5004A6F433330D7F12AC
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $WebSite = Get-WebSite -Name "$SiteName" | Select-Object *
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebSite -Name '$SiteName' | Select-Object *}"
        $WebSite = Invoke-Expression $PSCommand
    }

    $WebSiteDrive = ($WebSite.physicalPath -replace "%SystemDrive%", $env:SYSTEMDRIVE).Split("\")[0]
    If ($WebSiteDrive -eq $env:SYSTEMDRIVE) {
        $Status = "Open"
        $FindingDetails += "Both the OS and the web site are installed on $($env:SYSTEMDRIVE)" | Out-String
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "The OS is installed on $($env:SYSTEMDRIVE)" | Out-String
        $FindingDetails += "The web site is installed on $($WebSiteDrive)"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214464 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214464
        STIG ID    : IISW-SI-000225
        Rule ID    : SV-214464r879650_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246-WSR-000149
        Rule Title : The IIS 8.5 website must be configured to limit the maxURL.
        DiscussMD5 : 9E8371DE45CA8DB4EFC176731916D3E2
        CheckMD5   : 9A23281A54E0E37E78945B522530D2DD
        FixMD5     : C4944D76C2F417FFD7A2AAD726973BF8
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $MaxURL = Get-WebConfigurationProperty "/system.webServer/security/requestFiltering/requestLimits" -PsPath "IIS:\Sites\$SiteName" -Name maxURL
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/security/requestFiltering/requestLimits' -PsPath 'IIS:\Sites\$SiteName' -Name maxURL}"
        $MaxURL = Invoke-Expression $PSCommand
    }

    If ($MaxURL.Value -le 4096) {
        $Status = "NotAFinding"
    }
    Else {
        $Status = "Open"
    }

    $FindingDetails += "MaxURL is set to '$($MaxURL.Value)'"
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214465 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214465
        STIG ID    : IISW-SI-000226
        Rule ID    : SV-214465r879650_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246-WSR-000149
        Rule Title : The IIS 8.5 website must be configured to limit the size of web requests.
        DiscussMD5 : 64D38AF43426ADD6D9E6344353143E1B
        CheckMD5   : 8011960A615AAFF5847D2E06127CF8D8
        FixMD5     : 5C103AB3B3E2B2DF107671EEFF9124F2
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $MaxAllowedContentLength = Get-WebConfigurationProperty "/system.webServer/security/requestFiltering/requestLimits" -PsPath "IIS:\Sites\$SiteName" -Name maxAllowedContentLength
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/security/requestFiltering/requestLimits' -PsPath 'IIS:\Sites\$SiteName' -Name maxAllowedContentLength}"
        $MaxAllowedContentLength = Invoke-Expression $PSCommand
    }

    If ($MaxAllowedContentLength.Value -le 30000000) {
        $Status = "NotAFinding"
    }
    Else {
        $Status = "Open"
    }

    $FindingDetails += "MaxAllowedContentLength is set to '$($MaxAllowedContentLength.Value)'"
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214466 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214466
        STIG ID    : IISW-SI-000227
        Rule ID    : SV-214466r879650_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246-WSR-000149
        Rule Title : The IIS 8.5 websites Maximum Query String limit must be configured.
        DiscussMD5 : 37E426C64E7D1EC415CFB0A993809D90
        CheckMD5   : 8F5C214920B918EF70121D34C9B0BB8D
        FixMD5     : EDDC6F574B2FDD5B8D9D408D7F951101
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $MaxQueryString = Get-WebConfigurationProperty "/system.webServer/security/requestFiltering/requestLimits" -PsPath "IIS:\Sites\$SiteName" -Name maxQueryString
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/security/requestFiltering/requestLimits' -PsPath 'IIS:\Sites\$SiteName' -Name maxQueryString}"
        $MaxQueryString = Invoke-Expression $PSCommand
    }

    If ($MaxQueryString.Value -le 2048) {
        $Status = "NotAFinding"
    }
    Else {
        $Status = "Open"
    }

    $FindingDetails += "MaxQueryString is set to '$($MaxQueryString.Value)'"
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214467 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214467
        STIG ID    : IISW-SI-000228
        Rule ID    : SV-214467r879650_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246-WSR-000149
        Rule Title : Non-ASCII characters in URLs must be prohibited by any IIS 8.5 website.
        DiscussMD5 : B5A863728BBB7647FA2028D3D24BB5AD
        CheckMD5   : 18308EF4138881CD17B6B6D74938B963
        FixMD5     : EA59EA55FF2914037FA5B08F2AA3C59D
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $AllowHighBitCharacters = Get-WebConfigurationProperty "/system.webServer/security/requestFiltering" -PsPath "IIS:\Sites\$SiteName" -Name allowHighBitCharacters
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/security/requestFiltering' -PsPath 'IIS:\Sites\$SiteName' -Name allowHighBitCharacters}"
        $AllowHighBitCharacters = Invoke-Expression $PSCommand
    }

    If ($AllowHighBitCharacters.Value -eq $false) {
        $Status = "NotAFinding"
        $FindingDetails += "AllowHighBitCharacters is Disabled"
    }
    Else {
        $Status = "Open"
        $FindingDetails += "AllowHighBitCharacters is Enabled"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214468 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214468
        STIG ID    : IISW-SI-000229
        Rule ID    : SV-214468r903093_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246-WSR-000149
        Rule Title : Double encoded URL requests must be prohibited by any IIS 8.5 website.
        DiscussMD5 : C5F43CC9CB8BC5C11A4CDFB1E1AAA1EF
        CheckMD5   : 5B5054761184AE6CFECA6B392979D1F9
        FixMD5     : 2166C66F388F51D5D7F2C15C2E231E2B
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
    If (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    Else {
        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Import-Module WebAdministration
            $AllowDoubleEscaping = Get-WebConfigurationProperty "/system.webServer/security/requestFiltering" -PsPath "IIS:\Sites\$SiteName" -Name allowDoubleEscaping
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/security/requestFiltering' -PsPath 'IIS:\Sites\$SiteName' -Name allowDoubleEscaping}"
            $AllowDoubleEscaping = Invoke-Expression $PSCommand
        }

        If ($AllowDoubleEscaping.Value -eq $false) {
            $Status = "NotAFinding"
            $FindingDetails += "AllowDoubleEscaping is Disabled"
        }
        Else {
            $Status = "Open"
            $FindingDetails += "AllowDoubleEscaping is Enabled"
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

Function Get-V214469 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214469
        STIG ID    : IISW-SI-000230
        Rule ID    : SV-214469r903095_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246-WSR-000149
        Rule Title : Unlisted file extensions in URL requests must be filtered by any IIS 8.5 website.
        DiscussMD5 : C9ED24B3DF44EE38A47FA076F5D2721D
        CheckMD5   : 5B4638B277A94A4FBB30644310D917B0
        FixMD5     : B63C962DCA7CDE43D392BEE1F572E2D9
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
    If (Get-Service MSExchangeServiceHost -ErrorAction SilentlyContinue) {
        $Service = Get-Service MSExchangeServiceHost
        $FindingDetails += "Exchange service detected.  If this server only hosts Microsoft Exchange, mark this check as NA." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Service:`t$($Service.Name)" | Out-String
        $FindingDetails += "Status:`t$($Service.Status)" | Out-String
    }
    ElseIf (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "WsusService") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting WSUS so this requirement is NA."
    }
    ElseIf (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    Else {
        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Import-Module WebAdministration
            $AllowUnlisted = Get-WebConfigurationProperty "/system.webServer/security/requestFiltering/fileExtensions" -PsPath "IIS:\Sites\$SiteName" -Name allowUnlisted
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/security/requestFiltering/fileExtensions' -PsPath 'IIS:\Sites\$SiteName' -Name allowUnlisted}"
            $AllowUnlisted = Invoke-Expression $PSCommand
        }

        If ($AllowUnlisted.Value -eq $false) {
            $Status = "NotAFinding"
            $FindingDetails += "AllowUnlisted is Disabled"
        }
        Else {
            $Status = "Open"
            $FindingDetails += "AllowUnlisted is Enabled"
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

Function Get-V214470 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214470
        STIG ID    : IISW-SI-000231
        Rule ID    : SV-214470r879652_rule
        CCI ID     : CCI-001310
        Rule Name  : SRG-APP-000251-WSR-000157
        Rule Title : Directory Browsing on the IIS 8.5 website must be disabled.
        DiscussMD5 : 2A45AF472A723004D72E896EA986918E
        CheckMD5   : 3EE1BACD66E63CF27D399C295840A8BD
        FixMD5     : CD6444F0B3373D72AF274B24A3794AAA
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
    If ((Get-WindowsFeature -Name Web-Dir-Browsing).InstallState -ne "Installed") {
        $Status = "Not_Applicable"
        $FindingDetails += "Directory Browsing IIS Feature is not installed so this requirement is NA."
    }
    Else {
        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Import-Module WebAdministration
            $DirectoryBrowse = Get-WebConfigurationProperty "/system.webServer/directoryBrowse" -PsPath "IIS:\Sites\$SiteName" -Name enabled
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/directoryBrowse' -PsPath 'IIS:\Sites\$SiteName' -Name enabled}"
            $DirectoryBrowse = Invoke-Expression $PSCommand
        }

        If ($DirectoryBrowse.Value -eq $false) {
            $Status = "NotAFinding"
            $FindingDetails += "Directory Browsing is Disabled"
        }
        Else {
            $Status = "Open"
            $FindingDetails += "Directory Browsing is Enabled"
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

Function Get-V214472 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214472
        STIG ID    : IISW-SI-000233
        Rule ID    : SV-214472r879655_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266-WSR-000159
        Rule Title : Warning and error messages displayed to clients must be modified to minimize the identity of the IIS 8.5 website, patches, loaded modules, and directory paths.
        DiscussMD5 : 9A79AA3CE4FFA04A7672C0126E751178
        CheckMD5   : AA08364DA751091D10B07AE1ACA935DD
        FixMD5     : 895DBD05D305C09F18C7518CBF0354CB
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $HttpErrors = Get-WebConfigurationProperty "/system.webServer/httpErrors" -PsPath "IIS:\Sites\$SiteName" -Name *
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/httpErrors' -PsPath 'IIS:\Sites\$SiteName' -Name *}"
        $HttpErrors = Invoke-Expression $PSCommand
    }

    If ($HttpErrors.errorMode -eq "DetailedLocalOnly") {
        $Status = "NotAFinding"
        $FindingDetails += "Error Responses is configured to 'Detailed errors for local requests and custom error pages for remote requests'" | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "Error Responses is NOT configured to 'Detailed errors for local requests and custom error pages for remote requests'" | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214473 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214473
        STIG ID    : IISW-SI-000234
        Rule ID    : SV-214473r903097_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266-WSR-000160
        Rule Title : Debugging and trace information used to diagnose the IIS 8.5 website must be disabled.
        DiscussMD5 : CBF7B6F5E89A9CDAB75ADB6B81C49B75
        CheckMD5   : 26B44E18997AFEA166157BC60314D3E9
        FixMD5     : C1E82ACD8CE99DF2498E8068D68F4D00
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
    If (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    Else {
        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Import-Module WebAdministration
            $WebSite = Get-WebSite -Name "$SiteName" | Select-Object *
            $AppPools = Get-ChildItem IIS:\AppPools
        }
        Else {
            $PSCommand1 = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebSite -Name '$SiteName' | Select-Object *}"
            $PSCommand2 = "PowerShell.exe -Command {Import-Module WebAdministration; Get-ChildItem IIS:\AppPools}"
            $WebSite = Invoke-Expression $PSCommand1
            $AppPools = Invoke-Expression $PSCommand2
        }

        ForEach ($AppPool in $AppPools) {
            If ($AppPool.Name -in $WebSite.applicationPool) {
                If ($Apppool.managedRuntimeVersion -eq "") {
                    # "No Managed Code" (which means it's not using .NET) is an empty string and not a null
                    $Status = "Not_Applicable"
                    $FindingDetails += "The site is not using the .NET runtime so this check is Not Applicable." | Out-String
                }
                Else {
                    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
                        $DebugCompilation = Get-WebConfigurationProperty "system.web/compilation" -PsPath "IIS:\Sites\$SiteName" -Name debug
                    }
                    Else {
                        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty 'system.web/compilation' -PsPath 'IIS:\Sites\$SiteName' -Name debug}"
                        $DebugCompilation = Invoke-Expression $PSCommand
                    }
                    If ($DebugCompilation.Value -eq $false) {
                        $Status = "NotAFinding"
                        $FindingDetails += "Debug is set to 'False'" | Out-String
                    }
                    Else {
                        $Status = "Open"
                        $FindingDetails += "Debug is set NOT to 'False'" | Out-String
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

Function Get-V214474 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214474
        STIG ID    : IISW-SI-000235
        Rule ID    : SV-214474r879673_rule
        CCI ID     : CCI-002361
        Rule Name  : SRG-APP-000295-WSR-000012
        Rule Title : The Idle Time-out monitor for each IIS 8.5 website must be enabled.
        DiscussMD5 : 9E963E502C01CDAF1301F1ADA842AE55
        CheckMD5   : 4B74A3EEA3CC960AACDB8156CCBC032C
        FixMD5     : BE52FD158BC92D90416CB231A6D11CEC
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
    If (Get-Service MSExchangeServiceHost -ErrorAction SilentlyContinue) {
        $Service = Get-Service MSExchangeServiceHost
        $FindingDetails += "Exchange service detected.  If this server only hosts Microsoft Exchange, mark this check as NA." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Service:`t$($Service.Name)" | Out-String
        $FindingDetails += "Status:`t$($Service.Status)" | Out-String
    }
    Else {
        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Import-Module WebAdministration
            $WebSite = Get-WebSite -Name "$SiteName" | Select-Object *
            $AppPools = Get-ChildItem IIS:\AppPools
        }
        Else {
            $PSCommand1 = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebSite -Name '$SiteName' | Select-Object *}"
            $PSCommand2 = "PowerShell.exe -Command {Import-Module WebAdministration; Get-ChildItem IIS:\AppPools}"
            $WebSite = Invoke-Expression $PSCommand1
            $AppPools = Invoke-Expression $PSCommand2
        }

        ForEach ($AppPool in $AppPools) {
            If ($AppPool.Name -in $WebSite.applicationPool) {
                $IdleTimeout = $AppPool.processModel.idleTimeout
                If ($IdleTimeout.TotalMinutes -eq 0) {
                    $Status = "Open"
                }
                ElseIf ($IdleTimeout.TotalMinutes -le 20) {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }

                $FindingDetails += "Idle Time-out is configured to '$($AppPool.processModel.idleTimeout.TotalMinutes)' total minutes" | Out-String
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

Function Get-V214475 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214475
        STIG ID    : IISW-SI-000236
        Rule ID    : SV-214475r879673_rule
        CCI ID     : CCI-002361
        Rule Name  : SRG-APP-000295-WSR-000134
        Rule Title : The IIS 8.5 websites connectionTimeout setting must be explicitly configured to disconnect an idle session.
        DiscussMD5 : 5B4B658FDF60735E5083169BC93210DC
        CheckMD5   : 6DEC25AED88328B0D17AF375FE68F149
        FixMD5     : F0BA80BB353717E4C160D1ED327F05CB
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $SessionState = Get-WebConfigurationProperty "/system.web/sessionState" -PsPath "IIS:\Sites\$SiteName" -Name *
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.web/sessionState' -PsPath 'IIS:\Sites\$SiteName' -Name *}"
        $SessionState = Invoke-Expression $PSCommand
    }

    $Span = New-TimeSpan -Hours 00 -Minutes 20 -Seconds 00
    If ($SessionState.timeout.CompareTo($Span) -le 0) {
        $Status = "NotAFinding"
    }
    Else {
        $Status = "Open"
    }

    $FindingDetails += "Time-out is configured to '$($SessionState.timeout)'" | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214476 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214476
        STIG ID    : IISW-SI-000237
        Rule ID    : SV-214476r879693_rule
        CCI ID     : CCI-002322
        Rule Name  : SRG-APP-000316-WSR-000170
        Rule Title : The IIS 8.5 website must provide the capability to immediately disconnect or disable remote access to the hosted applications.
        DiscussMD5 : D8F5DF452EC0EFD073A632668032D90D
        CheckMD5   : 6B254CB3309EC1B29268DF27E826B62D
        FixMD5     : F88B936C03E30F1ADD60FC8492EF687F
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
    $FindingDetails += "There is nothing preventing an administrator from shutting down either the webservice or an individual IIS site in the event of an attack. Documentation exists describing how." | Out-String
    $Status = 'NotAFinding'
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214477 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214477
        STIG ID    : IISW-SI-000238
        Rule ID    : SV-214477r879730_rule
        CCI ID     : CCI-001849
        Rule Name  : SRG-APP-000357-WSR-000150
        Rule Title : The IIS 8.5 website must use a logging mechanism that is configured to allocate log record storage capacity large enough to accommodate the logging requirements of the IIS 8.5 website.
        DiscussMD5 : 69157122C4800CAA1130151DD5EE27C0
        CheckMD5   : 1FAC01B7357A193EEEC3B711C4E0D91F
        FixMD5     : 33F8C7F3F746C7A6ECA29D7B8A345F46
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $WebSite = Get-WebSite -Name "$SiteName" | Select-Object *
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebSite -Name '$SiteName' | Select-Object *}"
        $WebSite = Invoke-Expression $PSCommand
    }

    $SchedulesToCheck = ("Hourly", "Daily", "Weekly", "Monthly")
    If ($WebSite.logFile.period -in $SchedulesToCheck) {
        $Status = "NotAFinding"
        $FindingDetails += "Logs are set to roll over $($WebSite.logFile.period)." | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "Logs are NOT set to roll over on a schedule." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214478 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214478
        STIG ID    : IISW-SI-000239
        Rule ID    : SV-214478r879756_rule
        CCI ID     : CCI-001762
        Rule Name  : SRG-APP-000383-WSR-000175
        Rule Title : The IIS 8.5 websites must utilize ports, protocols, and services according to PPSM guidelines.
        DiscussMD5 : 9E54BC1C2F647EA1FEDCEB9705385199
        CheckMD5   : 841196A5970514C0DF3A59D18F127303
        FixMD5     : 4BB4DFB52277A439F51C8ED6D88413EA
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
    $NonPPSMPortFound = $false
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $WebSite = Get-WebSite -Name "$SiteName" | Select-Object *
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebSite -Name '$SiteName' | Select-Object *}"
        $WebSite = Invoke-Expression $PSCommand
    }
    $Bindings = $WebSite.bindings.collection | Where-Object { ($_.protocol -eq "http") -or ($_.protocol -eq "https") }
    $Ports = $Bindings.bindingInformation | ForEach-Object { ($_ -split ':')[1] }

    If ($Bindings) {
        ForEach ($Port in $Ports) {
            If ($Port -notin @("80", "443")) {
                $NonPPSMPortFound = $true
            }
        }
        Switch ($NonPPSMPortFound) {
            $true {
                $FindingDetails += "Non-standard port detected.  Confirm PPSM approval." | Out-String
                $FindingDetails += "" | Out-String
            }
            $false {
                $Status = "NotAFinding"
                $FindingDetails += "All ports are PPSM approved." | Out-String
                $FindingDetails += "" | Out-String
            }
        }
        $FindingDetails += "Below are the current HTTP and HTTPS bindings:" | Out-String
        $FindingDetails += "" | Out-String
        ForEach ($Binding in $Bindings) {
            $FindingDetails += "$($Binding.protocol) ($($Binding.bindingInformation))" | Out-String
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails = "There are no HTTP or HTTPS bindings on this site."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214479 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214479
        STIG ID    : IISW-SI-000241
        Rule ID    : SV-214479r879798_rule
        CCI ID     : CCI-002470
        Rule Name  : SRG-APP-000427-WSR-000186
        Rule Title : The IIS 8.5 private website have a server certificate issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs).
        DiscussMD5 : FE990A09BA9D124F6E37B66DD84BE4D2
        CheckMD5   : B128FA6C8A4CC98082BF4119812969AD
        FixMD5     : 125B5279FE49217490EB3A4985328FB5
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
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $WebSite = Get-WebSite -Name "$SiteName" | Select-Object *
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebSite -Name '$SiteName' | Select-Object *}"
        $WebSite = Invoke-Expression $PSCommand
    }

    $Bindings = $WebSite.bindings.collection | Where-Object protocol -EQ "https"
    If ($Bindings) {
        ForEach ($Binding in $Bindings) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "$($Binding.protocol) ($($Binding.bindingInformation)):" | Out-String
            If ($Binding.certificateHash) {
                $CertList = New-Object System.Collections.Generic.List[System.Object]

                $PathsToSearch = @()
                ForEach ($Item in (Get-ChildItem Cert:\LocalMachine).Name) {
                    $PathsToSearch += "LocalMachine\$($Item)"
                }
                ForEach ($Item in (Get-ChildItem Cert:\CurrentUser | Where-Object Name -ne "UserDS").Name) {
                    $PathsToSearch += "CurrentUser\$($Item)"
                }

                ForEach ($Path in $PathsToSearch) {
#                    $FoundCert = ""
                    $FoundCert = Get-ChildItem Cert:\$Path -Recurse -ErrorAction SilentlyContinue | Where-Object Thumbprint -in $Binding.certificateHash
                    If ($FoundCert) {
                        ForEach ($Cert in $FoundCert) {
                            $ApprovedChain = $false
                            $CertPath = @()
                            $Chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
                            $null = $Chain.Build($Cert)
                            ForEach ($Item in ($Chain.ChainElements.Certificate | Select-Object FriendlyName,Subject)) {
                                If ($Item.Subject -match "(^CN=DOD Root|^CN=ECA Root|^CN=NSS Root)") {
                                    $ApprovedChain = $true
                                }
                                If (-Not($Item.FriendlyName -eq "" -or $null -eq $Item.FriendlyName)) {
                                    $CertPath += $($Item.FriendlyName)
                                }
                                Else {
                                    $CertPath += $(($Item.Subject -split ',')[0] -replace 'CN=','')
                                }
                            }
                            [Array]::Reverse($CertPath)

                            $NewObj = [PSCustomObject]@{
                                BindingInfo    = $(($Binding | Where-Object certificateHash -eq $Cert.Thumbprint).bindingInformation)
                                Subject        = $Cert.Subject
                                CertStore      = $Path
                                Issuer         = $Cert.Issuer
                                FriendlyName   = $Cert.FriendlyName
                                NotAfter       = $Cert.NotAfter
                                Thumbprint     = $Cert.Thumbprint
                                CertPath       = $CertPath
                                ApprovedChain  = $ApprovedChain
                            }
                            $CertList.Add($NewObj)
                        }
                    }
                }

                If (($CertList | Where-Object ApprovedChain -eq $false | Measure-Object).Count -gt 0) {
                    $Compliant = $false
                    $FindingDetails += "Non-Compliant Certificates:" | Out-String
                    $FindingDetails += "---------------------------" | Out-String
                    ForEach ($Cert in $CertList | Where-Object ApprovedChain -eq $false) {
                        $FindingDetails += "Subject:`t`t`t$($Cert.Subject)" | Out-String
                        $FindingDetails += "CertStore:`t`t`t$($Cert.CertStore)" | Out-String
                        $FindingDetails += "Issuer:`t`t`t$($Cert.Issuer)" | Out-String
                        $FindingDetails += "FriendlyName:`t`t$($Cert.FriendlyName)" | Out-String
                        $FindingDetails += "NotAfter:`t`t`t$($Cert.NotAfter)" | Out-String
                        $FindingDetails += "Thumbprint:`t`t$($Cert.Thumbprint)" | Out-String
                        $FindingDetails += "ApprovedChain:`t$($Cert.ApprovedChain) [finding]" | Out-String
                        $FindingDetails += "CertificationPath..." | Out-String
                        $i = 0
                        ForEach ($Item in $Cert.CertPath) {
                            $FindingDetails += "($i) - $($Item)" | Out-String
                            $i++
                        }
                        $FindingDetails += "" | Out-String
                    }
                }

                $FindingDetails += "" | Out-String
                If (($CertList | Where-Object ApprovedChain -eq $true | Measure-Object).Count -gt 0) {
                    $Status = "Open"
                    $FindingDetails += "Compliant Certificates:" | Out-String
                    $FindingDetails += "---------------------------" | Out-String
                    ForEach ($Cert in $CertList | Where-Object ApprovedChain -eq $true) {
                        $FindingDetails += "Subject:`t`t`t$($Cert.Subject)" | Out-String
                        $FindingDetails += "CertStore:`t`t`t$($Cert.CertStore)" | Out-String
                        $FindingDetails += "Issuer:`t`t`t$($Cert.Issuer)" | Out-String
                        $FindingDetails += "FriendlyName:`t`t$($Cert.FriendlyName)" | Out-String
                        $FindingDetails += "NotAfter:`t`t`t$($Cert.NotAfter)" | Out-String
                        $FindingDetails += "Thumbprint:`t`t$($Cert.Thumbprint)" | Out-String
                        $FindingDetails += "ApprovedChain:`t$($Cert.ApprovedChain)" | Out-String
                        $FindingDetails += "CertificationPath..." | Out-String
                        $i = 0
                        ForEach ($Item in $Cert.CertPath) {
                            $FindingDetails += "($i) - $($Item)" | Out-String
                            $i++
                        }
                        $FindingDetails += "" | Out-String
                    }
                }
            }
            Else {
                $Compliant = $false
                $FindingDetails += "No certificate selected for HTTPS binding." | Out-String
            }
        }
    }

    Else {
        $Compliant = $false
        $FindingDetails = "There are no HTTPS bindings on this site."
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

Function Get-V214480 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214480
        STIG ID    : IISW-SI-000242
        Rule ID    : SV-214480r879800_rule
        CCI ID     : CCI-002476
        Rule Name  : SRG-APP-000429-WSR-000113
        Rule Title : The IIS 8.5 private website must employ cryptographic mechanisms (TLS) and require client certificates.
        DiscussMD5 : CA400469361F3E2D54A4FB7586699F02
        CheckMD5   : E8D80AFA0C751F4BCA9BC709B634295A
        FixMD5     : 90DAB97DA3204694DBF47E0DBA2ADBE3
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
    If (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "WsusService") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting WSUS so this requirement is NA."
    }
    ElseIf (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    Else {
        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Import-Module WebAdministration
            $Access = Get-WebConfigurationProperty "/system.webServer/security/access" -PsPath "IIS:\Sites\$SiteName" -Name *
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/security/access' -PsPath 'IIS:\Sites\$SiteName' -Name *}"
            $Access = Invoke-Expression $PSCommand
        }

        $Compliant = $true
        $FlagsToCheck = ("Ssl", "SslRequireCert", "Ssl128")
        $SslFlags = $Access.sslFlags -split ","
        $MissingFlags = ""

        ForEach ($Flag in $FlagsToCheck) {
            If ($Flag -notin $SslFlags) {
                $Compliant = $false
                $MissingFlags += $Flag | Out-String
            }
        }

        If ($Compliant -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "Ssl, SslRequireCert, and Ssl128 are all set."
        }
        Else {
            $Status = "Open"
            $FindingDetails += "The following SSL flags are missing:" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += $MissingFlags | Out-String
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

Function Get-V214481 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214481
        STIG ID    : IISW-SI-000244
        Rule ID    : SV-214481r879810_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000439-WSR-000152
        Rule Title : IIS 8.5 website session IDs must be sent to the client using TLS.
        DiscussMD5 : 5D2DDCA7C76E029B9B74B71A393CE4FB
        CheckMD5   : D035A181A82DEF4137DC6D453965318B
        FixMD5     : 5B3A25F105C970F27BDB8096BA4E31CF
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $session = Get-WebConfigurationProperty "/system.webServer/asp/session" -PsPath "IIS:\Sites\$SiteName" -Name *
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/asp/session' -PsPath 'IIS:\Sites\$SiteName' -Name *}"
        $session = Invoke-Expression $PSCommand
    }

    If ($Session.keepSessionIdSecure -eq $true) {
        $Status = "NotAFinding"
    }
    Else {
        $Status = "Open"
    }

    $FindingDetails += "KeepSessionIdSecure is set to '$($Session.keepSessionIdSecure)'" | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214482 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214482
        STIG ID    : IISW-SI-000246
        Rule ID    : SV-214482r903100_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000439-WSR-000154
        Rule Title : Cookies exchanged between the IIS 8.5 website and the client must use SSL/TLS, have cookie properties set to prohibit client-side scripts from reading the cookie data and must not be compressed.
        DiscussMD5 : D30FF798B524CDA675C7FF96019A1758
        CheckMD5   : 6AD301DE45E8247D10078E0B8BCED511
        FixMD5     : C9B322069A829FA482F68182F8308098
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
    If (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "WsusService") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting WSUS so this requirement is NA."
    }
    ElseIf (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    Else {
        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Import-Module WebAdministration
            $HttpCookies = Get-WebConfigurationProperty "/system.web/httpCookies" -PsPath "IIS:\Sites\$SiteName" -Name *
            $SessionState = Get-WebConfigurationProperty "/system.web/sessionState" -PsPath "IIS:\Sites\$SiteName" -Name *
        }
        Else {
            $PSCommand1 = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.web/httpCookies' -PsPath 'IIS:\Sites\$SiteName' -Name *}"
            $PSCommand2 = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.web/sessionState' -PsPath 'IIS:\Sites\$SiteName' -Name *}"
            $HttpCookies = Invoke-Expression $PSCommand1
            $SessionState = Invoke-Expression $PSCommand2
        }

        If (($HttpCookies.requireSSL -eq $true) -and ($SessionState.compressionEnabled -eq $false)) {
            $Status = "NotAFinding"
        }
        Else {
            $Status = "Open"
        }

        $FindingDetails += "RequireSSL is set to '$($HttpCookies.requireSSL)'" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "CompressionEnabled is set to '$($SessionState.compressionEnabled)'" | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214483 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214483
        STIG ID    : IISW-SI-000249
        Rule ID    : SV-214483r903103_rule
        CCI ID     : CCI-002420, CCI-002422
        Rule Name  : SRG-APP-000441-WSR-000181
        Rule Title : The IIS 8.5 website must maintain the confidentiality and integrity of information during preparation for transmission and during reception.
        DiscussMD5 : A86B7764D1B007010318896A1E0774E2
        CheckMD5   : 6442D7AE3CB34BDFB0B54BEC78FF09CF
        FixMD5     : 6F19FB3E2DBB9A60EED8AB19E4DD1A05
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
    If (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    Else {
        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Import-Module WebAdministration
            $Access = Get-WebConfigurationProperty "/system.webServer/security/access" -PsPath "IIS:\Sites\$SiteName" -Name *
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/security/access' -PsPath 'IIS:\Sites\$SiteName' -Name *}"
            $Access = Invoke-Expression $PSCommand
        }

        $Compliant = $true
        $FlagsToCheck = ("Ssl", "SslRequireCert", "Ssl128")
        $SslFlags = $Access.sslFlags -split ","
        $MissingFlags = ""

        ForEach ($Flag in $FlagsToCheck) {
            If ($Flag -notin $SslFlags) {
                $Compliant = $false
                $MissingFlags += $Flag | Out-String
            }
        }

        If ($Compliant -eq $true) {
            $Status = "NotAFinding"
            $FindingDetails += "Ssl, SslRequireCert, and Ssl128 are all set."
        }
        Else {
            $Status = "Open"
            $FindingDetails += "The following SSL flags are missing:" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += $MissingFlags | Out-String
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

Function Get-V214484 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214484
        STIG ID    : IISW-SI-000251
        Rule ID    : SV-214484r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The IIS 8.5 website must have a unique application pool.
        DiscussMD5 : 5106D2ED477928763694548B850C877F
        CheckMD5   : FA702EEE8A1BBBF1073F4214D41E6EB7
        FixMD5     : 8B2CACDF6DB07A101D3EE63224312BA4
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
    If (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    ElseIf (Get-Service MSExchangeServiceHost -ErrorAction SilentlyContinue) {
        $Service = Get-Service MSExchangeServiceHost
        $FindingDetails += "Exchange service detected.  If this server only hosts Microsoft Exchange, mark this check as NA." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Service:`t$($Service.Name)" | Out-String
        $FindingDetails += "Status:`t$($Service.Status)" | Out-String
    }
    Else {
        $Compliant = $true
        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Import-Module WebAdministration
            $AllSites = Get-WebSite
            $AllAppPools = Get-WebConfigurationProperty /system.applicationHost/sites/site/application -name applicationPool
        }
        Else {
            $PSCommand1 = 'PowerShell.exe -Command {Import-Module WebAdministration; Get-WebSite}'
            $PSCommand2 = 'PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty /system.applicationHost/sites/site/application -name applicationPool}'
            $AllSites = Invoke-Expression $PSCommand1
            $AllAppPools = Invoke-Expression $PSCommand2
        }

        $AppPoolNames = $AllAppPools.Value | Select-Object -Unique
        $AppPoolUsage = New-Object System.Collections.Generic.List[System.Object]
        ForEach ($AppPool in $AppPoolNames) {
            $SiteUsage = @()
            ForEach ($Item in ($AllAppPools | Where-Object Value -EQ $AppPool)) {
                ForEach ($Site in $AllSites) {
                    If ($Item.ItemXPath -match "@name='$($Site.Name)'") {
                        If ($Site.Name -notin $SiteUsage) {
                            $SiteUsage += $Site.Name
                        }
                    }
                }
            }
            $NewObj = [PSCustomObject]@{
                ApplicationPool = $AppPool
                WebSiteUsage    = $SiteUsage
            }
            $AppPoolUsage.Add($NewObj)
        }

        ForEach ($Item in ($AppPoolUsage | Where-Object WebSiteUsage -Contains $SiteName)) {
            $FindingDetails += "ApplicationPool:`t$($Item.ApplicationPool)" | Out-String
            If (($Item.WebSiteUsage | Measure-Object).Count -gt 1) {
                $Compliant = $false
                $FindingDetails += "WebSiteUsage:`t$($Item.WebSiteUsage -Join ', ') [Multiple websites. Finding.]" | Out-String
            }
            Else {
                $FindingDetails += "WebSiteUsage:`t$($Item.WebSiteUsage)" | Out-String
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

Function Get-V214485 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214485
        STIG ID    : IISW-SI-000252
        Rule ID    : SV-214485r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The maximum number of requests an application pool can process for each IIS 8.5 website must be explicitly set.
        DiscussMD5 : BC308B4474DA3E9E8DC3BC21EB332F69
        CheckMD5   : AC90116B7F97A2D90B68191AB589988B
        FixMD5     : 4207DD756C3225B421CEDC0A4211894A
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
    If (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    Else {
        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Import-Module WebAdministration
            $AppPools = Get-ChildItem IIS:\AppPools
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-ChildItem IIS:\AppPools}"
            $AppPools = Invoke-Expression $PSCommand
        }

        ForEach ($AppPool in $AppPools) {
            $FindingDetails += "Application Pool:`t$($AppPool.Name)" | Out-String
            $FindingDetails += "Request Limit:`t`t$($AppPool.recycling.periodicRestart.requests)" | Out-String
            $FindingDetails += "" | Out-String
            If ($AppPool.recycling.periodicRestart.requests -eq 0) {
                $Status = "Open"
            }
        }

        If ($Status -ne "Open") {
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

Function Get-V214488 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214488
        STIG ID    : IISW-SI-000255
        Rule ID    : SV-214488r881088_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The application pool for each IIS 8.5 website must have a recycle time explicitly set.
        DiscussMD5 : 85F41E23F947B3FFBF7BFE277197A2B1
        CheckMD5   : E9D15BC8D0A5FD9A77F4E2361811383D
        FixMD5     : 3611B71AACB83FD4F1563B494204C382
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
    If (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    ElseIf (Get-Service MSExchangeServiceHost -ErrorAction SilentlyContinue) {
        $Service = Get-Service MSExchangeServiceHost
        $FindingDetails += "Exchange service detected.  If this server only hosts Microsoft Exchange, mark this check as NA." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Service:`t$($Service.Name)" | Out-String
        $FindingDetails += "Status:`t$($Service.Status)" | Out-String
    }
    Else {
        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Import-Module WebAdministration
            $AppPools = Get-ChildItem IIS:\AppPools
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-ChildItem IIS:\AppPools}"
            $AppPools = Invoke-Expression $PSCommand
        }

        ForEach ($AppPool in $AppPools) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Application Pool:`t`t$($AppPool.Name)" | Out-String
            $LogEventFlags = $AppPool.recycling.logEventOnRecycle -split ","

            If ("Time" -in $LogEventFlags) {
                # "Regular time interval" flag
                $FindingDetails += "Regular Time Interval:`t$true" | Out-String
            }
            Else {
                $Status = "Open"
                $FindingDetails += "Regular Time Interval:`t$false" | Out-String
            }

            If ("Schedule" -in $LogEventFlags) {
                # "Specific time" flag
                $FindingDetails += "Specific Time:`t`t`t$true" | Out-String
            }
            Else {
                $Status = "Open"
                $FindingDetails += "Specific Time:`t`t`t$false" | Out-String
            }
        }

        If ($Status -ne "Open") {
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

Function Get-V214489 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214489
        STIG ID    : IISW-SI-000256
        Rule ID    : SV-214489r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The maximum queue length for HTTP.sys for each IIS 8.5 website must be explicitly configured.
        DiscussMD5 : 57E8C1D197379DF0C5FC98A4B03B68CF
        CheckMD5   : 6052D1A9C29A5B082B53F5A8ACFAEED0
        FixMD5     : 8C6B863122D2E02E5693A8FB96108822
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
    If (Get-Service MSExchangeServiceHost -ErrorAction SilentlyContinue) {
        $Service = Get-Service MSExchangeServiceHost
        $FindingDetails += "Exchange service detected.  If this server only hosts Microsoft Exchange, mark this check as NA." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Service:`t$($Service.Name)" | Out-String
        $FindingDetails += "Status:`t$($Service.Status)" | Out-String
    }
    Else {
        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Import-Module WebAdministration
            $AppPools = Get-ChildItem IIS:\AppPools
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-ChildItem IIS:\AppPools}"
            $AppPools = Invoke-Expression $PSCommand
        }

        ForEach ($AppPool in $AppPools) {
            $FindingDetails += "Application Pool:`t$($AppPool.Name)" | Out-String
            $FindingDetails += "Queue Length:`t`t$($AppPool.queueLength)" | Out-String
            $FindingDetails += "" | Out-String
            If ($AppPool.queueLength -gt 1000) {
                $Status = "Open"
            }
        }

        If ($Status -ne "Open") {
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

Function Get-V214490 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214490
        STIG ID    : IISW-SI-000257
        Rule ID    : SV-214490r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The application pools pinging monitor for each IIS 8.5 website must be enabled.
        DiscussMD5 : C5EB1BA826EFFE46B5260DE164AB883A
        CheckMD5   : 11E128EA76D3F439FA5B93F750A15F20
        FixMD5     : B5A86AFCFF76750C76EA008DDAE67F06
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
    If (Get-Service MSExchangeServiceHost -ErrorAction SilentlyContinue) {
        $Service = Get-Service MSExchangeServiceHost
        $FindingDetails += "Exchange service detected.  If this server only hosts Microsoft Exchange, mark this check as NA." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Service:`t$($Service.Name)" | Out-String
        $FindingDetails += "Status:`t$($Service.Status)" | Out-String
    }
    Else {
        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Import-Module WebAdministration
            $AppPools = Get-ChildItem IIS:\AppPools
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-ChildItem IIS:\AppPools}"
            $AppPools = Invoke-Expression $PSCommand
        }

        ForEach ($AppPool in $AppPools) {
            $FindingDetails += "Application Pool:`t$($AppPool.Name)" | Out-String
            $FindingDetails += "Ping Enabled:`t`t$($AppPool.processModel.pingingEnabled)" | Out-String
            $FindingDetails += "" | Out-String
            If ($AppPool.processModel.pingingEnabled -ne $true) {
                $Status = "Open"
            }
        }

        If ($Status -ne "Open") {
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

Function Get-V214491 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214491
        STIG ID    : IISW-SI-000258
        Rule ID    : SV-214491r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The application pools rapid fail protection for each IIS 8.5 website must be enabled.
        DiscussMD5 : 46424646ADFEAC1A8F235DC406FA1D4D
        CheckMD5   : CCDCB9C41C6833F7018089CF0EDDA950
        FixMD5     : 9AD89D754F6501AEA2145A032462B1F6
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
    If (Get-Service MSExchangeServiceHost -ErrorAction SilentlyContinue) {
        $Service = Get-Service MSExchangeServiceHost
        $FindingDetails += "Exchange service detected.  If this server only hosts Microsoft Exchange, mark this check as NA." | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Service:`t$($Service.Name)" | Out-String
        $FindingDetails += "Status:`t$($Service.Status)" | Out-String
    }
    Else {
        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Import-Module WebAdministration
            $AppPools = Get-ChildItem IIS:\AppPools
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-ChildItem IIS:\AppPools}"
            $AppPools = Invoke-Expression $PSCommand
        }

        ForEach ($AppPool in $AppPools) {
            $FindingDetails += "Application Pool:`t`t$($AppPool.Name)" | Out-String
            $FindingDetails += "Rapid Fail Protection:`t$($AppPool.failure.rapidFailProtection)" | Out-String
            $FindingDetails += "" | Out-String
            If ($AppPool.failure.rapidFailProtection -ne $true) {
                $Status = "Open"
            }
        }

        If ($Status -ne "Open") {
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

Function Get-V214492 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214492
        STIG ID    : IISW-SI-000259
        Rule ID    : SV-214492r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The application pools rapid fail protection settings for each IIS 8.5 website must be managed.
        DiscussMD5 : 7FEAC86403939EC9526508634BC69459
        CheckMD5   : CA2E6262F5DF15E7F2C2F26238E4D6DA
        FixMD5     : 10273126E24DF36E2083D9C634A66DC8
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $AppPools = Get-ChildItem IIS:\AppPools
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-ChildItem IIS:\AppPools}"
        $AppPools = Invoke-Expression $PSCommand
    }

    $Span = New-TimeSpan -Hours 00 -Minutes 05 -Seconds 00
    ForEach ($AppPool in $AppPools) {
        $FindingDetails += "Application Pool:`t$($AppPool.Name)" | Out-String
        $FindingDetails += "Failure Interval:`t$($AppPool.failure.rapidFailProtectionInterval.Minutes)" | Out-String
        $FindingDetails += "" | Out-String
        If ($AppPool.failure.rapidFailProtectionInterval.CompareTo($Span) -gt 0) {
            $Status = "Open"
        }
    }

    If ($Status -ne "Open") {
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

Function Get-V214493 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214493
        STIG ID    : IISW-SI-000261
        Rule ID    : SV-214493r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000087
        Rule Title : Interactive scripts on the IIS 8.5 web server must be located in unique and designated folders.
        DiscussMD5 : 1B3680C11CA287197B271B88FF7E5619
        CheckMD5   : 4D436792DC9683924495FF391D129CCE
        FixMD5     : CA9EF720647CD6EAD0FCF0BC44471B62
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $WebSite = Get-WebSite -Name "$SiteName" | Select-Object *
        $WebDirectories = @()
        $ListOfScripts = @()

        $WebDirectories += $WebSite.physicalPath -replace "%SystemDrive%", $env:SystemDrive
        # Required mechanism to leverage the extended attribute to be able to grab the name handle of hosted applications
        $Applications = Get-WebApplication -Site "$($WebSite.name)" | Select-Object @{n = 'Site'; e = {$_.GetParentElement().Attributes['name'].value + $_.path }}, @{n = 'PhysicalPath'; e = {$_.PhysicalPath}}
        $Applications | ForEach-Object {
            $WebDirectories += $_.PhysicalPath -replace "%SystemDrive%", $env:SystemDrive

            # Remove website name and trailing / from variable to allow for application name reference
            $ApplicationName = $_.Site.substring($_.Site.IndexOf('/') + 1)
            $VDirectories = Get-WebVirtualDirectory -Site "$($WebSite.Name)" -Application "$($ApplicationName)"
            $VDirectories | ForEach-Object {
                $WebDirectories += $_.physicalPath -replace "%SystemDrive%", $env:SystemDrive
            }
        }
        $VirtualDirectories = Get-WebVirtualDirectory -site "$($WebSite.Name)"
        $VirtualDirectories | ForEach-Object {
            $WebDirectories += $_.physicalPath -replace "%SystemDrive%", $env:SystemDrive
        }
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebSite -Name '$SiteName' | Select-Object *}"
        $WebSite = Invoke-Expression $PSCommand
        $WebDirectories = @()
        $ListOfScripts = @()

        $WebDirectories += $WebSite.physicalPath -replace "%SystemDrive%", $env:SystemDrive
        # Required mechanism to leverage the extended attribute to be able to grab the name handle of hosted applications
        $PSCommand = 'PowerShell.exe -Command {Import-Module WebAdministration; Get-WebApplication -Site "' + $WebSite.Name + '" | Select-Object @{n = "Site"; e = {$_.GetParentElement().Attributes["name"].value + $_.path }}, @{n = "PhysicalPath"; e = {$_.PhysicalPath}}}'
        $Applications = Invoke-Expression $PSCommand
        $Applications | ForEach-Object {
            $WebDirectories += $_.physicalPath -replace "%SystemDrive%", $env:SystemDrive

            # Remove website name and trailing / from variable to allow for application name reference
            $ApplicationName = $_.Site.substring($_.Site.IndexOf('/') + 1)
            $PSCommand = 'PowerShell.exe -Command {Import-Module WebAdministration; Get-WebVirtualDirectory -Site "' + $WebSite.Name + '" -Application "' + $ApplicationName + '"}'
            $VDirectories = Invoke-Expression $PSCommand
            $VDirectories | ForEach-Object {
                $WebDirectories += $_.physicalPath -replace "%SystemDrive%", $env:SystemDrive
            }
        }
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebVirtualDirectory -site '" + $WebSite.Name + "'}"
        $VirtualDirectories = Invoke-Expression $PSCommand
        $VirtualDirectories | ForEach-Object {
            $WebDirectories += $_.physicalPath -replace "%SystemDrive%", $env:SystemDrive
        }
    }

    $DirectoriesToScan = $WebDirectories | Select-Object -Unique
    ForEach ($Directory in $DirectoriesToScan) {
        If (Test-Path $Directory) {
            $ListOfScripts += Get-ChildItem $Directory -Recurse -Include *.cgi, *.pl, *.vb, *.class, *.c, *.php, *.asp | Select-Object FullName
        }
    }

    If (-Not($ListOfScripts) -or ($ListOfScripts -eq "") -or ($ListOfScripts.Count -le 0)) {
        $Status = "NotAFinding"
        $FindingDetails += "There are no interactive scripts detected for this site."
    }
    Else {
        $FindingDetails += "The following scripts were found:" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += $ListOfScripts.FullName | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214494 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214494
        STIG ID    : IISW-SI-000262
        Rule ID    : SV-214494r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000087
        Rule Title : Interactive scripts on the IIS 8.5 web server must have restrictive access controls.
        DiscussMD5 : 7C0FFDE077D41CF5407015D7A61D5D8B
        CheckMD5   : 49FFA818680FF26A8566A593EA582C17
        FixMD5     : DF8EFACBE690DA73C5AEF11031EE5FBE
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $WebSite = Get-WebSite -Name "$SiteName" | Select-Object *
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebSite -Name '$SiteName' | Select-Object *}"
        $WebSite = Invoke-Expression $PSCommand
    }
    $WebDirectories = @()
    $ListOfScripts = @()

    If ((Get-WindowsFeature -name "Web-CGI").Installed -eq $true) {
        $WebDirectories += $WebSite.physicalPath -replace "%SystemDrive%", $env:SystemDrive
        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            # Required mechanism to leverage the extended attribute to be able to grab the name handle of hosted applications
            $Applications = Get-WebApplication -Site "$($WebSite.name)" | Select-Object @{n = 'Site'; e = {$_.GetParentElement().Attributes['name'].value + $_.path }}, @{n = 'PhysicalPath'; e = {$_.PhysicalPath}}
            $Applications | ForEach-Object {
                $WebDirectories += $_.PhysicalPath -replace "%SystemDrive%", $env:SystemDrive

                # Remove website name and trailing / from variable to allow for application name reference
                $ApplicationName = $_.Site.substring($_.Site.IndexOf('/') + 1)
                $VDirectories = Get-WebVirtualDirectory -Site "$($WebSite.Name)" -Application "$($ApplicationName)"
                $VDirectories | ForEach-Object {
                    $WebDirectories += $_.physicalPath -replace "%SystemDrive%", $env:SystemDrive
                }
            }
            $VirtualDirectories = Get-WebVirtualDirectory -site "$($WebSite.Name)"
            $VirtualDirectories | ForEach-Object {
                $WebDirectories += $_.physicalPath -replace "%SystemDrive%", $env:SystemDrive
            }
        }
        Else {
            # Required mechanism to leverage the extended attribute to be able to grab the name handle of hosted applications
            $PSCommand = 'PowerShell.exe -Command {Import-Module WebAdministration; Get-WebApplication -Site "' + $WebSite.Name + '" | Select-Object @{n = "Site"; e = {$_.GetParentElement().Attributes["name"].value + $_.path }}, @{n = "PhysicalPath"; e = {$_.PhysicalPath}}}'
            $Applications = Invoke-Expression $PSCommand
            $Applications | ForEach-Object {
                $WebDirectories += $_.physicalPath -replace "%SystemDrive%", $env:SystemDrive

                # Remove website name and trailing / from variable to allow for application name reference
                $ApplicationName = $_.Site.substring($_.Site.IndexOf('/') + 1)
                $PSCommand = 'PowerShell.exe -Command {Import-Module WebAdministration; Get-WebVirtualDirectory -Site "' + $WebSite.Name + '" -Application "' + $ApplicationName + '"}'
                $VDirectories = Invoke-Expression $PSCommand
                $VDirectories | ForEach-Object {
                    $WebDirectories += $_.physicalPath -replace "%SystemDrive%", $env:SystemDrive
                }
            }
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebVirtualDirectory -site '" + $WebSite.Name + "'}"
            $VirtualDirectories = Invoke-Expression $PSCommand
            $VirtualDirectories | ForEach-Object {
                $WebDirectories += $_.physicalPath -replace "%SystemDrive%", $env:SystemDrive
            }
        }

        $DirectoriesToScan = $WebDirectories | Select-Object -Unique
        ForEach ($Directory in $DirectoriesToScan) {
            If (Test-Path $Directory) {
                $ListOfScripts += Get-ChildItem $Directory -Recurse -Include *.cgi, *.pl, *.vb, *.class, *.c, *.php, *.asp, *.aspx | Select-Object FullName
            }
        }

        If (-Not($ListOfScripts) -or ($ListOfScripts -eq "")) {
            $Status = "NotAFinding"
            $FindingDetails += "There are no interactive scripts detected for this site."
        }
        Else {
            $FindingDetails += "The following scripts were found:" | Out-String
            $FindingDetails += "" | Out-String
            ForEach ($Script in $ListOfScripts) {
                $FindingDetails += $Script.FullName | Out-String
                $Acl = Get-Acl $Script.FullName
                $FindingDetails += $Acl.Access | Select-Object IdentityReference, AccessControlType, FileSystemRights | Format-List | Out-String
                $FindingDetails += "------------------------------------------" | Out-String
            }
        }
    }
    Else {
        $Status = "Not_Applicable"
        $FindingDetails += "This website does not utilize CGI so this check is Not Applicable."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214495 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214495
        STIG ID    : IISW-SI-000263
        Rule ID    : SV-214495r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000087
        Rule Title : Backup interactive scripts on the IIS 8.5 server must be removed.
        DiscussMD5 : 16FE195BE4C481B86B358480769EC41A
        CheckMD5   : 3124FDFBE0EE044516D86173A7C126EE
        FixMD5     : ACD210A8BEF16A595452C35B9F13DCB1
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $WebSite = Get-WebSite -Name "$SiteName" | Select-Object *
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebSite -Name '$SiteName' | Select-Object *}"
        $WebSite = Invoke-Expression $PSCommand
    }
    $WebDirectories = @()
    $ListOfBackups = ""

    If ((Get-WindowsFeature -name "Web-CGI").Installed -eq $true) {
        $WebDirectories += $WebSite.physicalPath -replace "%SystemDrive%", $env:SystemDrive
        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            $Applications = Get-WebApplication -site "$($WebSite.Name)"
            $Applications | ForEach-Object {
                $WebDirectories += $_.physicalPath -replace "%SystemDrive%", $env:SystemDrive
            }
            $VirtualDirectories = Get-WebVirtualDirectory -site "$($WebSite.Name)"
            $VirtualDirectories | ForEach-Object {
                $WebDirectories += $_.physicalPath -replace "%SystemDrive%", $env:SystemDrive
            }
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebApplication -site '" + $WebSite.Name + "'}"
            $Applications = Invoke-Expression $PSCommand
            $Applications | ForEach-Object {
                $WebDirectories += $_.physicalPath -replace "%SystemDrive%", $env:SystemDrive
            }
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebVirtualDirectory -site '" + $WebSite.Name + "'}"
            $VirtualDirectories = Invoke-Expression $PSCommand
            $VirtualDirectories | ForEach-Object {
                $WebDirectories += $_.physicalPath -replace "%SystemDrive%", $env:SystemDrive
            }
        }

        $DirectoriesToScan = $WebDirectories | Select-Object -Unique
        ForEach ($Directory in $DirectoriesToScan) {
            If (Test-Path $Directory) {
                Get-ChildItem $Directory -Recurse -Include *.bak, *.old, *.temp, *.tmp, *.backup, "*copy of*" | Select-Object FullName | ForEach-Object {
                    $ListOfBackups += $_.FullName | Out-String
                }
            }
        }

        If (-Not($ListOfBackups) -or ($ListOfBackups -eq "")) {
            $Status = "NotAFinding"
            $FindingDetails += "There are no backup scripts on any of the websites."
        }
        Else {
            $FindingDetails += "The following backup files were found:" | Out-String
            $FindingDetails += "" | Out-String
            ForEach ($File in $ListOfBackups) {
                $FindingDetails += $File | Out-String
            }
        }
    }
    Else {
        $Status = "Not_Applicable"
        $FindingDetails += "This website does not utilize CGI so this check is Not Applicable."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V258445 {
    <#
    .DESCRIPTION
        Vuln ID    : V-258445
        STIG ID    : IISW-SI-009999
        Rule ID    : SV-258445r928856_rule
        CCI ID     : CCI-002605
        Rule Name  : SRG-APP-000456-WSR-000187
        Rule Title : The version of IIS running on the system must be a supported version.
        DiscussMD5 : 91915208A3398422F439F10C826CA918
        CheckMD5   : 2F7373D30F6ECB79F6454ECCC7CA2D15
        FixMD5     : E0239E38DE3DFE26FE333ABCA75A3CA5
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
    $Status = "Open"
    $FindingDetails += "System is running IIS 8.5" | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCACQrMf0bHaXe2I
# q7In4+Roy4Hlshv2lCycTp2Uhiur6aCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCB6AAXFgHk7FT1mCVG3QRVVLJ3sMIdt
# OBM0ua/h//tTEzANBgkqhkiG9w0BAQEFAASCAQB0rwWWgbcQyNFc7PxGg10GCvrx
# 5S4jS8zYermmd5uMRadxFgh/AxX268Ao7T4LU/+FyC+axW2kZtHOOchYQ4e0kqv2
# w9YdSwQ607DVMqOTsqOZMjEDQAKKiXdk1r8wW74UCBFSnbJkd8HvEXRKCLwjtbqu
# R9IuL1yywmgwsOLdE3dvLJU37Mg7RL62A3aZP8ZRiUVYQCkivvIP2b90yl/MEQTh
# zRQBe67GXrsr2nZeLbxCU8/th6KU4Tu6M1gih9LA4BuHl8r6OOWew00a1N2W67Re
# v17gCWyJEue00iYAKNBoeGWiynkM6WQV8cALOe5gO2X9+dVk8rB1UagGiOdt
# SIG # End signature block
