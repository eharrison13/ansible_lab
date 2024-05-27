##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Microsoft IIS 10.0 Site
# Version:  V2R9
# Class:    UNCLASSIFIED
# Updated:  5/13/2024
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V218735 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218735
        STIG ID    : IIST-SI-000201
        Rule ID    : SV-218735r879511_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-WSR-000002
        Rule Title : The IIS 10.0 website session state must be enabled.
        DiscussMD5 : A367D4E03CAD617F0F64ADE69B4FD99B
        CheckMD5   : 805E8BB317C02B2DF8558DC1D1D6A8A8
        FixMD5     : 1D95B1A4631DF06AE85D9E64F0380C28
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

Function Get-V218736 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218736
        STIG ID    : IIST-SI-000202
        Rule ID    : SV-218736r879511_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-WSR-000002
        Rule Title : The IIS 10.0 website session state cookie settings must be configured to Use Cookies mode.
        DiscussMD5 : 7493CE4E76F9287B57D53453C311FCCF
        CheckMD5   : BC5BEA2C0BC9DF6891B93823A22A2F91
        FixMD5     : 96C449FEFBFB810D6426AB6C3035CA11
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

Function Get-V218737 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218737
        STIG ID    : IIST-SI-000203
        Rule ID    : SV-218737r903109_rule
        CCI ID     : CCI-000068
        Rule Name  : SRG-APP-000014-WSR-000006
        Rule Title : A private IIS 10.0 website must only accept Secure Socket Layer (SSL) connections.
        DiscussMD5 : AB956EF9C261E12C7144487ECCA022E4
        CheckMD5   : C01ADD97453E234329B93CCE6EFED503
        FixMD5     : 937BE8BC0B99CC320FD8E38BC46CCB5C
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

Function Get-V218738 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218738
        STIG ID    : IIST-SI-000204
        Rule ID    : SV-218738r903111_rule
        CCI ID     : CCI-000068
        Rule Name  : SRG-APP-000014-WSR-000006
        Rule Title : A public IIS 10.0 website must only accept Secure Socket Layer (SSL) connections when authentication is required.
        DiscussMD5 : AB956EF9C261E12C7144487ECCA022E4
        CheckMD5   : BCC15A3C7CE521356E49A7E764090AC8
        FixMD5     : 5585A1F04DF8626629E869684618332D
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

Function Get-V218739 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218739
        STIG ID    : IIST-SI-000206
        Rule ID    : SV-218739r879562_rule
        CCI ID     : CCI-000139, CCI-001464
        Rule Name  : SRG-APP-000092-WSR-000055
        Rule Title : Both the log file and Event Tracing for Windows (ETW) for each IIS 10.0 website must be enabled.
        DiscussMD5 : DA633713224A0F4EC5CE9E20A8C2A373
        CheckMD5   : 3641A78EC90994C15B4A967C7661BDFB
        FixMD5     : A458689BBB16B3723E8FC0EA5B02FFA5
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

Function Get-V218741 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218741
        STIG ID    : IIST-SI-000209
        Rule ID    : SV-218741r879567_rule
        CCI ID     : CCI-000134
        Rule Name  : SRG-APP-000099-WSR-000061
        Rule Title : The IIS 10.0 website must produce log records that contain sufficient information to establish the outcome (success or failure) of IIS 10.0 website events.
        DiscussMD5 : F6FB05D8D47A1330B0AC1AC6D7F130CB
        CheckMD5   : B7812384D9274D153B189DB83AD6F9C4
        FixMD5     : 7B81715B746A5877C41EC9741847B0DA
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

Function Get-V218742 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218742
        STIG ID    : IIST-SI-000210
        Rule ID    : SV-218742r879568_rule
        CCI ID     : CCI-001487
        Rule Name  : SRG-APP-000100-WSR-000064
        Rule Title : The IIS 10.0 website must produce log records containing sufficient information to establish the identity of any user/subject or process associated with an event.
        DiscussMD5 : EDA80E0B5A3CEB39B0D0A4342C615A1D
        CheckMD5   : 18FBEF93AB287772A58EBFEF7377D0D9
        FixMD5     : E5FAA3E2A5B5EB76A2339B90E68328B9
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

Function Get-V218743 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218743
        STIG ID    : IIST-SI-000214
        Rule ID    : SV-218743r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000081
        Rule Title : The IIS 10.0 website must have Multipurpose Internet Mail Extensions (MIME) that invoke OS shell programs disabled.
        DiscussMD5 : 8A8FED5376557EDF7AEBED6981A6C5F0
        CheckMD5   : 58C58FAFE2BA5FA4E343019F6346ABCE
        FixMD5     : 2119EF09894990369ECEC6DDBB24DF35
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
    $ExtensionFindings = ""
    $ExtensionsToCheck = @(".exe", ".dll", ".com", ".bat", ".csh")
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $Configuration = (Get-WebConfiguration '/system.webServer/staticContent' -PsPath "IIS:\Sites\$SiteName").Collection
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; (Get-WebConfiguration '/system.webServer/staticContent' -PsPath 'IIS:\Sites\$SiteName').Collection}"
        $Configuration = Invoke-Expression $PSCommand
    }
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

Function Get-V218744 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218744
        STIG ID    : IIST-SI-000215
        Rule ID    : SV-218744r903113_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000082
        Rule Title : Mappings to unused and vulnerable scripts on the IIS 10.0 website must be removed.
        DiscussMD5 : E7565BAD72E71FE7E1F5610BE90AC4C5
        CheckMD5   : DFCB0722D9F953593ABA5E8D9EE4EECF
        FixMD5     : DCE4C8EDE460A1681F706DE555355F1D
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
            $AccessPolicy = Get-WebConfigurationProperty -PSPath "IIS:\Sites\$SiteName" -Filter '/system.webServer/handlers' -Name accessPolicy
            $ConfigHandlers = Get-WebHandler -PSPath "IIS:\Sites\$SiteName"
        }
        Else {
            $PSCommand1 = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty -PSPath 'IIS:\Sites\$SiteName' -Filter '/system.webServer/handlers' -Name accessPolicy}"
            $PSCommand2 = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebHandler -PSPath 'IIS:\Sites\$SiteName'}"
            $AccessPolicy = Invoke-Expression $PSCommand1
            $ConfigHandlers = Invoke-Expression $PSCommand2
        }

        $Handlers = New-Object System.Collections.Generic.List[System.Object]
        ForEach ($Item in $ConfigHandlers) {
            If (($Item.requireAccess -eq "None") -or ($Item.requireAccess -in ($AccessPolicy -split ","))) {
                $State = "Enabled"
            }
            Else {
                $State = "Disabled"
            }
            Switch ($Item.resourceType) {
                "Either" {
                    $PathType = "File or Folder"
                }
                DEFAULT {
                    $PathType = $Item.resourceType
                }
            }
            $NewObj = [PSCustomObject]@{
                Name          = $Item.name
                Path          = $Item.path
                State         = $State
                PathType      = $PathType
                Handler       = $Item.modules
                RequireAccess = $Item.requireAccess
            }
            $Handlers.Add($NewObj)
        }

        $FindingDetails += "Access Policy: $($AccessPolicy)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Enabled Handler Mappings:" | Out-String
        $FindingDetails += "-----------------------------------" | Out-String
        If (($Handlers | Where-Object State -EQ "Enabled" | Measure-Object).Count -eq 0) {
            $FindingDetails += "None" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            ForEach ($Item in ($Handlers | Where-Object State -EQ "Enabled")) {
                $FindingDetails += "Name:`t`t$($Item.Name)" | Out-String
                $FindingDetails += "Path:`t`t`t$($Item.Path)" | Out-String
                $FindingDetails += "State:`t`t$($Item.State)" | Out-String
                $FindingDetails += "PathType:`t`t$($Item.PathType)" | Out-String
                $FindingDetails += "Handler:`t`t$($Item.Handler)" | Out-String
                $FindingDetails += "ReqAccess:`t$($Item.RequireAccess)" | Out-String
                $FindingDetails += "" | Out-String
            }
        }
        $FindingDetails += "Disabled Handler Mappings:" | Out-String
        $FindingDetails += "-----------------------------------" | Out-String
        If (($Handlers | Where-Object State -EQ "Disabled" | Measure-Object).Count -eq 0) {
            $FindingDetails += "None" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            ForEach ($Item in ($Handlers | Where-Object State -EQ "Disabled")) {
                $FindingDetails += "Name:`t`t$($Item.Name)" | Out-String
                $FindingDetails += "Path:`t`t`t$($Item.Path)" | Out-String
                $FindingDetails += "State:`t`t$($Item.State)" | Out-String
                $FindingDetails += "PathType:`t`t$($Item.PathType)" | Out-String
                $FindingDetails += "Handler:`t`t$($Item.Handler)" | Out-String
                $FindingDetails += "ReqAccess:`t$($Item.RequireAccess)" | Out-String
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

Function Get-V218745 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218745
        STIG ID    : IIST-SI-000216
        Rule ID    : SV-218745r903115_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000083
        Rule Title : The IIS 10.0 website must have resource mappings set to disable the serving of certain file types.
        DiscussMD5 : D1E10C845049BC0A79C9F7A981C1E53E
        CheckMD5   : FBCC5058EEE8A7E98B71C065ED7EFB13
        FixMD5     : 0322F43341B1DE9DB4436410B63BD71B
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

Function Get-V218746 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218746
        STIG ID    : IIST-SI-000217
        Rule ID    : SV-218746r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000085
        Rule Title : The IIS 10.0 website must have Web Distributed Authoring and Versioning (WebDAV) disabled.
        DiscussMD5 : 8DCF2ACD10B20FC83EDDB4D1B162673A
        CheckMD5   : 8710AA6904A10EBEE854C60C4A672476
        FixMD5     : AA2B21E94199F7E6AF199DA1D1311700
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
    Switch -Wildcard (((Get-CimInstance Win32_OperatingSystem).Caption)) {
        "*Windows*Server*" {
            If ((Get-WindowsFeature -Name "Web-DAV-Publishing").Installed -eq $true) {
                $Status = "Open"
                $FindingDetails += "Web-DAV-Publishing is installed."
            }
        }
        "*Windows*10*" {
            Try {
                If ((Get-WindowsOptionalFeature -Online -FeatureName "IIS-WebDAV" -ErrorAction Stop).State -eq "Enabled") {
                    $Status = "Open"
                    $FindingDetails += "IIS-WebDAV is enabled."
                }
            }
            Catch {
                If ((Get-CimInstance -ClassName Win32_OptionalFeature | Where-Object Name -EQ "IIS-WebDAV").InstallState -eq 1) {
                    $Status = "Open"
                    $FindingDetails += "IIS-WebDAV is enabled."
                }
            }
        }
    }

    If ($Status -ne "Open") {
        $Status = "NotAFinding"
        $FindingDetails += "WebDAV is not installed."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V218748 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218748
        STIG ID    : IIST-SI-000219
        Rule ID    : SV-218748r879588_rule
        CCI ID     : CCI-000382
        Rule Name  : SRG-APP-000142-WSR-000089
        Rule Title : Each IIS 10.0 website must be assigned a default host header.
        DiscussMD5 : E9C9524A4E0D5B719E837C9BD3529168
        CheckMD5   : 5723B66DC9D0A9017E842C78A1C2E67F
        FixMD5     : CFAEFAAC796A60065580FF54A46A8DE6
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
            $WebSite = Get-WebSite -Name "$SiteName" | Select-Object *
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebSite -Name '$SiteName' | Select-Object *}"
            $WebSite = Invoke-Expression $PSCommand
        }
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

Function Get-V218749 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218749
        STIG ID    : IIST-SI-000220
        Rule ID    : SV-218749r903117_rule
        CCI ID     : CCI-000197, CCI-001188, CCI-002470
        Rule Name  : SRG-APP-000172-WSR-000104
        Rule Title : A private IIS 10.0 website authentication mechanism must use client certificates to transmit session identifier to assure integrity.
        DiscussMD5 : E274AF40E42E394623340C58A66A9DF1
        CheckMD5   : 4E9F7B06B6D7804F7CBC93C50EB28084
        FixMD5     : 78E15ECA19B9FBFB37FBD99678401F3F
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

Function Get-V218750 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218750
        STIG ID    : IIST-SI-000221
        Rule ID    : SV-218750r928848_rule
        CCI ID     : CCI-001082
        Rule Name  : SRG-APP-000211-WSR-000031
        Rule Title : Anonymous IIS 10.0 website access accounts must be restricted.
        DiscussMD5 : A37F8B01EBF7825C3F09B703D1E4DE0A
        CheckMD5   : 9F4D1C4E939B17FFAC07C597D0B8E971
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
    $Server = ($env:COMPUTERNAME)
    $Computer = [ADSI]"WinNT://$Server,computer"
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $AnonymousAuth = Get-WebConfigurationProperty "/system.webServer/security/authentication/anonymousAuthentication" -PsPath "IIS:\Sites\$SiteName" -Name *
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/security/authentication/anonymousAuthentication' -PsPath 'IIS:\Sites\$SiteName' -Name *}"
        $AnonymousAuth = Invoke-Expression $PSCommand
    }
    $GroupsToCheck = ("/Administrators", "/Backup Operators", "/Certificate Service", "/Distributed COM Users", "/Event Log Readers", "/Network Configuration Operators", "/Performance Log Users", "/Performance Monitor Users", "/Power Users", "/Print Operators", "/Remote Desktop Users", "/Replicator", "/Users")

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
                Try {
                    $GroupInfo = $Computer.psbase.children | Where-Object { $_.psbase.schemaClassname -eq 'group' } | Where-Object { $_.Path -like "*$Group*" }
                    $Members = $GroupInfo.psbase.Invoke("Members") | ForEach-Object { $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null) }
                    $Members | ForEach-Object {
                        If ($_ -eq $AnonymousAuth.userName) {
                            $PrivilegedMembership += $GroupInfo.Name | Out-String
                        }
                    }
                }
                Catch {
                    # Do Nothing
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

Function Get-V218751 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218751
        STIG ID    : IIST-SI-000223
        Rule ID    : SV-218751r879639_rule
        CCI ID     : CCI-001188
        Rule Name  : SRG-APP-000224-WSR-000136
        Rule Title : The IIS 10.0 website must generate unique session identifiers that cannot be reliably reproduced.
        DiscussMD5 : 2698FD87695BF5A47AB54F2926C18822
        CheckMD5   : 6FEE29C60874001C35496A7056B86311
        FixMD5     : C29D54B7420AE6FB8D01FE27BF3FFB1F
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

Function Get-V218752 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218752
        STIG ID    : IIST-SI-000224
        Rule ID    : SV-218752r928849_rule
        CCI ID     : CCI-001084
        Rule Name  : SRG-APP-000233-WSR-000146
        Rule Title : The IIS 10.0 website document directory must be in a separate partition from the IIS 10.0 websites system files.
        DiscussMD5 : F179270B5E1E1F687E62A6631724ABBD
        CheckMD5   : 30DD8FDC496220DE4EE6EFFB791423A7
        FixMD5     : F65D1730DBD270C0383A3C024D939F56
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
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V218753 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218753
        STIG ID    : IIST-SI-000225
        Rule ID    : SV-218753r879650_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246-WSR-000149
        Rule Title : The IIS 10.0 website must be configured to limit the maxURL.
        DiscussMD5 : 9E8371DE45CA8DB4EFC176731916D3E2
        CheckMD5   : 00CD5ED0EA7873542433789010F4CE9D
        FixMD5     : 903F8E87883DEB5F32DC51FAB124C91E
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

Function Get-V218754 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218754
        STIG ID    : IIST-SI-000226
        Rule ID    : SV-218754r879650_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246-WSR-000149
        Rule Title : The IIS 10.0 website must be configured to limit the size of web requests.
        DiscussMD5 : 64D38AF43426ADD6D9E6344353143E1B
        CheckMD5   : EB585001152025B246B14CB6B84BA372
        FixMD5     : 35F33E51589A96A3ADAF5E9B5E76B6F4
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

Function Get-V218755 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218755
        STIG ID    : IIST-SI-000227
        Rule ID    : SV-218755r879650_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246-WSR-000149
        Rule Title : The IIS 10.0 websites Maximum Query String limit must be configured.
        DiscussMD5 : 6B15FE81398B334E1CBC9D2306A28F98
        CheckMD5   : 2194EF0D7B5A9AE22423D745B886D908
        FixMD5     : AF2823F2D3254D52706E98FAC1DA9857
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

Function Get-V218756 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218756
        STIG ID    : IIST-SI-000228
        Rule ID    : SV-218756r879650_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246-WSR-000149
        Rule Title : Non-ASCII characters in URLs must be prohibited by any IIS 10.0 website.
        DiscussMD5 : 447E0E82F59C7A2E645DCC5AE88C4173
        CheckMD5   : 96EE7AE92A562ED29EFD145F9B51F754
        FixMD5     : 83013A07B6AA61205317BCA223A0EC6A
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
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V218757 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218757
        STIG ID    : IIST-SI-000229
        Rule ID    : SV-218757r903119_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246-WSR-000149
        Rule Title : Double encoded URL requests must be prohibited by any IIS 10.0 website.
        DiscussMD5 : 35E0F02F8A5ACE38B30B8753BE827B0E
        CheckMD5   : E92F3EC55B3EE709B51946116DECE83C
        FixMD5     : A81AD18DF3F10BEC78D66BF2CAA35C96
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

Function Get-V218758 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218758
        STIG ID    : IIST-SI-000230
        Rule ID    : SV-218758r903121_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246-WSR-000149
        Rule Title : Unlisted file extensions in URL requests must be filtered by any IIS 10.0 website.
        DiscussMD5 : 01893C6162323B259170B22BDDBB794A
        CheckMD5   : 4BE92774953075D8ECC38BCC515D6A8B
        FixMD5     : 071B2A1F17A4378E4D58453B65B3BAF2
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

Function Get-V218759 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218759
        STIG ID    : IIST-SI-000231
        Rule ID    : SV-218759r879652_rule
        CCI ID     : CCI-001310
        Rule Name  : SRG-APP-000251-WSR-000157
        Rule Title : Directory Browsing on the IIS 10.0 website must be disabled.
        DiscussMD5 : 2A45AF472A723004D72E896EA986918E
        CheckMD5   : 609225B24935C8DAB707185B820A7750
        FixMD5     : 95DBD02F21BF33E99CB8E58A9C0986E9
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
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V218760 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218760
        STIG ID    : IIST-SI-000233
        Rule ID    : SV-218760r879655_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266-WSR-000159
        Rule Title : Warning and error messages displayed to clients must be modified to minimize the identity of the IIS 10.0 website, patches, loaded modules, and directory paths.
        DiscussMD5 : 9A79AA3CE4FFA04A7672C0126E751178
        CheckMD5   : 20D718D40375BB0927DC5DEADE346A6C
        FixMD5     : 80DFC12EA4A13234EE454363239B669F
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
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfiguration system.webServer/httpErrors | Select-Object *}"
        $HttpErrors = Invoke-Expression $PSCommand
    }

    If ($HttpErrors.errorMode -eq "DetailedLocalOnly") {
        $Status = "NotAFinding"
        $FindingDetails += "Error Responses is configured to 'Detailed errors for local requests and custom error pages for remote requests'" | Out-String
    }
    ElseIf ($HttpErrors.errorMode -eq "Custom") {
        $Status = "NotAFinding"
        $FindingDetails += "Error Responses is configured to 'Custom error pages'" | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "Error Responses is NOT configured to 'Detailed errors for local requests and custom error pages for remote requests' or 'Custom error pages'" | Out-String
    }
    $FindingDetails += "" | Out-String
    $FindingDetails += "errorMode:`t$($HttpErrors.errorMode)" | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V218761 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218761
        STIG ID    : IIST-SI-000234
        Rule ID    : SV-218761r903123_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266-WSR-000160
        Rule Title : Debugging and trace information used to diagnose the IIS 10.0 website must be disabled.
        DiscussMD5 : CBF7B6F5E89A9CDAB75ADB6B81C49B75
        CheckMD5   : A43D82F70E443DA7A55BA87DFDF16494
        FixMD5     : A4438A2AEC24B6F45ADCC993622BB623
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

Function Get-V218762 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218762
        STIG ID    : IIST-SI-000235
        Rule ID    : SV-218762r879673_rule
        CCI ID     : CCI-002361
        Rule Name  : SRG-APP-000295-WSR-000012
        Rule Title : The Idle Time-out monitor for each IIS 10.0 website must be enabled.
        DiscussMD5 : 9E963E502C01CDAF1301F1ADA842AE55
        CheckMD5   : A477EE500BCB6A1A794CB39985B4A1EF
        FixMD5     : EF05B39B7911D79A298FB5DD5FDBC137
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
                ElseIf ($IdleTimeout.TotalMinutes -gt 0) {
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

Function Get-V218763 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218763
        STIG ID    : IIST-SI-000236
        Rule ID    : SV-218763r879673_rule
        CCI ID     : CCI-002361
        Rule Name  : SRG-APP-000295-WSR-000134
        Rule Title : The IIS 10.0 websites connectionTimeout setting must be explicitly configured to disconnect an idle session.
        DiscussMD5 : 1EE513CC1D31387CDF0BB25CDCC37DF1
        CheckMD5   : E9ED9B3E1893E074C8F834DAA26A4C95
        FixMD5     : 63852112EB0414D79DA76D0AE59E7C6E
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
    $Span = New-TimeSpan -Hours 00 -Minutes 15 -Seconds 00

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

Function Get-V218764 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218764
        STIG ID    : IIST-SI-000237
        Rule ID    : SV-218764r879693_rule
        CCI ID     : CCI-002322
        Rule Name  : SRG-APP-000316-WSR-000170
        Rule Title : The IIS 10.0 website must provide the capability to immediately disconnect or disable remote access to the hosted applications.
        DiscussMD5 : 1F4D022C71BE8033FC1D287DC1865DAF
        CheckMD5   : A60EA7C6D71ADBD87EE5718CF0A929E9
        FixMD5     : 65E0EE9EA6C83AB56CC4A173F952D3AB
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

Function Get-V218765 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218765
        STIG ID    : IIST-SI-000238
        Rule ID    : SV-218765r879730_rule
        CCI ID     : CCI-001849
        Rule Name  : SRG-APP-000357-WSR-000150
        Rule Title : The IIS 10.0 website must use a logging mechanism configured to allocate log record storage capacity large enough to accommodate the logging requirements of the IIS 10.0 website.
        DiscussMD5 : C0CC578BF451A674EE2A268EDB2EBCFB
        CheckMD5   : 98214ED42544EC3F1548BA38958C1171
        FixMD5     : 02B4F800F662E5BDC1F6B97BDD9EB010
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

Function Get-V218766 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218766
        STIG ID    : IIST-SI-000239
        Rule ID    : SV-218766r879756_rule
        CCI ID     : CCI-001762
        Rule Name  : SRG-APP-000383-WSR-000175
        Rule Title : The IIS 10.0 websites must use ports, protocols, and services according to Ports, Protocols, and Services Management (PPSM) guidelines.
        DiscussMD5 : E52DB55DE5D43F39142FBCB03CAF8FBF
        CheckMD5   : 2603C4A446DE13E04329264F2BD6A1FA
        FixMD5     : D32D7D92628F72FAEF3D5B2E99564FA9
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

Function Get-V218767 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218767
        STIG ID    : IIST-SI-000241
        Rule ID    : SV-218767r879798_rule
        CCI ID     : CCI-002470
        Rule Name  : SRG-APP-000427-WSR-000186
        Rule Title : The IIS 10.0 website must only accept client certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs).
        DiscussMD5 : FE990A09BA9D124F6E37B66DD84BE4D2
        CheckMD5   : 64AB31EDCFD0A5AA5F2F565CDB6089B4
        FixMD5     : FBC0BD244AC021414EB5553E4A170C16
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

Function Get-V218768 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218768
        STIG ID    : IIST-SI-000242
        Rule ID    : SV-218768r879800_rule
        CCI ID     : CCI-002476
        Rule Name  : SRG-APP-000429-WSR-000113
        Rule Title : The IIS 10.0 private website must employ cryptographic mechanisms (TLS) and require client certificates.
        DiscussMD5 : CA400469361F3E2D54A4FB7586699F02
        CheckMD5   : 59D8360B89147101B3032E440E3C3CDD
        FixMD5     : C34B6A23B485DFFEE8EF495235DDB6C8
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
        $Compliant = $true
        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Import-Module WebAdministration
            $Access = Get-WebConfigurationProperty "/system.webServer/security/access" -PsPath "IIS:\Sites\$SiteName" -Name *
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/security/access' -PsPath 'IIS:\Sites\$SiteName' -Name *}"
            $Access = Invoke-Expression $PSCommand
        }
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

Function Get-V218769 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218769
        STIG ID    : IIST-SI-000244
        Rule ID    : SV-218769r879810_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000439-WSR-000152
        Rule Title : IIS 10.0 website session IDs must be sent to the client using TLS.
        DiscussMD5 : 000CD73AF14A0386716C66AE794D8F4C
        CheckMD5   : B3EF033C495F47093F774FD74220515F
        FixMD5     : C6FB287D7B40BC4D58697C9CD41E262D
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

Function Get-V218770 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218770
        STIG ID    : IIST-SI-000246
        Rule ID    : SV-218770r903126_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000439-WSR-000154
        Rule Title : Cookies exchanged between the IIS 10.0 website and the client must have cookie properties set to prohibit client-side scripts from reading the cookie data.
        DiscussMD5 : B100D929843B6E467354E3DFF639990D
        CheckMD5   : 5646528A4C94D7E80DA0A5B37E180CC9
        FixMD5     : B5A422277971B58276E77C621F6B520F
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

Function Get-V218771 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218771
        STIG ID    : IIST-SI-000251
        Rule ID    : SV-218771r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The IIS 10.0 website must have a unique application pool.
        DiscussMD5 : 5106D2ED477928763694548B850C877F
        CheckMD5   : D4A88CCC5516FBA7191FE77CD8511FD3
        FixMD5     : 52332CEC0A27072970F53C688A27D320
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

Function Get-V218772 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218772
        STIG ID    : IIST-SI-000252
        Rule ID    : SV-218772r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The maximum number of requests an application pool can process for each IIS 10.0 website must be explicitly set.
        DiscussMD5 : BC308B4474DA3E9E8DC3BC21EB332F69
        CheckMD5   : 20801EE94B89D8A1D79A9E74FC569EA0
        FixMD5     : 9CE43C4163D7736041E2041601D485AF
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
                $Compliant = $false
            }
        }

        If ($Compliant -eq $true) {
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

Function Get-V218775 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218775
        STIG ID    : IIST-SI-000255
        Rule ID    : SV-218775r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The application pool for each IIS 10.0 website must have a recycle time explicitly set.
        DiscussMD5 : 85F41E23F947B3FFBF7BFE277197A2B1
        CheckMD5   : D9EEE9CBA8FA4AA6494E6DA66659D77E
        FixMD5     : 71B9490734F036C9913D36A6EB45CBEA
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
        $AppPoolRecycling = New-Object System.Collections.Generic.List[System.Object]
        ForEach ($AppPool in $AppPools) {
            $Conditions = New-Object System.Collections.Generic.List[System.Object]
            # Get 'memory', 'privateMemory', 'requests', and 'time'
            ForEach ($Attribute in $AppPool.recycling.periodicRestart.Attributes) {
                $NewObj = [PSCustomObject]@{
                    Name       = $Attribute.Name
                    Enabled    = $(If ($Attribute.Value -ne 0) {
                            $true
                        }
                        Else {
                            $false
                        })
                    LogEnabled = $(If ($Attribute.name -in @($AppPool.recycling.logEventOnRecycle -split ",")) {
                            $true
                        }
                        Else {
                            $false
                        })
                }
                $Conditions.Add($NewObj)
            }

            # Get 'schedule'
            $NewObj = [PSCustomObject]@{
                Name       = "schedule"
                Enabled    = $(If ($AppPool.recycling.periodicRestart.schedule.Collection) {
                        $true
                    }
                    Else {
                        $false
                    })
                LogEnabled = $(If ("Schedule" -in @($AppPool.recycling.logEventOnRecycle -split ",")) {
                        $true
                    }
                    Else {
                        $false
                    })
            }
            $Conditions.Add($NewObj)

            # Build AppPoolRecycling list
            $NewObj = [PSCustomObject]@{
                AppPoolName = $AppPool.name
                Conditions  = $Conditions
            }
            $AppPoolRecycling.Add($NewObj)
        }

        # Evaluate application pool recycling
        $Compliant = $true
        $CompliantAppPools = New-Object System.Collections.Generic.List[System.Object]
        $BadAppPools = New-Object System.Collections.Generic.List[System.Object]
        ForEach ($AppPool in $AppPoolRecycling) {
            If (-Not($AppPool.Conditions | Where-Object Enabled -EQ $true)) {
                $NewObj = [PSCustomObject]@{
                    AppPoolName = $AppPool.AppPoolName
                    Reason      = "No Recycling Conditions are enabled."
                }
                $BadAppPools.Add($NewObj)
            }
            Else {
                If ($AppPool.Conditions | Where-Object {($_.Enabled -eq $true -and $_.LogEnabled -ne $true)}) {
                    $NewObj = [PSCustomObject]@{
                        AppPoolName = $AppPool.AppPoolName
                        Reason      = "Logging not enabled for selected Recycling Conditions."
                        Conditions  = $($AppPool.Conditions | Where-Object {($_.Enabled -eq $true -and $_.LogEnabled -ne $true)})
                    }
                    $BadAppPools.Add($NewObj)
                }
                Else {
                    $NewObj = [PSCustomObject]@{
                        AppPoolName = $AppPool.AppPoolName
                        Conditions  = $($AppPool.Conditions | Where-Object {($_.Enabled -eq $true -and $_.LogEnabled -eq $true)})
                    }
                    $CompliantAppPools.Add($NewObj)
                }
            }
        }

        If ($BadAppPools) {
            $Compliant = $false
            $FindingDetails += "Non-Compliant AppPools:" | Out-String
            $FindingDetails += "-----------------------------------" | Out-String
            ForEach ($AppPool in $BadAppPools) {
                $FindingDetails += "AppPool:`t$($AppPool.AppPoolName)" | Out-String
                $FindingDetails += "Reason:`t$($AppPool.Reason)" | Out-String
                ForEach ($Condition in $AppPool.Conditions) {
                    $FindingDetails += "Condition:`t$($Condition.Name) [Enabled=$($Condition.Enabled); LogEnabled=$($Condition.LogEnabled)]" | Out-String
                }
                $FindingDetails += "" | Out-String
            }
            $FindingDetails += "" | Out-String
        }

        If ($CompliantAppPools) {
            $FindingDetails += "Compliant AppPools:" | Out-String
            $FindingDetails += "-----------------------------------" | Out-String
            ForEach ($AppPool in $CompliantAppPools) {
                $FindingDetails += "AppPool:`t$($AppPool.AppPoolName)" | Out-String
                ForEach ($Condition in $AppPool.Conditions) {
                    $FindingDetails += "Condition:`t$($Condition.Name) [Enabled=$($Condition.Enabled); LogEnabled=$($Condition.LogEnabled)]" | Out-String
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

Function Get-V218777 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218777
        STIG ID    : IIST-SI-000258
        Rule ID    : SV-218777r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The application pools rapid fail protection for each IIS 10.0 website must be enabled.
        DiscussMD5 : FD664C89A13E2B030E2BFB132FA3CDD1
        CheckMD5   : 826D768371BB96F4142D8A5F30873CC8
        FixMD5     : B782F14ABF48B2E7B7D84D90A5E942AA
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

Function Get-V218778 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218778
        STIG ID    : IIST-SI-000259
        Rule ID    : SV-218778r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The application pools rapid fail protection settings for each IIS 10.0 website must be managed.
        DiscussMD5 : 7FEAC86403939EC9526508634BC69459
        CheckMD5   : 72C9529F65E28D8FC7EA6E23ACA4C3AB
        FixMD5     : FDA669BD6DBC46CD0C785707F09B2695
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
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V218779 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218779
        STIG ID    : IIST-SI-000261
        Rule ID    : SV-218779r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000087
        Rule Title : Interactive scripts on the IIS 10.0 web server must be located in unique and designated folders.
        DiscussMD5 : 0572B5B1F6FA193BA557D59469552114
        CheckMD5   : B0D92AE8DE69468E52435C2F41CA3F53
        FixMD5     : 09A7C09CA7713C590AE849BB588E8751
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
        $VirtualDirectories = Get-WebVirtualDirectory -site "$($WebSite.name)"
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
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebVirtualDirectory -site '" + $WebSite.name + "'}"
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

Function Get-V218780 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218780
        STIG ID    : IIST-SI-000262
        Rule ID    : SV-218780r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000087
        Rule Title : Interactive scripts on the IIS 10.0 web server must have restrictive access controls.
        DiscussMD5 : 6007F8A21ABC8D716FFC4FBE87251AE3
        CheckMD5   : 99697C6341E4650278436928D54299B5
        FixMD5     : 9C30E9911BDED4DB74CF7C21238112C0
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

    If (((Get-CimInstance Win32_OperatingSystem).Caption -like "*Windows*Server*" -and (Get-WindowsFeature -Name "Web-CGI").Installed -eq $true) -or ((Get-CimInstance Win32_OperatingSystem).Caption -like "*Windows*10*" -and (Get-CimInstance -ClassName Win32_OptionalFeature | Where-Object Name -EQ "IIS-CGI").InstallState -eq 1)) {
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
            $VirtualDirectories = Get-WebVirtualDirectory -site "$($WebSite.name)"
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
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebVirtualDirectory -site '" + $WebSite.name + "'}"
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

Function Get-V218781 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218781
        STIG ID    : IIST-SI-000263
        Rule ID    : SV-218781r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000087
        Rule Title : Backup interactive scripts on the IIS 10.0 server must be removed.
        DiscussMD5 : 16FE195BE4C481B86B358480769EC41A
        CheckMD5   : 8E91709A983CBA761835AE25DB26CF7E
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

    If (((Get-CimInstance Win32_OperatingSystem).Caption -like "*Windows*Server*" -and (Get-WindowsFeature -Name "Web-CGI").Installed -eq $true) -or ((Get-CimInstance Win32_OperatingSystem).Caption -like "*Windows*10*" -and (Get-CimInstance -ClassName Win32_OptionalFeature | Where-Object Name -EQ "IIS-CGI").InstallState -eq 1)) {
        $WebDirectories += $WebSite.physicalPath -replace "%SystemDrive%", $env:SystemDrive
        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            $Applications = Get-WebApplication -site "$($WebSite.name)"
            $Applications | ForEach-Object {
                $WebDirectories += $_.physicalPath -replace "%SystemDrive%", $env:SystemDrive
            }
            $VirtualDirectories = Get-WebVirtualDirectory -site "$($WebSite.name)"
            $VirtualDirectories | ForEach-Object {
                $WebDirectories += $_.physicalPath -replace "%SystemDrive%", $env:SystemDrive
            }
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebApplication -site '" + $WebSite.name + "'}"
            $Applications = Invoke-Expression $PSCommand
            $Applications | ForEach-Object {
                $WebDirectories += $_.physicalPath -replace "%SystemDrive%", $env:SystemDrive
            }
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebVirtualDirectory -site '" + $WebSite.name + "'}"
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

# SIG # Begin signature block
# MIIL+QYJKoZIhvcNAQcCoIIL6jCCC+YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBW9yGt9Ba6lpyM
# yyyaUmYNAMSRnqNezdHFwXJxkzeZmaCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBK1sfcPfuPFln03t1nvaNVISCT5f8V
# R+UqhaOCnl1zYjANBgkqhkiG9w0BAQEFAASCAQDCdLqZBlDI7mwbphxx1pHQ01g8
# bhvVgZQJBCPilEkn78O363ZOFhw1Gz+OchGQ2jsgW3h1NCDsbLQOqUnInKRHSkWi
# pGLv52tQIihIw9qcpZkejLKLzBfhVvfaPCoY40I+MkgfBFnWNQJesaBP1PT0Nbte
# V4XImHWVK7g77cXuLbaXmy7Xq3yG8XpYAso+AJWL9EKpqsHcgQNPQwG+JbMFZfhb
# 0oINYSF397uFFhR6T4WDIftKZZcKOlu/nzpyzOKYyxMs+vzFmD9LO6cLfCUaqNTh
# fOid4sPeYU0v1Vdrb69DHCcGc+NrAgd9RcmFki26ud3GBfPu4RautwpYAiZr
# SIG # End signature block
