##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Cisco IOS XE Router NDM
# Version:  V2R9
# Class:    UNCLASSIFIED
# Updated:  5/13/2024
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V215807 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215807
        STIG ID    : CISC-ND-000010
        Rule ID    : SV-215807r879511_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-NDM-000200
        Rule Title : The Cisco router must be configured to limit the number of concurrent management sessions to an organization-defined number.
        DiscussMD5 : F19B0AA112F328426C40CFAB1E86CA11
        CheckMD5   : 5CDDAA36C4D9F1CA41CB6981B258D277
        FixMD5     : 9CF00F68C4F33B5D5D83473D810B5F4F
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
    $HttpServer = $ShowRunningConfig | Select-String -Pattern "^no ip http"
    $LineVtys = $ShowRunningConfig | Select-String -Pattern "line vty"
    IF ($HttpServer -like "no ip http server" -AND $HttpServer -like "no ip http secure-server") {
        $FindingDetails += "IP Http Server Settings:" | Out-String
        $FindingDetails += "http\https servers are disabled, https requirements are not applicable" | Out-String
        $FindingDetails += ($HttpServer | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $HttpMaxConnections = $ShowRunningConfig | Select-String -Pattern "ip http max-connections"
        IF ($HttpMaxConnections) {
            $FindingDetails += "IP http Server Settings:" | Out-String
            $FindingDetails += ($HttpMaxConnections | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += "" | Out-String
            IF (!((($HttpMaxConnections | Out-String).Trim()).Split([char[]]"")[3] -le "2")) {
                $OpenFinding = $True
            }
        }
        Else {
            $IPHttpServerConf = $ShowRunningConfig | Select-String -Pattern "^ip http"
            IF ($IPHttpServerConf -like "ip http server" -or $IPHttpServerConf -like "ip http secure-server") {
                $OpenFinding = $True
                $FindingDetails += "IP Http Server Settings:" | Out-String
                $FindingDetails += "The router is not configured to limit the number of concurrent management sessions (https)" | Out-String
                $FindingDetails += ($IPHttpServerConf | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $FindingDetails += "" | Out-String
            }
            Else {
                $FindingDetails += "Https server is not enabled, https requirements is not applicable" | Out-String
                $FindingDetails += ($IPHttpServerConf | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $FindingDetails += "" | Out-String
            }
        }
    }

    IF (!($LineVtys[0] | Select-String -Pattern "0\s1")) {
        $SessionLimit = Get-Section $ShowRunningConfig $LineVtys[0].ToString() | Select-String -Pattern "session-limit"
        IF ($SessionLimit) {
            IF (!(($SessionLimit | Out-String).Trim().Split([char[]]"")[1] -le 2)) {
                $OpenFinding = $True
            }
        }
        Else {
            $OpenFinding = $True
        }
    }
    IF (!(Get-Section $ShowRunningConfig $LineVtys[0] | Select-String -Pattern "transport input ssh")) {
        $OpenFinding = $True
    }

    if ($LineVtys[1]) {
        IF (!($LineVtys[1] | Select-String -Pattern "2\s4")) {
            $OpenFinding = $True
        }
    }

    $LineVtys | Select-Object -Skip 1 | ForEach-Object {
        IF (!(Get-Section $ShowRunningConfig $_ | Select-String -Pattern "transport input none")) {
            $OpenFinding = $True
        }
    }

    ForEach ($vty in $LineVtys) {
        $FindingDetails += ($vty | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += " " + (Get-Section $ShowRunningConfig $vty.ToString() | Select-String -Pattern "transport input" | Out-String).Trim()
        IF (Get-Section $ShowRunningConfig $Vty.ToString() | Select-String -Pattern "session-limit") {
            $FindingDetails += " " + (Get-Section $ShowRunningConfig $Vty.ToString() | Select-String -Pattern "session-limit" | Out-String).Trim()
        }
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

Function Get-V215808 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215808
        STIG ID    : CISC-ND-000090
        Rule ID    : SV-215808r879525_rule
        CCI ID     : CCI-000018
        Rule Name  : SRG-APP-000026-NDM-000208
        Rule Title : The Cisco router must be configured to automatically audit account creation.
        DiscussMD5 : 5BD5A3EBA7A250544DCD9F1F2F52573C
        CheckMD5   : E5A157B58B4289FE666AC39A19EAF8C1
        FixMD5     : 16681BC83DAADBA1FF8174A329566CD1
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
    $ArchiveSettings = Get-Section $ShowRunningConfig 'Archive'
    If (!$ArchiveSettings) {
        $FindingDetails += "Archive Settings not set" | Out-String
        $Status = "Open"
    }
    Else {
        [STRING]$LogEnable = $ArchiveSettings | Select-String -Pattern "logging enable"
        IF (!$LogEnable) {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "'logging enable' not set" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
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

Function Get-V215809 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215809
        STIG ID    : CISC-ND-000100
        Rule ID    : SV-215809r879526_rule
        CCI ID     : CCI-001403
        Rule Name  : SRG-APP-000027-NDM-000209
        Rule Title : The Cisco router must be configured to automatically audit account modification.
        DiscussMD5 : FE4ADA94FF7F50F50F5543749CDD697D
        CheckMD5   : D1391FD3B37D682BB4A4551A91CB1FC9
        FixMD5     : 15FF253BC23AF34E318EA783129A84CA
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
    $ArchiveSettings = Get-Section $ShowRunningConfig 'Archive'
    If (!$ArchiveSettings) {
        $FindingDetails += "Archive Settings not set" | Out-String
        $Status = "Open"
    }
    Else {
        [STRING]$LogEnable = $ArchiveSettings | Select-String -Pattern "logging enable"
        IF (!$LogEnable) {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "'logging enable' not set" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
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

Function Get-V215810 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215810
        STIG ID    : CISC-ND-000110
        Rule ID    : SV-215810r879527_rule
        CCI ID     : CCI-001404
        Rule Name  : SRG-APP-000028-NDM-000210
        Rule Title : The Cisco router must be configured to automatically audit account disabling actions.
        DiscussMD5 : 64F37D91E5CA5F3B115451673F8DCFD8
        CheckMD5   : 1F6CDE9ECDF734B9F221157684CD0A35
        FixMD5     : 6633439FCA1BA8706389AF05BEF4825E
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
    $ArchiveSettings = Get-Section $ShowRunningConfig 'Archive'
    If (!$ArchiveSettings) {
        $FindingDetails += "Archive Settings not set" | Out-String
        $Status = "Open"
    }
    Else {
        [STRING]$LogEnable = $ArchiveSettings | Select-String -Pattern "logging enable"
        IF (!$LogEnable) {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "'logging enable' not set" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
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

Function Get-V215811 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215811
        STIG ID    : CISC-ND-000120
        Rule ID    : SV-215811r879528_rule
        CCI ID     : CCI-001405
        Rule Name  : SRG-APP-000029-NDM-000211
        Rule Title : The Cisco router must be configured to automatically audit account removal actions.
        DiscussMD5 : 75F19E046AC7A61605629AF0B990D588
        CheckMD5   : 92E6E4BDCBB2E97246FC1D4D491E9BC7
        FixMD5     : EB27682BEF141DBFE049B76CECB15EB4
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
    $ArchiveSettings = Get-Section $ShowRunningConfig 'Archive'
    If (!$ArchiveSettings) {
        $FindingDetails += "Archive Settings not set" | Out-String
        $Status = "Open"
    }
    Else {
        [STRING]$LogEnable = $ArchiveSettings | Select-String -Pattern "logging enable"
        IF (!$LogEnable) {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "'logging enable' not set" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
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

Function Get-V215812 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215812
        STIG ID    : CISC-ND-000140
        Rule ID    : SV-215812r879533_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-APP-000038-NDM-000213
        Rule Title : The Cisco router must be configured to enforce approved authorizations for controlling the flow of management information within the device based on control policies.
        DiscussMD5 : 61B3FF6909A1F8732EFBB220FB482128
        CheckMD5   : 084E864D1D6EF4F5DC14F68289338DB2
        FixMD5     : 1A219AA6E552288291F55BF978E085ED
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
    $LineVtys = $ShowRunningConfig | Select-String -Pattern "line vty"

    $AccessClass = Get-Section $ShowRunningConfig $LineVtys[0].ToString() | Select-String -Pattern "access-class .* in"
    IF (!$AccessClass) {
        $FindingDetails += ($LineVtys[0] | Out-String).Trim() + " - No inbound access-class set" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += (Get-Section $ShowRunningConfig $LineVtys[0] | Out-String).Trim()
        $FindingDetails += "" | Out-String
    }
    Else {
        $AccessGroup = (($AccessClass | Out-String).Trim()).Split([char[]]"")[1]
        $SectionName = $ShowRunningConfig | Select-String -Pattern "ip access-list .* $AccessGroup"
        $FindingDetails += ($LineVtys[0] | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += (Get-Section $ShowRunningConfig $LineVtys[0].ToString() | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += "" | Out-String
        IF ($SectionName) {
            $IPAccessList = (Get-Section $ShowRunningConfig $SectionName | Out-String).Trim()
            $FindingDetails += ($SectionName | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += ($IPAccessList | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
        Else {
            $FindingDetails += "An IP Access List for $AccessGroup is not configured" | Out-String
            $FindingDetails += "" | Out-String
        }
    }

    $FindingDetails += "" | Out-String
    $LineVtys | Select-Object -Skip 1 | ForEach-Object {
        IF (!(Get-Section $ShowRunningConfig $_ | Select-String -Pattern "transport input none")) {
            $AccessClass = Get-Section $ShowRunningConfig $_ | Select-String -Pattern "access-class .* in"
            IF (!$AccessClass) {
                $FindingDetails += ($_ | Out-String).Trim() + " - No inbound access-class set" | Out-String
                $FindingDetails += (Get-Section $ShowRunningConfig $_ | Out-String).Trim()
                $FindingDetails += "" | Out-String
            }
            Else {
                $AccessGroup = (($AccessClass | Out-String).Trim()).Split([char[]]"")[1]
                $SectionName = $ShowRunningConfig | Select-String -Pattern "ip access-list .* $AccessGroup"
                $IPAccessList = (Get-Section $ShowRunningConfig $SectionName | Out-String).Trim()
                $FindingDetails += ($_ | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $FindingDetails += (Get-Section $ShowRunningConfig $_ | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $FindingDetails += ($SectionName | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $FindingDetails += ($IPAccessList | Out-String).Trim()
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

Function Get-V215813 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215813
        STIG ID    : CISC-ND-000150
        Rule ID    : SV-215813r879546_rule
        CCI ID     : CCI-000044
        Rule Name  : SRG-APP-000065-NDM-000214
        Rule Title : The Cisco router must be configured to enforce the limit of three consecutive invalid logon attempts, after which time it must lock out the user account from accessing the device for 15 minutes.
        DiscussMD5 : 65E729AE1725994BC038987712EED5E5
        CheckMD5   : 6EEBD978DD250E8BE4364AAC29116E7E
        FixMD5     : C4ED878650277F33823CCFAD064BEEB2
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
    $LogonAttemptsConf = $ShowRunningConfig | Select-String -Pattern "login block-for"
    IF (!$LogonAttemptsConf) {
        $FindingDetails += "Logon attempts are not limited" | Out-String
        $OpenFinding = $True
    }
    Else {
        #[INT]$LoginAttempts = ($LogonAttemptsConf -Split '(\d+)').Trim()[3]
        [INT]$LoginAttempts = (($LogonAttemptsConf | Out-String).Trim()).Split([char[]]"")[4]
        [INT]$LockOut = (($LogonAttemptsConf | Out-String).Trim()).Split([char[]]"")[2]
        IF ($LoginAttempts -gt "3") {
            $OpenFinding = $True
        }
        IF ($LockOut -lt "900") {
            $OpenFinding = $True
        }
        $FindingDetails += ($LogonAttemptsConf | Out-String).Trim()
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

Function Get-V215814 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215814
        STIG ID    : CISC-ND-000160
        Rule ID    : SV-215814r879547_rule
        CCI ID     : CCI-000048
        Rule Name  : SRG-APP-000068-NDM-000215
        Rule Title : The Cisco router must be configured to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.
        DiscussMD5 : CF61FAB7486D38C6A0974CBBE13DBBB4
        CheckMD5   : 9E07FC09CE6871C88E82F08CEFBB78E2
        FixMD5     : 7CA6B805012223D075B3304C9E2E3249
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
    $BannerStartSTR = ($ShowRunningConfig | Select-String -Pattern "^banner login \^C.*" | Out-String).Trim()
    IF ($BannerStartSTR) {
        $BannerEndSTR = "^\^C"
        $BannerStartIndex = $ShowRunningConfig.indexof($BannerStartSTR) + 1
        $BannerEndIndex = $BannerStartIndex + ((($ShowRunningConfig | Select-Object -Index ($BannerStartIndex..$ShowRunningConfig.Count) | Select-String $BannerEndSTR)[0]).LineNumber - 2)
        $RTRBanner = $ShowRunningConfig | Select-Object -Index ($BannerStartIndex..$BannerEndIndex) | Out-String
        $RTRBanner_CharArray = (($RTRBanner -replace "\s+", "" | Out-String).Trim()).Replace("`n", "").ToLower().ToCharArray()
        ForEach ($Char in $RTRBanner_CharArray) {
            $RTRBannerHex = $RTRBannerHex + [System.String]::Format("{0:X2}", [System.Convert]::ToUInt32($Char))
        }
        $DoDConsentBanner = "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.`r`nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:`r`n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.`r`n-At any time, the USG may inspect and seize data stored on this IS.`r`n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.`r`n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.`r`n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
        $DoDConsentBanner_CharArray = (($DoDConsentBanner -replace "\s+", "" | Out-String).Trim()).Replace("`n", "").ToLower().ToCharArray()
        ForEach ($Char in $DoDConsentBanner_CharArray) {
            $DoDConsentBannerHex = $DoDConsentBannerHex + [System.String]::Format("{0:X2}", [System.Convert]::ToUInt32($Char))
        }
        $FindingDetails += ($RTRBanner | Out-String).Trim()
        IF ($RTRBannerHex -eq $DoDConsentBannerHex) {
            $Status = "NotAFinding"
        }
        Else {
            $Status = "Open"
        }
    }
    Else {
        $FindingDetails += "Cisco router is not configured to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device" | Out-String
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

Function Get-V215815 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215815
        STIG ID    : CISC-ND-000210
        Rule ID    : SV-215815r879554_rule
        CCI ID     : CCI-000166, CCI-000172, CCI-002234
        Rule Name  : SRG-APP-000080-NDM-000220
        Rule Title : The Cisco device must be configured to audit all administrator activity.
        DiscussMD5 : DF73863590F776A7FFB87BC040502047
        CheckMD5   : 7D01FF65BDA22F71F46AEE431C4CDAE4
        FixMD5     : 59EEEB96FC635B01DFB9DE1C4ACA07F3
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
    $HostName = $ShowRunningConfig | Select-String -Pattern "hostname"
    $LoggingUserinfo = $ShowRunningConfig | Select-String -Pattern "logging userinfo"
    IF (!$LoggingUserinfo) {
        $FindingDetails += ($HostName | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += "Logging userinfo is not configured" | Out-String
        $Status = "Open"
    }
    Else {
        $ArchiveSettings = Get-Section $ShowRunningConfig 'Archive'
        [STRING]$LogEnable = $ArchiveSettings | Select-String -Pattern "logging enable"
        IF (!$LogEnable) {
            $FindingDetails += ($HostName | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += ($LoggingUserinfo | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += ($ArchiveSettings | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += "'logging enable' not set" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += ($HostName | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += ($LoggingUserinfo | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += "archive" | Out-String
            $FindingDetails += ($ArchiveSettings | Out-String).Trim()
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

Function Get-V215817 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215817
        STIG ID    : CISC-ND-000280
        Rule ID    : SV-215817r879564_rule
        CCI ID     : CCI-000131
        Rule Name  : SRG-APP-000096-NDM-000226
        Rule Title : The Cisco router must produce audit records containing information to establish when (date and time) the events occurred.
        DiscussMD5 : D3221577E453F1B93CE67F6D72965A55
        CheckMD5   : 163ACA06A8AC649C7E24C5B26512AF45
        FixMD5     : 3DB4870F45D2A3D800FEA4820C3E19D9
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
    $TimeStamp = $ShowRunningConfig | Select-String -Pattern "service timestamps log datetime"
    IF (!$TimeStamp) {
        $FindingDetails += "Date and Time timestamps are not configured" | Out-String
        $Status = "Open"
    }
    Else {
        $FindingDetails += ($TimeStamp | Out-String).Trim()
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

Function Get-V215818 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215818
        STIG ID    : CISC-ND-000290
        Rule ID    : SV-215818r929022_rule
        CCI ID     : CCI-000132
        Rule Name  : SRG-APP-000097-NDM-000227
        Rule Title : The Cisco router must produce audit records containing information to establish where the events occurred.
        DiscussMD5 : AFF39330BBAA35F46273890D1E49DA4A
        CheckMD5   : 0675C5E1367EBA65007E0C8496E259AC
        FixMD5     : 2153DFD22C560F6F11D3EF769011E54F
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
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface" | Where-Object {$_ -notlike "*loopback*" -AND $_ -notlike "*AppGigabitEthernet*"}
    $IPAccessListSectionNames = $ShowRunningConfig | Select-String -Pattern "^(ip access-list standard|ip access-list extended|ip access-list\s+\S+`$)" | Where-Object {$_ -notlike "*CoPP*"}
    $AclsMissingLogInput = [System.Collections.Generic.List[System.Object]]::new()
    $FoundInterfaceAcls = [System.Collections.Generic.List[System.Object]]::new()
    $StandardAclsOnInterface = [System.Collections.Generic.List[System.Object]]::new()
    $Compliant = $true

    If ($IPAccessListSectionNames) {
        ForEach ($Interface in $Interfaces) {
            $InterfaceConfig = Get-Section $ShowRunningConfig $Interface.ToString()
            IF ($InterfaceConfig -match "ip access-group*") {
                $InterfaceAclName = ($InterfaceConfig | Where-Object {$_ -like "*ip access-group*"} | Out-String).Trim().Split()[2]

                ForEach ($SectionName in $IPAccessListSectionNames) {
                    $SectionAclName = ($SectionName | Out-String).Trim().Split()[-1]
                    If ($SectionAclName -eq $InterfaceAclName) {
                        If ($SectionName -like "*ip access-list standard*") {
                            $Compliant = $false
                            $NewObj = [PSCustomObject]@{
                                ACL_Name  = ($SectionName | Out-String).Trim() + " [finding]"
                                Interface = ($Interface | Out-String).Trim()
                            }
                            $StandardAclsOnInterface.Add($NewObj)
                        }
                        Else {
                            If ($SectionAclName -notin $FoundInterfaceAcls) {
                                $FoundInterfaceAcls.Add($SectionAclName)

                                $DenyACL = Get-Section $ShowRunningConfig $SectionName | Select-String -Pattern "deny" | Where-Object {$_ -notmatch "remark"}
                                If ($DenyACL) {
                                    $LogInputMissing = $False
                                    $DenyStatements = [System.Collections.Generic.List[System.Object]]::new()
                                    ForEach ($Deny in $DenyACL) {
                                        If ($Deny -notlike "*log-input*") {
                                            $Compliant = $False
                                            $LogInputMissing = $True
                                            $NewObj = [PSCustomObject]@{
                                                Deny = ($Deny | Out-String).Trim() + " [finding]"
                                            }
                                            $DenyStatements.Add($NewObj)
                                        }
                                    }
                                    If ($LogInputMissing) {
                                        $NewObj = [PSCustomObject]@{
                                            ACL_Name = ($SectionName | Out-String).Trim()
                                            Denies   = $DenyStatements
                                        }
                                        $AclsMissingLogInput.Add($NewObj)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "IP Access Lists are not configured" | Out-String
    }

    If ($Compliant -ne $true) {
        $Status = "Open"
        If ($AclsMissingLogInput) {
            $FindingDetails += "The following interface-bound ACL's have deny statements that are missing 'log-input':" | Out-String
            ForEach ($Acl in $AclsMissingLogInput) {
                $FindingDetails += $Acl.ACL_Name | Out-String
                ForEach ($Deny in $Acl.Denies) {
                    $FindingDetails += " $($Deny.Deny)" | Out-String
                }
                $FindingDetails += "" | Out-String
            }
        }
        If ($StandardAclsOnInterface) {
            $FindingDetails += "The following standard ACL's are bound to an interface. Standard ACL's are not capable of 'log-input' on deny statements:" | Out-String
            ForEach ($StandardACL in $StandardAclsOnInterface) {
                $FindingDetails += "ACL Name: " + $StandardACL.ACL_Name | Out-String
                $FindingDetails += "Interface: " + $StandardACL.Interface | Out-String
                $FindingDetails += "" | Out-String
            }
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "All 'deny' statements are configured to log." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215819 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215819
        STIG ID    : CISC-ND-000330
        Rule ID    : SV-215819r879569_rule
        CCI ID     : CCI-000135
        Rule Name  : SRG-APP-000101-NDM-000231
        Rule Title : The Cisco router must be configured to generate audit records containing the full-text recording of privileged commands.
        DiscussMD5 : FA987022CB17AFB37AA1F4920CF8B471
        CheckMD5   : B15C717457B28658174DB1B3D67B98D2
        FixMD5     : B3B8D388AF4B621F3CECFBFC4B58A5F7
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
    $ArchiveSettings = Get-Section $ShowRunningConfig 'Archive'
    If (!$ArchiveSettings) {
        $FindingDetails += "Archive Settings not set" | Out-String
        $Status = "Open"
    }
    Else {
        [STRING]$LogEnable = $ArchiveSettings | Select-String -Pattern "logging enable"
        IF (!$LogEnable) {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "'logging enable' not set" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
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

Function Get-V215820 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215820
        STIG ID    : CISC-ND-000380
        Rule ID    : SV-215820r879577_rule
        CCI ID     : CCI-000163
        Rule Name  : SRG-APP-000119-NDM-000236
        Rule Title : The Cisco router must be configured to protect audit information from unauthorized modification.
        DiscussMD5 : 4B41337CEF97035D43B8316E7B0647F8
        CheckMD5   : 9E9C5CE62187B0E1952B19940C096BD2
        FixMD5     : 38064D54BF33B529398F995151417345
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
    $LoggingPersistent = $ShowRunningConfig | Select-String -Pattern "^logging persistent"
    IF (!$LoggingPersistent) {
        $FindingDetails += "Logging persistent not found, this requirement is not applicable" | Out-String
        $Status = "Not_Applicable"
    }
    Else {
        $FilePrivilege = $ShowRunningConfig | Select-String -Pattern "file privilege"
        IF (!$FilePrivilege) {
            $FindingDetails += "File privilege configuration was not found" | Out-String
            $FindingDetails += "File privilege 15 configuration is assumed" | Out-String
            $FindingDetails += "Please verify settings on router" | Out-String
        }
        Else {
            $FindingDetails += ($FilePrivilege | Out-String).Trim()
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

Function Get-V215821 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215821
        STIG ID    : CISC-ND-000390
        Rule ID    : SV-215821r879578_rule
        CCI ID     : CCI-000164
        Rule Name  : SRG-APP-000120-NDM-000237
        Rule Title : The Cisco router must be configured to protect audit information from unauthorized deletion.
        DiscussMD5 : 6114C7D76FD2C2EB038870814F4A6F91
        CheckMD5   : 9E9C5CE62187B0E1952B19940C096BD2
        FixMD5     : 38064D54BF33B529398F995151417345
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
    $LoggingPersistent = $ShowRunningConfig | Select-String -Pattern "^logging persistent"
    IF (!$LoggingPersistent) {
        $FindingDetails += "Logging persistent not found, this requirement is not applicable" | Out-String
        $Status = "Not_Applicable"
    }
    Else {
        $FilePrivilege = $ShowRunningConfig | Select-String -Pattern "file privilege"
        IF (!$FilePrivilege) {
            $FindingDetails += "File privilege configuration was not found" | Out-String
            $FindingDetails += "File privilege 15 configuration is assumed" | Out-String
            $FindingDetails += "Please verify settings on router" | Out-String
        }
        Else {
            $FindingDetails += ($FilePrivilege | Out-String).Trim()
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

Function Get-V215822 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215822
        STIG ID    : CISC-ND-000460
        Rule ID    : SV-215822r879586_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-NDM-000244
        Rule Title : The Cisco router must be configured to limit privileges to change the software resident within software libraries.
        DiscussMD5 : 481498A606DD89247A011C1C3394F033
        CheckMD5   : 6E86E753D5FD13CBF9E7992DA422867B
        FixMD5     : FBC1E69B58B84A8E5775D3401AD3C06B
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
    $FindingDetails = @()
    $FilePrivilege = $ShowRunningConfig | Select-String -Pattern "file privilege"
    IF (!$FilePrivilege) {
        $FindingDetails += "File privilege configuration was not found" | Out-String
        $FindingDetails += "File privilege 15 configuration is assumed" | Out-String
        $FindingDetails += "Please verify settings on router" | Out-String
    }
    Else {
        $FindingDetails += ($FilePrivilege | Out-String).Trim()
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

Function Get-V215823 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215823
        STIG ID    : CISC-ND-000470
        Rule ID    : SV-215823r892394_rule
        CCI ID     : CCI-000382
        Rule Name  : SRG-APP-000142-NDM-000245
        Rule Title : The Cisco router must be configured to prohibit the use of all unnecessary and nonsecure functions and services.
        DiscussMD5 : 3E6CD5ADF99942F100B05BEF828F3687
        CheckMD5   : DC4896E7C9B575E16483E55F5DEC10DD
        FixMD5     : EA5EABAD036305B35E758F6746A44630
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
    $DisallowedCommands = @(
        "boot network",
        "ip boot server",
        "ip bootp server",
        "ip dns server",
        "ip identd",
        "ip finger",
        "ip http server",
        "ip rcmd rcp-enable",
        "ip rcmd rsh-enable",
        "service config",
        "service finger",
        "service tcp-small-servers",
        "service udp-small-servers",
        "service pad",
        "service call-home"
    )
    ForEach ($Command in $DisallowedCommands) {
        $CommandCheck = $ShowRunningConfig | Select-String -Pattern "^\s*$Command"
        IF ([Bool]$CommandCheck) {
            $OpenFinding = $True
            $FindingDetails += ([STRING]"$CommandCheck Found").ToUpper() | Out-String
        }
        Else {
            $FindingDetails += "$Command not found" | Out-String
        }
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

Function Get-V215824 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215824
        STIG ID    : CISC-ND-000490
        Rule ID    : SV-215824r879589_rule
        CCI ID     : CCI-001358, CCI-002111
        Rule Name  : SRG-APP-000148-NDM-000346
        Rule Title : The Cisco router must be configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable.
        DiscussMD5 : 770661E395811E143543EDE334AC2B0C
        CheckMD5   : 5FC37EB1A478AD5E62E5FB332D2902EB
        FixMD5     : DA77018EB229361A85C1B82EED3B9740
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
    $NR = $False
    $AllUsers = $ShowRunningConfig | Select-String -Pattern "^username"
    $Users = @()
    $AAAGroupServer = $ShowRunningConfig | Select-String -Pattern "^aaa group server"
    $AAALoginMethod = $ShowRunningConfig | Select-String -Pattern "^aaa authentication login"

    #This removes pwd from variable
    ForEach ($User in $AllUsers) {
        $PwdHash = (($User | Out-String).Trim()).Split([char[]]"") | Select-Object -Last 1
        $Users += (($User | Out-String).Trim()).Replace("$PwdHash", "<pwd removed>")
    }

    $FindingDetails += "Accounts" | Out-String
    $FindingDetails += ($Users | Out-String).Trim()
    $FindingDetails += "" | Out-String

    IF ($Allusers.Count -gt "1") {
        $OpenFinding = $True
    }
    Else {
        [INT]$PrivLvl = (-Split $AllUsers)[3]
        if (!($PrivLvl -eq "15")) {
            $NR = $True
            $FindingDetails += "Verify that a local account for last resort has been configured with a privilege level that will enable the administrator to troubleshoot connectivity to the authentication server." | Out-String
            $FindingDetails += "" | Out-String
        }
    }

    IF (!$AAAGroupServer) {
        $OpenFinding = $True
        $FindingDetails += "Authentication Group Server:" | Out-String
        $FindingDetails += "AAA Group Server(s) not configured" | Out-String
    }
    Else {
        #$AAAMethod = (([STRING]$AAAGroupServer).Replace("aaa group server ","")).Split([char[]]"")[0].Trim()
        $AAAAuthSrvrGroupName = (([STRING]$AAAGroupServer).Replace("aaa group server ", "")).Split([char[]]"")[1].Trim()
        $AllowedAuthServers = @("tacacs+", "radius", "$AAAAuthSrvrGroupName")
        IF (!$AAALoginMethod) {
            $OpenFinding = $True
            $FindingDetails += "AAA authentication login method not configured" | Out-String
        }
        Else {
            $FindingDetails += "AAA Login Method:" | Out-String
            ForEach ($LoginMethod in $AAALoginMethod) {
                $AAALoginAuthServer = ($LoginMethod | Out-String).Trim().Replace("aaa authentication login ", "").Split([char[]]"")
                IF ($AAALoginAuthServer[2]) {
                    IF (!($AAALoginAuthServer[2] -in $AllowedAuthServers -AND $AAALoginAuthServer[3] -eq "local")) {
                        $OpenFinding = $True
                    }
                    $FindingDetails += ($LoginMethod | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                }
                Else {
                    $OpenFinding = $True
                    $FindingDetails += ($LoginMethod | Out-String).Trim() + " " + "- local is not defined after radius or tacas+ in the authentication order." | Out-String
                    $FindingDetails += "" | Out-String
                }
            }
        }
    }

    IF ($OpenFinding) {
        $Status = "Open"
    }
    Else {
        IF (!$NR) {
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

Function Get-V215826 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215826
        STIG ID    : CISC-ND-000550
        Rule ID    : SV-215826r879601_rule
        CCI ID     : CCI-000205
        Rule Name  : SRG-APP-000164-NDM-000252
        Rule Title : The Cisco router must be configured to enforce a minimum 15-character password length.
        DiscussMD5 : E86D767C7A84CA263D8A1284AD3C60EC
        CheckMD5   : 5D5D507EF089ECC393F3A276D451AD1F
        FixMD5     : 6796FB099BC3CF5E9B077812FD93CFC8
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
    $PwdPolicySectionName = $ShowRunningConfig | Select-String -Pattern "^aaa common-criteria policy"
    IF (!$PwdPolicySectionName) {
        $FindingDetails += "Password policy not configured" | Out-String
        $Status = "Open"
    }
    Else {
        $PwdPolicySettings = Get-Section $ShowRunningConfig $PwdPolicySectionName
        IF ($PwdPolicySettings -contains "min-length 15") {
            $Status = "NotAFinding"
        }
        Else {
            $Status = "Open"
        }
        $FindingDetails += ($PwdPolicySectionName | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += ($PwdPolicySettings | Out-String).Trim()
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215827 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215827
        STIG ID    : CISC-ND-000570
        Rule ID    : SV-215827r879603_rule
        CCI ID     : CCI-000192
        Rule Name  : SRG-APP-000166-NDM-000254
        Rule Title : The Cisco router must be configured to enforce password complexity by requiring that at least one upper-case character be used.
        DiscussMD5 : 36FEAE5F2BDE0023706C61CF0503DA74
        CheckMD5   : D3625E7301E8A3F146183D13B1732A3D
        FixMD5     : F0BA8F1C719EA2813C25718F53874A6B
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
    $PwdPolicySectionName = $ShowRunningConfig | Select-String -Pattern "^aaa common-criteria policy"
    IF (!$PwdPolicySectionName) {
        $FindingDetails += "Password policy not configured" | Out-String
        $Status = "Open"
    }
    Else {
        $PwdPolicySettings = Get-Section $ShowRunningConfig $PwdPolicySectionName
        IF ($PwdPolicySettings -contains "upper-case 1") {
            $Status = "NotAFinding"
        }
        Else {
            $Status = "Open"
        }
        $FindingDetails += ($PwdPolicySectionName | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += ($PwdPolicySettings | Out-String).Trim()
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215828 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215828
        STIG ID    : CISC-ND-000580
        Rule ID    : SV-215828r879604_rule
        CCI ID     : CCI-000193
        Rule Name  : SRG-APP-000167-NDM-000255
        Rule Title : The Cisco router must be configured to enforce password complexity by requiring that at least one lower-case character be used.
        DiscussMD5 : 3064BFCBB08D1423D8F28D13D9EB5B67
        CheckMD5   : A71AD0531C92AF751E6466829937D9FF
        FixMD5     : 2AB080315387D1CB92053D5F6D369059
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
    $PwdPolicySectionName = $ShowRunningConfig | Select-String -Pattern "^aaa common-criteria policy"
    IF (!$PwdPolicySectionName) {
        $FindingDetails += "Password policy not configured" | Out-String
        $Status = "Open"
    }
    Else {
        $PwdPolicySettings = Get-Section $ShowRunningConfig $PwdPolicySectionName
        IF ($PwdPolicySettings -contains "lower-case 1") {
            $Status = "NotAFinding"
        }
        Else {
            $Status = "Open"
        }
        $FindingDetails += ($PwdPolicySectionName | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += ($PwdPolicySettings | Out-String).Trim()
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215829 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215829
        STIG ID    : CISC-ND-000590
        Rule ID    : SV-215829r879605_rule
        CCI ID     : CCI-000194
        Rule Name  : SRG-APP-000168-NDM-000256
        Rule Title : The Cisco router must be configured to enforce password complexity by requiring that at least one numeric character be used.
        DiscussMD5 : 3064BFCBB08D1423D8F28D13D9EB5B67
        CheckMD5   : B55E81BAEA81A41E898A03FEE407CE97
        FixMD5     : BB5F6E164CCBD09A2F05BBE5BE9A23C7
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
    $PwdPolicySectionName = $ShowRunningConfig | Select-String -Pattern "^aaa common-criteria policy"
    IF (!$PwdPolicySectionName) {
        $FindingDetails += "Password policy not configured" | Out-String
        $Status = "Open"
    }
    Else {
        $PwdPolicySettings = Get-Section $ShowRunningConfig $PwdPolicySectionName
        IF ($PwdPolicySettings -contains "numeric-count 1") {
            $Status = "NotAFinding"
        }
        Else {
            $Status = "Open"
        }
        $FindingDetails += ($PwdPolicySectionName | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += ($PwdPolicySettings | Out-String).Trim()
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215830 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215830
        STIG ID    : CISC-ND-000600
        Rule ID    : SV-215830r879606_rule
        CCI ID     : CCI-001619
        Rule Name  : SRG-APP-000169-NDM-000257
        Rule Title : The Cisco router must be configured to enforce password complexity by requiring that at least one special character be used.
        DiscussMD5 : 3064BFCBB08D1423D8F28D13D9EB5B67
        CheckMD5   : D61846543B8BB5976258A0053739D5B0
        FixMD5     : 4F064EB063143734B6395DDE1CDC99FC
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
    $PwdPolicySectionName = $ShowRunningConfig | Select-String -Pattern "^aaa common-criteria policy"
    IF (!$PwdPolicySectionName) {
        $FindingDetails += "Password policy not configured" | Out-String
        $Status = "Open"
    }
    Else {
        $PwdPolicySettings = Get-Section $ShowRunningConfig $PwdPolicySectionName
        IF ($PwdPolicySettings -contains "special-case 1") {
            $Status = "NotAFinding"
        }
        Else {
            $Status = "Open"
        }
        $FindingDetails += ($PwdPolicySectionName | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += ($PwdPolicySettings | Out-String).Trim()
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215831 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215831
        STIG ID    : CISC-ND-000610
        Rule ID    : SV-215831r879607_rule
        CCI ID     : CCI-000195
        Rule Name  : SRG-APP-000170-NDM-000329
        Rule Title : The Cisco router must be configured to require that when a password is changed, the characters are changed in at least eight of the positions within the password.
        DiscussMD5 : 1BD1217C01F3BE8EB813263AE56D4A9F
        CheckMD5   : 62CF48B3793FC08C75C7E59C72220B0F
        FixMD5     : 623FD68E953362E6E5DFF116AF2AE505
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
    $PwdPolicySectionName = $ShowRunningConfig | Select-String -Pattern "^aaa common-criteria policy"
    IF (!$PwdPolicySectionName) {
        $FindingDetails += "Password policy not configured" | Out-String
        $Status = "Open"
    }
    Else {
        $PwdPolicySettings = Get-Section $ShowRunningConfig $PwdPolicySectionName
        IF ($PwdPolicySettings -contains "char-changes 8") {
            $Status = "NotAFinding"
        }
        Else {
            $Status = "Open"
        }
        $FindingDetails += ($PwdPolicySectionName | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += ($PwdPolicySettings | Out-String).Trim()
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215832 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215832
        STIG ID    : CISC-ND-000620
        Rule ID    : SV-215832r879608_rule
        CCI ID     : CCI-000196
        Rule Name  : SRG-APP-000171-NDM-000258
        Rule Title : The Cisco router must only store cryptographic representations of passwords.
        DiscussMD5 : 567338A4DCF9B517B41EDD04166B4766
        CheckMD5   : 9BAC61FBBA4E9844590826EE869E9F68
        FixMD5     : 1573982350947D974B22261AFACE2E70
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
    $PWDEncryption = $ShowRunningConfig | Select-String -Pattern "^service password-encryption"
    IF ($PWDEncryption) {
        $FindingDetails += ($PWDEncryption | Out-String).Trim()
        $Status = "NotAFinding"
    }
    Else {
        $FindingDetails += "service password-encryption not configured" | Out-String
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

Function Get-V215833 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215833
        STIG ID    : CISC-ND-000720
        Rule ID    : SV-215833r916342_rule
        CCI ID     : CCI-001133
        Rule Name  : SRG-APP-000190-NDM-000267
        Rule Title : The Cisco router must be configured to terminate all network connections associated with device management after five minutes of inactivity.
        DiscussMD5 : C55855B1F7DC3A2BCA7DC4A4B7EA8027
        CheckMD5   : 4087E71048E19E385771C782AF5C15D6
        FixMD5     : 292D2E7C97864CACB447EF4DCEC82C88
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
    $NR = $False
    $HttpServer = $ShowRunningConfig | Select-String -Pattern "^no ip http"
    $LineConTimeOut = Get-Section $ShowRunningConfig "line con 0" | Where-Object {$_ -like "exec-timeout*"}
    $LineVtys = $ShowRunningConfig | Select-String -Pattern "^line vty"

    IF ($HttpServer -like "no ip http server" -AND $HttpServer -like "no ip http secure-server") {
        $FindingDetails += "IP HTTP Timeout Settings" | Out-String
        $FindingDetails += ($HttpServer | Out-String).Trim()
        $FindingDetails += "" | Out-String
        $FindingDetails += "http\https servers are disabled, http\https requirements are not applicable" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $HttpTimeout = $ShowRunningConfig | Select-String -Pattern "^ip http timeout"
        IF ($HttpTimeout) {
            IF ((($HttpTimeout | Out-String).Trim()).Split([char[]]"")[4] -le "600") {
                $FindingDetails += "IP HTTP Timeout Settings" | Out-String
                $FindingDetails += ($HttpTimeout | Out-String).Trim()
                $FindingDetails += "" | Out-String
            }
            Else {
                $OpenFinding = $True
                $FindingDetails += "IP HTTP Timeout Settings" | Out-String
                $FindingDetails += ($HttpTimeout | Out-String).Trim()
                $FindingDetails += "" | Out-String
            }

        }
        Else {
            $OpenFinding = $True
            $FindingDetails += "IP HTTP Timeout Settings are not configured" | Out-String
            $FindingDetails += "" | Out-String
        }
    }

    IF ($LineConTimeOut) {
        IF (!([INT]$LineConTimeOut.Split([char[]]"")[1] -le "5")) {
            $OpenFinding = $True
        }
        $FindingDetails += "Console Port Timeout Settings" | Out-String
        $FindingDetails += "line con 0" | Out-String
        $FindingDetails += " " + ($LineConTimeOut | Out-String).Trim()
        $FindingDetails += "" | Out-String
    }
    Else {
        IF (Get-Section $ShowRunningConfig "line con 0") {
            $OpenFinding = $True
            $FindingDetails += "line con 0" | Out-String
            $FindingDetails += (Get-Section $ShowRunningConfig "line con 0" | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += "line con 0 exec-timeout is not configured. Default value of 10 is assumed" | Out-String
            $FindingDetails += "Confirm value is correctly configured by checking against 'show running-config all' configuration file" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $FindingDetails += "Console Port Line Configuration not configured" | Out-String
            $FindingDetails += "" | Out-String
        }
    }

    IF ($LineVtys) {
        $FindingDetails += "Line VTY Timeout Settings"
        $VTYTimeout = Get-Section $ShowRunningConfig $LineVtys[0] | Where-Object {$_ -like "exec-timeout*"}
        IF ($VTYTimeout) {
            IF (!([INT]$VTYTimeout.Split([char[]]"")[1] -le "5")) {
                $OpenFinding = $True
            }
            $FindingDetails += ($LineVtys[0] | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += " " + ($VTYTimeout | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
        Else {
            $OpenFinding = $True
            $FindingDetails += ($LineVtys[0] | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += (Get-Section $ShowRunningConfig $LineVtys[0] | Out-String).Trim()
            $FindingDetails += "" | Out-String
            $FindingDetails += ($LineVtys[0] | Out-String).Trim() + " " + "exec-timeout is not configured. Default value of 10 is assumed" | Out-String
            $FindingDetails += "Confirm value is correctly configured by checking against 'show running-config all' configuration file" | Out-String
            $FindingDetails += "" | Out-String
        }

        $LineVtys | Select-Object -Skip 1 | ForEach-Object {
            $VTYTimeout = Get-Section $ShowRunningConfig $_ | Where-Object {$_ -like "exec-timeout*"}
            IF ($VTYTimeout) {
                IF (!([INT]$VTYTimeout.Split([char[]]"")[1] -le "5")) {
                    $OpenFinding = $True
                }
                $FindingDetails += ($_ | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $FindingDetails += " " + ($VTYTimeout | Out-String).Trim()
                $FindingDetails += "" | Out-String
            }
            Else {
                $OpenFinding = $True
                $FindingDetails += ($_ | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $FindingDetails += (Get-Section $ShowRunningConfig $_ | Out-String).Trim()
                $FindingDetails += "" | Out-String
                $FindingDetails += ($_ | Out-String).Trim() + " " + "exec-timeout is not configured. Default value of 10 is assumed" | Out-String
                $FindingDetails += "Confirm value is correctly configured by checking against 'show running-config all' configuration file" | Out-String
                $FindingDetails += "" | Out-String
            }
        }
    }
    Else {
        $OpenFinding = $true
        $FindingDetails += "Line VTY Timeout Settings not set" | Out-String
        $FindingDetails += ""
    }
    IF ($OpenFinding) {
        $Status = "Open"
    }
    Else {
        IF (!$NR) {
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

Function Get-V215834 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215834
        STIG ID    : CISC-ND-000880
        Rule ID    : SV-215834r879696_rule
        CCI ID     : CCI-002130
        Rule Name  : SRG-APP-000319-NDM-000283
        Rule Title : The Cisco router must be configured to automatically audit account enabling actions.
        DiscussMD5 : 7F7DEDA73BE5190E575339FCA6BFD3B6
        CheckMD5   : 3DC2A6C63CF49D3E22205E4DD0202BDB
        FixMD5     : A1E6AAA99C056DF493AAC69D5DC441C9
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
    $ArchiveSettings = Get-Section $ShowRunningConfig 'Archive'
    If (!$ArchiveSettings) {
        $FindingDetails += "Archive Settings not set" | Out-String
        $Status = "Open"
    }
    Else {
        [STRING]$LogEnable = $ArchiveSettings | Select-String -Pattern "logging enable"
        IF (!$LogEnable) {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "'logging enable' not set" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
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

Function Get-V215836 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215836
        STIG ID    : CISC-ND-000980
        Rule ID    : SV-215836r879730_rule
        CCI ID     : CCI-001849
        Rule Name  : SRG-APP-000357-NDM-000293
        Rule Title : The Cisco router must be configured to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.
        DiscussMD5 : 3796374344336078FA1BEEE6A23D7D08
        CheckMD5   : 8C7F1416E0A9200DBA8678045BF4861B
        FixMD5     : 2AD2DDE416E4CAEEF34A7FC33561E21E
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
    $LoggingBuffer = $ShowRunningConfig | Select-String -Pattern "^logging buffered"
    IF ($LoggingBuffer) {
        $LoggingBuffer -match "\d+" | Out-Null
        $BufferSize = $Matches[0]
        $FindingDetails += "Logging buffer size: $BufferSize " | Out-String
        $Status = "NotAFinding"
    }
    Else {
        $FindingDetails += "Logging buffer size is not configured" | Out-String
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

Function Get-V215837 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215837
        STIG ID    : CISC-ND-001000
        Rule ID    : SV-215837r879733_rule
        CCI ID     : CCI-001858
        Rule Name  : SRG-APP-000360-NDM-000295
        Rule Title : The Cisco router must be configured to generate an alert for all audit failure events.
        DiscussMD5 : 5A2FE043544D5FA66D313940CA473FE4
        CheckMD5   : D912606632F4B6129D095F736E5BBF3F
        FixMD5     : 00A46EC582469271C9F665D1F5B707ED
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
    $LoggingTrap = $ShowRunningConfig | Select-String -Pattern "^logging trap"
    IF ($LoggingTrap) {
        $FindingDetails += ($LoggingTrap | Out-String).Trim()
        $Status = "NotAFinding"
    }
    Else {
        IF ($ShowRunningConfig | Select-String -Pattern "^no logging trap") {
            $FindingDetails += ($ShowRunningConfig | Select-String -Pattern "^no logging trap" | Out-String).Trim()
            $Status = "Open"
        }
        Else {
            $ShowLoggingStartStr = "------------------ show logging ------------------"
            $ShowLoggingEndStr = "------------------ show pnp tech-support ------------------"
            $ShowLoggingstartIndex = $ShowTech.indexof($ShowLoggingStartStr) + 1
            $ShowLoggingendIndex = $ShowTech.indexof($ShowLoggingEndStr) - 1
            $ShowLoggingConfig = $ShowTech | Select-Object -Index ($ShowLoggingstartIndex..$ShowLoggingendIndex)
            $FindingDetails += ($ShowLoggingConfig | Select-String -Pattern "\sTrap logging.*" | Out-String).Trim()
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

Function Get-V215838 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215838
        STIG ID    : CISC-ND-001030
        Rule ID    : SV-215838r879746_rule
        CCI ID     : CCI-001889, CCI-001890, CCI-001893
        Rule Name  : SRG-APP-000373-NDM-000298
        Rule Title : The Cisco router must be configured to synchronize its clock with the primary and secondary time sources using redundant authoritative time sources.
        DiscussMD5 : 34059B1C8483FDB948E0BDBFE3212644
        CheckMD5   : 7954F4FBCE62EBBD9F576405340E481F
        FixMD5     : D5DA1C14DE233FCC0F18F26848CCD8AE
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
    $NTPServers = $ShowRunningConfig | Select-String -Pattern "^ntp server"
    IF ($NTPServers) {
        IF ($NTPServers.Count -gt "1") {
            $NTPServerPrimary = $NTPServers[0] -match "\d+\.\d+\.\d+\.\d+" | ForEach-Object {$Matches[0]}
            $NTPServerBackup = $NTPServers[1] -match "\d+\.\d+\.\d+\.\d+" | ForEach-Object {$Matches[0]}
            IF ($NTPServerPrimary -ne $NTPServerBackup) {
                $FindingDetails += ($NTPServers | Out-String).Trim()
                $Status = "NotAFinding"
            }
            Else {
                $FindingDetails += "Primary and Backup NTP server are set to the same IP Address" | Out-String
                $FindingDetails += "Redundant NTP Server not configured" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += ($NTPServers | Out-String).Trim()
                $Status = "Open"
            }
        }
        Else {
            $FindingDetails += "Redundant NTP Server not configured" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += ($NTPServers | Out-String).Trim()
            $Status = "Open"
        }
    }
    Else {
        $FindingDetails += "NTP servers not configured" | Out-String
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

Function Get-V215841 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215841
        STIG ID    : CISC-ND-001130
        Rule ID    : SV-215841r879768_rule
        CCI ID     : CCI-001967
        Rule Name  : SRG-APP-000395-NDM-000310
        Rule Title : The Cisco router must be configured to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).
        DiscussMD5 : D496EF6E2854AA9218CFE0EDD0C58874
        CheckMD5   : 48DA28B3D339CEDC2C46CE5A4E8C9859
        FixMD5     : 9CEB8F1836298C5725B12099833A43D2
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
    $FindingDetails += "Requires information not provide by show tech or show running configuration file" | Out-String
    $FindingDetails += ($ShowRunningConfig | Select-String -Pattern "^snmp-server" | Out-String).Trim()
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215842 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215842
        STIG ID    : CISC-ND-001140
        Rule ID    : SV-215842r879768_rule
        CCI ID     : CCI-000068
        Rule Name  : SRG-APP-000395-NDM-000310
        Rule Title : The Cisco router must be configured to encrypt SNMP messages using a FIPS 140-2 approved algorithm.
        DiscussMD5 : EC38084E1A006FA7ADEE0533040CE597
        CheckMD5   : BDBF0509B5956836A1AE91BD69DDA347
        FixMD5     : 7BAFC3731CDA4D0B49354009D5FEEF99
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
    $FindingDetails += "Requires information not provided by show tech or show running configuration file" | Out-String
    $FindingDetails += ($ShowRunningConfig | Select-String -Pattern "^snmp-server" | Out-String).Trim()
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215843 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215843
        STIG ID    : CISC-ND-001150
        Rule ID    : SV-215843r879768_rule
        CCI ID     : CCI-001967
        Rule Name  : SRG-APP-000395-NDM-000347
        Rule Title : The Cisco router must be configured to authenticate Network Time Protocol (NTP) sources using authentication that is cryptographically based.
        DiscussMD5 : B9CAD587304827035D1B323D3221D8E0
        CheckMD5   : EAA7B323902C25BABAFC3E7407FABE66
        FixMD5     : 8DA42F8E09A6D55CE57339BEFED30DB6
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
    $NTPInfo = $ShowRunningConfig | Select-String -Pattern "^ntp"
    IF ($NTPInfo) {
        IF ([BOOL]($NTPInfo | Where-Object {$_ -like "*md5*"})) {
            $FindingDetails += ($NTPInfo | Out-String).Trim()
            $Status = "NotAFinding"
        }
        Else {
            $FindingDetails += ($NTPInfo | Out-String).Trim()
            $Status = "Open"
        }
    }
    Else {
        $FindingDetails += "NTP authenitcation is not configured" | Out-String
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

Function Get-V215844 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215844
        STIG ID    : CISC-ND-001200
        Rule ID    : SV-215844r879784_rule
        CCI ID     : CCI-001941, CCI-002890
        Rule Name  : SRG-APP-000411-NDM-000330
        Rule Title : The Cisco router must be configured to use FIPS-validated Keyed-Hash Message Authentication Code (HMAC) to protect the integrity of remote maintenance sessions.
        DiscussMD5 : 515464A1D5B98B44D4F12FA3F0A50083
        CheckMD5   : 930014117BBB480B0D8586C6FA745DF3
        FixMD5     : F3F6BE472877E959CA84874659C796EF
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
    $IPSSHServer = $ShowRunningConfig | Select-String -Pattern "^ip ssh version 2"

    IF ($IPSSHServer) {
        $IPSSHSrvrEncAlgorithm = $ShowRunningConfig | Select-String -Pattern "^ip ssh server algorithm mac hmac-sha2-256"
        IF ($IPSSHSrvrEncAlgorithm) {
            $FindingDetails += ($IPSSHSrvrEncAlgorithm | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
        Else {
            $OpenFinding = $True
            $FindingDetails += "SSH Server Algorithm is not configured per STIG check guidelines" | Out-String
            $FindingDetails += ($ShowRunningConfig | Select-String -Pattern "^ip ssh" | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $OpenFinding = $True
        $FindingDetails += "SSH server is not configured per STIG check guidelines" | Out-String
        $FindingDetails += ($ShowRunningConfig | Select-String -Pattern "^ip ssh" | Out-String).Trim()
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

Function Get-V215845 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215845
        STIG ID    : CISC-ND-001210
        Rule ID    : SV-215845r879785_rule
        CCI ID     : CCI-003123
        Rule Name  : SRG-APP-000412-NDM-000331
        Rule Title : The Cisco router must be configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions.
        DiscussMD5 : 451042AAB21D5513C191D553EC3B6ADF
        CheckMD5   : 742F37493052FE4C90FE2B4509BE89AA
        FixMD5     : A1167CC0769548D5C6C661F15CE0832C
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
    $IPSSHSrvrEncAlgorithm = $ShowRunningConfig | Select-String -Pattern "^ip ssh server algorithm encryption(?: aes128-ctr| aes192-ctr| aes256-ctr)"
    IF (!$IPSSHSrvrEncAlgorithm) {
        IF ($null -eq ($ShowRunningConfig | Select-String -Pattern "^ip ssh server algorithm encryption")) {
            $FindingDetails += "ip ssh server algorithm encryption not configured" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += ($ShowRunningConfig | Select-String -Pattern "^ip ssh server algorithm encryption" | Out-String).Trim()
            $Status = "Open"
        }
    }
    Else {
        $FindingDetails += ($IPSSHSrvrEncAlgorithm | Out-String).Trim()
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

Function Get-V215848 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215848
        STIG ID    : CISC-ND-001250
        Rule ID    : SV-215848r879870_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000499-NDM-000319
        Rule Title : The Cisco router must be configured to generate log records when administrator privileges are deleted.
        DiscussMD5 : FA1F339C351D1C903620B12A1C65FF0A
        CheckMD5   : 02FF0523C8101B391FCF4D5A53F1477E
        FixMD5     : 2498DC391EBF03A675DB221FDAEE4DC8
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
    $ArchiveSettings = Get-Section $ShowRunningConfig 'Archive'
    If (!$ArchiveSettings) {
        $FindingDetails += "Archive Settings not set" | Out-String
        $Status = "Open"
    }
    Else {
        [STRING]$LogEnable = $ArchiveSettings | Select-String -Pattern "logging enable"
        IF (!$LogEnable) {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "'logging enable' not set" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
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

Function Get-V215849 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215849
        STIG ID    : CISC-ND-001260
        Rule ID    : SV-215849r879874_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000503-NDM-000320
        Rule Title : The Cisco router must be configured to generate audit records when successful/unsuccessful logon attempts occur.
        DiscussMD5 : FA1F339C351D1C903620B12A1C65FF0A
        CheckMD5   : CA310613A27451A9BE45A5DA51CAB141
        FixMD5     : 1DF014239E7D44157D9587125515B33C
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
    $LoginFailure = $ShowRunningConfig | Select-String -Pattern "login on-failure log"
    $LoginSuccess = $ShowRunningConfig | Select-String -Pattern "login on-success log"
    IF (!$LoginFailure) {
        $LoginFailure = "login on-failure not configured" | Out-String
        $FindingDetails += "" | Out-String
        $OpenFinding = $True
    }
    IF (!$LoginSuccess) {
        $LoginSuccess = "login on-success not configured" | Out-String
        $OpenFinding = $True
    }
    $FindingDetails += ($LoginFailure | Out-String).Trim()
    $FindingDetails += "" | Out-String
    $FindingDetails += ($LoginSuccess | Out-String).Trim()
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

Function Get-V215850 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215850
        STIG ID    : CISC-ND-001270
        Rule ID    : SV-215850r879875_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000504-NDM-000321
        Rule Title : The Cisco router must be configured to generate log records for privileged activities.
        DiscussMD5 : FA1F339C351D1C903620B12A1C65FF0A
        CheckMD5   : 8C49529CCA5C92BEB41332F589375D6D
        FixMD5     : 3FF06C089D905636D15D3774358B22CB
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
    $ArchiveSettings = Get-Section $ShowRunningConfig 'Archive'
    If (!$ArchiveSettings) {
        $FindingDetails += "Archive Settings not set" | Out-String
        $Status = "Open"
    }
    Else {
        [STRING]$LogEnable = $ArchiveSettings | Select-String -Pattern "logging enable"
        IF (!$LogEnable) {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "'logging enable' not set" | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "Archive" | Out-String
            $FindingDetails += $ArchiveSettings | Out-String
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

Function Get-V215855 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215855
        STIG ID    : CISC-ND-001410
        Rule ID    : SV-215855r916221_rule
        CCI ID     : CCI-000366, CCI-000537
        Rule Name  : SRG-APP-000516-NDM-000340
        Rule Title : The Cisco router must be configured to back up the configuration when changes occur.
        DiscussMD5 : 6D8F1725F65C6027E6A4DB4EE39E1B5D
        CheckMD5   : C9A60AF5A87BFC0802D716D1B5695BC7
        FixMD5     : 6C5EA3CDD6E5C344D61826C30429FAB4
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
    $FindingDetails = @()
    $EventManager = $ShowRunningConfig | Select-String -Pattern "^event manager applet"
    IF ($EventManager) {
        ForEach ($BackupConfig in $EventManager) {
            $FindingDetails += ($BackupConfig | Out-String).Trim()
            $FindingDetails += (Get-Section $ShowRunningConfig $BackupConfig | Out-String).Trim()
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $FindingDetails += "Cisco router is not configured to conduct backups of the configuration when changes occur" | Out-String
        $Status = "Open"
    } #<--------------------------------------------------------- Might be able to dermine full status in the future, however I would need configuration files that are properly configured to test against.
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215856 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215856
        STIG ID    : CISC-ND-001440
        Rule ID    : SV-215856r879887_rule
        CCI ID     : CCI-000366, CCI-001159
        Rule Name  : SRG-APP-000516-NDM-000344
        Rule Title : The Cisco router must be configured to obtain its public key certificates from an appropriate certificate policy through an approved service provider.
        DiscussMD5 : 90C82E3DF14F4AA185857EC1A544EB50
        CheckMD5   : A5F532227CB9384C418A7E1F4697721C
        FixMD5     : 05BBB5294BF7D7AA2291FED2BB06021C
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
    $Trustpoint = $ShowRunningConfig | Select-String -Pattern "^crypto pki trustpoint"
    IF ($Trustpoint) {
        ForEach ($Point in $Trustpoint) {
            $Enrollment = Get-Section $ShowRunningConfig $Point.ToString() | Select-String -Pattern "enrollment"
            IF ($Enrollment) {
                If ($Enrollment -like "*url*") {
                    $FindingDetails += ($Point | Out-String).Trim() + " - ensure url is from a trusted CA. " | Out-String
                    $FindingDetails += ($Point | Out-String).Trim()
                    $FindingDetails += " " + ($Enrollment | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                }
                Else {
                    $OpenFinding = $True
                    $FindingDetails += ($Point | Out-String).Trim() + " is not configured for url enrollment" | Out-String
                    $FindingDetails += ($Point | Out-String).Trim()
                    $FindingDetails += " " + ($Enrollment | Out-String).Trim()
                    $FindingDetails += "" | Out-String
                }
            }
            Else {
                $OpenFinding = $True
                $FindingDetails += "There is no enrollment configuration configured for: " + ($Point | Out-String).Trim()
                $FindingDetails += ($Point | Out-String).Trim()
                $FindingDetails += (Get-Section $ShowRunningConfig $Point.ToString() | Out-String).Trim()
            }
        }
    }
    Else {
        $FindingDetails += "PKI trust point have not been configured" | Out-String
    }
    IF ($OpenFinding) {
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

Function Get-V220139 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220139
        STIG ID    : CISC-ND-001450
        Rule ID    : SV-220139r916114_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-APP-000516-NDM-000350
        Rule Title : The Cisco router must be configured to send log data to at least two syslog servers for the purpose of forwarding alerts to the administrators and the information system security officer (ISSO).
        DiscussMD5 : 2B60B499490110C0A7C4C1920395BB82
        CheckMD5   : 1B706946007EACAC4CDE4EEC9EEAC465
        FixMD5     : 46F1C7DF06307FF389D8E34AF97A8DE7
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
    $LoggingHost = $ShowRunningConfig | Select-String -Pattern "^logging host"
    $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
    $RouterIPs = @()
    ForEach ($Interface in $Interfaces) {
        $IP = (((Get-Section $ShowRunningConfig $Interface | Select-String -Pattern "ip address" | Out-String).Trim()).Replace("ip address ", "")).Split([char[]]"")[0]
        IF ($IP -match "\d+\.\d+\.\d+\.\d+") {
            $RouterIPs += $IP
        }
    }
    IF ($LoggingHost) {
        foreach ($SysLogServer in $LoggingHost) {
            $SysLogServer = (($SysLogServer | Out-String).Trim()).Replace("logging host ", "")
            IF ($SysLogServer -in $RouterIPs) {
                $OpenFinding = $True
                $FindingDetails += "The router is not configured to off-load log records onto a different system." | Out-String
                $FindingDetails += "" | Out-String
            }
        }
        $FindingDetails += ($LoggingHost | Out-String).Trim()
    }
    Else {
        $FindingDetails += "The router is not configured to send log data to the syslog server, this is a finding." | Out-String
        $OpenFinding = $True
    }

    If ($LoggingHost -and ($LoggingHost | Measure-Object).Count -lt 2) {
        $OpenFinding = $True
        $FindingDetails += "" | Out-String
        $FindingDetails += "A minimum of two syslog servers are required." | Out-String
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

Function Get-V220140 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220140
        STIG ID    : CISC-ND-001470
        Rule ID    : SV-220140r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-NDM-000351
        Rule Title : The Cisco router must be running an IOS release that is currently supported by Cisco Systems.
        DiscussMD5 : 48C9EDC8AEA8EE82D3771483542AB7DB
        CheckMD5   : 3BC8574C55E3EA3DF7B92C575B7B12CB
        FixMD5     : 6B4D73D26C5614740F02021AADF6ED58
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
    $FindingDetails += "Check with vendor for support status of the device" | Out-String
    $FindingDetails += "Device Info:" | Out-String
    $FindingDetails += ($DeviceInfo | Out-String).Trim()
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDsT3i55pckX+AI
# G+aSJKxwK54IFbIyiwYKewxrBDGDmqCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAhUNQMSQoJvEkeiFt3KFaKdxOVTDT3
# frGcFsDqOwLa+zANBgkqhkiG9w0BAQEFAASCAQBTw48cwB9mpDlJidevIryEOqQF
# biHnPJu+w0xZMyel4LCpnF4l++1ofK+GmWT82vaRzpN1aR2Y2n6Ibbr78GOmGMaX
# aUoKjF4ZUpg2LeTGaoyIUPz+h0SHDEp4ldFL91YF1S4Prj2ak2SqtHLV1xXKGguf
# hQnl8EHN+yveEVzFd77cZf7DYkjOxk+ev/CnopATaJMIz6X00e6+2WAMb/2TryZr
# yebeyryKk2Mvt4m3aTJmzTfL6uhENQ+mO85FOf2/6zglQ35h84hx4pa9Qvnogi46
# H4uIJS5EnHdiE8uOSmAU811NgkAQUEF8GNGit6D9upqga3grFTzu3Bwe2GqB
# SIG # End signature block
