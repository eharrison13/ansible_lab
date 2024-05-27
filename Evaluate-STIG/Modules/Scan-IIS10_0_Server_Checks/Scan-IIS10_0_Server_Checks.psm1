##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Microsoft IIS 10.0 Server
# Version:  V2R10
# Class:    UNCLASSIFIED
# Updated:  5/13/2024
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V218785 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218785
        STIG ID    : IIST-SV-000102
        Rule ID    : SV-218785r879562_rule
        CCI ID     : CCI-000130, CCI-000131, CCI-000132, CCI-000133, CCI-001462, CCI-001464
        Rule Name  : SRG-APP-000092-WSR-000055
        Rule Title : The enhanced logging for the IIS 10.0 web server must be enabled and capture all user and web server events.
        DiscussMD5 : 0A9B0278E9BB72422646524E3C0C5995
        CheckMD5   : 6ECFF6FEE5D972AE5E74417BD404BA5F
        FixMD5     : 2AFEDD2DED367F0CB4783C6DE4376C5A
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
    $FlagsToCheck = ("Date", "Time", "ClientIP", "UserName", "Method", "URIQuery", "HttpStatus", "Referer")
    $MissingFlags = ""
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $Log = Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name logFile
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name logFile}"
        $Log = Invoke-Expression $PSCommand
    }
    $LogFlags = $Log.logExtFileFlags -split ","

    Foreach ($Flag in $FlagsToCheck) {
        If ($Flag -notin $LogFlags) {
            $Compliant = $false
            $MissingFlags += $Flag | Out-String
        }
    }

    If ($Compliant -eq $true) {
        $Status = "NotAFinding"
        $FindingDetails += "Date, Time, Client IP Address, User Name, Method, URI Query, Protocol Status, and Referrer are all logged." | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "The following minimum fields are not logged:" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += $MissingFlags | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V218786 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218786
        STIG ID    : IIST-SV-000103
        Rule ID    : SV-218786r879562_rule
        CCI ID     : CCI-000139, CCI-001464, CCI-001851
        Rule Name  : SRG-APP-000092-WSR-000055
        Rule Title : Both the log file and Event Tracing for Windows (ETW) for the IIS 10.0 web server must be enabled.
        DiscussMD5 : F434548807E6F8113C2DD05CD61F4933
        CheckMD5   : 956E5DB6E68DAFEA606524DB66413D80
        FixMD5     : 39F140C4A3EA48BB93C3AD4058EF9008
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        $Log = Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name logFile
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name logFile}"
        $Log = Invoke-Expression $PSCommand
    }
    $LogTargetFormat = $Log.logTargetW3C

    If ($logTargetFormat -like "*ETW*" -and $logTargetFormat -like "*File*") {
        $FindingDetails += "Both ETW and Log file logging are enabled." | Out-String
        $Status = "NotAFinding"
    }
    Else {
        $FindingDetails += "$LogTargetFormat is the only option selected." | Out-String
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

Function Get-V218788 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218788
        STIG ID    : IIST-SV-000110
        Rule ID    : SV-218788r879567_rule
        CCI ID     : CCI-000134
        Rule Name  : SRG-APP-000099-WSR-000061
        Rule Title : The IIS 10.0 web server must produce log records that contain sufficient information to establish the outcome (success or failure) of IIS 10.0 web server events.
        DiscussMD5 : 5EA39D37105A662C7E1989390C5B404E
        CheckMD5   : AD4AD48CF677B44A1E641F89F8D7814D
        FixMD5     : 2125E7D90AF35D16A00D953A7665B32E
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        $Log = Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name logFile
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name logFile}"
        $Log = Invoke-Expression $PSCommand
    }

    $customField1_logged = $false # the custom "Connection" field we're looking for
    $customField2_logged = $false # the custom "Warning" field we're looking for

    If ($Log.logFormat -ne "W3C") {
        $Status = "Open"
        $FindingDetails += "Log format is '$($Log.logFormat)' [Expected 'W3C']" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $FindingDetails += "Log format is '$($Log.logFormat)'" | Out-String
        $FindingDetails += "" | Out-String
    }

    ForEach ($Item in $Log.customFields.Collection) {
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

Function Get-V218789 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218789
        STIG ID    : IIST-SV-000111
        Rule ID    : SV-218789r879568_rule
        CCI ID     : CCI-001487
        Rule Name  : SRG-APP-000100-WSR-000064
        Rule Title : The IIS 10.0 web server must produce log records containing sufficient information to establish the identity of any user/subject or process associated with an event.
        DiscussMD5 : EDA80E0B5A3CEB39B0D0A4342C615A1D
        CheckMD5   : DC0855F512F7A993ECD08869BD276DE8
        FixMD5     : 95EF4DE70E988231C4968546E4CCE853
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        $Log = Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name logFile
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name logFile}"
        $Log = Invoke-Expression $PSCommand
    }

    $LogFlags = $Log.logExtFileFlags -Split ","
    $FlagsToCheck = ("UserAgent", "UserName", "Referer")
    $MissingFlags = ""
    $customField1_logged = $false # the custom "Authorization" field we're looking for
    $customField2_logged = $false # the custom "Content-Type" field we're looking for

    If ($Log.logFormat -ne "W3C") {
        $Status = "Open"
        $FindingDetails += "Log format is '$($Log.logFormat)' [Expected 'W3C']" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $FindingDetails += "Log format is '$($Log.logFormat)'" | Out-String
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

        ForEach ($Item in $Log.customFields.Collection) {
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

Function Get-V218790 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218790
        STIG ID    : IIST-SV-000115
        Rule ID    : SV-218790r879578_rule
        CCI ID     : CCI-000164
        Rule Name  : SRG-APP-000120-WSR-000070
        Rule Title : The log information from the IIS 10.0 web server must be protected from unauthorized modification or deletion.
        DiscussMD5 : 6829D136C38F6394A0D4793B7C9EBF7D
        CheckMD5   : 6341048EFE228505282AE3E9E9C0FF69
        FixMD5     : 12097271F17D56938BF2FE6C4FFE0935
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        $Log = Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name logFile
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name logFile}"
        $Log = Invoke-Expression $PSCommand
    }
    $LogPath = $Log.directory -replace "%SystemDrive%", $env:SYSTEMDRIVE
    If (Test-Path $LogPath) {
        $acl = Get-Acl -Path $LogPath
        $FindingDetails += "Current ACL of $LogPath is:" | Out-String
        $FindingDetails += $acl.Access | Format-List | Out-String
    }
    Else {
        $FindingDetails += "'$LogPath' does not exist." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V218791 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218791
        STIG ID    : IIST-SV-000116
        Rule ID    : SV-218791r879582_rule
        CCI ID     : CCI-001348
        Rule Name  : SRG-APP-000125-WSR-000071
        Rule Title : The log data and records from the IIS 10.0 web server must be backed up onto a different system or media.
        DiscussMD5 : 609EB5AE0618B67333D927FBD5A83163
        CheckMD5   : B73FA66F53357A7CA1DED5663D3EC96B
        FixMD5     : 75F5D25D1EAA3052FCE116792274653D
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        $Log = Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name logFile
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name logFile}"
        $Log = Invoke-Expression $PSCommand
    }
    $LogPath = $Log.directory
    $FindingDetails += "Log Directory: $LogPath" | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += "Ensure the logs in the directory above are being backed up." | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V218793 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218793
        STIG ID    : IIST-SV-000118
        Rule ID    : SV-218793r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000075
        Rule Title : The IIS 10.0 web server must only contain functions necessary for operation.
        DiscussMD5 : C7D978E44A67836832C08298325F17AB
        CheckMD5   : A6DB3013B81CB3683CD8B1344B2B9D06
        FixMD5     : 891AC4FDBB88B1D18C4B5AFA013416F9
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $SoftwareList = Get-InstalledSoftware
    $FindingDetails += "Software installed on this system:" | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += $SoftwareList.DisplayName | Sort-Object | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V218794 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218794
        STIG ID    : IIST-SV-000119
        Rule ID    : SV-218794r928918_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000076
        Rule Title : The IIS 10.0 web server must not be both a website server and a proxy server.
        DiscussMD5 : 5F6FCF0699CC351E46A0EAF8E83895FA
        CheckMD5   : DE34BB30621A3602D1BE97141DB0CEA1
        FixMD5     : 5D4D97206B3569BF34807A5A111957DB
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        If (Get-WebConfiguration /webFarms/applicationRequestRouting) {
            $Proxy = Get-WebConfigurationProperty '/system.webServer/proxy' -Name enabled
            $FindingDetails += "Application Request Routing Cache is installed." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Proxy Enabled: $($Proxy.Value)" | Out-String
            If ($Proxy.Value -eq $true) {
                $Status = "Open"
            }
            Else {
                $Status = "NotAFinding"
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "Application Request Routing Cache is not installed." | Out-String
        }
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfiguration /webFarms/applicationRequestRouting}"
        $ARR = Invoke-Expression $PSCommand
        If ($ARR) {
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/proxy' -Name enabled}"
            $Proxy = Invoke-Expression $PSCommand
            $FindingDetails += "Application Request Routing Cache is installed." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Proxy Enabled: $($Proxy.Value)" | Out-String
            If ($Proxy.Value -eq $true) {
                $Status = "Open"
            }
            Else {
                $Status = "NotAFinding"
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "Application Request Routing Cache is not installed." | Out-String
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

Function Get-V218795 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218795
        STIG ID    : IIST-SV-000120
        Rule ID    : SV-218795r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000077
        Rule Title : All IIS 10.0 web server sample code, example applications, and tutorials must be removed from a production IIS 10.0 server.
        DiscussMD5 : 09C13A7890F7B050E42A30D32AB0B75C
        CheckMD5   : C4B39D13FFF2D630A3F462F62A71BFEF
        FixMD5     : 1178C847BC12CEC2F52B2F706A02BBE9
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ListOfSamples = ""
    $Drives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType = 3" | Select-Object DeviceID
    $Paths = @("inetpub\", "Program Files\Common Files\System\msadc", "Program Files (x86)\Common Files\System\msadc")

    ForEach ($Drive in $Drives) {
        ForEach ($Path in $Paths) {
            $SearchPath = $Drive.DeviceID + "\" + $Path
            $FileSearch = Get-ChildItem -Path $SearchPath -Recurse -Filter *sample* -ErrorAction SilentlyContinue
            If ($FileSearch) {
                ForEach ($File in $FileSearch) {
                    $ListOfSamples += $File.FullName | Out-String
                }
            }
        }
    }

    If ($ListOfSamples -ne "") {
        $FindingDetails += "The following sample files were found:" | Out-String
        $FindingDetails += "" | Out-String
        ForEach ($File in $ListOfSamples) {
            $FindingDetails += $File
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "There are no sample files in the targeted directories." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V218796 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218796
        STIG ID    : IIST-SV-000121
        Rule ID    : SV-218796r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000078
        Rule Title : The accounts created by uninstalled features (i.e., tools, utilities, specific, etc.) must be deleted from the IIS 10.0 server.
        DiscussMD5 : 2D767F9D486BEE9D7418C1014A339D48
        CheckMD5   : 746892252BC339FAECDB08377006AB33
        FixMD5     : 2F96537028721CDACA7BBEA9C527F5BE
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $FindingDetails += "Local user accounts on this system:" | Out-String
    $FindingDetails += "" | Out-String
    $server = ${env:computername}
    $computer = [ADSI]"WinNT://$server,computer"
    $computer.psbase.children | Where-Object { $_.psbase.schemaClassname -eq 'user' } | ForEach-Object {
        $FindingDetails += $_.Name | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V218797 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218797
        STIG ID    : IIST-SV-000123
        Rule ID    : SV-218797r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000080
        Rule Title : The IIS 10.0 web server must be reviewed on a regular basis to remove any Operating System features, utility programs, plug-ins, and modules not necessary for operation.
        DiscussMD5 : C5993580E73864EC4A4367E5AC56A9EB
        CheckMD5   : DD1CDBB81E9EC1CC208E78F903A3C3EB
        FixMD5     : E2379B5209BFB4044F3017356C1B2A19
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
            $Features = (Get-WindowsFeature | Where-Object Installed -EQ $true | Sort-Object Name).Name
        }
        "*Windows*10*" {
            Try {
                $Features = (Get-WindowsOptionalFeature -Online -ErrorAction Stop | Where-Object State -EQ "Enabled" | Sort-Object FeatureName).FeatureName
            }
            Catch {
                $Features = (Get-CimInstance -ClassName Win32_OptionalFeature | Where-Object InstallState -EQ 1 | Sort-Object Name).Name
            }
        }
    }

    $FindingDetails += "The following Windows features are installed:" | Out-String
    $FindingDetails += "" | Out-String
    ForEach ($Feature in $Features) {
        $FindingDetails += $Feature | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V218798 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218798
        STIG ID    : IIST-SV-000124
        Rule ID    : SV-218798r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000081
        Rule Title : The IIS 10.0 web server must have Multipurpose Internet Mail Extensions (MIME) that invoke OS shell programs disabled.
        DiscussMD5 : 8ECB7CDAD8E2AE04ADF63ED3334D0439
        CheckMD5   : BA945D1DF60D5013D823D6B1540ECDCE
        FixMD5     : 25A01DF8145D93F8D0E562155C2DB88E
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        $Configuration = (Get-WebConfiguration /system.webServer/staticContent).Collection
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; (Get-WebConfiguration /system.webServer/staticContent).Collection}"
        $Configuration = Invoke-Expression $PSCommand
    }
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

Function Get-V218799 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218799
        STIG ID    : IIST-SV-000125
        Rule ID    : SV-218799r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000085
        Rule Title : The IIS 10.0 web server must have Web Distributed Authoring and Versioning (WebDAV) disabled.
        DiscussMD5 : 347994A3E43DE623DB39C2D565B3472A
        CheckMD5   : 5AA697F323FA57E444C5DB3B535E8069
        FixMD5     : AC3DCA5FBB377986F093AD523D24AF9A
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V218800 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218800
        STIG ID    : IIST-SV-000129
        Rule ID    : SV-218800r879612_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-APP-000175-WSR-000095
        Rule Title : The IIS 10.0 web server must perform RFC 5280-compliant certification path validation.
        DiscussMD5 : 908EF21FE464ABDD781A84381981A242
        CheckMD5   : 70C5112C5D98FAB0BE4355ADDCD04BA6
        FixMD5     : 23C4C748B919E91AACD0FF8B07A3FEA3
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        $IISCertsInUse = (Get-WebBinding | Where-Object CertificateHash -ne '' | Select-Object Protocol,BindingInformation,CertificateHash,ItemXPath)
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; (Get-WebBinding | Where-Object CertificateHash -ne '' | Select Protocol,BindingInformation,CertificateHash,ItemXPath)}"
        $IISCertsInUse = Invoke-Expression $PSCommand
    }

    $CertList = New-Object System.Collections.Generic.List[System.Object]

    $PathsToSearch = @()
    ForEach ($Item in (Get-ChildItem Cert:\LocalMachine).Name) {
        $PathsToSearch += "LocalMachine\$($Item)"
    }
    ForEach ($Item in (Get-ChildItem Cert:\CurrentUser | Where-Object Name -ne "UserDS").Name) {
        $PathsToSearch += "CurrentUser\$($Item)"
    }

    ForEach ($Path in $PathsToSearch) {
#        $FoundCert = ""
        $FoundCert = Get-ChildItem Cert:\$Path -Recurse -ErrorAction SilentlyContinue | Where-Object Thumbprint -in $IISCertsInUse.certificateHash
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
                    BindingInfo    = $(($IISCertsInUse | Where-Object certificateHash -eq $Cert.Thumbprint).bindingInformation)
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

    If ($CertList) {
        If (($CertList | Where-Object ApprovedChain -eq $false | Measure-Object).Count -gt 0) {
            $Compliant = $false
            $FindingDetails += "Non-Compliant Certificates:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            ForEach ($Cert in $CertList | Where-Object ApprovedChain -eq $false) {
                $FindingDetails += "BindingInfo:`t`t$($Cert.BindingInfo)" | Out-String
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
            $FindingDetails += "Compliant Certificates:" | Out-String
            $FindingDetails += "---------------------------" | Out-String
            ForEach ($Cert in $CertList | Where-Object ApprovedChain -eq $true) {
                $FindingDetails += "BindingInfo:`t$($Cert.BindingInfo)" | Out-String
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
        $FindingDetails += "No certificates found." | Out-String
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

Function Get-V218801 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218801
        STIG ID    : IIST-SV-000130
        Rule ID    : SV-218801r879627_rule
        CCI ID     : CCI-001166
        Rule Name  : SRG-APP-000206-WSR-000128
        Rule Title : Java software installed on a production IIS 10.0 web server must be limited to .class files and the Java Virtual Machine.
        DiscussMD5 : C34C675663EFB946C566BB691B6BF1E6
        CheckMD5   : 688C9B689E7A8A8017FCE2E72288F4DB
        FixMD5     : D7FF0D77CFCFB32396ABDF0F88526E99
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $FileFindings = ""
    $Drives = Get-CimInstance Win32_LogicalDisk -Filter "DriveType = 3" | Select-Object DeviceID

    ForEach ($Drive in $Drives) {
        $BadFiles = (Get-ChildItem "$($Drive.DeviceID)\" -File -Recurse -Filter *.j??? -ErrorAction SilentlyContinue | Where-Object { ($_.FullName -NotLike "*Windows\CSC\*") -and ($_.FullName -NotLike "*Windows\WinSxS\*") -and ($_.Extension -in ".java", ".jpp") }).FullName
        If ($BadFiles) {
            ForEach ($File in $BadFiles) {
                $FileFindings += $File | Out-String
            }
        }
    }

    If ($FileFindings -eq $null -or $FileFindings -eq "") {
        $FindingDetails += "No .java or .jpp files were found on the system." | Out-String
        $Status = 'NotAFinding'
    }
    Else {
        $FindingDetails += "The following .java and/or .jpp files were found:" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += $FileFindings | Out-String
        $Status = 'Open'
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V218802 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218802
        STIG ID    : IIST-SV-000131
        Rule ID    : SV-218802r879631_rule
        CCI ID     : CCI-001082
        Rule Name  : SRG-APP-000211-WSR-000030
        Rule Title : IIS 10.0 Web server accounts accessing the directory tree, the shell, or other operating system functions and utilities must only be administrative accounts.
        DiscussMD5 : FC50236097F9C5E2009F86C84F3D924A
        CheckMD5   : 8B5C6635757839C59A4DD2F1D9339FED
        FixMD5     : 2F96654FBF48370297BFD3781F879221
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $server = ($env:COMPUTERNAME)
    $computer = [ADSI]"WinNT://$server,computer"

    $FindingDetails += "Below is a list of local groups and their members (if any):" | Out-String
    $FindingDetails += "" | Out-String

    $computer.psbase.children | Where-Object { $_.psbase.schemaClassname -eq 'group' } | ForEach-Object {
        $FindingDetails += "Group:`t" + $_.name | Out-String
        $group = [ADSI]$_.psbase.path
        $group = [ADSI]$_.psbase.path
        $group.psbase.Invoke("Members") | ForEach-Object {
            $Member = $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
            If ($Member) {
                $FindingDetails += "  $($Member)" | Out-String
            }
        }
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

Function Get-V218804 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218804
        STIG ID    : IIST-SV-000134
        Rule ID    : SV-218804r879638_rule
        CCI ID     : CCI-001664
        Rule Name  : SRG-APP-000223-WSR-000011
        Rule Title : The IIS 10.0 web server must use cookies to track session state.
        DiscussMD5 : 472CC3305D2F1AA9618D54EE19E30BD9
        CheckMD5   : 7167B0174207A0C1722FD1B7AFA8FB8F
        FixMD5     : F87A791F07751B217C77D10B7A80AB82
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        $SessionState = Get-WebConfiguration /system.web/sessionState | Select-Object *
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfiguration /system.web/sessionState | Select-Object *}"
        $SessionState = Invoke-Expression $PSCommand
    }

    If ($SessionState.cookieless -eq "UseCookies") {
        $Status = "NotAFinding"
    }
    Else {
        $Status = "Open"
    }

    $FindingDetails += "Cookie Settings Mode is configured to '$($SessionState.cookieless)'" | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V218805 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218805
        STIG ID    : IIST-SV-000135
        Rule ID    : SV-218805r928917_rule
        CCI ID     : CCI-001664
        Rule Name  : SRG-APP-000223-WSR-000145
        Rule Title : The IIS 10.0 web server must accept only system-generated session identifiers.
        DiscussMD5 : 6A41554AE9BB890F0159D610F8E95D9E
        CheckMD5   : 250D32C3BF7B4C6F24C21A6BAF4B3626
        FixMD5     : C80873CE247FD3710B1483D34F2CE786
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        $SessionState = Get-WebConfiguration /system.web/sessionState | Select-Object *
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfiguration /system.web/sessionState | Select-Object *}"
        $SessionState = Invoke-Expression $PSCommand
    }

    $MinTimeout = New-TimeSpan -Hours 00 -Minutes 20 -Seconds 00

    If (($SessionState.cookieless -eq "UseCookies") -and ($SessionState.timeout.CompareTo($MinTimeout) -le 0)) {
        $Status = "NotAFinding"
    }
    Else {
        $Status = "Open"
    }

    $FindingDetails += "Cookie Settings Mode is configured to '$($SessionState.cookieless)'" | Out-String
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

Function Get-V218807 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218807
        STIG ID    : IIST-SV-000137
        Rule ID    : SV-218807r879642_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231-WSR-000144
        Rule Title : The production IIS 10.0 web server must utilize SHA2 encryption for the Machine Key.
        DiscussMD5 : 01853B181F6F22E37F0C534E55737D04
        CheckMD5   : 9256853A613F62C12B03E9A99035AF0F
        FixMD5     : F53A3D26C643D64953E1EB9F16DAF323
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        $MachineKey = Get-WebConfiguration /system.web/machineKey | Select-Object *
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfiguration /system.web/machineKey | Select-Object *}"
        $MachineKey = Invoke-Expression $PSCommand
    }

    If (($MachineKey.validation -like "*HMAC*") -and ($MachineKey.decryption -eq "Auto")) {
        $Status = "NotAFinding"
    }
    Else {
        $Status = "Open"
    }

    $FindingDetails += "Validation method is configured to '$($MachineKey.validation)'" | Out-String
    $FindingDetails += "Encryption method is configured to '$($MachineKey.decryption)'" | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V218808 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218808
        STIG ID    : IIST-SV-000138
        Rule ID    : SV-218808r879652_rule
        CCI ID     : CCI-001310
        Rule Name  : SRG-APP-000251-WSR-000157
        Rule Title : Directory Browsing on the IIS 10.0 web server must be disabled.
        DiscussMD5 : AF5E47ECEED5B9DA40409315F14F8F59
        CheckMD5   : 577C9B19598EE64826CD331D79C5789B
        FixMD5     : 6C653F614A6BEBFD5DF85158B90305A9
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        $DirectoryBrowse = Get-WebConfiguration /system.webServer/directoryBrowse | Select-Object *
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfiguration /system.webServer/directoryBrowse | Select-Object *}"
        $DirectoryBrowse = Invoke-Expression $PSCommand
    }

    If ($DirectoryBrowse.enabled -like "*False*") {
        $Status = "NotAFinding"
        $FindingDetails += "Directory Browsing is disabled." | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "Directory Browsing is NOT disabled." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V218809 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218809
        STIG ID    : IIST-SV-000139
        Rule ID    : SV-218809r879655_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266-WSR-000142
        Rule Title : The IIS 10.0 web server Indexing must only index web content.
        DiscussMD5 : 3E7C79DBE5C25E7A6AEFE53BC12FB760
        CheckMD5   : 4DA73BF11B8974D86F334202B478EADB
        FixMD5     : 93B95736F1111669355442C21211796B
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $indexKey = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\ContentIndex\Catalogs" -ErrorAction SilentlyContinue | Out-String
    If ($indexKey -eq '') {
        #failed return of the registry key value leaves an empty string and not NULL
        $FindingDetails += "The ContentIndex\Catalogs key does not exist so this check is Not Applicable." | Out-String
        $Status = 'Not_Applicable'
    }
    Else {
        $FindingDetails += "The contentIndex key exists." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V218810 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218810
        STIG ID    : IIST-SV-000140
        Rule ID    : SV-218810r879655_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266-WSR-000159
        Rule Title : Warning and error messages displayed to clients must be modified to minimize the identity of the IIS 10.0 web server, patches, loaded modules, and directory paths.
        DiscussMD5 : 9A79AA3CE4FFA04A7672C0126E751178
        CheckMD5   : BC2D86C5E1BAA49C5B46E3B4BBCB9E02
        FixMD5     : CBDE0FDCC689DFFE13495948350CDB33
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        $HttpErrors = Get-WebConfiguration system.webServer/httpErrors | Select-Object *
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

Function Get-V218812 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218812
        STIG ID    : IIST-SV-000142
        Rule ID    : SV-218812r879692_rule
        CCI ID     : CCI-002314
        Rule Name  : SRG-APP-000315-WSR-000004
        Rule Title : The IIS 10.0 web server must restrict inbound connections from non-secure zones.
        DiscussMD5 : 08CD9504FFB47A8FF8EC3C922C406607
        CheckMD5   : B9E64FB1BE26AA0CEE6F66E0DAE00251
        FixMD5     : E663A42191074C0ABACDCB7D3B8CB266
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $managerService = Get-ItemProperty HKLM:\Software\Microsoft\WebManagement\Server -ErrorAction SilentlyContinue

    If ($managerService.EnableRemoteManagement -eq 1) {
        $FindingDetails += "The Web Management service is installed and active. This means that remote administration of IIS is possible." | Out-String
        $FindingDetails += "Verify only known, secure IP ranges are configured as 'Allow'." | Out-String
    }
    Else {
        $FindingDetails += "The remote management feature of IIS is not installed so this check is Not Applicable." | Out-String
        $Status = 'Not_Applicable'
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V218813 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218813
        STIG ID    : IIST-SV-000143
        Rule ID    : SV-218813r879693_rule
        CCI ID     : CCI-002322
        Rule Name  : SRG-APP-000316-WSR-000170
        Rule Title : The IIS 10.0 web server must provide the capability to immediately disconnect or disable remote access to the hosted applications.
        DiscussMD5 : D8F5DF452EC0EFD073A632668032D90D
        CheckMD5   : B6166A2B6D471477A74E6F2A3F7AEBD0
        FixMD5     : 12257F127470A767F9608B260EFA0852
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V218814 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218814
        STIG ID    : IIST-SV-000144
        Rule ID    : SV-218814r879717_rule
        CCI ID     : CCI-002235
        Rule Name  : SRG-APP-000340-WSR-000029
        Rule Title : IIS 10.0 web server system files must conform to minimum file permission requirements.
        DiscussMD5 : 477E584ED8F4E4FFD923BFDF65FED4E6
        CheckMD5   : 7398EBC599E7903766D78B62A03CC644
        FixMD5     : 74B28B36777656C280DC0B8B194119B2
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Path = ((Get-ItemProperty HKLM:\SOFTWARE\Microsoft\InetStp).PathWWWRoot -split "inetpub")[0] + "inetpub"

    $FindingDetails += "ACL for $($Path):" | Out-String
    $FindingDetails += (Get-Acl $Path).Access | Format-List | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V218815 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218815
        STIG ID    : IIST-SV-000145
        Rule ID    : SV-218815r879730_rule
        CCI ID     : CCI-001849
        Rule Name  : SRG-APP-000357-WSR-000150
        Rule Title : The IIS 10.0 web server must use a logging mechanism configured to allocate log record storage capacity large enough to accommodate the logging requirements of the IIS 10.0 web server.
        DiscussMD5 : 33408D1C2D140E741B60DAB0B27F4212
        CheckMD5   : 905F6405078B6BCA5522D53CAEB81DB2
        FixMD5     : 4372F25F7ABDC1E32470414B84B6F97B
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        $Log = Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name logFile
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults' -Name logFile}"
        $Log = Invoke-Expression $PSCommand
    }

    $SchedulesToCheck = ("Hourly", "Daily", "Weekly", "Monthly")

    If ($Log.period -in $SchedulesToCheck) {
        $Status = "NotAFinding"
        $FindingDetails += "Logs are set to roll over $($Log.period)." | Out-String
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

Function Get-V218816 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218816
        STIG ID    : IIST-SV-000147
        Rule ID    : SV-218816r879753_rule
        CCI ID     : CCI-000213, CCI-001813, CCI-002385
        Rule Name  : SRG-APP-000380-WSR-000072
        Rule Title : Access to web administration tools must be restricted to the web manager and the web managers designees.
        DiscussMD5 : 0A21821F27900AF53D95D1A0CF60E427
        CheckMD5   : 2BACCE4CCF43D52E5FA50AA28B6F853F
        FixMD5     : B0E9BF469A8A34363C872FDE9F84BE1B
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-Path "$($env:WINDIR)\system32\inetsrv\Inetmgr.exe") {
        $FindingDetails += "ACL for $($env:WINDIR)\system32\inetsrv\Inetmgr.exe:" | Out-String
        $FindingDetails += (Get-Acl "$env:WINDIR\system32\inetsrv\Inetmgr.exe").Access | Format-List | Out-String
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "InetMgr.exe does not exist on this system." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V218817 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218817
        STIG ID    : IIST-SV-000148
        Rule ID    : SV-218817r879756_rule
        CCI ID     : CCI-001762
        Rule Name  : SRG-APP-000383-WSR-000175
        Rule Title : The IIS 10.0 web server must not be running on a system providing any other role.
        DiscussMD5 : 33EB819CF30A698D3E5F72D6B4047690
        CheckMD5   : DD4E67916A5A99A312CADB599041EC35
        FixMD5     : 9286EC86ED9F3409683DBC095281B6EE
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $SoftwareList = Get-InstalledSoftware
    $FindingDetails += "Software installed on this system:" | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += $SoftwareList.DisplayName | Sort-Object | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V218818 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218818
        STIG ID    : IIST-SV-000149
        Rule ID    : SV-218818r879756_rule
        CCI ID     : CCI-001762
        Rule Name  : SRG-APP-000383-WSR-000175
        Rule Title : The Internet Printing Protocol (IPP) must be disabled on the IIS 10.0 web server.
        DiscussMD5 : EBA8DB2774B57D02EF73267B40D89B2B
        CheckMD5   : B109FB8C37C166F768FF299976AA05E4
        FixMD5     : A2266D9B4EC262D14F83774CF2517A62
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (Test-Path "$env:windir\web\printers") {
        $Status = "Open"
        $FindingDetails += "'$env:windir\web\printers' exists. [Finding]" | Out-String
    }
    Else {
        $FindingDetails += "'$env:windir\web\printers' does not exist." | Out-String
        $FindingDetails += "" | Out-String
        Switch -Wildcard (((Get-CimInstance Win32_OperatingSystem).Caption)) {
            "*Windows*Server*" {
                If (((Get-WindowsFeature -Name Print-Services).Installed -eq $false) -and ((Get-WindowsFeature -Name Internet-Print-Client).Installed -eq $false)) {
                    $Status = "Not_Applicable"
                    $FindingDetails += "The Print Services role and the Internet Printing role are not installed so this check is Not Applicable." | Out-String
                }
                ElseIf ((Get-WindowsFeature -name "Internet-Print-Client").installed -eq $true) {
                    $Status = "Open"
                    $FindingDetails += "Internet-Print-Client is installed." | Out-String
                }
                Else {
                    $Status = "NotAFinding"
                    $FindingDetails += "Internet-Print-Client is not installed." | Out-String
                }
            }
            "*Windows*10*" {
                Try {
                    If ((Get-WindowsOptionalFeature -Online -FeatureName "Printing-Foundation-InternetPrinting-Client" -ErrorAction Stop).State -eq "Enabled") {
                        $Status = "Open"
                        $FindingDetails += "Printing-Foundation-InternetPrinting-Client is enabled." | Out-String
                    }
                    Else {
                        $Status = "NotAFinding"
                        $FindingDetails += "Printing-Foundation-InternetPrinting-Client is not enabled." | Out-String
                    }
                }
                Catch {
                    If ((Get-CimInstance -ClassName Win32_OptionalFeature | Where-Object Name -EQ "Printing-Foundation-InternetPrinting-Client").InstallState -eq 1) {
                        $Status = "Open"
                        $FindingDetails += "Printing-Foundation-InternetPrinting-Client is enabled." | Out-String
                    }
                    Else {
                        $Status = "NotAFinding"
                        $FindingDetails += "Printing-Foundation-InternetPrinting-Client is not enabled." | Out-String
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

Function Get-V218819 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218819
        STIG ID    : IIST-SV-000151
        Rule ID    : SV-218819r879806_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-APP-000435-WSR-000148
        Rule Title : The IIS 10.0 web server must be tuned to handle the operational requirements of the hosted application.
        DiscussMD5 : DFAE83FBE76B2602F2327361A69713C4
        CheckMD5   : 4DA25E0301AC7DECC089ECF82E48142D
        FixMD5     : 2A5BB84F0AEA2E5C29979D34BCA69D30
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
    $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters"

    $uriEnableCache = Get-RegistryResult -Path $RegistryPath -ValueName URIEnableCache
    $uriMaxUriBytes = Get-RegistryResult -Path $RegistryPath -ValueName UriMaxUriBytes
    $uriScavengerPeriod = Get-RegistryResult -Path $RegistryPath -ValueName UriScavengerPeriod

    If ($uriEnableCache.Value -eq "(NotFound)" -or $uriMaxUriBytes.Value -eq "(NotFound)" -or $uriScavengerPeriod.Value -eq "(NotFound)") {
        $Compliant = $false
    }

    $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
    $FindingDetails += "Value Name:`turiEnableCache" | Out-String
    $FindingDetails += "Value:`t`t$($uriEnableCache.Value)" | Out-String
    $FindingDetails += "Type:`t`t$($uriEnableCache.Type)" | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
    $FindingDetails += "Value Name:`turiMaxUriBytes" | Out-String
    $FindingDetails += "Value:`t`t$($uriMaxUriBytes.Value)" | Out-String
    $FindingDetails += "Type:`t`t$($uriMaxUriBytes.Type)" | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
    $FindingDetails += "Value Name:`turiScavengerPeriod" | Out-String
    $FindingDetails += "Value:`t`t$($uriScavengerPeriod.Value)" | Out-String
    $FindingDetails += "Type:`t`t$($uriScavengerPeriod.Type)" | Out-String
    $FindingDetails += "" | Out-String

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

Function Get-V218820 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218820
        STIG ID    : IIST-SV-000152
        Rule ID    : SV-218820r879810_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000439-WSR-000152
        Rule Title : IIS 10.0 web server session IDs must be sent to the client using TLS.
        DiscussMD5 : 000CD73AF14A0386716C66AE794D8F4C
        CheckMD5   : 7A5B9BACD5C983AF669369E815F9DE14
        FixMD5     : 9B8044562AC78B2019EB04D4F1009897
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        $Session = Get-WebConfigurationProperty '/system.webServer/asp' -Name session
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/asp' -Name session}"
        $Session = Invoke-Expression $PSCommand
    }

    If ($Session.keepSessionIdSecure -eq $true) {
        $Status = "NotAFinding"
    }
    Else {
        $Status = "Open"
    }

    $FindingDetails += "keepSessionIdSecure is set to $($Session.keepSessionIdSecure)"
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V218821 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218821
        STIG ID    : IIST-SV-000153
        Rule ID    : SV-218821r903106_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000439-WSR-000156
        Rule Title : An IIS 10.0 web server must maintain the confidentiality of controlled information during transmission through the use of an approved Transport Layer Security (TLS) version.
        DiscussMD5 : CA400469361F3E2D54A4FB7586699F02
        CheckMD5   : 77EEB35BFAFBA3D6962E984B68DD5EBE
        FixMD5     : 5FFDC5AFD37B41AAACE2ED0C4B49F447
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

    # TLS 1.2 Check
    # -------------
    # Check DisabledByDefault - "0" REG_DWORD
    $Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
    $RegistryResult = Get-RegistryResult -Path $Path -ValueName "DisabledByDefault"
    $FindingDetails += $Path | Out-String
    If ($RegistryResult.Value -ne "(NotFound)") {
        $FindingDetails += "ValueName 'DisabledByDefault' is '$($RegistryResult.Value)' ($($RegistryResult.Type))" | Out-String
    }
    Else {
        $FindingDetails += "ValueName 'DisabledByDefault' does NOT exist" | Out-String
    }
    If ($RegistryResult.Value -ne "0" -or $RegistryResult.Type -ne "REG_DWORD") {
        $Compliant = $false
    }

    # Check Enabled - "1" REG_DWORD
    $RegistryResult = Get-RegistryResult -Path $Path -ValueName "Enabled"
    If ($RegistryResult.Value -ne "(NotFound)") {
        $FindingDetails += "ValueName 'Enabled' is '$($RegistryResult.Value)' ($($RegistryResult.Type))" | Out-String
    }
    Else {
        $FindingDetails += "ValueName 'Enabled' does NOT exist" | Out-String
    }
    If ($RegistryResult.Value -ne "1" -or $RegistryResult.Type -ne "REG_DWORD") {
        $Compliant = $false
    }
    $FindingDetails += "" | Out-String

    # TLS 1.0, TLS 1.1, SSL 2.0, and SSL 3.0 Checks
    # ---------------------------------------------
    $Paths = @("HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server", "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server", "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server", "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server")
    ForEach ($Path in $Paths) {
        # Check DisabledByDefault - "1" REG_DWORD
        $RegistryResult = Get-RegistryResult -Path $Path -ValueName "DisabledByDefault"
        $FindingDetails += $Path | Out-String
        If ($RegistryResult.Value -ne "(NotFound)") {
            $FindingDetails += "ValueName 'DisabledByDefault' is '$($RegistryResult.Value)' ($($RegistryResult.Type))" | Out-String
        }
        Else {
            $FindingDetails += "ValueName 'DisabledByDefault' does NOT exist" | Out-String
        }
        If ($RegistryResult.Value -ne "1" -or $RegistryResult.Type -ne "REG_DWORD") {
            $Compliant = $false
        }

        # Check Enabled - "0" REG_DWORD
        $RegistryResult = Get-RegistryResult -Path $Path -ValueName "Enabled"
        If ($RegistryResult.Value -ne "(NotFound)") {
            $FindingDetails += "ValueName 'Enabled' is '$($RegistryResult.Value)' ($($RegistryResult.Type))" | Out-String
        }
        Else {
            $FindingDetails += "ValueName 'Enabled' does NOT exist" | Out-String
        }
        If ($RegistryResult.Value -ne "0" -or $RegistryResult.Type -ne "REG_DWORD") {
            $Compliant = $false
        }
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

Function Get-V218822 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218822
        STIG ID    : IIST-SV-000154
        Rule ID    : SV-218822r879810_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000439-WSR-000156
        Rule Title : The IIS 10.0 web server must maintain the confidentiality of controlled information during transmission through the use of an approved Transport Layer Security (TLS) version.
        DiscussMD5 : AE2A46B51632E995EE565C87124F81FD
        CheckMD5   : 76FB933687D73DF42D38E4B9B3760715
        FixMD5     : EB8AEA8ED19DEDAF98FC26498867238F
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

    # TLS 1.2 Check
    $Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
    $RegistryResult = Get-RegistryResult -Path $Path -ValueName "DisabledByDefault"
    $FindingDetails += $Path | Out-String
    If ($RegistryResult.Value -ne "(NotFound)") {
        $FindingDetails += "ValueName 'DisabledByDefault' is '$($RegistryResult.Value)' ($($RegistryResult.Type))" | Out-String
    }
    Else {
        $FindingDetails += "ValueName 'DisabledByDefault' does NOT exist" | Out-String
    }
    $FindingDetails += "" | Out-String
    If ($RegistryResult.Value -ne "0" -or $RegistryResult.Type -ne "REG_DWORD") {
        $Compliant = $false
    }

    # TLS 1.0, TLS 1.1, SSL 2.0, and SSL 3.0 Checks
    $Paths = @("HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server", "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server", "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server", "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server")
    ForEach ($Path in $Paths) {
        # Check DisabledByDefault - "1" REG_DWORD
        $RegistryResult = Get-RegistryResult -Path $Path -ValueName "DisabledByDefault"
        $FindingDetails += $Path | Out-String
        If ($RegistryResult.Value -ne "(NotFound)") {
            $FindingDetails += "ValueName 'DisabledByDefault' is '$($RegistryResult.Value)' ($($RegistryResult.Type))" | Out-String
        }
        Else {
            $FindingDetails += "ValueName 'DisabledByDefault' does NOT exist" | Out-String
        }
        If ($RegistryResult.Value -ne "1" -or $RegistryResult.Type -ne "REG_DWORD") {
            $Compliant = $false
        }

        # Check Enabled - "0" REG_DWORD
        $RegistryResult = Get-RegistryResult -Path $Path -ValueName "Enabled"
        If ($RegistryResult.Value -ne "(NotFound)") {
            $FindingDetails += "ValueName 'Enabled' is '$($RegistryResult.Value)' ($($RegistryResult.Type))" | Out-String
        }
        Else {
            $FindingDetails += "ValueName 'Enabled' does NOT exist" | Out-String
        }
        If ($RegistryResult.Value -ne "0" -or $RegistryResult.Type -ne "REG_DWORD") {
            $Compliant = $false
        }
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

Function Get-V218823 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218823
        STIG ID    : IIST-SV-000156
        Rule ID    : SV-218823r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000079
        Rule Title : All accounts installed with the IIS 10.0 web server software and tools must have passwords assigned and default passwords changed.
        DiscussMD5 : 765F969A6907D0491E17D96752F8981C
        CheckMD5   : 8EC408AEEF8585DBA09583CC8779BCD4
        FixMD5     : 257E5F90EB9EA3F778F69B7A137745F5
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $LocalUsers = Get-LocalUser | Where-Object SID -NotLike "*-503" # Exclude 'DefaultAccount'

    $FindingDetails += "Local user accounts on this system.  Confirm if any are used by IIS and if so, verify that default passwords have been changed:" | Out-String
    $FindingDetails += "" | Out-String
    ForEach ($User in $LocalUsers) {
        $FindingDetails += "Name:`t`t$($User.Name)" | Out-String
        $FindingDetails += "Enabled:`t`t$($User.Enabled)" | Out-String
        $FindingDetails += "SID:`t`t`t$($User.SID)" | Out-String
        If ($null -eq $User.PasswordLastSet) {
            $FindingDetails += "Password Age:`tNever Set" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $FindingDetails += "Password Age:`t$((New-TimeSpan -Start $($User.PasswordLastSet) -End (Get-Date)).Days) days" | Out-String
            $FindingDetails += "" | Out-String
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

Function Get-V218824 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218824
        STIG ID    : IIST-SV-000158
        Rule ID    : SV-218824r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : Unspecified file extensions on a production IIS 10.0 web server must be removed.
        DiscussMD5 : DBE580B563E337D7DD1A48ADEC6F1F8E
        CheckMD5   : EE8248873AC7FA3B9CED0A568926C004
        FixMD5     : 3C86DD6FF359042EF697B063E4A381DE
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        $isapiRestriction = Get-WebConfigurationProperty '/system.webServer/security/isapiCgiRestriction' -Name notListedIsapisAllowed | Select-Object Value
        $cgiRestriction = Get-WebConfigurationProperty '/system.webServer/security/isapiCgiRestriction' -Name notListedCgisAllowed | Select-Object Value
    }
    Else {
        $PSCommand1 = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/security/isapiCgiRestriction' -Name notListedIsapisAllowed | Select-Object Value}"
        $PSCommand2 = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/security/isapiCgiRestriction' -Name notListedCgisAllowed | Select-Object Value}"
        $isapiRestriction = Invoke-Expression $PSCommand1
        $cgiRestriction = Invoke-Expression $PSCommand2
    }

    If ($isapiRestriction.value -eq $false) {
        $FindingDetails += "Unspecified ISAPI is not enabled. NOT A FINDING." | Out-String
    }
    Else {
        $FindingDetails += "Unspecified ISAPI is enabled. FINDING." | Out-String
        $Status = 'Open'
    }
    If ($cgiRestriction.value -eq $false) {
        $FindingDetails += "Unspecified CGI is not enabled. NOT A FINDING." | Out-String
    }
    Else {
        $FindingDetails += "Unspecified CGI is enabled. FINDING." | Out-String
        $Status = 'Open'
    }

    If ($Status -ne 'Open') {
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

Function Get-V218825 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218825
        STIG ID    : IIST-SV-000159
        Rule ID    : SV-218825r928846_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The IIS 10.0 web server must have a global authorization rule configured to restrict access.
        DiscussMD5 : DDAC35E21CC8DDA3A508E6007F7D43F9
        CheckMD5   : 3A5FA80D65610E901B812AA46B94BDB1
        FixMD5     : F5209E21863D7ABF56BBA786FB7D74AC
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    Try {
        $IIS_NetFxFeatures = Get-WindowsOptionalFeature -Online -ErrorAction Stop | Where-Object {($_.FeatureName -like "IIS-NetFxExtensibility*") -and ($_.State -eq "Enabled")}
    }
    Catch {
        $IIS_NetFxFeatures = Get-CimInstance -ClassName Win32_OptionalFeature | Where-Object {($_.Name -like "IIS-NetFxExtensibility*") -and ($_.InstallState -eq 1)}
    }

    If (-Not($IIS_NetFxFeatures)) {
        $Status = "Not_Applicable"
        $FindingDetails += "IIS .NET Extensibility features are not installed so this requirement is NA."
    }
    ElseIf (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -Like "SPTimer*") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting SharePoint so this requirement is NA."
    }
    ElseIf (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "WsusService") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting WSUS so this requirement is NA."
    }
    ElseIf (Get-Service -ErrorAction SilentlyContinue | Where-Object Name -EQ "MSExchangeServiceHost") {
        $Status = "Not_Applicable"
        $FindingDetails += "This system is currently hosting Exchange so this requirement is NA."
    }
    Else {
        $Compliant = $true
        $RuleList = New-Object System.Collections.Generic.List[System.Object]

        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Import-Module WebAdministration
            $AuthCollection = Get-WebConfigurationProperty -Filter '/system.web/authorization' -Name *
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty -Filter '/system.web/authorization' -Name *}"
            $AuthCollection = Invoke-Expression $PSCommand
        }

        # If All Users rule does not exist, mark as non-compliant
        If (-Not($AuthCollection.Collection | Where-Object {($_.users -eq "*" -and $_.ElementTagName -eq "allow")})) {
            $Compliant = $false
            $NewObj = [PSCustomObject]@{
                Mode      = "allow"
                Users     = "All Users"
                Roles     = ""
                Verbs     = ""
                Compliant = $false
                Reason    = "Expected rule missing"
            }
            $RuleList.Add($NewObj)
        }

        # If Anonymous Users rule does not exist, mark as non-compliant
        If (-Not($AuthCollection.Collection | Where-Object {($_.users -eq "?" -and $_.ElementTagName -eq "deny")})) {
            $Compliant = $false
            $NewObj = [PSCustomObject]@{
                Mode      = "deny"
                Users     = "Anonymous Users"
                Roles     = ""
                Verbs     = ""
                Compliant = $false
                Reason    = "Expected rule missing"
            }
            $RuleList.Add($NewObj)
        }

        # If any unexpected rules exist, mark as non-compliant
        ForEach ($Item in $AuthCollection.Collection) {
            If (($Item.users -eq "*" -and $Item.ElementTagName -eq "allow") -or ($Item.users -eq "?" -and $Item.ElementTagName -eq "deny")) {
                $RuleCompliant = $true
                $Reason = ""
            }
            Else {
                $Compliant = $false
                $RuleCompliant = $false
                $Reason = "Unexpected rule"
            }

            $NewObj = [PSCustomObject]@{
                Mode      = $Item.ElementTagName
                Users     = $(Switch ($Item.users) {
                        "*" {
                            "All Users"
                        } "?" {
                            "Anonymous Users"
                        } Default {
                            $Item.users
                        }
                    })
                Roles     = $Item.roles
                Verbs     = $Item.verbs
                Compliant = $RuleCompliant
                Reason    = $Reason
            }
            $RuleList.Add($NewObj)
        }

        If ($RuleList | Where-Object Compliant -EQ $false) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Non-Compliant Rules:" | Out-String
            $FindingDetails += "--------------------" | Out-String
            ForEach ($Rule in ($RuleList | Where-Object Compliant -EQ $false)) {
                $FindingDetails += "Mode:`t$($Rule.mode)" | Out-String
                $FindingDetails += "Users:`t$($Rule.users)" | Out-String
                $FindingDetails += "Roles:`t$($Rule.roles)" | Out-String
                $FindingDetails += "Verbs:`t$($Rule.verbs)" | Out-String
                $FindingDetails += "Reason:`t$($Rule.Reason)" | Out-String
                $FindingDetails += "" | Out-String
            }
        }

        $FindingDetails += "Compliant Rules:" | Out-String
        $FindingDetails += "----------------" | Out-String
        ForEach ($Rule in ($RuleList | Where-Object Compliant -EQ $true)) {
            $FindingDetails += "Mode:`t$($Rule.mode)" | Out-String
            $FindingDetails += "Users:`t$($Rule.users)" | Out-String
            $FindingDetails += "Roles:`t$($Rule.roles)" | Out-String
            $FindingDetails += "Verbs:`t$($Rule.verbs)" | Out-String
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

Function Get-V218826 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218826
        STIG ID    : IIST-SV-000200
        Rule ID    : SV-218826r879511_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-WSR-000001
        Rule Title : The IIS 10.0 websites MaxConnections setting must be configured to limit the number of allowed simultaneous session requests.
        DiscussMD5 : F70469AF3681FD3332192F56E30517A9
        CheckMD5   : AA4135646BA1B2A8C230646557A45852
        FixMD5     : 6D553DD0970CACF3DBCB620179D1C3F0
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        $MaxConnections = Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults/limits' -Name maxConnections
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults/limits' -Name maxConnections}"
        $MaxConnections = Invoke-Expression $PSCommand
    }

    If ($MaxConnections.Value -gt 0) {
        $Status = "NotAFinding"
    }
    Else {
        $Status = "Open"
    }

    $FindingDetails += "MaxConnections is set to $($MaxConnections.Value)" | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V218827 {
    <#
    .DESCRIPTION
        Vuln ID    : V-218827
        STIG ID    : IIST-SV-000205
        Rule ID    : SV-218827r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The IIS 10.0 web server must enable HTTP Strict Transport Security (HSTS).
        DiscussMD5 : F2EE977F620FB8F92CD92C285B937CEB
        CheckMD5   : 9593BE282149BBAE6DCA49D292FD317B
        FixMD5     : D33D3F2483263DB94EF62AA7FD889ABE
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ReleaseId = Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ReleaseId
    If ($ReleaseId -lt "1709") {
        $Status = "NotAFinding"
        $FindingDetails += "Windows Server 2016 version is $ReleaseId which does not natively support HTST so this requirement is Not A Finding."
    }
    Else {
        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Import-Module WebAdministration
            $HSTSenabled = Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults/hsts' -Name enabled
            $HSTSmaxage = Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults/hsts' -Name max-age
            $HSTSincludeSubDomains = Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults/hsts' -Name includeSubDomains
            $HSTSredirectHttpToHttps = Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults/hsts' -Name redirectHttpToHttps
        }
        Else {
            $PSCommand1 = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults/hsts' -Name enabled}"
            $PSCommand2 = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults/hsts' -Name max-age}"
            $PSCommand3 = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults/hsts' -Name includeSubDomains}"
            $PSCommand4 = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.applicationHost/sites/siteDefaults/hsts' -Name redirectHttpToHttps}"
            $HSTSenabled = Invoke-Expression $PSCommand1
            $HSTSmaxage = Invoke-Expression $PSCommand2
            $HSTSincludeSubDomains = Invoke-Expression $PSCommand3
            $HSTSredirectHttpToHttps = Invoke-Expression $PSCommand4
        }

        If ($HSTSenabled.Value -eq $true) {
            $FindingDetails += "HSTS is enabled. NOT A FINDING." | Out-String
        }
        Else {
            $FindingDetails += "HSTS is not enabled. FINDING." | Out-String
            $Status = "Open"
        }

        If ($HSTSmaxage.Value -gt 0) {
            $FindingDetails += "HSTS max-age is $($HSTSmaxage.Value). NOT A FINDING." | Out-String
        }
        ElseIf (-Not($HSTSmaxage.Value)) {
            $FindingDetails += "HSTS max-age is not configured. FINDING." | Out-String
            $Status = "Open"
        }
        Else {
            $FindingDetails += "HSTS max-age is $($HSTSmaxage.Value). FINDING." | Out-String
            $Status = "Open"
        }

        If ($HSTSincludeSubDomains.Value -eq $true) {
            $FindingDetails += "HSTS includeSubDomains is enabled. NOT A FINDING." | Out-String
        }
        Else {
            $FindingDetails += "HSTS includeSubDomains is not enabled. FINDING." | Out-String
            $Status = "Open"
        }

        If ($HSTSredirectHttpToHttps.Value -eq $true) {
            $FindingDetails += "HSTS redirectHttpToHttps is enabled. NOT A FINDING." | Out-String
        }
        Else {
            $FindingDetails += "HSTS redirectHttpToHttps is not enabled. FINDING." | Out-String
            $Status = 'Open'
        }

        If ($Status -ne 'Open') {
            $Status = 'NotAFinding'
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

Function Get-V228572 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228572
        STIG ID    : IIST-SV-000160
        Rule ID    : SV-228572r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000075
        Rule Title : An IIS Server configured to be a SMTP relay must require authentication.
        DiscussMD5 : 7C24F99DC2824D9CA7F1F4BE3415DB76
        CheckMD5   : 65A78EAF903E0BC113394796E6A22495
        FixMD5     : 288FF1C2C54726F3F49126342B2BAF7D
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ((Get-CimInstance Win32_OperatingSystem).Caption -like "*Windows*Server*") {
        $SMTP_Feature = Get-WindowsFeature | Where-Object Name -EQ "SMTP-Server"
        $FindingDetails += "SMTP-Server Feature:`t$($SMTP_Feature.InstallState)" | Out-String
        $FindingDetails += "" | Out-String
    }

    $Port25 = Get-NetTCPConnection | Where-Object LocalPort -EQ 25 | Select-Object -Property LocalPort, State, @{'Name' = 'ProcessName'; 'Expression' = {(Get-Process -Id $_.OwningProcess).Name}}
    If (-Not($Port25)) {
        $FindingDetails += "System is not listening on port 25.  Confirm there are no SMTP relays using a custom port.  If no SMTP relays exist, this may be marked as 'Not Applicable'." | Out-String
    }
    Else {
        $FindingDetails += "Process found on port 25.  Confirm if it is SMTP and if so, that it's configured per STIG." | Out-String
        $FindingDetails += "" | Out-String
        ForEach ($Item in $Port25) {
            $FindingDetails += "LocalPort:`t$($Item.LocalPort)" | Out-String
            $FindingDetails += "State`t`t:$($Item.State)" | Out-String
            $FindingDetails += "ProcessName:`t$($Item.ProcessName)" | Out-String
            $FindingDetails += "" | Out-String
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

Function Get-V241788 {
    <#
    .DESCRIPTION
        Vuln ID    : V-241788
        STIG ID    : IIST-SV-000210
        Rule ID    : SV-241788r879655_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266-WSR-000159
        Rule Title : HTTPAPI Server version must be removed from the HTTP Response Header information.
        DiscussMD5 : 1C7BBFE951E2B9E4229EF993EFE5FE9E
        CheckMD5   : 38EAA29172D44EFFD1DE79880C84CA83
        FixMD5     : 3E2BB397C2F4401B7CCEDC66B93383B2
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
    $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters"  # Registry path identified in STIG
    $RegistryValueName = "DisableServerHeader"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "HTTPAPI Server version"  # GPO setting name identified in STIG
    $SettingState = "removed from the HTTP Response Header information"  # GPO configured state identified in STIG.

    $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        $Status = "Open"
        $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
        $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
    }
    Else {
        #If the registry value is found...
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
            $Status = "NotAFinding"
            $FindingDetails += "$($SettingName) is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
            $Status = "Open"
            $FindingDetails += "$($SettingName) is NOT $($SettingState)" | Out-String
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

Function Get-V241789 {
    <#
    .DESCRIPTION
        Vuln ID    : V-241789
        STIG ID    : IIST-SV-000215
        Rule ID    : SV-241789r879655_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266-WSR-000159
        Rule Title : ASP.NET version must be removed from the HTTP Response Header information.
        DiscussMD5 : 1C7BBFE951E2B9E4229EF993EFE5FE9E
        CheckMD5   : 63755B33557A558FB000CE3DEC23FA06
        FixMD5     : D1C20F6D1EF75385303E6A26B3A41A75
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
    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Import-Module WebAdministration
        $CustomHeaders = Get-WebConfiguration -Filter 'system.webServer/httpProtocol/customHeaders' | Select-Object -ExpandProperty Collection
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfiguration -Filter 'system.webServer/httpProtocol/customHeaders' | Select-Object -ExpandProperty Collection}"
        $CustomHeaders = Invoke-Expression $PSCommand
    }

    If ("X-Powered-By" -in $CustomHeaders.Name) {
        $Status = "Open"
        $FindingDetails += "'X-Powered-By' HTTP header has NOT been removed:" | Out-String
        ForEach ($Item in ($CustomHeaders | Where-Object Name -EQ "X-Powered-By")) {
            $FindingDetails += "" | Out-String
            $FindingDetails += "Name:`t$($Item.name)" | Out-String
            $FindingDetails += "Value:`t$($Item.value)" | Out-String
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "'X-Powered-By' HTTP header has been removed." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAZpYHh0w0lNnF0
# enfF8Y2qd0SjivArLS/+oV+1wP5fxqCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCC74Cc4QBx0wF20cPbT0HTgfcBQjR7H
# ZId83jFiyla4nTANBgkqhkiG9w0BAQEFAASCAQAmyNLlJQQhvBoamqi0U6gKkJAi
# FhG7i9/7mzfP5bhE7mYR6xjvhROuhUY+eOwv1i/fvpbUTDZC/jNUspiq57wr8KWo
# W2+j6Yj9IxkiMxhmKhQqIt5i6rwWaeIXVqHkmZChPx6pJwz97VzYWx158ON90LcY
# KU68g2kYSwOaZXce3diWStvLbafOX1TvkSqn3H51bByNrQSwJSYOaSa/6tocTaYv
# inByFFFOQGb27C2AnYOb2/fzqekc3wWTJsS8DJT+2AQHCtZ45jFKWgQRmqNcoWcw
# V/4MlHLOTetDrMQNo9e0bhTWMZ4jeLqVHFt6KgPP6ruJ/cVq3DNSRN95CkHr
# SIG # End signature block
