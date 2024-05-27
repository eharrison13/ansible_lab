##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Microsoft IIS 8.5 Server
# Version:  V2R7
# Class:    UNCLASSIFIED
# Updated:  5/13/2024
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V214400 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214400
        STIG ID    : IISW-SV-000102
        Rule ID    : SV-214400r879562_rule
        CCI ID     : CCI-000130, CCI-000131, CCI-000132, CCI-000133, CCI-001462, CCI-001464
        Rule Name  : SRG-APP-000092-WSR-000055
        Rule Title : The enhanced logging for the IIS 8.5 web server must be enabled and capture all user and web server events.
        DiscussMD5 : B7789C0CB383441A61A7AFA06FF55699
        CheckMD5   : 33C9CFC1A578D883FC9E30953CF3494E
        FixMD5     : D72D9BEA23B0741C3F9089ECF7909272
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V214401 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214401
        STIG ID    : IISW-SV-000103
        Rule ID    : SV-214401r879562_rule
        CCI ID     : CCI-000139, CCI-001464, CCI-001851
        Rule Name  : SRG-APP-000092-WSR-000055
        Rule Title : Both the log file and Event Tracing for Windows (ETW) for the IIS 8.5 web server must be enabled.
        DiscussMD5 : CE50042EBCEDEC0CA45B951E350B444E
        CheckMD5   : 416FBEE12284655B8898969404A798EB
        FixMD5     : 409478844713FA54A464851559907345
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V214403 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214403
        STIG ID    : IISW-SV-000110
        Rule ID    : SV-214403r879567_rule
        CCI ID     : CCI-000134
        Rule Name  : SRG-APP-000099-WSR-000061
        Rule Title : The IIS 8.5 web server must produce log records that contain sufficient information to establish the outcome (success or failure) of IIS 8.5 web server events.
        DiscussMD5 : 4CBE40B042FDA8A92BC8FCE2E5AFC138
        CheckMD5   : 4DDBC443D3F2DA52148771E7E15E43E7
        FixMD5     : 9FDD5C8B01AAD69B85B8BEEDE3CB6E3B
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V214404 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214404
        STIG ID    : IISW-SV-000111
        Rule ID    : SV-214404r879568_rule
        CCI ID     : CCI-001487
        Rule Name  : SRG-APP-000100-WSR-000064
        Rule Title : The IIS 8.5 web server must produce log records containing sufficient information to establish the identity of any user/subject or process associated with an event.
        DiscussMD5 : EDA80E0B5A3CEB39B0D0A4342C615A1D
        CheckMD5   : F1D8FEB2C0C093C7FAAA63B141F93B73
        FixMD5     : 02A271C39A5BC110F94EC3C94795D496
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V214405 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214405
        STIG ID    : IISW-SV-000115
        Rule ID    : SV-214405r879578_rule
        CCI ID     : CCI-000162, CCI-000163, CCI-000164
        Rule Name  : SRG-APP-000120-WSR-000070
        Rule Title : The log information from the IIS 8.5 web server must be protected from unauthorized modification or deletion.
        DiscussMD5 : 6141D87623D411749B62D8D809501358
        CheckMD5   : 7E71BF465AD55CA837DD4A167E078C28
        FixMD5     : FD916801D31AF9DF9ECA22D00312D78B
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V214406 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214406
        STIG ID    : IISW-SV-000116
        Rule ID    : SV-214406r879582_rule
        CCI ID     : CCI-001348
        Rule Name  : SRG-APP-000125-WSR-000071
        Rule Title : The log data and records from the IIS 8.5 web server must be backed up onto a different system or media.
        DiscussMD5 : AA07D61AF9D2A1EA53502F58F59E26E6
        CheckMD5   : 95D3E5E9404ED7BDC8F65B761B5D9506
        FixMD5     : DBBB39BADA5A2327513A14DD7F7C45C3
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V214408 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214408
        STIG ID    : IISW-SV-000118
        Rule ID    : SV-214408r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000075
        Rule Title : The IIS 8.5 web server must only contain functions necessary for operation.
        DiscussMD5 : B5C1B6D042AB37DB8AB103660F2B7AA5
        CheckMD5   : 655B542F490F1AE77B63037E45E0056E
        FixMD5     : 80C789254AC80A163E78955B4D821933
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V214409 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214409
        STIG ID    : IISW-SV-000119
        Rule ID    : SV-214409r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000076
        Rule Title : The IIS 8.5 web server must not be both a website server and a proxy server.
        DiscussMD5 : C8A4498C7BFDECF9C554A08F50EFCB4C
        CheckMD5   : 2BFCDA7AAB426769FA5D5CC0732618AB
        FixMD5     : 6FD88BFDE0749A4B93C3291E303CFB35
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
            $FindingDetails += "Application Request Routing is installed." | Out-String
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
            $FindingDetails += "Application Request Routing is not installed." | Out-String
        }
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfiguration /webFarms/applicationRequestRouting}"
        $ARR = Invoke-Expression $PSCommand
        If ($ARR) {
            $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/proxy' -Name enabled}"
            $Proxy = Invoke-Expression $PSCommand
            $FindingDetails += "Application Request Routing is installed." | Out-String
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
            $FindingDetails += "Application Request Routing is not installed." | Out-String
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

Function Get-V214410 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214410
        STIG ID    : IISW-SV-000120
        Rule ID    : SV-214410r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000077
        Rule Title : All IIS 8.5 web server sample code, example applications, and tutorials must be removed from a production IIS 8.5 server.
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

Function Get-V214411 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214411
        STIG ID    : IISW-SV-000121
        Rule ID    : SV-214411r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000078
        Rule Title : The accounts created by uninstalled features (i.e., tools, utilities, specific, etc.) must be deleted from the IIS 8.5 server.
        DiscussMD5 : 4953949DA6AC69E80F4BE3BE1040075E
        CheckMD5   : 6F5BDD210B59F238F363716080A45D45
        FixMD5     : 1A9E481E29C63400985B740FAF3FFFFF
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V214412 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214412
        STIG ID    : IISW-SV-000123
        Rule ID    : SV-214412r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000080
        Rule Title : The IIS 8.5 web server must be reviewed on a regular basis to remove any Operating System features, utility programs, plug-ins, and modules not necessary for operation.
        DiscussMD5 : 4F028114970AE7A0BCD3892A2996F521
        CheckMD5   : 7DDE532A5258E2810E694F9411CD33D7
        FixMD5     : E0005079001B6D1883C39DA420F59011
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Features = Get-WindowsFeature | Where-Object Installed -EQ $true | Sort-Object Name

    $FindingDetails += "The following Windows features are installed:" | Out-String
    $FindingDetails += "" | Out-String
    ForEach ($Feature in $Features) {
        $FindingDetails += $Feature.Name | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214413 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214413
        STIG ID    : IISW-SV-000124
        Rule ID    : SV-214413r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000081
        Rule Title : The IIS 8.5 web server must have Multipurpose Internet Mail Extensions (MIME) that invoke OS shell programs disabled.
        DiscussMD5 : 81ECB85BEC8852A78D7D2D33E87A6567
        CheckMD5   : F39DEEDEBC505D289A4712875FABCF9A
        FixMD5     : B0A3B59A7B75671EA2ECCDF2E4BF69F9
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        $Configuration = (Get-WebConfiguration /system.webServer/staticContent).Collection
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; (Get-WebConfiguration /system.webServer/staticContent).Collection}"
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

Function Get-V214414 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214414
        STIG ID    : IISW-SV-000125
        Rule ID    : SV-214414r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000085
        Rule Title : The IIS 8.5 web server must have Web Distributed Authoring and Versioning (WebDAV) disabled.
        DiscussMD5 : 755E1D5550A79779DF357F74323C8F0A
        CheckMD5   : E8759F1B305B7C88F9ADF2573BED1ABA
        FixMD5     : 1BB351C804B8EC1C32859430F8C85F88
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        $Status = "Open"
        $FindingDetails += "Web-DAV-Publishing is installed."
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

Function Get-V214415 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214415
        STIG ID    : IISW-SV-000129
        Rule ID    : SV-214415r879612_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-APP-000175-WSR-000095
        Rule Title : The IIS 8.5 web server must perform RFC 5280-compliant certification path validation.
        DiscussMD5 : 4E9FF5CE3C0230C638A8750F4D583D01
        CheckMD5   : CF9FF59EBC63E28E195D6F02D82F7BE6
        FixMD5     : DA2C64F1AC5310FFA04570B327E0A45F
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V214416 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214416
        STIG ID    : IISW-SV-000130
        Rule ID    : SV-214416r879627_rule
        CCI ID     : CCI-001166
        Rule Name  : SRG-APP-000206-WSR-000128
        Rule Title : Java software installed on a production IIS 8.5 web server must be limited to .class files and the Java Virtual Machine.
        DiscussMD5 : BF7506C13599E9660A609405B0D036D3
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

Function Get-V214417 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214417
        STIG ID    : IISW-SV-000131
        Rule ID    : SV-214417r879631_rule
        CCI ID     : CCI-001082
        Rule Name  : SRG-APP-000211-WSR-000030
        Rule Title : IIS 8.5 Web server accounts accessing the directory tree, the shell, or other operating system functions and utilities must only be administrative accounts.
        DiscussMD5 : FC50236097F9C5E2009F86C84F3D924A
        CheckMD5   : A83DD6C609D0A894196E38A6845010A5
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

Function Get-V214419 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214419
        STIG ID    : IISW-SV-000134
        Rule ID    : SV-214419r879638_rule
        CCI ID     : CCI-001185, CCI-001664
        Rule Name  : SRG-APP-000223-WSR-000011
        Rule Title : The IIS 8.5 web server must use cookies to track session state.
        DiscussMD5 : 9A5C74B7EEFAB22AD8456C2E0098FD9C
        CheckMD5   : CB5AE43016EC5FC628A035735BEE41EE
        FixMD5     : 043F9217C1DA2966269C9DF562AF1EB1
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V214420 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214420
        STIG ID    : IISW-SV-000135
        Rule ID    : SV-214420r879638_rule
        CCI ID     : CCI-001664
        Rule Name  : SRG-APP-000223-WSR-000145
        Rule Title : The IIS 8.5 web server must limit the amount of time a cookie persists.
        DiscussMD5 : F802D63B2B8A888D3A010B91BDB3E0FD
        CheckMD5   : 1118A1CF2D36ED3FE4C55572C7C39947
        FixMD5     : EE68C190FB583A13D2C794D17792510F
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V214422 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214422
        STIG ID    : IISW-SV-000137
        Rule ID    : SV-214422r879642_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231-WSR-000144
        Rule Title : The production IIS 8.5 web server must utilize SHA2 encryption for the Machine Key.
        DiscussMD5 : 01853B181F6F22E37F0C534E55737D04
        CheckMD5   : D24223EDB59E9D8F5FC0E4D019DD9D9A
        FixMD5     : B3329E50D7C2B05C2D77CD0190F8ABFE
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V214423 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214423
        STIG ID    : IISW-SV-000138
        Rule ID    : SV-214423r879652_rule
        CCI ID     : CCI-001310
        Rule Name  : SRG-APP-000251-WSR-000157
        Rule Title : Directory Browsing on the IIS 8.5 web server must be disabled.
        DiscussMD5 : 2A45AF472A723004D72E896EA986918E
        CheckMD5   : 6E24DF48B02008E93140D3E9E97FC073
        FixMD5     : 7CBD3C5F04B42599B424A1A4EA406954
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214424 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214424
        STIG ID    : IISW-SV-000139
        Rule ID    : SV-214424r879655_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266-WSR-000142
        Rule Title : The IIS 8.5 web server Indexing must only index web content.
        DiscussMD5 : 3E7C79DBE5C25E7A6AEFE53BC12FB760
        CheckMD5   : 0230123FD2F058DBC2D0D510BE4FA086
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

Function Get-V214425 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214425
        STIG ID    : IISW-SV-000140
        Rule ID    : SV-214425r879655_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266-WSR-000159
        Rule Title : Warning and error messages displayed to clients must be modified to minimize the identity of the IIS 8.5 web server, patches, loaded modules, and directory paths.
        DiscussMD5 : 9A79AA3CE4FFA04A7672C0126E751178
        CheckMD5   : E353A5AFE7086CE995440B574DC5530A
        FixMD5     : 145937E671C08698E6DAD8C78A033F7F
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V214428 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214428
        STIG ID    : IISW-SV-000143
        Rule ID    : SV-214428r879693_rule
        CCI ID     : CCI-002322
        Rule Name  : SRG-APP-000316-WSR-000170
        Rule Title : The IIS 8.5 web server must provide the capability to immediately disconnect or disable remote access to the hosted applications.
        DiscussMD5 : D8F5DF452EC0EFD073A632668032D90D
        CheckMD5   : 83B33721F042F98B69F4A8080B7856B4
        FixMD5     : 9F7FE793FF1927B9C2454D9EDE134FBA
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V214429 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214429
        STIG ID    : IISW-SV-000144
        Rule ID    : SV-214429r879717_rule
        CCI ID     : CCI-002235
        Rule Name  : SRG-APP-000340-WSR-000029
        Rule Title : IIS 8.5 web server system files must conform to minimum file permission requirements.
        DiscussMD5 : 477E584ED8F4E4FFD923BFDF65FED4E6
        CheckMD5   : D0641E8D8DA0ED99EDE46DD82740A078
        FixMD5     : 265F7E3283CE69E1A945EF34FDD8D443
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V214430 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214430
        STIG ID    : IISW-SV-000145
        Rule ID    : SV-214430r879730_rule
        CCI ID     : CCI-001849
        Rule Name  : SRG-APP-000357-WSR-000150
        Rule Title : The IIS 8.5 web server must use a logging mechanism that is configured to allocate log record storage capacity large enough to accommodate the logging requirements of the IIS 8.5 web server.
        DiscussMD5 : 69157122C4800CAA1130151DD5EE27C0
        CheckMD5   : 54DA37C7711E5215EA812616296D319E
        FixMD5     : 7AB8055F9A7C39BD91241DC293883E54
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V214431 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214431
        STIG ID    : IISW-SV-000147
        Rule ID    : SV-214431r879753_rule
        CCI ID     : CCI-000213, CCI-001813, CCI-002385
        Rule Name  : SRG-APP-000380-WSR-000072
        Rule Title : Access to web administration tools must be restricted to the web manager and the web managers designees.
        DiscussMD5 : 0A21821F27900AF53D95D1A0CF60E427
        CheckMD5   : 0FC9FB985A9E5BCC495950CE78504481
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

Function Get-V214432 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214432
        STIG ID    : IISW-SV-000148
        Rule ID    : SV-214432r879756_rule
        CCI ID     : CCI-001762
        Rule Name  : SRG-APP-000383-WSR-000175
        Rule Title : The IIS 8.5 web server must not be running on a system providing any other role.
        DiscussMD5 : 0B710CCFF2F934F0617A5990C01F26AB
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

Function Get-V214433 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214433
        STIG ID    : IISW-SV-000149
        Rule ID    : SV-214433r879756_rule
        CCI ID     : CCI-001762
        Rule Name  : SRG-APP-000383-WSR-000175
        Rule Title : The Internet Printing Protocol (IPP) must be disabled on the IIS 8.5 web server.
        DiscussMD5 : D5089B974C5670991BFBD783435B07A9
        CheckMD5   : 95A3145308EEF41762A0649DFA6DED0D
        FixMD5     : 2E76063939641CE7301AE58414654EE0
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If (((Get-WindowsFeature -Name Print-Services).Installed -eq $false) -and ((Get-WindowsFeature -Name Internet-Print-Client).Installed -eq $false)) {
        $FindingDetails += "The Print Services role and the Internet Printing role are not installed so this check is Not Applicable."
        $Status = "Not_Applicable"
    }

    If ((Get-WindowsFeature -name "Internet-Print-Client").installed -eq $true) {
        $FindingDetails += "Internet-Print-Client is installed."
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

Function Get-V214434 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214434
        STIG ID    : IISW-SV-000151
        Rule ID    : SV-214434r879806_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-APP-000435-WSR-000148
        Rule Title : The IIS 8.5 web server must be tuned to handle the operational requirements of the hosted application.
        DiscussMD5 : 0A7141E665ABC8BB4B23A8E1167DAE5A
        CheckMD5   : 33BBB58FE7DCEA44FEDB16269A18779C
        FixMD5     : 6B5391A7603CA6A565BD28713A508BD2
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V214435 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214435
        STIG ID    : IISW-SV-000152
        Rule ID    : SV-214435r879810_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000439-WSR-000152
        Rule Title : IIS 8.5 web server session IDs must be sent to the client using TLS.
        DiscussMD5 : 5D2DDCA7C76E029B9B74B71A393CE4FB
        CheckMD5   : A504E42E761084ECA04951F086ED8337
        FixMD5     : 05082A3F56F0306221F0B77FCA378883
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V214436 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214436
        STIG ID    : IISW-SV-000153
        Rule ID    : SV-214436r903078_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000439-WSR-000156
        Rule Title : An IIS 8.5 web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version.
        DiscussMD5 : AB956EF9C261E12C7144487ECCA022E4
        CheckMD5   : 5CC6A464F7033BD0E3817A608A18BCB5
        FixMD5     : 1D1D3C60FFF8027600CE919462A656C5
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V214437 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214437
        STIG ID    : IISW-SV-000154
        Rule ID    : SV-214437r879810_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000439-WSR-000156
        Rule Title : A web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version.
        DiscussMD5 : BEEEA3D610E1F6A1AADE42F8AB0C9641
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
    $RegistryResult = Get-RegistryResult -Path $Path -ValueName "Enabled"
    $FindingDetails += $Path | Out-String
    If ($RegistryResult.Value -ne "(NotFound)") {
        $FindingDetails += "ValueName 'Enabled' is '$($RegistryResult.Value)' ($($RegistryResult.Type))" | Out-String
    }
    Else {
        $FindingDetails += "ValueName 'Enabled' does NOT exist" | Out-String
    }
    $FindingDetails += "" | Out-String
    If ($RegistryResult.Value -ne "1" -or $RegistryResult.Type -ne "REG_DWORD") {
        $Compliant = $false
    }

    # TLS 1.0, TLS 1.1, SSL 2.0, and SSL 3.0 Checks
    $Paths = @("HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server", "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server", "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server", "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server")
    ForEach ($Path in $Paths) {
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

Function Get-V214438 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214438
        STIG ID    : IISW-SV-000156
        Rule ID    : SV-214438r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000079
        Rule Title : All accounts installed with the IIS 8.5 web server software and tools must have passwords assigned and default passwords changed.
        DiscussMD5 : 765F969A6907D0491E17D96752F8981C
        CheckMD5   : F41A4C36D219E6B1D2C0B376AF4EC88C
        FixMD5     : 410A61F8E96B69B1E525D2A7A34DE9C5
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V214440 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214440
        STIG ID    : IISW-SV-000158
        Rule ID    : SV-214440r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : Unspecified file extensions on a production IIS 8.5 web server must be removed.
        DiscussMD5 : DBE580B563E337D7DD1A48ADEC6F1F8E
        CheckMD5   : 098650B8D079DE643B368FD25F32F109
        FixMD5     : 8E5984894530B72592D4498549175DCF
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V214441 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214441
        STIG ID    : IISW-SV-000159
        Rule ID    : SV-214441r881085_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The IIS 8.5 web server must have a global authorization rule configured to restrict access.
        DiscussMD5 : 42717C8EDE05D4029BDD669E850AC84D
        CheckMD5   : 6126D1ED24BB5F93A84B63C9243678D4
        FixMD5     : D263BC41CC59DC9BBB491DC141A93A99
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
    ElseIf (Get-Service MSExchangeServiceHost -ErrorAction SilentlyContinue) {
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

Function Get-V214442 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214442
        STIG ID    : IISW-SV-000200
        Rule ID    : SV-214442r879511_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-WSR-000001
        Rule Title : The IIS 8.5 MaxConnections setting must be configured to limit the number of allowed simultaneous session requests.
        DiscussMD5 : BAE82FBAB5DCF6F1D04077F6FF67813F
        CheckMD5   : 84FAF4945543A708AE604E0A8BB22D4C
        FixMD5     : D01CF85FC6EC400953E7E3C04DA15C12
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V228573 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228573
        STIG ID    : IISW-SV-000161
        Rule ID    : SV-228573r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000075
        Rule Title : An IIS Server configured to be a SMTP relay must require authentication.
        DiscussMD5 : 7C24F99DC2824D9CA7F1F4BE3415DB76
        CheckMD5   : 6F89C6A1A53E2E5AE973690156B6423C
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
    $SMTP_Feature = Get-WindowsFeature | Where-Object Name -EQ "SMTP-Server"
    $Port25 = Get-NetTCPConnection | Where-Object LocalPort -EQ 25 | Select-Object -Property LocalPort, State, @{'Name' = 'ProcessName'; 'Expression' = {(Get-Process -Id $_.OwningProcess).Name}}

    $FindingDetails += "SMTP-Server Feature:`t$($SMTP_Feature.InstallState)" | Out-String
    $FindingDetails += "" | Out-String
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

Function Get-V258446 {
    <#
    .DESCRIPTION
        Vuln ID    : V-258446
        STIG ID    : IISW-SV-009999
        Rule ID    : SV-258446r928857_rule
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA9mGqgWz445dPJ
# PqkSUDfPGoU7t3TH8/lxs5T14Cfd96CCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCD3Y1tlgb77rmJvwzagHeTwNQXXWAGZ
# gOs4m3ESuui7ETANBgkqhkiG9w0BAQEFAASCAQByTGApdn9MUJbtL6o4TSUNlWHY
# K8XP6q1J2TJSofyCUhH9QNxECyNFpiDuPpJzDTRhFw6fO0Vf3wAvsoXSyYLzpInc
# egAsTP0bfJjlaX41ITGvDhwAe/Md1+ZieHq+FZYVW26kF5w2WlTyNMqh4Y1fkND1
# ACXq+oyeDYekRLurRn4Lon5NUBUN6zFLvcwOR/8nVJmEN+5dGHHfkNKJbMlTd25e
# 6dBT4Nm7TsliK2DBwXSylPQAhstyUObA1Wd1pEV9mUUO1rWe6hf4dw5O0cdQP5FY
# Un5S6nf8A01m2WoHUwTmcoqgph/jZ3opf4x9fjPkIm1kxTuvm5Vvv/mqCkOe
# SIG # End signature block
