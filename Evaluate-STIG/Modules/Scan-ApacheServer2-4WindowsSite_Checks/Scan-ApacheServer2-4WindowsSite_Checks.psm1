##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Apache Server 2.4 Windows Site
# Version:  V2R1
# Class:    UNCLASSIFIED
# Updated:  5/13/2024
# Author:   U.S. Army Communications-Electronics Command, Software Engineering Center (CECOM SEC)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V214362 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214362
        STIG ID    : AS24-W2-000010
        Rule ID    : SV-214362r395442_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-WSR-000001
        Rule Title : The Apache web server must limit the number of allowed simultaneous session requests.
        DiscussMD5 : 403C6D4189CA97D0F3F8A93BE1C42AF3
        CheckMD5   : 0FFD57A1286A2D7C1CF46B01ABC60BF5
        FixMD5     : D364FB13F238204DBDA6C84F6E441083
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
    $FoundCount = 0
    $DirectiveToFind = "MaxKeepAliveRequests"
    $ExpectedValue = "100 or greater"
    $DirectivesFound = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveToFind
    $FindingDetails = Get-ApacheFormattedOutput -FoundValues $DirectivesFound -ExpectedValue $ExpectedValue

    foreach ($found In $DirectivesFound ) {
        if ($found.Status -eq "Not Found") {
            continue
        }

        $FoundCount++

        $FoundValue = ($found.ConfigFileLine.ToString() -split '\s+')[1] -as [int]
        if ($FoundValue -ge 100) {
            continue
        }

        $ErrorCount++
        break
    }

    if ($ErrorCount -ge 1 -or $FoundCount -le 0) {
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

Function Get-V214363 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214363
        STIG ID    : AS24-W2-000020
        Rule ID    : SV-214363r395442_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-WSR-000002
        Rule Title : The Apache web server must perform server-side session management.
        DiscussMD5 : A8E5E2F1239C1E2238227DECC2DE6E9A
        CheckMD5   : 41F64122517F675BA5DB79A395B5503D
        FixMD5     : 9DDB4315594FA0DFE4F5BE70561E80A2
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ApacheModuleName = "session_module"
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

Function Get-V214364 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214364
        STIG ID    : AS24-W2-000090
        Rule ID    : SV-214364r395721_rule
        CCI ID     : CCI-000130, CCI-000133, CCI-000134, CCI-001487
        Rule Name  : SRG-APP-000095-WSR-000056
        Rule Title : The Apache web server must produce log records containing sufficient information to establish what type of events occurred.
        DiscussMD5 : 1F3095A85B560D488F35262B45669E01
        CheckMD5   : E39BD063D9F6549D84F2450DF905545D
        FixMD5     : E7D9C71CF1CFBF47E8E1CB347F83C45D
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V214366 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214366
        STIG ID    : AS24-W2-000300
        Rule ID    : SV-214366r395853_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000081
        Rule Title : The Apache web server must have resource mappings set to disable the serving of certain file types.
        DiscussMD5 : 893943AF1C9E2E2EA4C50059E1C66C7D
        CheckMD5   : 855EAB7331BAB28DF3F3E88E8F2FF424
        FixMD5     : A3EB09FF3CF8700314BDA7BF21A2E63D
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResults -ExpectedValue $ExpectedValue
        foreach ($foundDirective in $DirectiveResults) {
            if ($foundDirective.Status -eq "Not Found") {
                continue
            }

            $HasFoundDirectives = $true
            break
        }
    }

    # This check will be marked as NotAFinding if nothing is found.
    # If we have found something, it will be marked as Not_Reviewed.
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

Function Get-V214367 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214367
        STIG ID    : AS24-W2-000310
        Rule ID    : SV-214367r395853_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000082
        Rule Title : The Apache web server must allow the mappings to unused and vulnerable scripts to be removed.
        DiscussMD5 : 5111E74263E14CCB3C3C18D532AC1C9C
        CheckMD5   : C9E7A041AD64BCA13407952D4F83FF30
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
    $DirectivesToFind = @('Script', 'ScriptAlias', 'ScriptAliasMatch', 'ScriptInterpreterSource')
    $ExpectedValue = "Must be needed for application operation"
    foreach ($DirectiveToFind in $DirectivesToFind) {
        $AllDirectiveLines = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveToFind
        $FindingDetails += Get-ApacheFormattedOutput -FoundValues $AllDirectiveLines -ExpectedValue $ExpectedValue

        foreach ($line in $AllDirectiveLines) {
            if ($line.status -ne "Not Found") {
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

Function Get-V214368 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214368
        STIG ID    : AS24-W2-000350
        Rule ID    : SV-214368r395853_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-WSR-000087
        Rule Title : Users and scripts running on behalf of users must be contained to the document root or home directory tree of the Apache web server.
        DiscussMD5 : B09C650C4AB53BAAB977482A1BED81A6
        CheckMD5   : D7FB9A7B110EC875B52D4AFA2C347E8C
        FixMD5     : A3FC64565696E7953A554635C65F7782
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $RequireFoundCount = 0
    $startBlock = "Directory\s+\`"?/\`"?" # Directives identified in STIG
    $endBlock = "Directory" # Directives identified in STIG
    $DirectiveCheck = 'Require\s+all\s+denied'
    $ExpectedValue = "Require all denied"

    $DirectiveResults = Get-ApacheDirectiveFromBlock -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -BlockStart $startBlock -BlockEnd $endBlock -DirectivePattern $DirectiveCheck

    foreach ($foundDirective in $DirectiveResults) {
        $foundDirective.Name = "Require all denied in directory entry"
    }
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResults -ExpectedValue $ExpectedValue

    foreach ($foundDirective in $DirectiveResults) {

        if ($foundDirective.Status -eq "Not Found") {
            continue
        }
        $RequireFoundCount++
    }

    if ($RequireFoundCount -lt 1) {
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

Function Get-V214369 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214369
        STIG ID    : AS24-W2-000360
        Rule ID    : SV-214369r395856_rule
        CCI ID     : CCI-000382
        Rule Name  : SRG-APP-000142-WSR-000089
        Rule Title : The Apache web server must be configured to use a specified IP address and port.
        DiscussMD5 : E9C9524A4E0D5B719E837C9BD3529168
        CheckMD5   : 4C9957DD279D4B688A15B41BE7142416
        FixMD5     : 25141250B1B8C06AF6FA8CDC5C0C1CC3
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
    $DirectiveResults = Get-ApacheDirectiveFromGlobalConfig -ApacheInstance $ApacheInstance -DirectiveName $DirectiveName
    $FindingDetails = Get-ApacheFormattedOutput -FoundValues $DirectiveResults -ExpectedValue $ExpectedValue

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

Function Get-V214370 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214370
        STIG ID    : AS24-W2-000380
        Rule ID    : SV-214370r505100_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-APP-000175-WSR-000095
        Rule Title : The Apache web server must perform RFC 5280-compliant certification path validation.
        DiscussMD5 : 3570D71CF21A5B2EF7A8EDBDE42326F8
        CheckMD5   : E4F04D7544845F48613A10779694023E
        FixMD5     : 47FD45F9A52C01D6675C10FC00488526
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
    $SSLVerifyClient = "SSLVerifyClient"
    $SSLVerifyDepth = "SSLVerifyDepth"
    $Directives = @($SSLVerifyDepth, $SSLVerifyClient) # Directives identified in STIG
    foreach ($directive in $Directives) {

        if ($directive -eq $SSLVerifyDepth) {
            $Pattern = [regex]('^\s*[0]\s*$')
            $ExpectedValue = "Must exist and must NOT be set to '0'"
        }
        elseif ($directive -eq $SSLVerifyClient) {
            $Pattern = [regex]('require\b')
            $ExpectedValue = "Must be set to 'require'"
        }

        $FoundCount = 0
        $DirectiveResults = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $directive
        $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResults -ExpectedValue $ExpectedValue

        foreach ($foundDirective in $DirectiveResults) {
            if ($foundDirective.Status -eq "Not Found") {
                continue
            }

            $FoundCount++

            $TestValue = ($foundDirective.ConfigFileLine.ToString() -split '\s+')[1]
            $Test = [bool]($TestValue | Select-String -Pattern $Pattern -Quiet)

            if ($directive -eq $SSLVerifyClient) {
                if ($Test -eq $false) {
                    $ErrorCount++ #If we don't find 'require'
                }
            }
            elseif ($directive -eq $SSLVerifyDepth) {
                if ($Test -eq $true) {
                    $ErrorCount++ # If we find '0'
                }
            }
        }

        if ($FoundCount -eq 0) {
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

Function Get-V214371 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214371
        STIG ID    : AS24-W2-000390
        Rule ID    : SV-214371r397597_rule
        CCI ID     : CCI-000186
        Rule Name  : SRG-APP-000176-WSR-000096
        Rule Title : Only authenticated system administrators or the designated PKI Sponsor for the Apache web server must have access to the Apache web servers private key.
        DiscussMD5 : 9EF5969C442BADA8ADD8F92A50AF8600
        CheckMD5   : BE9A8492DCA367FAC700DD2CC8712E00
        FixMD5     : 2E65ED15B9A5931E8C949BDB8C1A4E7F
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $FoundCount = 0
    $DirectiveName = "SSLCertificateFile"
    $ExpectedValue = "Inaccessible by unauthorized and unauthenticated users."
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails = Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue

    foreach ($line In $FoundValues ) {
        if ($line.Status -ne "Not Found") {
            $caFilePath = $line.ConfigFileLine.ToString().Split('"')[1]
            if ($null -eq $caFilePath) {
                $caFilePath = $line.ConfigFileLine.ToString().Split()[1]
            }
            $FileFound = $false

            #check unaltered directive path
            $filePath = $caFilePath
            if (Test-Path -Path "$filePath") {
                $FileFound = $true
                $RealPath = $filePath
            }

            #check path ${SRVROOT} with HttpdRootPath substitution
            if ($FileFound -ne $true) {
                $filePath = $caFilePath.Replace('${SRVROOT}', $ApacheInstance.HttpdRootPath)
                if (Test-Path -Path "$filePath") {
                    $FileFound = $true
                    $RealPath = $filepath
                }
            }

            #check relative path
            if ($FileFound -ne $true) {
                $filePath = Join-Path -Path $ApacheInstance.HttpdRootPath -ChildPath $caFilePath
                if (Test-Path -Path "$filePath") {
                    $FileFound = $true
                    $RealPath = $filePath
                }
            }

            if ($FileFound -eq $true) {
                $FoundCount++
                $CertACLCommandOutput = ""
                $CertACLs = Get-Acl -Path $RealPath | Select-Object -exp Access | Select-Object -exp IdentityReference -Unique
                foreach ( $aclid in $CertACLs ) {
                    $CertACLCommandOutput += "$($aclid)" | Out-String
                }
                $directiveIndex = $FindingDetails.IndexOf($caFilePath)
                $onLineIndex = $FindingDetails.IndexOf("On Line", $directiveIndex)
                $insertIndex = $FindingDetails.IndexOf("`n", $onLineIndex)
                $FindingDetails = $FindingDetails.Insert($insertIndex, "`n`nUSERS/GROUPS WITH ACCESS:`n") | Out-String
                $accessIndex = $FindingDetails.IndexOf("WITH ACCESS", $insertIndex)
                $insertIndex = $FindingDetails.IndexOf("`n", $accessIndex)
                $FindingDetails = $FindingDetails.Insert($insertIndex, "`n`n$CertACLCommandOutput") | Out-String
            }
        }
    }

    if ($FoundCount -le 0) {
        $Status = "Not_Applicable"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214372 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214372
        STIG ID    : AS24-W2-000430
        Rule ID    : SV-214372r397711_rule
        CCI ID     : CCI-001082
        Rule Name  : SRG-APP-000211-WSR-000030
        Rule Title : Apache web server accounts accessing the directory tree, the shell, or other operating system functions and utilities must only be administrative accounts.
        DiscussMD5 : 3D748CCAB39740BDC35EBEB9C37B7E58
        CheckMD5   : 7F0B2D283A3EE6686A732BF8740CD508
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

Function Get-V214373 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214373
        STIG ID    : AS24-W2-000440
        Rule ID    : SV-214373r397711_rule
        CCI ID     : CCI-001082, CCI-001813
        Rule Name  : SRG-APP-000211-WSR-000031
        Rule Title : Anonymous user access to the Apache web server application directories must be prohibited.
        DiscussMD5 : 94AD7456C3B9B23F8A6A7C361FFE9220
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

Function Get-V214375 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214375
        STIG ID    : AS24-W2-000460
        Rule ID    : SV-214375r803279_rule
        CCI ID     : CCI-001185
        Rule Name  : SRG-APP-000220-WSR-000201
        Rule Title : The Apache web server must invalidate session identifiers upon hosted application user logout or other session termination.
        DiscussMD5 : 6A8419E9435BCECB032B98E0D87E4C0A
        CheckMD5   : 33BA908F46925E7FF563A93DB966AF0F
        FixMD5     : 7A14F2D866DD531B32785E6FAA5D76DC
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
    $FoundCount = 0
    $DirectiveName = "SessionMaxAge"
    $ExpectedValue = "600 or Less"
    $DirectivesFound = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails = Get-ApacheFormattedOutput -FoundValues $DirectivesFound -ExpectedValue $ExpectedValue

    foreach ($found In $DirectivesFound ) {
        if ($found.Status -ne "Not Found") {
            $FoundValue = $found.ConfigFileLine.ToString().Split()[1] -as [int]
            if ($FoundValue -le "600") {
                $FoundCount++
            }
            else {
                $ErrorCount++
                break
            }
        }
    }

    if ($FoundCount -le 0) {
        $ErrorCount++
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

Function Get-V214376 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214376
        STIG ID    : AS24-W2-000470
        Rule ID    : SV-214376r505103_rule
        CCI ID     : CCI-001664
        Rule Name  : SRG-APP-000223-WSR-000011
        Rule Title : Cookies exchanged between the Apache web server and client, such as session cookies, must have security settings that disallow cookie access outside the originating Apache web server and hosted application.
        DiscussMD5 : AD6B50F36EB3CBE0812431727E69EB13
        CheckMD5   : 2662926DA637DA0DC989ACD8F6B0237E
        FixMD5     : C83F59DD2C158DFC8A19E156634346AA
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    foreach ($directive in $FoundValues) {
        $directive.Name = $directive.Name -replace "\*\.\*", " " -replace "\s+", " "
    }
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue

    foreach ($line in $FoundValues) {
        if ($line.Status -eq "Not Found") {
            continue
        }

        if ($line | Select-String -Pattern "$($DirectiveName)\b\s.*\b(httponly.*secure|secure.*httponly)\b") {
            continue # Our Pattern Matches so we ignore it.
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

Function Get-V214377 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214377
        STIG ID    : AS24-W2-000480
        Rule ID    : SV-214377r397732_rule
        CCI ID     : CCI-001664
        Rule Name  : SRG-APP-000223-WSR-000145
        Rule Title : The Apache web server must accept only system-generated session identifiers.
        DiscussMD5 : D7A5EAC1585C4DD5399FBB657BCDAB40
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

Function Get-V214378 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214378
        STIG ID    : AS24-W2-000500
        Rule ID    : SV-214378r397735_rule
        CCI ID     : CCI-001188
        Rule Name  : SRG-APP-000224-WSR-000136
        Rule Title : The Apache web server must generate unique session identifiers that cannot be reliably reproduced.
        DiscussMD5 : 34A08B3EBA11CF19D0FBB4AF1AFDABB7
        CheckMD5   : DA55BC5BF2797E018583B7DEE0427724
        FixMD5     : 775079644E524C81C5B7D282D5119DAF
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V214379 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214379
        STIG ID    : AS24-W2-000520
        Rule ID    : SV-214379r397735_rule
        CCI ID     : CCI-001188
        Rule Name  : SRG-APP-000224-WSR-000138
        Rule Title : The Apache web server must generate a session ID using as much of the character set as possible to reduce the risk of brute force.
        DiscussMD5 : C88176168E7F0C29E2A71A2B874F6565
        CheckMD5   : E476740EE3C17DCCBAF63976968B0F4F
        FixMD5     : 775079644E524C81C5B7D282D5119DAF
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V214381 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214381
        STIG ID    : AS24-W2-000560
        Rule ID    : SV-214381r397738_rule
        CCI ID     : CCI-001190, CCI-001844
        Rule Name  : SRG-APP-000225-WSR-000141
        Rule Title : The Apache web server must be configured to provide clustering.
        DiscussMD5 : 64A898CF1C5EA6F4B7D501D536180804
        CheckMD5   : 90507E6AFE42992402F6D8FA878B4C6C
        FixMD5     : 7E741E9C216A28FF3CAC5C4F54E278D5
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
    $FoundCount = 0
    $ApacheModuleName = "proxy_module"
    $ExpectedState = "Enabled"
    $ModuleStatus = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $ApacheModuleName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $ModuleStatus -ExpectedValue $ExpectedState

    $DirectiveName = "ProxyPass"
    $ExpectedValue = "Must be configured"
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue


    if ($ModuleStatus.Status -eq "Disabled") {
        $ErrorCount++
    }
    else {
        foreach ($line in $FoundValues) {
            if ($line.Status -ne "Not Found") {
                $FoundCount++
            }
        }
    }

    if ($ErrorCount -ge 1 -or $FoundCount -le 0) {
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

Function Get-V214382 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214382
        STIG ID    : AS24-W2-000580
        Rule ID    : SV-214382r397747_rule
        CCI ID     : CCI-001084
        Rule Name  : SRG-APP-000233-WSR-000146
        Rule Title : The Apache web server document directory must be in a separate partition from the Apache web servers system files.
        DiscussMD5 : 32F52408D4BDDB3B1E3A24E08F7DD4D8
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
    $ErrorCount = 0
    $RemoteDrives = @()
    $NonDefaultShares = @()

    $UserSIDs = Get-LocalUser | Select-Object * | Select-Object SID
    foreach ($sid in $UserSIDs) {
        $RegistryPath = "REGISTRY::HKEY_USERS\$($sid.SID)\Network\*"
        $RegistryValueName = "RemotePath"
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName

        if ($RegistryResult.Value -ne "(NotFound)") {
            $RemoteDrives += $RegistryResult.Value
        }
    }

    $SMBShares = Get-SmbShare -IncludeHidden
    foreach ($share in $SMBShares) {
        if ($share.Name -match '.*\$') {
            continue
        }
        $ErrorCount ++
        $NonDefaultShares += $share
    }

    $Printers = Get-Printer
    if ($null -ne $Printers -and ($Printers | Measure-Object).Count -ge 1) {
        $ErrorCount++
    }

    if ($null -ne $RemoteDrives -and ($RemoteDrives | Measure-Object).Count -ge 1) {
        $ErrorCount ++
    }

    if ($ErrorCount -ge 1) {
        $FindingDetails += "Printers:" | Out-String
        if (($Printers | Measure-Object).Count -le 0) {
            $FindingDetails += "No non-default printers found." | Out-String
        }
        else {
            foreach ($printer in $Printers) {
                $FindingDetails += "Printer Name:`t$($printer.Name)" | Out-String
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

Function Get-V214383 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214383
        STIG ID    : AS24-W2-000610
        Rule ID    : SV-214383r397843_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266-WSR-000142
        Rule Title : The Apache web server must display a default hosted application web page, not a directory listing, when a requested web page cannot be found.
        DiscussMD5 : 6221E3A1AB85F58CDC363729B1DFEF55
        CheckMD5   : 05E10754FA33C1A6BA9FBCE2CA243D22
        FixMD5     : C14D6180DE173929F44A9195A24A8DF3
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
    $SRVROOT = '${SRVROOT}/'

    $DirectiveName = "DocumentRoot"
    $ExpectedValue = "'DocumentRoot' directory and subdirectories contain 'index.html' or equivalent default document"
    $DirectoriesChecked = [System.Collections.ArrayList]@()
    $BadDirectories = [System.Collections.ArrayList]@()
    $DocumentRoots = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DocumentRoots -ExpectedValue $ExpectedValue

    $DIDirectiveName = "DirectoryIndex"
    $DirectoryIndexes = [System.Collections.ArrayList]@("index.html", "index.htm")
    $DirectiveResults = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DIDirectiveName

    foreach ($directoryIndex in $DirectiveResults) {
        if ($directoryIndex.Status -eq "Not Found") {
            continue
        }

        $DefaultDocuments = @(($directoryIndex.ConfigFileLine -replace $DIDirectiveName) -split "\s+")
        foreach ($defaultDoc in $DefaultDocuments) {
            if ([string]::IsNullOrWhiteSpace($defaultDoc) -or $DirectoryIndexes -contains $defaultDoc) {
                continue
            }

            [void]$DirectoryIndexes.Add($defaultDoc)
        }
    }

    if ($DirectoryIndexes.Count -ge 1 ) {
        $FindingDetails += "Default Documents: [$($DirectoryIndexes)]`n" | Out-String
    }
    else {
        $FindingDetails += "Default Documents: $($DIDirectiveName) not set.`n" | Out-String
    }

    foreach ($documentRoot in $DocumentRoots) {
        if ($documentRoot.Status -eq "Not Found") {
            continue
        }

        $DirectoryPath = ((($documentRoot.ConfigFileLine.ToString().Replace($SRVROOT, $ApacheInstance.HttpdRootPath)).Trim() -replace $DirectiveName) -replace '"').Trim()
        if (Test-Path -Path $DirectoryPath) {
            $DirectoryPath = [System.IO.Path]::GetFullPath($DirectoryPath)
            if ($DirectoriesChecked -contains $DirectoryPath) {
                continue
            }
        }
        else {
            $DirectoryPath = [System.IO.Path]::GetFullPath($DirectoryPath)
            if (Test-Path -Path $DirectoryPath) {
                if ($DirectoriesChecked -contains $DirectoryPath) {
                    continue
                }
            }
            else {
                $FindingDetails += "$($DirectoryPath) does not exist." | Out-String
                $ErrorCount ++
                continue
            }
        }

        $FindingDetails += "Checking directory `"$($DirectoryPath)`" and subdirectories for 'index.html' and default documents:" | Out-String

        [void]$DirectoriesChecked.Add("$($DirectoryPath)")

        # Recurse through each directory and subdirectory
        $SubDirectories = [System.Collections.ArrayList]@(Get-ChildItem -Path $DirectoryPath -Recurse -Force -Directory).FullName
        if ($null -ne $SubDirectories) {
            [void]$SubDirectories.Add("$DirectoryPath") # Make sure we add the root directory into the search

            foreach ($subDirectory in $SubDirectories) {
                $GoodDir = $false
                $Files = @(Get-ChildItem -Path $subDirectory -File)

                if ($null -eq $Files -or ($Files | Measure-Object).Count -le 0) {
                    [void]$BadDirectories.Add("$($subDirectory)")
                    $ErrorCount++
                    continue
                }

                foreach ($file in $Files) {
                    foreach ($DirectoryIndex in $DirectoryIndexes) {
                        if ($file.Name -match $DirectoryIndex) {
                            $GoodDir = $true
                            break
                        }
                    }

                    if ($GoodDir -eq $true) {
                        break
                    }
                }

                if ($GoodDir -eq $false) {
                    [void]$BadDirectories.Add("$($subDirectory)")
                    $ErrorCount ++
                }
            }
        }
    }

    $FindingDetails += "" | Out-String

    if ($ErrorCount -ge 1) {
        $Status = "Not_Reviewed"
        if ($BadDirectories.Count -ge 1) {
            $FindingDetails += "The following directories do not contain an 'index.html' or equivalent default documents file:" | Out-String
            foreach ($directory in $BadDirectories) {
                $FindingDetails += $directory | Out-String
            }
        }
    }
    else {
        $FindingDetails += "'index.html' or equivalent default documents file found." | Out-String
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

Function Get-V214384 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214384
        STIG ID    : AS24-W2-000620
        Rule ID    : SV-214384r505106_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266-WSR-000159
        Rule Title : Warning and error messages displayed to clients must be modified to minimize the identity of the Apache web server, patches, loaded modules, and directory paths.
        DiscussMD5 : B5A8C6DC3C4EE3C0DE41F80A65101388
        CheckMD5   : 6E11B2C90B587601614D20C1DB20F4D3
        FixMD5     : 3BEBE1DCEA9AA96466975EF758B049EA
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
    $DirectiveResults = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails = Get-ApacheFormattedOutput -FoundValues $DirectiveResults -ExpectedValue $ExpectedValue
    $foundcount = 0

    foreach ($foundDirective in $DirectiveResults) {
        if ($foundDirective.Status -eq "Not Found") {
            continue
        }
        $foundcount++
    }

    If ($FoundCount -le 0) {
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

Function Get-V214385 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214385
        STIG ID    : AS24-W2-000630
        Rule ID    : SV-214385r397843_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-APP-000266-WSR-000160
        Rule Title : Debugging and trace information used to diagnose the Apache web server must be disabled.
        DiscussMD5 : 60628E81F9A80DA1FD7F0904BA68F038
        CheckMD5   : 3A1F8AA2179B7D774F906065BB340222
        FixMD5     : 907ADBE11CD6C1AC7701388FD5B2CBF7
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
    $FoundCount = 0
    $DirectiveName = "TraceEnable"
    $ExpectedValue = "Off"
    $DirectivesFound = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails = Get-ApacheFormattedOutput -FoundValues $DirectivesFound -ExpectedValue $ExpectedValue

    foreach ($found In $DirectivesFound ) {
        if ($found.Status -eq "Not Found") {
            continue
        }
        $FoundCount++
        $FoundValue = ($found.ConfigFileLine.ToString() -split '\s+')[1]
        $FoundValue = $FoundValue | Select-String -Pattern $ExpectedValue

        if ($null -eq $FoundValue) {
            $ErrorCount++
            break
        }
    }

    if ($ErrorCount -eq 0 -and $FoundCount -ge 1) {
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

Function Get-V214386 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214386
        STIG ID    : AS24-W2-000640
        Rule ID    : SV-214386r803282_rule
        CCI ID     : CCI-002361
        Rule Name  : SRG-APP-000295-WSR-000012
        Rule Title : The Apache web server must set an absolute timeout for sessions.
        DiscussMD5 : 2E14464BDEFE576C7A93AF21D1477762
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
    $ErrorCount = 0
    $FoundCount = 0
    $DirectiveName = "SessionMaxAge"
    $ExpectedValue = "600 or Less"
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails = Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue

    foreach ($directiveValue In $FoundValues ) {
        if ($directiveValue.Status -eq "Not Found") {
            continue
        }

        $FoundCount++

        $MaxAge = ($directiveValue.ConfigFileLine.ToString() -split '\s+')[1] -as [int]
        if ($MaxAge -le "600") {
            continue
        }

        $ErrorCount++
        break
    }

    if ($ErrorCount -ge 1 -or $FoundCount -le 0) {
        $Status = "Open"
    }
    else {
        # All SessionMaxAge Directives found meet the requirements of the STIG.
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

Function Get-V214387 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214387
        STIG ID    : AS24-W2-000650
        Rule ID    : SV-214387r505109_rule
        CCI ID     : CCI-002361
        Rule Name  : SRG-APP-000295-WSR-000134
        Rule Title : The Apache web server must set an inactive timeout for completing the TLS handshake.
        DiscussMD5 : E3CBC0BA02735E05B176715DA2C42DCE
        CheckMD5   : 66CBACC94C90B7E2D31AF75775C50A21
        FixMD5     : 218C49C2C5BD22B734E66412F2BA3E46
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
    $FoundCount = 0
    $Patterns = @('stage\s*=\s*\d+', 'handshake\s*=\s*\d+', 'header\s*=\s*\d+', 'body\s*=\s*\d+', 'maxtimeout\s*=\s*\d+')
    $ApacheModuleName = "reqtimeout_module"
    $ExpectedState = "Enabled"
    $ModuleStatus = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $ApacheModuleName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $ModuleStatus -ExpectedValue $ExpectedState

    $DirectiveName = "RequestReadTimeout"
    $ExpectedValue = "Must be explicitly configured"
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue

    if ($ModuleStatus.Status -eq "Disabled") {
        $ErrorCount++
    }
    else {
        foreach ($line in $FoundValues) {
            if ($line.Status -eq "Not Found") {
                continue
            }
            #Directive Found
            $FoundCount++
            $LineToTest = ($line.ConfigFileLine.ToString() -split ',')
            #split FoundValues  to parse timeout for pattern test
            #loop for timeout patterns
            Foreach ($timeout in $Patterns) {
                Foreach ($testline in $LineToTest) {
                    #match pattern e.g. header with Regex pattern to get int values from timeout patterns
                    $TimeoutValue = ($testline | Select-String -Pattern $timeout).Matches.Value -replace "^*.*="
                    if ($TimeoutValue -ne "") {
                        #test if timeout value is default value 0 infinite AKA no timeout and warn
                        if ([int]$TimeoutValue -eq 0) {
                            $ErrorCount++
                            break
                        }
                    }
                }
            }
        }
    }
    if ($ErrorCount -ge 1 -or $FoundCount -le 0) {
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

Function Get-V214388 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214388
        STIG ID    : AS24-W2-000670
        Rule ID    : SV-214388r399640_rule
        CCI ID     : CCI-002314
        Rule Name  : SRG-APP-000315-WSR-000004
        Rule Title : The Apache web server must restrict inbound connections from nonsecure zones.
        DiscussMD5 : D3FB5E112198D0699FAE8CDCB2617149
        CheckMD5   : DEE2ABD0E4341A23EBCE6BAD8CB00126
        FixMD5     : 987F9C51BD4DF07226E472C8483113A2
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $FoundCount = 0
    $blockName = "RequireAll" # Directives identified in STIG
    $DirectiveCheck = 'Require'
    $ExpectedValue = "Restrict IPs from nonsecure zones."

    $DirectiveResults = Get-ApacheDirectiveFromBlock -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -BlockStart $blockName -BlockEnd $blockName -DirectivePattern $DirectiveCheck
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResults -ExpectedValue $ExpectedValue

    foreach ($foundDirective in $DirectiveResults) {

        if ($foundDirective.Status -ne "Not Found") {
            $FoundCount++
        }
    }

    if ($FoundCount -le 0) {
        $Status = "Open"
    }
    else {
        $Status = "Not_Reviewed"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214390 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214390
        STIG ID    : AS24-W2-000780
        Rule ID    : SV-214390r400015_rule
        CCI ID     : CCI-001762
        Rule Name  : SRG-APP-000383-WSR-000175
        Rule Title : The Apache web server must prohibit or restrict the use of nonsecure or unnecessary ports, protocols, modules, and/or services.
        DiscussMD5 : CBA88CC2AC0FBB2499713315A5309D11
        CheckMD5   : 315BAF4D99685C9EAC070C8EDB9103BB
        FixMD5     : 631512945C45913030FF2A8D6F88E3E0
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $DirectiveName1 = "Listen"
    $BadListen = 0
    $ExpectedValue = "Only the listener for IANA well-known ports for HTTP and HTTPS are in use"
    $Patterns = ('\b80\b', '\b443\b', ':80\b', ':443\b')
    $FoundValues += Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName1

    $IsInGlobalConfig = Test-ApacheDirectiveInGlobal -ApacheDirectives $FoundValues
    $IsInAllVirtualHosts = Test-ApacheDirectiveInAllVirtualHosts -ApacheInstance $ApacheInstance -ApacheDirectives $FoundValues

    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue -IsInGlobalConfig $IsInGlobalConfig -IsInAllVirtualHosts $IsInAllVirtualHosts
    foreach ($listen1 in $FoundValues) {
        if ($listen1.Status -eq "Not Found") {
            continue
        }
        if ( $null -eq ($listen1 | Select-String -Pattern $Patterns)) {
            $BadListen++
        }
    }

    if ($BadListen -eq 0) {
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

Function Get-V214391 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214391
        STIG ID    : AS24-W2-000800
        Rule ID    : SV-214391r400378_rule
        CCI ID     : CCI-002470
        Rule Name  : SRG-APP-000427-WSR-000186
        Rule Title : The Apache web server must only accept client certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs).
        DiscussMD5 : 511DD4AE3A87DA17F93CF8B0C7B4E17E
        CheckMD5   : D5056C8A973C4EB350097A4AD6EB1F5F
        FixMD5     : 0E8D4987C01F2939F23C6081B3F9D93D
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214392 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214392
        STIG ID    : AS24-W2-000830
        Rule ID    : SV-214392r400402_rule
        CCI ID     : CCI-001094, CCI-002385
        Rule Name  : SRG-APP-000435-WSR-000148
        Rule Title : The Apache web server must be tuned to handle the operational requirements of the hosted application.
        DiscussMD5 : 3EAC2286CC4FACA76787A3E9C3A67F4B
        CheckMD5   : 70952BC01E60F3658D335FF16B77AED3
        FixMD5     : 97063BA320BE5FD7FD6140DDDD016193
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $GoodDirective = 0
    $BadDirective = 0
    $DirectiveName = "Timeout"
    $ExpectedValue = "10 or Less"
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails = Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue

    foreach ($directive in $FoundValues) {
        if ($directive.Status -eq "Not Found") {
            continue
        }
        $MaxTimeout = ($directive.ConfigFileLine.ToString() -split '\s+')[1] -as [int]
        if ($MaxTimeout -le 10) {
            $GoodDirective++
            continue
        }
        $BadDirective++
        break
    }

    if ($GoodDirective -gt 0 -and $BadDirective -eq 0) {
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

Function Get-V214393 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214393
        STIG ID    : AS24-W2-000860
        Rule ID    : SV-214393r400474_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000439-WSR-000153
        Rule Title : The Apache web server cookies, such as session cookies, sent to the client using SSL/TLS must not be compressed.
        DiscussMD5 : DFB02AE4A10B4AC5C3C431C32CA7E2F4
        CheckMD5   : 357B4872D7287A929AB2FF23B0315509
        FixMD5     : EA816A29EB0DD7F12BBD1327D8EB265B
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V214394 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214394
        STIG ID    : AS24-W2-000870
        Rule ID    : SV-214394r803285_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000439-WSR-000154
        Rule Title : Cookies exchanged between the Apache web server and the client, such as session cookies, must have cookie properties set to prohibit client-side scripts from reading the cookie data.
        DiscussMD5 : F6FA42FDB1FE5D2EE19BE0BA08743EF3
        CheckMD5   : E2F61FDBB3293AF5E898DF15558858FA
        FixMD5     : 155927538C09337F9A64B5D2D4FE434D
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

    $FoundCount = 0
    $DirectiveName = "Session"
    $ExpectedValue = "Set to `"On`""
    $Pattern = "\bon\b"
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue

    foreach ($line in $FoundValues) {
        if ($line.Status -eq "Not Found") {
            continue
        }

        $FoundCount++

        $DirectiveValue = (($line.ConfigFileLine.ToString() -split '\s+')[1]).Trim()
        $IsOn = [bool] ($DirectiveValue | Select-String -Pattern $Pattern -Quiet)
        if ($IsOn -eq $true) {
            continue
        }

        $ErrorCount++
        break
    }

    if ($FoundCount -le 0) {
        $ErrorCount++
    }

    $DirectiveName = "SessionCookieName"
    $ExpectedValue = "Must contain `"HttpOnly`", `"Secure`" settings"
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue

    foreach ($line in $FoundValues) {
        if ($line.Status -eq "Not Found") {
            continue
        }

        if ($line | Select-String -Pattern "$($DirectiveName)\b\s.*\b(httponly.*secure|secure.*httponly)\b") {
            continue # Our Pattern Matches so we ignore it.
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

Function Get-V214395 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214395
        STIG ID    : AS24-W2-000880
        Rule ID    : SV-214395r400474_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000439-WSR-000155
        Rule Title : Cookies exchanged between the Apache web server and the client, such as session cookies, must have cookie properties set to force the encryption of cookies.
        DiscussMD5 : DE0D3567B0224C6E3A886A3128098CB3
        CheckMD5   : BA3A1B8367D13A5FD94E4B957327DDFD
        FixMD5     : E9471F76C1D44BDA34A719AEE62BDD93
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

    if ($ModuleResult.Status -eq "Disabled") {
        $ErrorCount++
    }

    $SessionExpectedValue = "Set to On"
    $SessionDirective = "Session"
    $SessionResult = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $SessionDirective
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $SessionResult -ExpectedValue $SessionExpectedValue
    $foundsession = 0
    foreach ($directive in $SessionResult) {
        if ($directive.Status -eq "Not Found") {
            continue
        }

        $Pattern = [regex]("Session\s+on")
        $Test = $directive.ConfigFileLine | Select-String -Pattern $Pattern
        if ($null -eq $Test -or $Test -eq "") {
            # If this doesn't match, that's not good.
            $ErrorCount++
        }
        $foundsession++
    }

    $SessionCookieExpectedValue = "Must be in use"
    $SessionCookieNameDirective = "SessionCookieName"
    $SessionCookieNameResult = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $SessionCookieNameDirective
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $SessionCookieNameResult -ExpectedValue $SessionCookieExpectedValue
    $foundcookie = 0
    foreach ($directive in $SessionCookieNameResult) {
        if ($directive.Status -eq "Not Found") {
            continue
        }
        $foundcookie++
    }

    $SessionCryptoPassphraseExpectedValue = "Must be in use"
    $SessionCryptoPassphrase = "SessionCryptoPassphrase"
    $SessionCryptoPassphraseResult = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $SessionCryptoPassphrase
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $SessionCryptoPassphraseResult -ExpectedValue $SessionCryptoPassphraseExpectedValue
    $foundcrypto = 0
    foreach ($directive in $SessionCryptoPassphraseResult) {
        if ($directive.Status -eq "Not Found") {
            continue
        }
        $foundcrypto++
    }

    if ($ErrorCount -ge 1 -or $foundsession -eq 0 -or $foundcookie -eq 0 -or $foundcrypto -eq 0) {
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

Function Get-V214396 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214396
        STIG ID    : AS24-W2-000890
        Rule ID    : SV-214396r395466_rule
        CCI ID     : CCI-000068, CCI-000197, CCI-000213, CCI-000803, CCI-001166, CCI-001453, CCI-002418, CCI-002420, CCI-002422, CCI-002476
        Rule Name  : SRG-APP-000014-WSR-000006
        Rule Title : An Apache web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version.
        DiscussMD5 : 238F3FBCDED51DE1377064FEC476FDF1
        CheckMD5   : 78822653EC74916056889EC080771FD8
        FixMD5     : 5A8B191E6EB059CC5B76BFF9ACDC544D
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
    $SessionModule = "ssl_module"
    $ExpectedValue = "Enabled"
    $ModuleResult = Get-ApacheModule -ApacheInstance $ApacheInstance -ModuleName $SessionModule
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $ModuleResult -ExpectedValue $ExpectedValue

    if ($ModuleObject.Status -eq "Disabled") {
        $ErrorCount++
    }

    $SSLProtocolFoundCount = 0
    $SessionExpectedValue = "-ALL +TLSv1.2"
    $SessionDirective = "SSLProtocol"
    $SessionResult = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $SessionDirective
    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $SessionResult -ExpectedValue $SessionExpectedValue
    foreach ($directive in $SessionResult) {
        if ($directive.Status -eq "Not Found") {
            continue
        }

        $SSLProtocolFoundCount++

        $SplitArray = @($directive.ConfigFileLine -split "\s+")

        $HasSetting = $false
        $MustAppear = "\-ALL"
        foreach ($item in $SplitArray) {
            $HasAllSetting = [bool]($item.Trim() | Select-String -Pattern $MustAppear -Quiet)
            if ($HasAllSetting -eq $false) {
                continue
            }

            $HasSetting = $true
            break
        }

        if ($HasSetting -eq $false) {
            $ErrorCount++
            break
        }

        $HasApprovedTLSVersion = $false
        $ShouldAppear = @("\+TLSv1.2", "\+TLSv1.3")
        foreach ($item in $SplitArray) {
            foreach ($test in $ShouldAppear) {
                $Result = [bool]($item.Trim() | Select-String -Pattern $test -Quiet)
                if ($Result -eq $true) {
                    $HasApprovedTLSVersion = $true
                    break
                }
            }
        }

        if ($HasApprovedTLSVersion -eq $false) {
            $ErrorCount++
            break
        }

        $ShouldNotAppear = @("\+TLSv1\w", "\+TLSv1.1\w", "\+SSL\w")
        foreach ($item in $SplitArray) {
            foreach ($test in $ShouldNotAppear) {
                $Result = [bool]($item.Trim() | Select-String -Pattern $test -Quiet)
                if ($Result -eq $true) {
                    $ErrorCount++
                    break
                }
            }
        }
    }

    if ($SSLProtocolFoundCount -le 0) {
        $ErrorCount++
    }

    if ($VirtualHost.Index -ge 0) {
        $FoundCount = 0
        $DirectiveName = "SSLEngine"
        $ExpectedValue = "On"
        $DirectiveResults = Get-ApacheDirectiveFromVirtualBlock -VirtualHost $VirtualHost -DirectiveName $DirectiveName
        $FindingDetails += Get-ApacheFormattedOutput -FoundValues $DirectiveResults -ExpectedValue $ExpectedValue
        foreach ($Directive in $DirectiveResults) {
            if ($Directive.Status -eq "Not Found") {
                continue
            }

            $FoundCount++

            $IsValid = [bool](($Directive.ConfigFileLine -split "\s+")[1] | Select-String -Pattern $ExpectedValue -Quiet)
            if ($IsValid -eq $true) {
                continue
            }

            $ErrorCount++
            break
        }

        if ($FoundCount -le 0) {
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

Function Get-V214397 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214397
        STIG ID    : AS24-W2-000950
        Rule ID    : SV-214397r401224_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-WSR-000174
        Rule Title : The Apache web server must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.
        DiscussMD5 : 954A8291EC7D2C5644835499D2C5F1F1
        CheckMD5   : 8F011A1CF042C2193300488F69945814
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

    if ($VirtualHost.Index -eq -1) {
        $DirectiveName = "ServerName"
    }
    else {
        $DirectiveName = "<\s*VirtualHost"
    }

    $ExpectedValue = "Website utilizes IANA well-known ports for HTTP and HTTPS"
    $Patterns = ('\b80\b', '\b443\b', ':80\b', ':443\b')
    $FoundValues = Get-ApacheDirective -ApacheInstance $ApacheInstance -VirtualHost $VirtualHost -DirectiveName $DirectiveName

    if ($VirtualHost.Index -ne -1) {
        foreach ($foundDirective in $FoundValues) {
            $foundDirective.Name = "VirtualHost"
        }
    }

    $FindingDetails += Get-ApacheFormattedOutput -FoundValues $FoundValues -ExpectedValue $ExpectedValue

    foreach ($website in $FoundValues) {
        if ($website.Status -eq "Not Found") {
            continue
        }

        $Pattern = ".*:[0-9]{1,5}"
        if ($null -eq ($website | Select-String -Pattern $Pattern | Select-String -Pattern $Patterns)) {
            $ErrorCount++
            break
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

# SIG # Begin signature block
# MIIL+QYJKoZIhvcNAQcCoIIL6jCCC+YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDyIEkwdwMRAvSA
# DgjbUYsRnnjNLoxXa1+5wcDBFiqAbaCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDgS70ZPZLmSFbwZcbBb4jroBj3ETam
# D65Fam/SK4coVjANBgkqhkiG9w0BAQEFAASCAQDAv1xHQxX7d5SvIKS3GOB/m0Qj
# SJbT3jx+4M3pPNl64ICiPWCUQtoQGT92QlmcFgMPATin7VHnDx8BN4Bc1xSjmv+S
# 7ngHyCCUStwnTiynt1FkydSk1Wmkhbs6StrjId+b2ITDjwOriuL1YrTFHrdf890g
# T5nxdV7DwMi2XrHqcGoYRthBUnU5MgIYSRvCpxFOJh91X8cyKH5zXNK/qcIpbLQd
# PW6d1FrBB/1ZBgaB5STZlwKX0flhXpc3muQtIN1nr1Gh7TimYeTqVVol1ZxEk2x8
# Js/iMbtgjViVNuEHkmwsaJAA+CzUrBZRaW2RkS4K4lRkIiKMQ4XG+etLGyn3
# SIG # End signature block
