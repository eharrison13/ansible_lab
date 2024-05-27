##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Canonical Ubuntu 20.04 LTS
# Version:  V1R12
# Class:    UNCLASSIFIED
# Updated:  5/13/2024
# Author:   Daniel Frye
##########################################################################
$ErrorActionPreference = "Stop"

Function CheckPermissions {
    Param(
        [Parameter (Mandatory = $true)]
        [string]$FindPath,

        [Parameter (Mandatory = $false)]
        [ValidateSet("File", "Directory")]
        [string]$Type,

        [Parameter (Mandatory = $true)]
        [int]$MinPerms,

        [Parameter (Mandatory = $false)]
        [switch]$Recurse
    )

    $ValidPerms = $(find $FindPath -not -path '*/.*' -maxdepth 0 -perm /$("{0:D4}" -f $(7777 - $MinPerms)) -printf "%04m %p\n")

    if ($Type -eq "File"){
        $ValidPerms = $(find $FindPath -not -path '*/.*' -maxdepth 0 -type f -perm /$("{0:D4}" -f $(7777 - $MinPerms)) -printf "%04m %p\n")
    }
    elseif ($Type -eq "Directory"){
        $ValidPerms = $(find $FindPath -not -path '*/.*' -maxdepth 0 -type d -perm /$("{0:D4}" -f $(7777 - $MinPerms)) -printf "%04m %p\n")
    }

    if ($Recurse){
        if ($Type -eq "File"){
            $ValidPerms = $(find $FindPath -not -path '*/.*' -xdev -type f -perm /$("{0:D4}" -f $(7777 - $MinPerms)) -printf "%04m %p\n")
        }
        elseif ($Type -eq "Directory"){
            $ValidPerms = $(find $FindPath -not -path '*/.*' -xdev -type d -perm /$("{0:D4}" -f $(7777 - $MinPerms)) -printf "%04m %p\n")
        }
        else{
            $ValidPerms = $(find $FindPath -not -path '*/.*' -xdev -perm /$("{0:D4}" -f $(7777 - $MinPerms)) -printf "%04m %p\n")
        }
    }

    if ($ValidPerms -eq "" -or $null -eq $ValidPerms){
        Return $True
    }
    else{
        Return $ValidPerms
    }
}

Function FormatFinding {
    # Return string which is added at end of $FindingDetails by each V-XXXXX method.
    # Requires finding argument.
    Param(
        [parameter (Mandatory = $true, position = 0, ParameterSetName = 'finding')]
        [AllowNull()]
        $line
    )

    # insert separator line between $FindingMessage and $finding
    $BarLine = "------------------------------------------------------------------------"
    $FormattedFinding += $BarLine | Out-String

    # insert findings
    $FormattedFinding += $finding | Out-String

    return $FormattedFinding
}

Function Get-V238196 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238196
        STIG ID    : UBTU-20-010000
        Rule ID    : SV-238196r653763_rule
        CCI ID     : CCI-000016
        Rule Name  : SRG-OS-000002-GPOS-00002
        Rule Title : The Ubuntu operating system must provision temporary user accounts with an expiration time of 72 hours or less.
        DiscussMD5 : 071E546FDC1CA9119F0E96B5EB30E865
        CheckMD5   : 2CD288CA1316844841F3139CB34EB378
        FixMD5     : 828D056207B93DAE8EFC9AE82AA22CC6
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
    $user_list = $(awk -F: '{print $1}' /etc/passwd)
    $user_list | ForEach-Object {
        $user_info = $(chage -l $_ | grep -s expires)
        $finding = $_ + "`r`n" + $user_info[0] + "`r`n" + $user_info[1] + "`r`n" + $user_info[2]
        $FindingDetails += $(FormatFinding $finding) | Out-String }

    $Status = "Not_Reviewed"
    $FindingMessage = "Verify the Ubuntu operating system expires temporary user accounts within 72 hours or less."

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails = , $FindingMessage + $FindingDetails   | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238197 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238197
        STIG ID    : UBTU-20-010002
        Rule ID    : SV-238197r653766_rule
        CCI ID     : CCI-000048
        Rule Name  : SRG-OS-000023-GPOS-00006
        Rule Title : The Ubuntu operating system must enable the graphical user logon banner to display the Standard Mandatory DoD Notice and Consent Banner before granting local access to the system via a graphical user logon.
        DiscussMD5 : C66EEECFCF7E6AC1D7031D02F997EC8F
        CheckMD5   : F5A582FA0D3253A39FA6DEAAC3AA4569
        FixMD5     : B37976A78406D47AE0438CF971A29CC1
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
    $finding = $(dpkg -l | egrep -s -i "gdm|lightdm" | awk '{print $2}')
    $finding ?? $($finding = "Check text: No results found.")
    $finding_2 = ""

    if ($finding.Contains("gdm3")) {
        $finding_2 = $(grep -s -i ^[[:blank:]]*banner-message-enable /etc/gdm3/greeter.dconf-defaults)
        if ($finding_2 = "banner-message-enable=true") {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system displays banner text before granting local access to the system via a graphical user logon."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not display banner text before granting local access to the system via a graphical user logon."
        }
    }
    else {
        $Status = "Not_Applicable"
        $FindingMessage = "The system does not have the Gnome Graphical User Interface installed."

        if ($finding.Contains("lightdm")) {
            $Status = "Open"
            $FindingMessage += "The operating system is using LightDM for a Graphical User Interface; therefore the banner text must be manually verified."
        }
        else {
            $FindingMessage += "The system does not have the LightDM Graphical User Interface installed."
        }
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238198 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238198
        STIG ID    : UBTU-20-010003
        Rule ID    : SV-238198r951459_rule
        CCI ID     : CCI-000048
        Rule Name  : SRG-OS-000023-GPOS-00006
        Rule Title : The Ubuntu operating system must display the Standard Mandatory DOD Notice and Consent Banner before granting local access to the system via a graphical user logon.
        DiscussMD5 : D8C09A2EB53C05B0AC010F8528B5669E
        CheckMD5   : 072A06FAA30A8D7F42FFC238FEA97BC7
        FixMD5     : 8DE842D33C8DEACAECB047B996E8B882
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
    $finding = $(dpkg -l | egrep -s -i "gdm|lightdm" | awk '{print $2}')
    $finding ?? $($finding = "Check text: No results found.")
    $finding_2 = ""

    if ($finding.Contains("gdm3")) {
        $finding_2 = $(grep -s -i ^[[:blank:]]*banner-message-text /etc/gdm3/greeter.dconf-defaults)
        $finding_2 ?? $($finding_2 = "Check text: No results found.")

        if ((($finding_2 | awk '{$2=$2};1').replace("\n", "").replace('"',"'") | tr -d '[:space:]"') -eq "banner-message-text='YouareaccessingaU.S.Government\(USG\)InformationSystem\(IS\)thatisprovidedforUSG-authorizeduseonly.\s+ByusingthisIS\(whichincludesanydeviceattachedtothisIS\),youconsenttothefollowingconditions:\s+-TheUSGroutinelyinterceptsandmonitorscommunicationsonthisISforpurposesincluding,butnotlimitedto,penetrationtesting,COMSECmonitoring,networkoperationsanddefense,personnelmisconduct\(PM\),lawenforcement\(LE\),andcounterintelligence\(CI\)investigations.\s+-Atanytime,theUSGmayinspectandseizedatastoredonthisIS.\s+-Communicationsusing,ordatastoredon,thisISarenotprivate,aresubjecttoroutinemonitoring,interception,andsearch,andmaybedisclosedorusedforanyUSG-authorizedpurpose.\s+-ThisISincludessecuritymeasures\(e.g.,authenticationandaccesscontrols\)toprotectUSGinterests--notforyourpersonalbenefitorprivacy.\s+-Notwithstandingtheabove,usingthisISdoesnotconstituteconsenttoPM,LEorCIinvestigativesearchingormonitoringofthecontentofprivilegedcommunications,orworkproduct,relatedtopersonalrepresentationorservicesbyattorneys,psychotherapists,orclergy,andtheirassistants.Suchcommunicationsandworkproductareprivateandconfidential.SeeUserAgreementfordetails.'") {
            $Status = "NotAFinding"
            $FindingMessage += "The operating system displays the exact approved Standard Mandatory DoD Notice and Consent Banner text."
        }
        else {
            $Status = "Open"
            $FindingMessage += "The operating system does not display the exact approved Standard Mandatory DoD Notice and Consent Banner text."
        }
    }
    else {
        $Status = "Not_Applicable"
        $FindingMessage = "The system does not have the Gnome Graphical User Interface installed."

        if ($finding.Contains("lightdm")) {
            $Status = "Open"
            $FindingMessage += "The operating system is using LightDM for a Graphical User Interface; therefore the banner text must be manually verified."
        }
        else {
            $FindingMessage += "The system does not have the LightDM Graphical User Interface installed."
        }
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238199 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238199
        STIG ID    : UBTU-20-010004
        Rule ID    : SV-238199r653772_rule
        CCI ID     : CCI-000056, CCI-000057
        Rule Name  : SRG-OS-000028-GPOS-00009
        Rule Title : The Ubuntu operating system must retain a user's session lock until that user reestablishes access using established identification and authentication procedures.
        DiscussMD5 : C6D131B5C5E07E6754B93F7C35CB9F42
        CheckMD5   : B505D0985E691C8CB644156FBEAE5E6D
        FixMD5     : A766C8032408039633A16CA2B5730754
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
    $finding = $(gsettings get org.gnome.desktop.screensaver lock-enabled)
    $finding ?? $($finding = "Check text: No results found.")

    if ($finding -eq "true") {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operation system has a graphical user interface session lock enabled."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operation system does not have a graphical user interface session lock enabled."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238200 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238200
        STIG ID    : UBTU-20-010005
        Rule ID    : SV-238200r653775_rule
        CCI ID     : CCI-000058, CCI-000060
        Rule Name  : SRG-OS-000030-GPOS-00011
        Rule Title : The Ubuntu operating system must allow users to directly initiate a session lock for all connection types.
        DiscussMD5 : DFEBAA057CB0F0C9C684573A29A4530F
        CheckMD5   : 02426013B9F30D5E2BCFF099C85E4EDD
        FixMD5     : 1D63E011DAA7759D698089F6C7A2F96A
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
    $finding = $(dpkg -l | grep -s vlock)

    if (($finding | awk '{print $2}') -eq "vlock") {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system has the 'vlock' package installed."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not have the 'vlock' package installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238201 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238201
        STIG ID    : UBTU-20-010006
        Rule ID    : SV-238201r832933_rule
        CCI ID     : CCI-000187
        Rule Name  : SRG-OS-000068-GPOS-00036
        Rule Title : The Ubuntu operating system must map the authenticated identity to the user or group account for PKI-based authentication.
        DiscussMD5 : 4AC24BE571CD2A826C5A37762348F100
        CheckMD5   : 384CA7734316183CB5C09E64F5FA5D98
        FixMD5     : EEF41395DE523C2C7BDFD6DAB5DDAEF4
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
    $finding = $(dpkg -l | grep -s libpam-pkcs11)

    if (($finding | awk '{print $2}') -match "libpam-pkcs11") {
        $finding_2 = $(grep -s -i ^[[:blank:]]*use_mappers /etc/pam_pkcs11/pam_pkcs11.conf)
        $better_finding_2 = $(grep -i -s use_mappers /etc/pam_pkcs11/pam_pkcs11.conf)
        if ($better_finding_2) {
            if ((($better_finding_2.trimstart()).StartsWith("use_mappers")) -and (($better_finding_2 | awk '{$2=$2};1').ToLower()).replace(" ", "").split("=")[1] -match "pwent") {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system has the 'libpam-pkcs11' package installed and 'use_mappers' is set to pwent."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system has the 'libpam-pkcs11' package installed but 'use_mappers' is not configured."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system has the 'libpam-pkcs11' package installed but 'use_mappers' is missing."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not have the 'libpam-pkcs11' package installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $better_Finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238202 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238202
        STIG ID    : UBTU-20-010007
        Rule ID    : SV-238202r653781_rule
        CCI ID     : CCI-000198
        Rule Name  : SRG-OS-000075-GPOS-00043
        Rule Title : The Ubuntu operating system must enforce 24 hours/1 day as the minimum password lifetime. Passwords for new users must have a 24 hours/1 day minimum password lifetime restriction.
        DiscussMD5 : C2BA91E7DF2AFA3F2BA2D0D3960066F7
        CheckMD5   : EDAF809739775A58531599D7910F3421
        FixMD5     : CBF9D02B69C421FD94A8950CD14483B7
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
    $finding = $(grep -s -i ^[[:blank:]]*pass_min_days /etc/login.defs)
    $finding ?? $($finding = "Check text: No results found.")

    if ([int](($finding | awk '{$2=$2};1').Split(" ")[1]) -ge 1) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system enforces a 24 hours/1 day minimum password lifetime for new user accounts."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not enforce a 24 hours/1 day minimum password lifetime for new user accounts."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238203 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238203
        STIG ID    : UBTU-20-010008
        Rule ID    : SV-238203r653784_rule
        CCI ID     : CCI-000199
        Rule Name  : SRG-OS-000076-GPOS-00044
        Rule Title : The Ubuntu operating system must enforce a 60-day maximum password lifetime restriction. Passwords for new users must have a 60-day maximum password lifetime restriction.
        DiscussMD5 : EEF9B4502F0ADB50ADEDDBB4B14BD48A
        CheckMD5   : B6C5E897804D4D097F2B637C1937116B
        FixMD5     : 0C2ED3916A482D2EB5490326B893D743
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
    $finding = $(grep -s -i ^[[:blank:]]*pass_max_days /etc/login.defs)
    $finding ?? $($finding = "Check text: No results found.")

    if ([int](($finding | awk '{$2=$2};1').Split(" ")[1]) -ge 60) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system enforces a 60-day maximum password lifetime for new user accounts."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not enforce a 60-day maximum password lifetime for new user accounts."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238204 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238204
        STIG ID    : UBTU-20-010009
        Rule ID    : SV-238204r832936_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-OS-000080-GPOS-00048
        Rule Title : Ubuntu operating systems when booted must require authentication upon booting into single-user and maintenance modes.
        DiscussMD5 : 47AE30D841BFA56AF34E1A6DA4149C7E
        CheckMD5   : 58C96B5B422EF40BBEDDEA5CB03ABEC9
        FixMD5     : 84EE501A950080BB94247AEC63D5F4C4
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
    $finding = $(Test-Path /sys/firmware/efi)

    If ($finding) {
        $Status = "Not_Applicable"
        $FindingMessage = "This is only applicable on systems that use a basic Input/Output System BIOS."
    }
    Else {
        $finding = $(grep -s -i password /boot/grub/grub.cfg)

        If ($finding -match "password_pbkdf2 root grub.pbkdf2.sha512.10000.") {
            $Status = "NotAFinding"
            $FindingMessage = "The root password entry does begin with 'password_pbkdf2'"
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The root password entry does not begin with 'password_pbkdf2'"
        }
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238205 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238205
        STIG ID    : UBTU-20-010010
        Rule ID    : SV-238205r653790_rule
        CCI ID     : CCI-000764, CCI-000804
        Rule Name  : SRG-OS-000104-GPOS-00051
        Rule Title : The Ubuntu operating system must uniquely identify interactive users.
        DiscussMD5 : 8A1F590DA8C032167B655EF97507CF37
        CheckMD5   : 18E0A66509E4C2DE547640E4ABDF0094
        FixMD5     : 00F89260B0EE246E7628E599E2FE5377
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
    $finding = $(awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd)

    if ($finding) {
        $Status = "Not_Reviewed"
        $FindingMessage = "The Ubuntu operating system may contains duplicate User IDs (UIDs) for interactive users."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system contains no duplicate User IDs (UIDs) for interactive users."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238206 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238206
        STIG ID    : UBTU-20-010012
        Rule ID    : SV-238206r653793_rule
        CCI ID     : CCI-001084
        Rule Name  : SRG-OS-000134-GPOS-00068
        Rule Title : The Ubuntu operating system must ensure only users who need access to security functions are part of sudo group.
        DiscussMD5 : C1B810B3615A09AE1EE64772E427A787
        CheckMD5   : F501EE573844096C074DCA5B4AB07517
        FixMD5     : FA7899D6E0C9995860EB5F20766E8383
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
    $finding = $(grep -s sudo /etc/group)

    $FindingMessage = "Verify that the sudo group has only members who should have access to security functions."

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238207 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238207
        STIG ID    : UBTU-20-010013
        Rule ID    : SV-238207r853404_rule
        CCI ID     : CCI-002361
        Rule Name  : SRG-OS-000279-GPOS-00109
        Rule Title : The Ubuntu operating system must automatically terminate a user session after inactivity timeouts have expired.
        DiscussMD5 : 58CD5A012951CD72B4F09EBFA3B59410
        CheckMD5   : C8561A7B388C2C80E0A788C9B5931346
        FixMD5     : 775E924DFD9F3E6B9501BDDB78CC8FC6
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
    $finding = $(grep -s -E "\bTMOUT=[0-9]+" /etc/bash.bashrc /etc/profile.d/*)
    $finding ?? $($finding = "Check text: No results found.")

    if (((($finding.ToUpper()).split(":")[1]).startswith("TMOUT")) -and (($finding | awk '{$2=$2};1').replace(" ", "").Split("=")[1] -ne 0)) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system initiates a session logout after greater than a 15-minute period of inactivity."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not initiate a session logout."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238208 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238208
        STIG ID    : UBTU-20-010014
        Rule ID    : SV-238208r853405_rule
        CCI ID     : CCI-002038
        Rule Name  : SRG-OS-000373-GPOS-00156
        Rule Title : The Ubuntu operating system must require users to reauthenticate for privilege escalation or when changing roles.
        DiscussMD5 : 4A0B5DD7047FE8A1C164A3E5B323D8A9
        CheckMD5   : E2CE9FAEFFAD13A93024BDF006916D63
        FixMD5     : 20DE1CE4461254ED06E70A079EC35305
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
    $finding = $(egrep -s -i '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/*)
    $uncommented_count = 0

    $finding | ForEach-Object { if ($_.StartsWith("#") -eq $False) {
            $uncommented_count++
        }
    }
    If ($uncommented_count -gt 0) {
        $Status = "Open"
        $FindingMessage = "The '/etc/sudoers' file has occurrences of 'NOPASSWD' or '!authenticate'."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The '/etc/sudoers' file has no occurrences of 'NOPASSWD' or '!authenticate'."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238209 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238209
        STIG ID    : UBTU-20-010016
        Rule ID    : SV-238209r653802_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00228
        Rule Title : The Ubuntu operating system default filesystem permissions must be defined in such a way that all authenticated users can read and modify only their own files.
        DiscussMD5 : 118F410ACCBA0FE68E7A2B605B30D976
        CheckMD5   : 3516D5B3FBD68AA31EAECD0706F0536A
        FixMD5     : 6E5632C0DBAB58C09DD394869097D7BF
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
    $finding = $(grep -s -i ^[[:blank:]]*umask /etc/login.defs)
    $finding ?? $($finding = "Check text: No results found.")

    if ((($finding | awk '{$2=$2};1').split(" ")[1] -eq "077")) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system defines default permissions for all authenticated users in such a way that the user can only read and modify their own files."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not define default permissions for all authenticated users in such a way that the user can only read and modify their own files."
        if ((($finding | awk '{$2=$2};1').split(" ")[1] -eq "000")) {
            $SeverityOverride = "CAT_I"
            $Justification = "The 'UMASK' variable is set to '000, therefore this is a finding with the severity raised to a CAT I."
            $FindingMessage += "`r`n"
            $FindingMessage += $Justification
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238210 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238210
        STIG ID    : UBTU-20-010033
        Rule ID    : SV-238210r951462_rule
        CCI ID     : CCI-000765, CCI-000766, CCI-000767, CCI-000768
        Rule Name  : SRG-OS-000105-GPOS-00052
        Rule Title : The Ubuntu operating system must implement smart card logins for multifactor authentication for local and network access to privileged and nonprivileged accounts.
        DiscussMD5 : 238A26EE719412B875924BC679FAE62E
        CheckMD5   : 2AADA561499BE76426198AF2D58A06BF
        FixMD5     : 5D00C34CDB97B454DBBBF3F1699896DA
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
    $finding = $(dpkg -l | grep -s libpam-pkcs11)

    if (($finding | awk '{print $2}') -match "libpam-pkcs11") {
        $finding_2 = $(grep -s -i ^[[:blank:]]*pubkeyauthentication /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*)
        $finding_2 ?? $($finding_2 = "Check text: No results found.")
        $correct_message_count = 0

        $finding_2 | ForEach-Object { if ((($_.split(":")[1] | awk '{$2=$2};1').split(" ")).ToLower() -eq "yes"){
            $correct_message_count++
        } }
        if ($correct_message_count -eq $finding_2.count) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system has the packages required for multifactor authentication installed and public key authentication is configured."
        }
        else{
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system has the packages required for multifactor authentication installed, but public key authentication is not configured."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not have the packages required for multifactor authentication installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238211 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238211
        STIG ID    : UBTU-20-010035
        Rule ID    : SV-238211r951464_rule
        CCI ID     : CCI-000877
        Rule Name  : SRG-OS-000125-GPOS-00065
        Rule Title : The Ubuntu operating system must use strong authenticators in establishing nonlocal maintenance and diagnostic sessions.
        DiscussMD5 : 5133FABF63BC036E7A26C084CB14E1A2
        CheckMD5   : C6EE049519E5334A77EBA87F9A559E4F
        FixMD5     : 0288B722CF25D1002095582B0B9E759D
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
    $finding = $(grep -s -i ^[[:blank:]]*UsePAM /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*)
    $finding ?? $($finding = "Check text: No results found.")
    $correct_message_count = 0

    $finding | ForEach-Object { if ((($_.split(":")[1] | awk '{$2=$2};1').split(" ")).ToLower() -eq "yes"){
        $correct_message_count++
    } }
    if ($correct_message_count -eq $finding.count) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system is configured to use strong authenticators in the establishment of nonlocal maintenance and diagnostic maintenance."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system is not configured to use strong authenticators in the establishment of nonlocal maintenance and diagnostic maintenance."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238212 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238212
        STIG ID    : UBTU-20-010036
        Rule ID    : SV-238212r951466_rule
        CCI ID     : CCI-000879
        Rule Name  : SRG-OS-000126-GPOS-00066
        Rule Title : The Ubuntu operating system must immediately terminate all network connections associated with SSH traffic after a period of inactivity.
        DiscussMD5 : BFCED6712397071FD0B31455720FC50F
        CheckMD5   : F675A22F17B8A45F15A164EE0F1AEC86
        FixMD5     : F568BCC8904E508E3BF16EB697A4D0CD
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
    $finding = $(grep -s -i ^[[:blank:]]*clientalivecountmax /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*)
    $finding ?? $($finding = "Check text: No results found.")
    $correct_message_count = 0

    $finding | ForEach-Object { if (($_.split(":")[1] | awk '{$2=$2};1').split(" ")[1] -eq 1){
        $correct_message_count++
    } }
    if ($correct_message_count -eq $finding.count) {
        $Status = "NotAFinding"
        $FindingMessage = "All network connections associated with SSH traffic automatically terminate after a period of inactivity."
    }
    else {
        $Status = "Open"
        $FindingMessage = "All network connections associated with SSH traffic automatically do not terminate after a period of inactivity."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238213 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238213
        STIG ID    : UBTU-20-010037
        Rule ID    : SV-238213r951468_rule
        CCI ID     : CCI-001133
        Rule Name  : SRG-OS-000163-GPOS-00072
        Rule Title : The Ubuntu operating system must immediately terminate all network connections associated with SSH traffic at the end of the session or after 10 minutes of inactivity.
        DiscussMD5 : 8D51E6E4EFDF99129C25349DE2935F2B
        CheckMD5   : 03F538F314E8033FCBAFF78457AF5471
        FixMD5     : 4B3AB586FFEFFF8D0D03642DD8040BF8
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
    $finding = $(grep -s -i ^[[:blank:]]*clientaliveinterval /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*)
    $finding ?? $($finding = "Check text: No results found.")
    $correct_message_count = 0

    $finding | ForEach-Object { if (($_.split(":")[1] | awk '{$2=$2};1').split(" ")[1] -le 600){
        $correct_message_count++
    } }
    if ($correct_message_count -eq $finding.count) {
        $Status = "NotAFinding"
        $FindingMessage = "All network connections associated with SSH traffic are automatically terminated at the end of the session or after 10 minutes of inactivity."
    }
    else {
        $Status = "Open"
        $FindingMessage = "All network connections associated with SSH traffic are automatically terminated at the end of the session or after 10 minutes of inactivity."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238214 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238214
        STIG ID    : UBTU-20-010038
        Rule ID    : SV-238214r951471_rule
        CCI ID     : CCI-000048, CCI-001384, CCI-001385, CCI-001386, CCI-001387, CCI-001388
        Rule Name  : SRG-OS-000228-GPOS-00088
        Rule Title : The Ubuntu operating system must display the Standard Mandatory DOD Notice and Consent Banner before granting any local or remote connection to the system.
        DiscussMD5 : 31E7B52C2DB5C3B32D14A13BD79BD35D
        CheckMD5   : 576CA85D331EB19F6D9DCC3AEE03AFAA
        FixMD5     : DB10EA02A2A7DEC2AA63E6ADC5B915E7
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
    $finding = $(grep -s -i ^[[:blank:]]*banner /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*)
    $finding_2 = ""

    if ($finding){
        $correct_message_count = 0
        $finding | Foreach-Object {
            $banner_path = ($_.split(":")[1] | awk '{$2=$2};1').split(" ")[1]
            $finding_2 = $(cat $banner_path)

            if ((($finding_2 | awk '{$2=$2};1').replace("\n", "") | tr -d '[:space:]"') -eq "YouareaccessingaU.S.Government(USG)InformationSystem(IS)thatisprovidedforUSG-authorizeduseonly.ByusingthisIS(whichincludesanydeviceattachedtothisIS),youconsenttothefollowingconditions:-TheUSGroutinelyinterceptsandmonitorscommunicationsonthisISforpurposesincluding,butnotlimitedto,penetrationtesting,COMSECmonitoring,networkoperationsanddefense,personnelmisconduct(PM),lawenforcement(LE),andcounterintelligence(CI)investigations.-Atanytime,theUSGmayinspectandseizedatastoredonthisIS.-Communicationsusing,ordatastoredon,thisISarenotprivate,aresubjecttoroutinemonitoring,interception,andsearch,andmaybedisclosedorusedforanyUSG-authorizedpurpose.-ThisISincludessecuritymeasures(e.g.,authenticationandaccesscontrols)toprotectUSGinterests--notforyourpersonalbenefitorprivacy.-Notwithstandingtheabove,usingthisISdoesnotconstituteconsenttoPM,LEorCIinvestigativesearchingormonitoringofthecontentofprivilegedcommunications,orworkproduct,relatedtopersonalrepresentationorservicesbyattorneys,psychotherapists,orclergy,andtheirassistants.Suchcommunicationsandworkproductareprivateandconfidential.SeeUserAgreementfordetails.") {
                $correct_message_count++
            }
        }
        if ($correct_message_count -eq $finding.count) {
            $Status = "NotAFinding"
            $FindingMessage = "The operating system displays the Standard Mandatory DoD Notice and Consent Banner before granting access to the operating system via a command line user logon."
        }
        else{
            $Status = "Open"
            $FindingMessage = "The operating system does not display the Standard Mandatory DoD Notice and Consent Banner before granting access to the operating system via a command line user logon."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The operating system does not display the Standard Mandatory DoD Notice and Consent Banner before granting access to the operating system via a command line user logon."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $Finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238215 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238215
        STIG ID    : UBTU-20-010042
        Rule ID    : SV-238215r916422_rule
        CCI ID     : CCI-002418, CCI-002420, CCI-002422
        Rule Name  : SRG-OS-000423-GPOS-00187
        Rule Title : The Ubuntu operating system must use SSH to protect the confidentiality and integrity of transmitted information.
        DiscussMD5 : 7CE7587484A0E3FC6C9BDEB296764BEC
        CheckMD5   : FEBEB8EB6B85F79EA4D53466D41474CB
        FixMD5     : C795798CFD6F3051916CBEECFCB76B2A
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
    $finding = $(dpkg -l | grep -s openssh)
    $finding_2 = ""

    if (($finding | awk '{print $2}').contains("openssh-server")) {
        $finding_2 = $(systemctl status sshd.service | egrep -s -i "(active|loaded)")

        if ($finding_2 -match "Loaded: loaded") {
            if ($finding_2 -match "Active: active") {
                $Status = "NotAFinding"
                $FindingMessage = "The ssh package is installed and the 'sshd.service' is loaded and active."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The ssh package is installed but the 'sshd.service' is not active."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The ssh package is installed but the 'sshd.service' is not loaded."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The ssh package is not installed."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $Finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238216 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238216
        STIG ID    : UBTU-20-010043
        Rule ID    : SV-238216r951473_rule
        CCI ID     : CCI-001453, CCI-002421, CCI-002890
        Rule Name  : SRG-OS-000424-GPOS-00188
        Rule Title : The Ubuntu operating system must configure the SSH daemon to use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hashes to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.
        DiscussMD5 : D3F16BBACD0D6F59A624BD87A55CC9D8
        CheckMD5   : 806ABED1FAADE9F12E16AE01C40FDB5E
        FixMD5     : 5FA2B009D797C8048AB7271E0E5ECD2B
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
    $finding = $(grep -s -i ^[[:blank:]]*macs /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*)
    $finding ?? $($finding = "Check text: No results found.")
    $correct_message_count = 0

    $finding | ForEach-Object { if ((($_.split(":")[1] | awk '{$2=$2};1').replace(" ", "")).ToLower() -eq "macshmac-sha2-512,hmac-sha2-256"){
        $correct_message_count++
    } }
    if ($correct_message_count -eq $finding.count) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system configures the SSH daemon to only use Message Authentication Codes (MACs) that employ FIPS 140-2 approved ciphers."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system configures the SSH daemon but does not use Message Authentication Codes (MACs) that employ FIPS 140-2 approved ciphers."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238217 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238217
        STIG ID    : UBTU-20-010044
        Rule ID    : SV-238217r951475_rule
        CCI ID     : CCI-000068, CCI-002421, CCI-003123
        Rule Name  : SRG-OS-000424-GPOS-00188
        Rule Title : The Ubuntu operating system must configure the SSH daemon to use FIPS 140-2 approved ciphers to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.
        DiscussMD5 : 837BDA7526FB7F9817B6EBB7B3906054
        CheckMD5   : 2BEA70F7ED18A7E77BD8C77F9DA6CA82
        FixMD5     : AED400A9DFE7CD4ED05BD762A879D836
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
    $finding = $(grep -s -i ^[[:blank:]]*ciphers /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*)
    $finding ?? $($finding = "Check text: No results found.")
    $correct_message_count = 0

    $finding | ForEach-Object { if ((($_.split(":")[1] | awk '{$2=$2};1').replace(" ", "")).ToLower() -eq "ciphersaes256-ctr,aes192-ctr,aes128-ctr"){
        $correct_message_count++
    } }
    if ($correct_message_count -eq $finding.count) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system configures the SSH daemon to only use FIPS-approved ciphers."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system configures the SSH daemon but does not use FIPS-approved ciphers."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238218 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238218
        STIG ID    : UBTU-20-010047
        Rule ID    : SV-238218r951479_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00229
        Rule Title : The Ubuntu operating system must not allow unattended or automatic login via SSH.
        DiscussMD5 : A54F06A419728C948532186EF87EC314
        CheckMD5   : 3731C858674A35295957F5D1232010D0
        FixMD5     : 63CEAB438F68180BA4A4D36E64E205AD
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
    $finding = $(egrep -s '(Permit(.*?)(Passwords|Environment))' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*)
    $PE_correct_message = $false
    $PU_correct_message = $false

    if ($finding) {
        $PermitEmpty = $(grep -s -i ^[[:blank:]]*PermitEmpty /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*)
        $PermitUser = $(grep -s -i ^[[:blank:]]*PermitUser /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*)

        $correct_message_count = 0
        if ($PermitEmpty) {
            $PermitEmpty | ForEach-Object { if (($_.split(":")[1] | awk '{$2=$2};1').split(" ")[1].ToLower() -eq "no") {
                $correct_message_count++
            } }
            if ($correct_message_count -eq $PermitEmpty.count) {
                    $PE_correct_message = $true
            }
        }
        $correct_message_count = 0
        if ($PermitUser) {
            $PermitUser | ForEach-Object { if (($_.split(":")[1] | awk '{$2=$2};1').split(" ")[1].ToLower() -eq "no") {
                $correct_message_count++
            } }
            if ($correct_message_count -eq $PermitUser.count) {
                $PU_correct_message = $true
            }
        }

        if (($PE_correct_message) -and ($PU_correct_message)) {
            $Status = "NotAFinding"
            $FindingMessage = "Unattended or automatic login via ssh is disabled."
        }
        else {
            $Status = "Open"
            $FindingMessage = "Unattended or automatic login via ssh is not disabled."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "Unattended or automatic login via ssh is not disabled."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238219 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238219
        STIG ID    : UBTU-20-010048
        Rule ID    : SV-238219r952102_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Ubuntu operating system must be configured so that remote X connections are disabled, unless to fulfill documented and validated mission requirements.
        DiscussMD5 : E5969222EC8680D3AE77ABD0BEBED811
        CheckMD5   : 1D92091B4E24BE34F884CD199E444355
        FixMD5     : 026731B354C0571783D7C893A9ED4F3D
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
    $finding = $(grep -s -i ^[[:blank:]]*x11forwarding /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*)
    $finding ?? $($finding = "Check text: No results found.")
    $correct_message_count = 0

    $finding | ForEach-Object { if (((($_.split(":")[1] | awk '{$2=$2};1').split(" "))[1]).ToLower() -eq "no"){
        $correct_message_count++
    } }
    if ($correct_message_count -eq $finding.count) {
        $Status = "NotAFinding"
        $FindingMessage = "X11Forwarding is disabled."
    }
    else {
        $Status = "Open"
        $FindingMessage = "X11Forwarding is not disabled."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238220 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238220
        STIG ID    : UBTU-20-010049
        Rule ID    : SV-238220r951483_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Ubuntu operating system SSH daemon must prevent remote hosts from connecting to the proxy display.
        DiscussMD5 : 42EF94ABF769BB918502DBBDEEBE36AA
        CheckMD5   : 38963FCA4E6B7F028F09511B0A84D950
        FixMD5     : 3A687B626CC535CD665683B3EF685D44
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
    $finding = $(grep -s -i ^[[:blank:]]*x11uselocalhost /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*)
    $finding ?? $($finding = "Check text: No results found.")
    $correct_message_count = 0

    $finding | ForEach-Object { if (((($_ | awk '{$2=$2};1').split(" "))[1]).ToLower() -eq "yes"){
        $correct_message_count++
    } }
    if ($correct_message_count -eq $finding.count) {
        $Status = "NotAFinding"
        $FindingMessage = "The SSH daemon prevents remote hosts from connecting to the proxy display."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The SSH daemon does not prevent remote hosts from connecting to the proxy display."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238221 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238221
        STIG ID    : UBTU-20-010050
        Rule ID    : SV-238221r653838_rule
        CCI ID     : CCI-000192
        Rule Name  : SRG-OS-000069-GPOS-00037
        Rule Title : The Ubuntu operating system must enforce password complexity by requiring that at least one upper-case character be used.
        DiscussMD5 : 5F477D1467AAB2349EDDEEB408909DEE
        CheckMD5   : EC7018F972A542C568D068960AEB926B
        FixMD5     : 0380CEDA000D863F8AEC90C7C05E1231
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
    $finding = $(grep -s -i ^[[:blank:]]*ucredit /etc/security/pwquality.conf)
    $finding ?? $($finding = "Check text: No results found.")

    if (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -le -1) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system enforces password complexity by requiring that at least one upper-case character be used."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not enforce password complexity by requiring that at least one upper-case character be used."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238222 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238222
        STIG ID    : UBTU-20-010051
        Rule ID    : SV-238222r653841_rule
        CCI ID     : CCI-000193
        Rule Name  : SRG-OS-000070-GPOS-00038
        Rule Title : The Ubuntu operating system must enforce password complexity by requiring that at least one lower-case character be used.
        DiscussMD5 : 5F477D1467AAB2349EDDEEB408909DEE
        CheckMD5   : 6DFCAE31581E9F1D0FF463D5098ADCF1
        FixMD5     : E853CA530AC926DF6DEB4470EDF967F4
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
    $finding = $(grep -s -i ^[[:blank:]]*lcredit /etc/security/pwquality.conf)
    $finding ?? $($finding = "Check text: No results found.")

    if (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -le -1) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system enforces password complexity by requiring that at least one lower-case character be used."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not enforce password complexity by requiring that at least one lower-case character be used."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238223 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238223
        STIG ID    : UBTU-20-010052
        Rule ID    : SV-238223r653844_rule
        CCI ID     : CCI-000194
        Rule Name  : SRG-OS-000071-GPOS-00039
        Rule Title : The Ubuntu operating system must enforce password complexity by requiring that at least one numeric character be used.
        DiscussMD5 : 5F477D1467AAB2349EDDEEB408909DEE
        CheckMD5   : 74942EF0F7788A249FF5C31F18002060
        FixMD5     : 2C93E32CB6F7CB47157132CD486639A9
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
    $finding = $(grep -s -i ^[[:blank:]]*dcredit /etc/security/pwquality.conf)
    $finding ?? $($finding = "Check text: No results found.")

    if (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -le -1) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system enforces password complexity by requiring that at least one numeric character be used."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not enforce password complexity by requiring that at least one numeric character be used."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238224 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238224
        STIG ID    : UBTU-20-010053
        Rule ID    : SV-238224r653847_rule
        CCI ID     : CCI-000195
        Rule Name  : SRG-OS-000072-GPOS-00040
        Rule Title : The Ubuntu operating system must require the change of at least 8 characters when passwords are changed.
        DiscussMD5 : 085B692BE9B735F0BB8674370426B6C4
        CheckMD5   : 64BA47BD5FFC1E33D340327F659396EC
        FixMD5     : 58017F555D08DF0590956EC287C91326
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
    $finding = $(grep -s -i ^[[:blank:]]*difok /etc/security/pwquality.conf)
    $finding ?? $($finding = "Check text: No results found.")

    if ([int](($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1]) -ge 8) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system requires the change of at least 8 characters when passwords are changed."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not require the change of at least 8 characters when passwords are changed.."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238225 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238225
        STIG ID    : UBTU-20-010054
        Rule ID    : SV-238225r832942_rule
        CCI ID     : CCI-000205
        Rule Name  : SRG-OS-000078-GPOS-00046
        Rule Title : The Ubuntu operating system must enforce a minimum 15-character password length.
        DiscussMD5 : 8F2D28C0975CC1FCBE3B5359D49694FD
        CheckMD5   : 90F11798A8003575B374016B57859F28
        FixMD5     : 95FFFF7B32EF6DD540155DF18B8F5568
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
    $finding = $(grep -s -i ^[[:blank:]]*minlen /etc/security/pwquality.conf)
    $finding ?? $($finding = "Check text: No results found.")

    if ([int](($finding | awk '{$2=$2};1').replace(" ", "").Split("=")[1]) -ge 15) {
        $Status = "NotAFinding"
        $FindingMessage = "The pwquality configuration file enforces a minimum 15-character password length."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The pwquality configuration file does not enforce a minimum 15-character password length."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238226 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238226
        STIG ID    : UBTU-20-010055
        Rule ID    : SV-238226r653853_rule
        CCI ID     : CCI-001619
        Rule Name  : SRG-OS-000266-GPOS-00101
        Rule Title : The Ubuntu operating system must enforce password complexity by requiring that at least one special character be used.
        DiscussMD5 : DFDA4AD9C0C59A560FE92F421D23A647
        CheckMD5   : 2DB4D9F266AE0094FC3BF1DD2C4CD587
        FixMD5     : 7BBECF2F60255DDBD9FCE632001F1299
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
    $finding = $(grep -s -i ^[[:blank:]]*ocredit /etc/security/pwquality.conf)
    $finding ?? $($finding = "Check text: No results found.")

    if (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -le -1) {
        $Status = "NotAFinding"
        $FindingMessage = "The field 'ocredit' is set in the '/etc/security/pwquality.conf'."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The field 'ocredit' is not set in the '/etc/security/pwquality.conf'."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238227 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238227
        STIG ID    : UBTU-20-010056
        Rule ID    : SV-238227r653856_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00225
        Rule Title : The Ubuntu operating system must prevent the use of dictionary words for passwords.
        DiscussMD5 : 28F0F0D235C2975A167A8453CD20F171
        CheckMD5   : B5456AF9C38FB154F15A44FE815E9D16
        FixMD5     : FE51CB05BC0DD3B3D4185A311FFD430A
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
    $finding = $(grep -s -i ^[[:blank:]]*dictcheck /etc/security/pwquality.conf)
    $finding ?? $($finding = "Check text: No results found.")

    if (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 1) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system uses the cracklib library to prevent the use of dictionary words."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not use the cracklib library to prevent the use of dictionary words."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238228 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238228
        STIG ID    : UBTU-20-010057
        Rule ID    : SV-238228r653859_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00225
        Rule Title : The Ubuntu operating system must be configured so that when passwords are changed or new passwords are established, pwquality must be used.
        DiscussMD5 : 4AF4C1E3A5017E0922F67CCAEF89849A
        CheckMD5   : 6060E48D6ED6CBD3665C31D840233A5B
        FixMD5     : 124B70805ACCA075EC7445C2E64C19D6
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
    $finding = $(dpkg -l libpam-pwquality)
    $finding_2 = ""
    $finding_3 = ""

    if ($finding -match "libpam-pwquality") {
        $finding_2 = $(grep -s -i enforcing /etc/security/pwquality.conf)
        $finding_2 ?? $($finding_2 = "Check text: No results found.")

        if ((($finding_2 | awk '{$2=$2};1').replace(" ", "")).ToLower() -eq "enforcing=1") {
            $finding_3 = $(cat /etc/pam.d/common-password | grep -s requisite | grep -s pam_pwquality)
            $finding_3 ?? $($finding_3 = "Check text: No results found.")

            if ((($finding_3 | awk '{$2=$2};1').split(" ") | Where-Object { $_ -match "retry" }).split("=")[1] -in 1..3) {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system has the libpam-pwquality package installed and is configured correctly."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system has the libpam-pwquality package installed and enforced but is not configured correctly."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system has the libpam-pwquality package installed but is not being enforced."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not have the libpam-pwquality package installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238229 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238229
        STIG ID    : UBTU-20-010060
        Rule ID    : SV-238229r653862_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-OS-000066-GPOS-00034
        Rule Title : The Ubuntu operating system, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.
        DiscussMD5 : 5D3C6CE7F56C738420A4D97713BFB774
        CheckMD5   : FA5FE22EA1D2B8386CD03217D4D39FF6
        FixMD5     : C4414920C10969408460252EE1CB2F78
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
    $finding = $(grep -s use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep -s cert_policy | grep -s ca)
    $finding ?? $($finding = "Check text: No results found.")

    if (((($Finding.trimstart()).ToLower()).StartsWith("cert_policy")) -and (($finding.ToLower()).contains("ca"))) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system is configured to use strong authenticators in the establishment of nonlocal maintenance and diagnostic maintenance."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system is not configured to use strong authenticators in the establishment of nonlocal maintenance and diagnostic maintenance."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238230 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238230
        STIG ID    : UBTU-20-010063
        Rule ID    : SV-238230r853410_rule
        CCI ID     : CCI-001948
        Rule Name  : SRG-OS-000375-GPOS-00160
        Rule Title : The Ubuntu operating system must implement multifactor authentication for remote access to privileged accounts in such a way that one of the factors is provided by a device separate from the system gaining access.
        DiscussMD5 : 608ADEA75D1015389AA7A36B0DBCA85D
        CheckMD5   : 53EFEE19288FC848184122CFECC16598
        FixMD5     : BAE7BF0D4E2193AAD5DE11115C5A6D2E
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
    $finding = $(dpkg -l | grep -s libpam-pkcs11)

    if (($finding | awk '{print $2}') -match "libpam-pkcs11") {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system has the packages required for multifactor authentication installed."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not have the packages required for multifactor authentication installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238231 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238231
        STIG ID    : UBTU-20-010064
        Rule ID    : SV-238231r853411_rule
        CCI ID     : CCI-001953
        Rule Name  : SRG-OS-000376-GPOS-00161
        Rule Title : The Ubuntu operating system must accept Personal Identity Verification (PIV) credentials.
        DiscussMD5 : 6D2ABDDFA50C0E3A944288DDF09F944B
        CheckMD5   : 832DAD7F49509CBC9D2FDDC95499F97B
        FixMD5     : 7EC01609D7A609117751055064CECC7E
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
    $finding = $(dpkg -l | grep -s opensc-pkcs11)

    if (($finding | awk '{print $2}') -match "opensc-pkcs11") {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system accepts Personal Identity Verification (PIV) credentials."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not accept Personal Identity Verification (PIV) credentials."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238232 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238232
        STIG ID    : UBTU-20-010065
        Rule ID    : SV-238232r853412_rule
        CCI ID     : CCI-001954
        Rule Name  : SRG-OS-000377-GPOS-00162
        Rule Title : The Ubuntu operating system must electronically verify Personal Identity Verification (PIV) credentials.
        DiscussMD5 : 6D2ABDDFA50C0E3A944288DDF09F944B
        CheckMD5   : D4DA292B5CDF54B091B13F2F80BF3B6A
        FixMD5     : BFAE9C35DFBC0D32FEE44D2675DE8D47
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
    $finding = $(grep -s use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep -s cert_policy | grep -s ocsp_on)
    $finding ?? $($finding = "Check text: No results found.")

    if ((($Finding.Trim().ToLower()).StartsWith("cert_policy")) -and (($finding.ToLower()).contains("ocsp_on"))) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system implements certificate status checking for multifactor authentication."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not implement certificate status checking for multifactor authentication."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238233 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238233
        STIG ID    : UBTU-20-010066
        Rule ID    : SV-238233r880870_rule
        CCI ID     : CCI-001991
        Rule Name  : SRG-OS-000384-GPOS-00167
        Rule Title : The Ubuntu operating system for PKI-based authentication, must implement a local cache of revocation data in case of the inability to access revocation information via the network.
        DiscussMD5 : F695B0E69E83A3C59D09A27D253E6A0A
        CheckMD5   : AA75FFDA92C94B665D3BCC915FA45ACD
        FixMD5     : F0BC5E688B392531CD39689F1FD6E79F
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
    $finding = $(grep -s -i ^[[:blank:]]*cert_policy /etc/pam_pkcs11/pam_pkcs11.conf | grep -s -E -- 'crl_auto|crl_offline')
    $finding ?? $($finding = "Check text: No results found.")

    if ((($finding.ToLower()).contains("crl_auto")) -or (($finding.ToLower()).contains("crl_offline"))) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system uses local revocation data when unable to access it from the network."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not use local revocation data when unable to access it from the network."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238234 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238234
        STIG ID    : UBTU-20-010070
        Rule ID    : SV-238234r832945_rule
        CCI ID     : CCI-000196, CCI-000200
        Rule Name  : SRG-OS-000077-GPOS-00045
        Rule Title : The Ubuntu operating system must prohibit password reuse for a minimum of five generations.
        DiscussMD5 : 9C0D0728C3907F8B1552B5162B6C60B4
        CheckMD5   : FB58946631089239D72DD6E3C91E4245
        FixMD5     : 5DEDCD92585EBB9F3D179692FCEC820D
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
    $finding = $(grep -s -i remember /etc/pam.d/common-password)
    $finding ?? $($finding = "Check text: No results found.")
    $remember_line = (($finding | awk '{$2=$2};1').split(" ") | grep -s -i remember)
    if (!($remember_line)) { $remember_line = $finding }

    if (($finding.ToLower().StartsWith("password")) -and ([int]($remember_line.replace(" ", "").Split("=")[1]) -ge 5)) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system prevents passwords from being reused for a minimum of five generations."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not prevent passwords from being reused for a minimum of five generations."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238235 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238235
        STIG ID    : UBTU-20-010072
        Rule ID    : SV-238235r853414_rule
        CCI ID     : CCI-000044, CCI-002238
        Rule Name  : SRG-OS-000329-GPOS-00128
        Rule Title : The Ubuntu operating system must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts have been made.
        DiscussMD5 : 03E6FD05BB851EF3CBA33722D11D8DB9
        CheckMD5   : 2C4D8BD1C8A2285998B868F653F931B1
        FixMD5     : 8274C2E82E67894AABEAAAF517E1F24B
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
    $finding = $(grep -s -i faillock /etc/pam.d/common-auth)
    $silent = $false
    $deny = $false
    $audit = $false
    $fail_interval = $false
    $unlock_time = $false

    if ($finding){
        $finding_2 = $(egrep -s -i 'silent|audit|deny|fail_interval|unlock_time' /etc/security/faillock.conf)
        $finding_2 ?? $($finding_2 = "Check text: No results found.")

        if (($finding_2 | awk '{$2=$2};1').replace(" ", "") -match "silent"){
            if ((($finding_2 | awk '{$2=$2};1').replace(" ", "") -match "silent").StartsWith("silent")){
                $silent = $true
            }
        }
        if (($finding_2 | awk '{$2=$2};1').replace(" ", "") -match "audit"){
            if ((($finding_2 | awk '{$2=$2};1').replace(" ", "") -match "audit").StartsWith("audit")){
                $audit = $true
            }
        }
        if (($finding_2 | awk '{$2=$2};1').replace(" ", "") -match "deny="){
            if (((($finding_2 | awk '{$2=$2};1').replace(" ", "") -match "deny=").StartsWith("deny")) -and ([int]((($finding_2 | awk '{$2=$2};1').replace(" ", "") -match "deny=").split("=")[1]) -le 3)){
                $deny = $true
            }
        }
        if (($finding_2 | awk '{$2=$2};1').replace(" ", "") -match "fail_interval="){
            if (((($finding_2 | awk '{$2=$2};1').replace(" ", "") -match "fail_interval=").StartsWith("fail_interval")) -and ([int]((($finding_2 | awk '{$2=$2};1').replace(" ", "") -match "fail_interval=").split("=")[1]) -le 900)){
                $fail_interval = $true
            }
        }
        if (($finding_2 | awk '{$2=$2};1').replace(" ", "") -match "unlock_time="){
            if (((($finding_2 | awk '{$2=$2};1').replace(" ", "") -match "unlock_time=").StartsWith("unlock_time")) -and ([int]((($finding_2 | awk '{$2=$2};1').replace(" ", "") -match "unlock_time=").split("=")[1]) -eq 0)){
                $unlock_time = $true
            }
        }

        if ($silent -and $deny -and $audit -and $fail_interval -and $unlock_time){
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system utilizes the 'pam_faillock' module and is configured with the correct options."
        }
        else{
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system utilizes the 'pam_faillock' module but is not configured with the correct options."
        }

    }
    else{
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not utilize the 'pam_faillock' module."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238237 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238237
        STIG ID    : UBTU-20-010075
        Rule ID    : SV-238237r653886_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00226
        Rule Title : The Ubuntu operating system must enforce a delay of at least 4 seconds between logon prompts following a failed logon attempt.
        DiscussMD5 : 7C22D07C283ABAC40CC9DD2E8DC76D89
        CheckMD5   : 752D32BB1DAD43A485FCDA8234E3E8D1
        FixMD5     : A2121BC7F8C4A6E89DCA161D8F9A8F63
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
    $finding = $(grep -s pam_faildelay /etc/pam.d/common-auth | grep -v "^#")

    if (($finding | awk '{$2=$2};1') -match "auth required pam_faildelay.so delay=") {
        if ([int]($finding.split("=")[1]) -ge 4000000) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system enforces a delay of at least 4 seconds between logon prompts."
        }
        else {
            $Status = "Open"
            $FindingMessage += "`r`n"
            $FindingMessage += "the Ubuntu operating system enforces a delay of less than 4 seconds between logon prompts following a failed logon attempt."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not enforce a delay between logon prompts following a failed logon attempt."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238238 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238238
        STIG ID    : UBTU-20-010100
        Rule ID    : SV-238238r853416_rule
        CCI ID     : CCI-000018, CCI-000172, CCI-001403, CCI-001404, CCI-001405, CCI-002130
        Rule Name  : SRG-OS-000004-GPOS-00004
        Rule Title : The Ubuntu operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd.
        DiscussMD5 : FAF4D1ACC8B6635F80F188EFBEBCFFA8
        CheckMD5   : 8C732CFFC2D79300B013A6B5DAB7173F
        FixMD5     : 29B68F4A8F2E879645842535B950506B
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s passwd)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/etc\/passwd[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238239 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238239
        STIG ID    : UBTU-20-010101
        Rule ID    : SV-238239r853417_rule
        CCI ID     : CCI-000018, CCI-000172, CCI-001403, CCI-001404, CCI-001405, CCI-002130
        Rule Name  : SRG-OS-000004-GPOS-00004
        Rule Title : The Ubuntu operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/group.
        DiscussMD5 : 84AB3746CD8FB8F27DD1EF8D7515EDD2
        CheckMD5   : 5BDEB45C417A31DE7EF06E65FE4B364D
        FixMD5     : FAB9163E11E599F6D71831E6020E5323
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s group)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/etc\/group[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records for all account creations, modifications, disabling, and termination events that affect /etc/group."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/group."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238240 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238240
        STIG ID    : UBTU-20-010102
        Rule ID    : SV-238240r853418_rule
        CCI ID     : CCI-000018, CCI-000172, CCI-001403, CCI-001404, CCI-001405, CCI-002130
        Rule Name  : SRG-OS-000004-GPOS-00004
        Rule Title : The Ubuntu operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow.
        DiscussMD5 : 84AB3746CD8FB8F27DD1EF8D7515EDD2
        CheckMD5   : 430BB681F036DC667B060E38710A24E0
        FixMD5     : 4F96ACFA04EA32865922C637D62D1AFE
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s shadow)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/etc\/shadow[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238241 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238241
        STIG ID    : UBTU-20-010103
        Rule ID    : SV-238241r853419_rule
        CCI ID     : CCI-000172, CCI-001403, CCI-001404, CCI-001405, CCI-002130
        Rule Name  : SRG-OS-000004-GPOS-00004
        Rule Title : The Ubuntu operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow.
        DiscussMD5 : 84AB3746CD8FB8F27DD1EF8D7515EDD2
        CheckMD5   : 8FBAF5E3C0314C7FF25BE5B781011268
        FixMD5     : 2D4E634B621D63F979BC020163705694
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s gshadow)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/etc\/gshadow[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238242 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238242
        STIG ID    : UBTU-20-010104
        Rule ID    : SV-238242r853420_rule
        CCI ID     : CCI-000018, CCI-000172, CCI-001403, CCI-001404, CCI-001405, CCI-002130
        Rule Name  : SRG-OS-000004-GPOS-00004
        Rule Title : The Ubuntu operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd.
        DiscussMD5 : 77DE0233CFFDE94583AD7AA496662754
        CheckMD5   : 35E81F9FF3F7F39B45F2EEFF06EA86DB
        FixMD5     : ADC683EFD73ABA7791D758A6B5CE7E95
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s opasswd)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/etc\/security\/opasswd[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records for all account creations, modifications, disabling, and termination events that affect /etc/security/opasswd."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/security/opasswd."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238243 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238243
        STIG ID    : UBTU-20-010117
        Rule ID    : SV-238243r653904_rule
        CCI ID     : CCI-000139
        Rule Name  : SRG-OS-000046-GPOS-00022
        Rule Title : The Ubuntu operating system must alert the ISSO and SA (at a minimum) in the event of an audit processing failure.
        DiscussMD5 : 002D4B408C1DF9505021F5507D35C9BA
        CheckMD5   : C416EC7D8669D9E5F3EFB41D6580BDA6
        FixMD5     : F52A532B8769843B0C869E8BDDC23DB6
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
    $finding = $(grep -s -i ^[[:blank:]]*action_mail_acct /etc/audit/auditd.conf)

    if ($finding) {
        $Status = "Not_Reviewed"
        $FindingMessage = "The System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) are notified in the event of an audit processing failure."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) are not notified in the event of an audit processing failure."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238244 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238244
        STIG ID    : UBTU-20-010118
        Rule ID    : SV-238244r653907_rule
        CCI ID     : CCI-000140
        Rule Name  : SRG-OS-000047-GPOS-00023
        Rule Title : The Ubuntu operating system must shut down by default upon audit failure (unless availability is an overriding concern).
        DiscussMD5 : 7E8FB5AADD3AD5999E32188DF5698FC9
        CheckMD5   : FEDF96BFB9E0113A11B822F385CEC122
        FixMD5     : CFD4FF6F47DB32B9D4C1DBDD220170CE
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
    $finding = $(grep -s -i ^[[:blank:]]*disk_full_action /etc/audit/auditd.conf)

    if ($finding) {
        if (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1].ToUpper() -in ("SYSLOG", "SINGLE", "HALT")) {
            $Status = "NotAFinding"
            $FindingMessage = "The System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) are notified in the event of an audit processing failure."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) are not notified correctly in the event of an audit processing failure."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) are not notified in the event of an audit processing failure."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238245 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238245
        STIG ID    : UBTU-20-010122
        Rule ID    : SV-238245r653910_rule
        CCI ID     : CCI-000162, CCI-000163
        Rule Name  : SRG-OS-000057-GPOS-00027
        Rule Title : The Ubuntu operating system must be configured so that audit log files are not read or write-accessible by unauthorized users.
        DiscussMD5 : 4298E514FFFD83A0F9AC721E5290D1FE
        CheckMD5   : 99D4FCDF3D466A01ED396C20AF164F88
        FixMD5     : 3B29B6A7A52005CB580FCDFF082723DE
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
    $finding = $(grep -s -iw log_file /etc/audit/auditd.conf)
    $finding ?? $($finding = "Check text: No results found.")

    $dirname = dirname $finding.replace(" ", "").split("=")[1]
    $dirname = $dirname + "/*"
    $finding_2 = $(stat -c "%n %a" $dirname)
    if ($finding) {
        if ((($finding_2 | Select-String (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] + " ")) -split (" "))[1] -le 600) {
            $Status = "NotAFinding"
            $FindingMessage = "The audit log files have a mode of '0600' or less permissive."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The audit log files do not have a mode of '0600' or less permissive."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit log path was not found."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238246 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238246
        STIG ID    : UBTU-20-010123
        Rule ID    : SV-238246r653913_rule
        CCI ID     : CCI-000162
        Rule Name  : SRG-OS-000057-GPOS-00027
        Rule Title : The Ubuntu operating system must be configured to permit only authorized users ownership of the audit log files.
        DiscussMD5 : 46DDB695BE245D63A72A189EA426DC31
        CheckMD5   : D68C0FBA86AB96C91D51776DA7E11E2A
        FixMD5     : C9E4BCB57EC1E7481E63532076B6FBB7
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
    $finding = $(grep -s -iw log_file /etc/audit/auditd.conf)
    $finding ?? $($finding = "Check text: No results found.")

    $dirname = dirname $finding.replace(" ", "").split("=")[1]
    $dirname = $dirname + "/*"
    $finding_2 = $(stat -c "%n %U" $dirname)
    if ($finding) {
        if ((($finding_2 | Select-String (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] + " ")) -split (" "))[1] -eq "root") {
            $Status = "NotAFinding"
            $FindingMessage = "The audit log files are owned by 'root' account."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The audit log files are owned by 'root' account."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit log path was not found."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238247 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238247
        STIG ID    : UBTU-20-010124
        Rule ID    : SV-238247r832947_rule
        CCI ID     : CCI-000162
        Rule Name  : SRG-OS-000057-GPOS-00027
        Rule Title : The Ubuntu operating system must permit only authorized groups ownership of the audit log files.
        DiscussMD5 : 46DDB695BE245D63A72A189EA426DC31
        CheckMD5   : D27ABC201D60A91A03C7D192E903DD44
        FixMD5     : 7E062B2959237594553A6F4DEDCFA20B
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
    $finding = $(grep -s -iw log_file /etc/audit/auditd.conf)
    $finding ?? $($finding = "Check text: No results found.")

    $dirname = dirname $finding.replace(" ", "").split("=")[1]
    $dirname = $dirname + "/*"
    $finding_2 = $(stat -c "%n %G" $dirname)
    if ($finding) {
        if ((($finding_2 | Select-String (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] + " ")) -split (" "))[1] -eq "root") {
            $Status = "NotAFinding"
            $FindingMessage = "The audit log files are owned by 'root' group."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The audit log files are owned by 'root' group."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit log path was not found."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238248 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238248
        STIG ID    : UBTU-20-010128
        Rule ID    : SV-238248r653919_rule
        CCI ID     : CCI-000164
        Rule Name  : SRG-OS-000059-GPOS-00029
        Rule Title : The Ubuntu operating system must be configured so that the audit log directory is not write-accessible by unauthorized users.
        DiscussMD5 : 1A9DADB9FD791640F60FD7A8491D1E6A
        CheckMD5   : 44AFEC64AF5B0F2B5F40FC1F11BD5291
        FixMD5     : EB39BEB8ACBDAEF80F3DC79207963FC9
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
    $finding = $(grep -s -iw log_file /etc/audit/auditd.conf)
    $finding_2 = ""

    if ($finding) {
        $dirname = dirname $finding.replace(" ", "").split("=")[1]
        $finding_2 = $(stat -c "%n %a" $dirname)
        $better_finding_2 = $(CheckPermissions -FindPath $dirname -MinPerms 750 -Type Directory -Recurse)

        if ($better_finding_2 -eq $True) {
            $Status = "NotAFinding"
            $FindingMessage = "The audit log directory has a mode of '0750' or less permissive."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The audit log directory has a mode of '0750' or less permissive."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit log path was not found."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238249 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238249
        STIG ID    : UBTU-20-010133
        Rule ID    : SV-238249r653922_rule
        CCI ID     : CCI-000171
        Rule Name  : SRG-OS-000063-GPOS-00032
        Rule Title : The Ubuntu operating system must be configured so that audit configuration files are not write-accessible by unauthorized users.
        DiscussMD5 : 62CB8ACA8106DFE3D3D59C5A43F5053B
        CheckMD5   : 949937319029932C87BEEE956E231338
        FixMD5     : 6078B7E749336F93390FCB9E32FBB10B
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
    $finding = $(CheckPermissions -FindPath /etc/audit/ -MinPerms 640 -Type File -Recurse)

    if ($finding -ne $true) {
        $Status = "Open"
        $FindingMessage = "'/etc/audit/audit.rules', '/etc/audit/rules.d/*' and '/etc/audit/auditd.conf' files do not have a mode of 0640 or less permissive."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "'/etc/audit/audit.rules', '/etc/audit/rules.d/*' and '/etc/audit/auditd.conf' files have a mode of 0640 or less permissive."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238250 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238250
        STIG ID    : UBTU-20-010134
        Rule ID    : SV-238250r653925_rule
        CCI ID     : CCI-000171
        Rule Name  : SRG-OS-000063-GPOS-00032
        Rule Title : The Ubuntu operating system must permit only authorized accounts to own the audit configuration files.
        DiscussMD5 : 860761B6BE2F1B3D2795F41FDF9B8772
        CheckMD5   : 8FDC032A647AA1CD085378A3035AAA59
        FixMD5     : E2B7EF9E0793FC84F1CAE4E2590F9402
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
    $finding = $(ls -al /etc/audit/ /etc/audit/rules.d/)
    $correct_message_count = 0
    $line_count = 0

    $finding | ForEach-Object {
        if ($_.StartsWith("-")) {
            $line_count++
            if (($_ | awk '{$2=$2};1').split(" ")[2] -eq "root") {
                $correct_message_count++
            }
        }
    }
    if ($correct_message_count -eq $line_count) {
        $Status = "NotAFinding"
        $FindingMessage = "'/etc/audit/audit.rules', '/etc/audit/rules.d/*' and '/etc/audit/auditd.conf' files are owned by root account."
    }
    else {
        $Status = "Open"
        $FindingMessage = "'/etc/audit/audit.rules', '/etc/audit/rules.d/*' and '/etc/audit/auditd.conf' files are not owned by root account."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238251 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238251
        STIG ID    : UBTU-20-010135
        Rule ID    : SV-238251r653928_rule
        CCI ID     : CCI-000171
        Rule Name  : SRG-OS-000063-GPOS-00032
        Rule Title : The Ubuntu operating system must permit only authorized groups to own the audit configuration files.
        DiscussMD5 : 860761B6BE2F1B3D2795F41FDF9B8772
        CheckMD5   : E063DB0C6A3476629E2783DE940DB8E5
        FixMD5     : A58EBA73FB229A69E1250E89C05DAFB4
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
    $finding = $(ls -al /etc/audit/ /etc/audit/rules.d/)
    $correct_message_count = 0
    $line_count = 0

    $finding | ForEach-Object {
        if ($_.StartsWith("-")) {
            $line_count++
            if (($_ | awk '{$2=$2};1').split(" ")[3] -eq "root") {
                $correct_message_count++
            }
        }
    }
    if ($correct_message_count -eq $line_count) {
        $Status = "NotAFinding"
        $FindingMessage = "'/etc/audit/audit.rules', '/etc/audit/rules.d/*' and '/etc/audit/auditd.conf' files are owned by root group."
    }
    else {
        $Status = "Open"
        $FindingMessage = "'/etc/audit/audit.rules', '/etc/audit/rules.d/*' and '/etc/audit/auditd.conf' files are not owned by root group."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238252 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238252
        STIG ID    : UBTU-20-010136
        Rule ID    : SV-238252r951486_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the su command.
        DiscussMD5 : 3F95598DA130A32AA1484C0772DA87A0
        CheckMD5   : 0026BA0EBCB799E4D15B253C01A5C5DC
        FixMD5     : 5E37BD576C1734978C8967F20495B24C
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s '/bin/su')
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/bin/su ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/bin\/su[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'su' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generate correct audit records when successful/unsuccessful attempts to use the 'su' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate audit records when successful/unsuccessful attempts to use the 'su' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238253 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238253
        STIG ID    : UBTU-20-010137
        Rule ID    : SV-238253r951489_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the chfn command.
        DiscussMD5 : 3F95598DA130A32AA1484C0772DA87A0
        CheckMD5   : F841F34B6A2BA85A7FAF2B87DEDC2D25
        FixMD5     : D37F007A9D596758BEDB476755D6E911
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s '/usr/bin/chfn')
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/chfn ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/chfn[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use of the 'chfn' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generate correct audit records when successful/unsuccessful attempts to use the 'chfn' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate audit records when successful/unsuccessful attempts to use the 'chfn' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238254 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238254
        STIG ID    : UBTU-20-010138
        Rule ID    : SV-238254r951492_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the mount command.
        DiscussMD5 : 3F95598DA130A32AA1484C0772DA87A0
        CheckMD5   : 61A729E354A9C2B8EAD6715C31B09EDF
        FixMD5     : 8EC60DA0F138B3BE99BA654902A72A90
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s '/usr/bin/mount')
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/mount ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/mount[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use of the 'mount' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generate correct audit records when successful/unsuccessful attempts to use the 'mount' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate correct audit records when successful/unsuccessful attempts to use the 'mount' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not generate audit records when successful/unsuccessful attempts to use the 'mount' command occur."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238255 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238255
        STIG ID    : UBTU-20-010139
        Rule ID    : SV-238255r951495_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the umount command.
        DiscussMD5 : 3F95598DA130A32AA1484C0772DA87A0
        CheckMD5   : 23CCC32B4BA32142AE2E13969A6E14C5
        FixMD5     : FF169776E54634900F77FA3EB8479D26
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s '/usr/bin/umount')
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/umount ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/umount[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use of the 'umount' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generate correct audit records when successful/unsuccessful attempts to use the 'umount' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate correct audit records when successful/unsuccessful attempts to use the 'umount' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not generate audit records when successful/unsuccessful attempts to use the 'umount' command occur."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238256 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238256
        STIG ID    : UBTU-20-010140
        Rule ID    : SV-238256r951498_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the ssh-agent command.
        DiscussMD5 : 3F95598DA130A32AA1484C0772DA87A0
        CheckMD5   : 044316329E6BFAD90D42F5AC952E2568
        FixMD5     : 052987A53A390F946EE9E5D2238320C7
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s '/usr/bin/ssh-agent')
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/ssh-agent ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/ssh-agent[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use of the 'ssh-agent' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generate correct audit records when successful/unsuccessful attempts to use the 'ssh-agent' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate audit records when successful/unsuccessful attempts to use the 'ssh-agent' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238257 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238257
        STIG ID    : UBTU-20-010141
        Rule ID    : SV-238257r951501_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the ssh-keysign command.
        DiscussMD5 : 3F95598DA130A32AA1484C0772DA87A0
        CheckMD5   : 9394524943400B5428434A869C2D47D1
        FixMD5     : FE47E2DEA196D56FD1FA134E4F8F64D1
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s ssh-keysign)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/lib/openssh/ssh-keysign ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/lib\/openssh\/ssh-keysign[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates an audit record when successful/unsuccessful attempts to use the 'ssh-keysign' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generate correct audit records when successful/unsuccessful attempts to use the 'ssh-keysign' command occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate audit records when successful/unsuccessful attempts to use the 'ssh-keysign' command occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238258 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238258
        STIG ID    : UBTU-20-010142
        Rule ID    : SV-238258r808474_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for any use of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr system calls.
        DiscussMD5 : 21FB496F91AF688C3AB4A60CBCC81507
        CheckMD5   : E92619C1DFA87B6FAA11C5A34825E57D
        FixMD5     : E4AEAD13C73F63F4EA05F504F0F64499
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s xattr)
        $finding ?? $($finding = "Check text: No results found.")

        if (
            (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+setxattr[\s]+|([\s]+|[,])setxattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+setxattr[\s]+|([\s]+|[,])setxattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+fsetxattr[\s]+|([\s]+|[,])fsetxattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+fsetxattr[\s]+|([\s]+|[,])fsetxattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+lsetxattr[\s]+|([\s]+|[,])lsetxattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+lsetxattr[\s]+|([\s]+|[,])lsetxattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+removexattr[\s]+|([\s]+|[,])removexattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+removexattr[\s]+|([\s]+|[,])removexattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+fremovexattr[\s]+|([\s]+|[,])fremovexattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+fremovexattr[\s]+|([\s]+|[,])fremovexattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+lremovexattr[\s]+|([\s]+|[,])lremovexattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+lremovexattr[\s]+|([\s]+|[,])lremovexattr([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
            )
        ) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system generates an audit record when successful/unsuccessful attempts to use the 'setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr' system calls."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate correct audit records when successful/unsuccessful attempts to use the 'setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr' commands occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238264 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238264
        STIG ID    : UBTU-20-010148
        Rule ID    : SV-238264r808477_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the chown, fchown, fchownat, and lchown system calls.
        DiscussMD5 : 21FB496F91AF688C3AB4A60CBCC81507
        CheckMD5   : 6EE4976F5C2920E06E24BD411DFE954F
        FixMD5     : 7CD51FDFE4BF6DF370840BA66750602D
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s chown)
        $finding ?? $($finding = "Check text: No results found.")

        if (
            (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+chown[\s]+|([\s]+|[,])chown([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+chown[\s]+|([\s]+|[,])chown([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+fchown[\s]+|([\s]+|[,])fchown([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|unset|-1)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+fchown[\s]+|([\s]+|[,])fchown([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|unset|-1)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+lchown[\s]+|([\s]+|[,])lchown([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+lchown[\s]+|([\s]+|[,])lchown([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+fchownat[\s]+|([\s]+|[,])fchownat([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+fchownat[\s]+|([\s]+|[,])fchownat([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
            )
        ) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system generates an audit record when successful/unsuccessful attempts to use the 'chown,fchown,fchownat,lchown' system calls."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate correct audit records when successful/unsuccessful attempts to use the 'chown,fchown,fchownat,lchown' commands occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238268 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238268
        STIG ID    : UBTU-20-010152
        Rule ID    : SV-238268r808480_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the chmod, fchmod, and fchmodat system calls.
        DiscussMD5 : 21FB496F91AF688C3AB4A60CBCC81507
        CheckMD5   : 20F8CEDA3F0D0127BADDA5595F29821D
        FixMD5     : 8DE7D8C6B25BDD2159C696BC970905FD
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s chmod)
        $finding ?? $($finding = "Check text: No results found.")

        if (
            (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+chmod[\s]+|([\s]+|[,])chmod([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+chmod[\s]+|([\s]+|[,])chmod([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+fchmod[\s]+|([\s]+|[,])fchmod([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|unset|-1)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+fchmod[\s]+|([\s]+|[,])fchmod([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|unset|-1)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+fchmodat[\s]+|([\s]+|[,])fchmodat([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+fchmodat[\s]+|([\s]+|[,])fchmodat([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
            )
        ) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system generates an audit record when successful/unsuccessful attempts to use the 'chmod,fchmod,fchmodat' system calls."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate correct audit records when successful/unsuccessful attempts to use the 'chmod,fchmod,fchmodat' commands occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238271 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238271
        STIG ID    : UBTU-20-010155
        Rule ID    : SV-238271r808483_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the creat, open, openat, open_by_handle_at, truncate, and ftruncate system calls.
        DiscussMD5 : 2E61B2E851C071D44213B06515586FDB
        CheckMD5   : 8B6163154CC90B026C8C39E803BF9747
        FixMD5     : 647C52F0B638EB9B69988916E60C24ED
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s open)
        $finding ?? $($finding = "Check text: No results found.")

        if (
            (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+creat[\s]+|([\s]+|[,])creat([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+creat[\s]+|([\s]+|[,])creat([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+creat[\s]+|([\s]+|[,])creat([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+creat[\s]+|([\s]+|[,])creat([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+open[\s]+|([\s]+|[,])open([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+open[\s]+|([\s]+|[,])open([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+open[\s]+|([\s]+|[,])open([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+open[\s]+|([\s]+|[,])open([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+openat[\s]+|([\s]+|[,])openat([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+openat[\s]+|([\s]+|[,])openat([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+openat[\s]+|([\s]+|[,])openat([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+openat[\s]+|([\s]+|[,])openat([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+open_by_handle_at[\s]+|([\s]+|[,])open_by_handle_at([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+open_by_handle_at[\s]+|([\s]+|[,])open_by_handle_at([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+open_by_handle_at[\s]+|([\s]+|[,])open_by_handle_at([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+open_by_handle_at[\s]+|([\s]+|[,])open_by_handle_at([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+truncate[\s]+|([\s]+|[,])truncate([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+truncate[\s]+|([\s]+|[,])truncate([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+truncate[\s]+|([\s]+|[,])truncate([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+truncate[\s]+|([\s]+|[,])truncate([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+ftruncate[\s]+|([\s]+|[,])ftruncate([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+ftruncate[\s]+|([\s]+|[,])ftruncate([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+ftruncate[\s]+|([\s]+|[,])ftruncate([\s]+|[,])))(?:.*-F\s+exit=\-EACCES[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+ftruncate[\s]+|([\s]+|[,])ftruncate([\s]+|[,])))(?:.*-F\s+exit=\-EPERM[\s]+)(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
            )
        ) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system generates an audit record when unsuccessful attempts to use the 'creat,open,openat,open_by_handle_at,truncate,ftruncate' system calls."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'creat,open,openat,open_by_handle_at,truncate,ftruncate' system calls."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238277 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238277
        STIG ID    : UBTU-20-010161
        Rule ID    : SV-238277r951504_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the sudo command.
        DiscussMD5 : 3F95598DA130A32AA1484C0772DA87A0
        CheckMD5   : 52C0F53A0A7681EB251B9D1ABFDD60CF
        FixMD5     : 51187DA685FA77A9F3EE4B853A7B359B
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s /usr/bin/sudo)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/sudo ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/sudo[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'sudo' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'sudo' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'sudo' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238278 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238278
        STIG ID    : UBTU-20-010162
        Rule ID    : SV-238278r951507_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the sudoedit command.
        DiscussMD5 : 3F95598DA130A32AA1484C0772DA87A0
        CheckMD5   : 5948CD17317235D920E4918EB98FD23F
        FixMD5     : 29F74D9FE2C0607D98061FC3454C03AF
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s /usr/bin/sudoedit)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/sudoedit ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/sudoedit[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'sudoedit' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'sudoedit' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'sudoedit' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238279 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238279
        STIG ID    : UBTU-20-010163
        Rule ID    : SV-238279r951510_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the chsh command.
        DiscussMD5 : 3F95598DA130A32AA1484C0772DA87A0
        CheckMD5   : 374386FD1DCE8C22A6DC96BE95B302D4
        FixMD5     : 1046FEEF63CA2484F878C2A861FC3909
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s chsh)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/chsh ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/chsh[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'chsh' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'chsh' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'chsh' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238280 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238280
        STIG ID    : UBTU-20-010164
        Rule ID    : SV-238280r951513_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the newgrp command.
        DiscussMD5 : 3F95598DA130A32AA1484C0772DA87A0
        CheckMD5   : C4CF7C9DB9E29D171C1FDBBE756B07A1
        FixMD5     : 5DB73BF85F83CD1D837C183EBDF1CBBD
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s newgrp)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/newgrp ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/newgrp[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'newgrp' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'newgrp' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'newgrp' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238281 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238281
        STIG ID    : UBTU-20-010165
        Rule ID    : SV-238281r951516_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the chcon command.
        DiscussMD5 : 3F95598DA130A32AA1484C0772DA87A0
        CheckMD5   : 16741A03348DBACF1A00B7C14F964137
        FixMD5     : C5EED7C4257A8D1BE224211F675373BE
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s chcon)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/chcon ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/chcon[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'chcon' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'chcon' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'chcon' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238282 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238282
        STIG ID    : UBTU-20-010166
        Rule ID    : SV-238282r951519_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the apparmor_parser command.
        DiscussMD5 : 3F95598DA130A32AA1484C0772DA87A0
        CheckMD5   : 54F3C4F6111A10C42A7825F2C36E2C61
        FixMD5     : 048BD48BFB48B1ED27FC8CB7C33726FF
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s apparmor_parser)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/sbin/apparmor_parser ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/sbin\/apparmor_parser[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'apparmor_parser' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'apparmor_parser' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'apparmor_parser' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238283 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238283
        STIG ID    : UBTU-20-010167
        Rule ID    : SV-238283r951522_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the setfacl command.
        DiscussMD5 : 3F95598DA130A32AA1484C0772DA87A0
        CheckMD5   : E2AE1C669778731D81391EC9B0C15A2C
        FixMD5     : 1B9AF30D0BA39C89AC76C81EBF6CAF17
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s setfacl)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/setfacl ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/setfacl[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'setfacl' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'setfacl' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'setfacl' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238284 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238284
        STIG ID    : UBTU-20-010168
        Rule ID    : SV-238284r951525_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the chacl command.
        DiscussMD5 : 3F95598DA130A32AA1484C0772DA87A0
        CheckMD5   : 661DAC179B377404C80C098C1063FB9C
        FixMD5     : 143A98A5C4F352F90898C5473619A5C7
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s chacl)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/chacl ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/chacl[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'chacl' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'chacl' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'chacl' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238285 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238285
        STIG ID    : UBTU-20-010169
        Rule ID    : SV-238285r654030_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for the use and modification of the tallylog file.
        DiscussMD5 : 9931CFF26CBF1FBAC0BF2271CE07A3A3
        CheckMD5   : 837CD90695AC02436613AA5E9E4A8D63
        FixMD5     : 94C3044E24A3F86901BDDAEC5DE26E74
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s tallylog)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/var\/log\/tallylog[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates an audit record when successful/unsuccessful modifications to the 'tallylog' file occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when successful/unsuccessful modifications to the 'tallylog' file occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238286 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238286
        STIG ID    : UBTU-20-010170
        Rule ID    : SV-238286r654033_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for the use and modification of faillog file.
        DiscussMD5 : 9931CFF26CBF1FBAC0BF2271CE07A3A3
        CheckMD5   : 20FB4C1F9F3A71EA868DEB3B523F2787
        FixMD5     : EECFFF375B96208D3FC89E272868379C
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s faillog)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/var\/log\/faillog[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates an audit record when successful/unsuccessful modifications to the 'faillog' file occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when successful/unsuccessful modifications to the 'faillog' file occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238287 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238287
        STIG ID    : UBTU-20-010171
        Rule ID    : SV-238287r654036_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for the use and modification of the lastlog file.
        DiscussMD5 : 9931CFF26CBF1FBAC0BF2271CE07A3A3
        CheckMD5   : 15B6D17D9348B0C3BA2693E467660D04
        FixMD5     : 0F825D873DB7EE4D4E9900E2B380C36D
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s lastlog)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/var\/log\/lastlog[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates an audit record when successful/unsuccessful modifications to the 'lastlog' file occur."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when successful/unsuccessful modifications to the 'lastlog' file occur."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238288 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238288
        STIG ID    : UBTU-20-010172
        Rule ID    : SV-238288r951528_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the passwd command.
        DiscussMD5 : 3F95598DA130A32AA1484C0772DA87A0
        CheckMD5   : A62AED31DF882011668A352B10BFF3B5
        FixMD5     : F300A0A79EFA0F2324AF7ABF96FAB941
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s -w passwd)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/passwd ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/passwd[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'passwd' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'passwd' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'passwd' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238289 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238289
        STIG ID    : UBTU-20-010173
        Rule ID    : SV-238289r951531_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the unix_update command.
        DiscussMD5 : 3F95598DA130A32AA1484C0772DA87A0
        CheckMD5   : 618A5CCDCCAF2937DAD2D6331EE4E5A7
        FixMD5     : 63BE430DC77E8DE88C5E202D1D838C16
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s -w unix_update)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/sbin/unix_update ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/sbin\/unix_update[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'unix_update' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'unix_update' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'unix_update' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238290 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238290
        STIG ID    : UBTU-20-010174
        Rule ID    : SV-238290r951534_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the gpasswd command.
        DiscussMD5 : 3F95598DA130A32AA1484C0772DA87A0
        CheckMD5   : 0972E48B9DAAF897AC9B1B4A9BC4E3E0
        FixMD5     : 16F2F4A9444871FC4EB5ED7AA7C250B0
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s -w gpasswd)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/gpasswd ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/gpasswd[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'gpasswd' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'gpasswd' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'gpasswd' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238291 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238291
        STIG ID    : UBTU-20-010175
        Rule ID    : SV-238291r951537_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the chage command.
        DiscussMD5 : 3F95598DA130A32AA1484C0772DA87A0
        CheckMD5   : 086EA2EB08E56BC30505A9DE3B5EFD74
        FixMD5     : 16A8C9C28C776E5813310A294099D8D5
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s -w chage)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/chage ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/chage[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'chage' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'chage' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'chage' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238292 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238292
        STIG ID    : UBTU-20-010176
        Rule ID    : SV-238292r951540_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the usermod command.
        DiscussMD5 : 3F95598DA130A32AA1484C0772DA87A0
        CheckMD5   : FB2662D01DD1BDF4E72B91B863478181
        FixMD5     : 58720B7D4C2B95D5462B63CC3833B55E
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s -w usermod)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/sbin/usermod ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/sbin\/usermod[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'usermod' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'usermod' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'usermod' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238293 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238293
        STIG ID    : UBTU-20-010177
        Rule ID    : SV-238293r951543_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the crontab command.
        DiscussMD5 : 3F95598DA130A32AA1484C0772DA87A0
        CheckMD5   : D2409602745C56A35F76FC80F67F27C1
        FixMD5     : 1D2A1C5F067E153A0DCF459BA2209B45
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s -w crontab)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/bin/crontab ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/bin\/crontab[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'crontab' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'crontab' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'crontab' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238294 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238294
        STIG ID    : UBTU-20-010178
        Rule ID    : SV-238294r951546_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the pam_timestamp_check command.
        DiscussMD5 : 3F95598DA130A32AA1484C0772DA87A0
        CheckMD5   : 6330D03CFAA3F0586BF90E87B597762B
        FixMD5     : E43DF18C30BB026DA42DC8E5A234BD80
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s -w pam_timestamp_check)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a") -and (($finding | awk '{$2=$2};1') -match '=/usr/sbin/pam_timestamp_check ')) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+path=\/usr\/sbin\/pam_timestamp_check[\s]+)(?:-F[\s]+perm=x[\s]+)(?:-F[\s]+auid>=1000[\s]+)(?:-F[\s]+auid!=(?:4294967295|-1|unset)[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'pam_timestamp_check' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'pam_timestamp_check' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'pam_timestamp_check' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238295 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238295
        STIG ID    : UBTU-20-010179
        Rule ID    : SV-238295r808486_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the init_module and finit_module syscalls.
        DiscussMD5 : 5FEC25047C3489B5E42C7DD859C246E8
        CheckMD5   : F6426AC52F50847A4F2F696E9D928280
        FixMD5     : 01670B13B8D5543B6A041CC2D5157914
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s -w init_module)
        $finding ?? $($finding = "Check text: No results found.")

        if (
            (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+init_module[\s]+|([\s]+|[,])init_module([\s]+|[,]))).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+init_module[\s]+|([\s]+|[,])init_module([\s]+|[,]))).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+finit_module[\s]+|([\s]+|[,])finit_module([\s]+|[,]))).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+finit_module[\s]+|([\s]+|[,])finit_module([\s]+|[,]))).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
            )
        ) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'init_module,finit_module' commands occur."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'init_module,finit_module' system calls."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238297 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238297
        STIG ID    : UBTU-20-010181
        Rule ID    : SV-238297r802387_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000064-GPOS-00033
        Rule Title : The Ubuntu operating system must generate audit records for successful/unsuccessful uses of the delete_module syscall.
        DiscussMD5 : 6D7230A73135B70DD5A30D2948530154
        CheckMD5   : 8018ED5B301F2565026950165AB09704
        FixMD5     : D42AC10D3C1970272EEB08FBCE6115CB
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | egrep -s delete_module)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-a")) {
            if (
                (
                    ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+delete_module[\s]+|([\s]+|[,])delete_module([\s]+|[,]))).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                    ) -and (
                    ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+delete_module[\s]+|([\s]+|[,])delete_module([\s]+|[,]))).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                )
            ) {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'delete_module' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'delete_module' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'delete_module' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238298 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238298
        STIG ID    : UBTU-20-010182
        Rule ID    : SV-238298r853421_rule
        CCI ID     : CCI-000130, CCI-000131, CCI-000132, CCI-000133, CCI-000134, CCI-000135, CCI-000154, CCI-000158, CCI-000169, CCI-000172, CCI-001875, CCI-001876, CCI-001877, CCI-001878, CCI-001879, CCI-001880, CCI-001881, CCI-001882, CCI-001914
        Rule Name  : SRG-OS-000122-GPOS-00063
        Rule Title : The Ubuntu operating system must produce audit records and reports containing information to establish when, where, what type, the source, and the outcome for all DoD-defined auditable events and actions in near real time.
        DiscussMD5 : 2F996BC79F244B54785F60C0046A2BFF
        CheckMD5   : 3E438209DFBD601194500B7FA037402A
        FixMD5     : 22726B1B18CC13D580F4A4F24335F6B1
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
    $finding = $(dpkg -l auditd)
    $finding_2 = ""
    $finding_3 = ""

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding_2 = $(systemctl is-enabled auditd.service)
        if ($finding_2 -eq "enabled") {
            $finding_3 = $(systemctl is-active auditd.service)
            if ($finding_3 -eq "active") {
                $Status = "NotAFinding"
                $FindingMessage = "The audit service is configured to produce audit records."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The audit service is not active."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The audit service is not enabled."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238299 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238299
        STIG ID    : UBTU-20-010198
        Rule ID    : SV-238299r654072_rule
        CCI ID     : CCI-001464
        Rule Name  : SRG-OS-000254-GPOS-00095
        Rule Title : The Ubuntu operating system must initiate session audits at system start-up.
        DiscussMD5 : 03AA43669479F840039F0D14F314729C
        CheckMD5   : 0AA4BAC9476457C016F14D243F247B59
        FixMD5     : 747FE13F877B4FD23E165CC0E5E6313F
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
    $finding = $(grep -s -i ^[[:blank:]]*linux /boot/grub/grub.cfg)
    $correct_message_count = 0

    $finding | ForEach-Object {
        If ($_ -match "audit=1") {
            $correct_message_count++
        }
    }
    if ($correct_message_count -eq $finding.count) {
        $Status = "NotAFinding"
        $FindingMessage = "All linux lines contain 'audit=1'"
    }
    else {
        $Status = "Open"
        $FindingMessage = "A linux line does not contain 'audit=1'"
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238300 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238300
        STIG ID    : UBTU-20-010199
        Rule ID    : SV-238300r654075_rule
        CCI ID     : CCI-001493, CCI-001494
        Rule Name  : SRG-OS-000256-GPOS-00097
        Rule Title : The Ubuntu operating system must configure audit tools with a mode of 0755 or less permissive.
        DiscussMD5 : F7D32F6968D887645462CB0A0E9154E6
        CheckMD5   : 75080B9667156F0056AC7F3CEB89404F
        FixMD5     : D6A9B5FE2672E6E2BC17229CEC16D50A
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
    $audit_tools = @("/sbin/auditctl", "/sbin/aureport", "/sbin/ausearch", "/sbin/autrace", "/sbin/auditd", "/sbin/audispd", "/sbin/augenrules")
    $incorrect_message_count = 0

    $audit_tools | ForEach-Object {
        $finding = $(stat -c "%n %a" $_)
        $finding ?? $($finding = "Check text: No results found.")
        $FindingDetails += $(FormatFinding $finding) | Out-String

        if ((CheckPermissions -FindPath $_ -MinPerms 755) -eq $True) {
            $incorrect_message_count++
        }
    }
    if ($incorrect_message_count -eq 0) {
        $Status = "NotAFinding"
        $FindingMessage = "The audit tools are protected from unauthorized access, deletion, or modification."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit tools are protected from unauthorized access, deletion, or modification."
    }

    $FindingDetails = , $FindingMessage + $FindingDetails | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238301 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238301
        STIG ID    : UBTU-20-010200
        Rule ID    : SV-238301r654078_rule
        CCI ID     : CCI-001493, CCI-001494
        Rule Name  : SRG-OS-000256-GPOS-00097
        Rule Title : The Ubuntu operating system must configure audit tools to be owned by root.
        DiscussMD5 : F7D32F6968D887645462CB0A0E9154E6
        CheckMD5   : BCCD2AEE94DFB5B0A2F915FDB46C1CCB
        FixMD5     : B7D331550B4E25EBA015DECF0CD57019
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
    $audit_tools = @("/sbin/auditctl", "/sbin/aureport", "/sbin/ausearch", "/sbin/autrace", "/sbin/auditd", "/sbin/audispd", "/sbin/augenrules")
    $correct_message_count = 0

    $audit_tools | ForEach-Object {
        $finding = $(stat -c "%n %U" $_)
        $FindingDetails += $(FormatFinding $finding) | Out-String

        if ($finding -eq "$_ root") {
            $correct_message_count++
        }
    }
    if ($correct_message_count -eq $audit_tools.Count) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system configures the audit tools to be owned by root to prevent any unauthorized access, deletion, or modification."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not configure the audit tools to be owned by root to prevent any unauthorized access, deletion, or modification."
    }

    $FindingDetails = , $FindingMessage + $FindingDetails | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238302 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238302
        STIG ID    : UBTU-20-010201
        Rule ID    : SV-238302r654081_rule
        CCI ID     : CCI-001493, CCI-001494
        Rule Name  : SRG-OS-000256-GPOS-00097
        Rule Title : The Ubuntu operating system must configure the audit tools to be group-owned by root.
        DiscussMD5 : F7D32F6968D887645462CB0A0E9154E6
        CheckMD5   : D5E0AE0942D6C311713AA5588C85485C
        FixMD5     : FCEC5D70CCC25A5214F77F6E2DA36C51
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
    $audit_tools = @("/sbin/auditctl", "/sbin/aureport", "/sbin/ausearch", "/sbin/autrace", "/sbin/auditd", "/sbin/audispd", "/sbin/augenrules")
    $correct_message_count = 0

    $audit_tools | ForEach-Object {
        $finding = $(stat -c "%n %G" $_)
        $FindingDetails += $(FormatFinding $finding) | Out-String

        if ($finding -eq "$_ root") {
            $correct_message_count++
        }
    }
    if ($correct_message_count -eq $audit_tools.Count) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system configures the audit tools to be group-owned by root to prevent any unauthorized access, deletion, or modification."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not configure the audit tools to be group-owned by root to prevent any unauthorized access, deletion, or modification."
    }

    $FindingDetails = , $FindingMessage + $FindingDetails | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238303 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238303
        STIG ID    : UBTU-20-010205
        Rule ID    : SV-238303r877393_rule
        CCI ID     : CCI-001496
        Rule Name  : SRG-OS-000278-GPOS-00108
        Rule Title : The Ubuntu operating system must use cryptographic mechanisms to protect the integrity of audit tools.
        DiscussMD5 : 6EBD65BFDA3DAE3F2913D02E07E69DB1
        CheckMD5   : 8B7304027CB3029D1584E19AD5CBBC3E
        FixMD5     : D877917E55A5AF68ECCD6A633D9CC42E
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
    $finding = $(egrep -s '(\/sbin\/(audit|au))' /etc/aide/aide.conf)
    $finding ?? $($finding = "Check text: No results found.")
    $audit_tools = @("/sbin/auditctl", "/sbin/aureport", "/sbin/ausearch", "/sbin/autrace", "/sbin/auditd", "/sbin/audispd", "/sbin/augenrules")
    $missing_audit_tools = @()
    $correct_message_count = 0

    $audit_tools | ForEach-Object {
        if ($finding -match $_) {
            $correct_message_count++
        }
        else {
            $missing_audit_tools += $_
        }
    }

    if ($correct_message_count -eq 7) {
        $Status = "NotAFinding"
        $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) is properly configured to use cryptographic mechanisms to protect the integrity of audit tools."
    }
    else {
        $Status = "Open"
        $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) is not properly configured to use cryptographic mechanisms to protect the integrity of audit tools."
        $FindingMessage += "`r`n"
        $FindingMEssage += "Missing audit tools - $missing_audit_tools"
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238304 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238304
        STIG ID    : UBTU-20-010211
        Rule ID    : SV-238304r853422_rule
        CCI ID     : CCI-002233, CCI-002234
        Rule Name  : SRG-OS-000326-GPOS-00126
        Rule Title : The Ubuntu operating system must prevent all software from executing at higher privilege levels than users executing the software and the audit system must be configured to audit the execution of privileged functions.
        DiscussMD5 : F5282D77506149869F3D4992FF228437
        CheckMD5   : AE32740590905EDE59E890B0B8BCA9A9
        FixMD5     : CF72F1D407F39D70A7C77222F37F61F5
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s -w execve)
        $finding ?? $($finding = "Check text: No results found.")

        $not_commented = 0
        $line = 0
        ($finding | grep -s -i " execve ") | ForEach-Object {
            $line++
            if ((($_ | awk '{$2=$2};1').StartsWith("-a")) -and (($_ | awk '{$2=$2};1') -match " execve ")) {
                $not_commented++
            }
        }

        if ($not_commented -eq $line) {
            if ((($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+arch=b32[\s]+)(?:(-S[\s]+execve[\s]))(?:-C[\s]+uid!=euid[\s]+)(?:-F[\s]+euid=0[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') -and (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+arch=b64[\s]+)(?:(-S[\s]+execve[\s]))(?:-C[\s]+uid!=euid[\s]+)(?:-F[\s]+euid=0[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') -and
                (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+arch=b32[\s]+)(?:(-S[\s]+execve[\s]))(?:-C[\s]+gid!=egid[\s]+)(?:-F[\s]+egid=0[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') -and (($finding | awk '{$2=$2};1') -match [regex]'^-a[\s]+always,exit[\s]+(?:-S[\s]+all[\s]+)(?:-F[\s]+arch=b64[\s]+)(?:(-S[\s]+execve[\s]))(?:-C[\s]+gid!=egid[\s]+)(?:-F[\s]+egid=0[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$')) {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'execve' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'execve' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'execve' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238305 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238305
        STIG ID    : UBTU-20-010215
        Rule ID    : SV-238305r877391_rule
        CCI ID     : CCI-001849
        Rule Name  : SRG-OS-000341-GPOS-00132
        Rule Title : The Ubuntu operating system must allocate audit record storage capacity to store at least one weeks' worth of audit records, when audit records are not immediately sent to a central audit record storage facility.
        DiscussMD5 : 0AA1CF3B04BFD76DE5B1DE5B2EC28D9C
        CheckMD5   : 28C557F1204902DE1A59E27467A08C48
        FixMD5     : 63AB305BC010DE0AA77A6DC705FE7A6D
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
    $finding = $(grep -s -i ^[[:blank:]]*log_file /etc/audit/auditd.conf)
    $finding ?? $($finding = "Check text: No results found.")

    $dirname = dirname $finding.replace(" ", "").split("=")[1]
    $finding_2 = $(df -h $dirname)
    if ($finding) {
        $Status = "Not_Reviewed"
        $FindingMessage = "Check the size of the partition ($dirname) that audit records are written to."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit log path was not found."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238306 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238306
        STIG ID    : UBTU-20-010216
        Rule ID    : SV-238306r877390_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-OS-000342-GPOS-00133
        Rule Title : The Ubuntu operating system audit event multiplexor must be configured to off-load audit logs onto a different system or storage media from the system being audited.
        DiscussMD5 : 8D9B7D9105347F5C4743A8893A44A471
        CheckMD5   : D216C281CA667B4A44C0B89FEF713524
        FixMD5     : 8F6935B7BBBEEA9DFC347EE3E4CF19C6
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
    $finding = $(dpkg -l | grep -s auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(grep -s -i active /etc/audisp/plugins.d/au-remote.conf)

        if ($finding -eq "active = yes") {
            $status = "NotAFinding"
            $FindingMessage = "The audit logs are off-loaded to a different system or storage media."
        }
        else {
            $Status = "Open"
            $FindingMessage = "How are the audit logs off-loaded to a different system or storage media?"
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "Status is 'not installed', verify that another method to off-load audit logs has been implemented."
    }
    
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238307 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238307
        STIG ID    : UBTU-20-010217
        Rule ID    : SV-238307r877389_rule
        CCI ID     : CCI-001855
        Rule Name  : SRG-OS-000343-GPOS-00134
        Rule Title : The Ubuntu operating system must immediately notify the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity.
        DiscussMD5 : C35E588D648DBEA54FD4365AD7137DF5
        CheckMD5   : 4F406D17F08F57B6685FA68B3A22D69D
        FixMD5     : 0C12BEA5AF4A4D014974E98EBFB0CA38
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
    $finding = $(grep -s -i ^[[:blank:]]*space_left_action /etc/audit/auditd.conf)
    $finding_2 = $(grep -s -i "^[[:blank:]]*space_left " /etc/audit/auditd.conf) #differentiate between space_left = and space_left_action
    $finding_3 = $(grep -s action_mail_acct /etc/audit/auditd.conf)

    $finding ?? $($finding = "Check text: No results found.")
    $finding_2 ?? $($finding_2 = "Check text: No results found.")
    $finding_3 ?? $($finding_3 = "Check text: No results found.")

    switch -Wildcard ($finding.ToLower()) {
        "*email" {
            $FindingMessage = "The 'space_left_action' is set to 'email'."
            $FindingMessage += "`r`n"
            if ($finding_3) {
                $FindingMessage += "The email address is $finding_3 and should be the e-mail address of the system administrator(s) and/or ISSO."
                $FindingMessage += "`r`n"
                $FindingMessage += "Note: If the email address of the system administrator is on a remote system a mail package must be available."
                $FindingMessage += "`r`n"
            }
            elseif ($finding_3.contains("root")) {
                $FindingMessage += "The email defaults to root."
                $FindingMessage += "`r`n"
            }
            else {
                $FindingMessage += "The email address missing."
                $FindingMessage += "`r`n"
            }
        }
        "*exec" {
            $FindingMessage = "The 'space_left_action' is set to 'exec'."
            $FindingMessage += "`r`n"
            $FindingMessage += "The system executes a designated script. If this script informs the SA of the event."
            $FindingMessage += "`r`n"
        }
        "*syslog" {
            $FindingMessage = "The 'space_left_action' is set to 'syslog'."
            $FindingMessage += "`r`n"
            $FindingMessage += "The system logs the event, but does not generate a notification."
            $FindingMessage += "`r`n"
        }
    }

    If ((($Finding_2.ToLower()).startswith("space_left")) -and ((($Finding_2 | awk '{$2=$2};1').replace(" ","")).split("=")[1] -eq "25%")) {
        $FindingMessage += "$finding_2 is at least 25% of the space free in the allocated audit record storage."
    }
    else {
        $FindingMessage += "The 'space_left' parameter is missing or not equal to 25%."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String

    $Status = "Not_Reviewed"
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238308 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238308
        STIG ID    : UBTU-20-010230
        Rule ID    : SV-238308r877383_rule
        CCI ID     : CCI-001890
        Rule Name  : SRG-OS-000359-GPOS-00146
        Rule Title : The Ubuntu operating system must record time stamps for audit records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT).
        DiscussMD5 : AF6C5BFC05EA168C74F5FCC38E9AA283
        CheckMD5   : 0B030CA664AB5E8078C1E02B3D1D2D78
        FixMD5     : 51A436D9BFD3BFD3483857A7C58D377B
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
    $finding = $(timedatectl status | grep -s -i "time zone")
    $finding ?? $($finding = "Check text: No results found.")

    if (($Finding.ToUpper() -match "UTC") -or ($Finding.ToUpper() -match "GMT")) {
        $Status = "NotAFinding"
        $FindingMessage = "The time zone is configured to use Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT)."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The time zone is not configured to use Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT)."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238309 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238309
        STIG ID    : UBTU-20-010244
        Rule ID    : SV-238309r853427_rule
        CCI ID     : CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000392-GPOS-00172
        Rule Title : The Ubuntu operating system must generate audit records for privileged activities, nonlocal maintenance, diagnostic sessions and other system-level access.
        DiscussMD5 : 7EAD581D4A0DA1E46847B1498588CAD4
        CheckMD5   : 46CAC54934E6B7796509E1B62FB7AF36
        FixMD5     : 4FED0FB2276293796EE6D705831A30BB
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s sudo.log)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/var\/log\/sudo.log[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system audits privileged activities."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system audits privileged activities."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238310 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238310
        STIG ID    : UBTU-20-010267
        Rule ID    : SV-238310r832953_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000468-GPOS-00212
        Rule Title : The Ubuntu operating system must generate audit records for any successful/unsuccessful use of unlink, unlinkat, rename, renameat, and rmdir system calls.
        DiscussMD5 : 06EA96ADC209455A8351C5E91F401CAB
        CheckMD5   : 431A74A7F50CE2DFE07FEF0DDE953FE5
        FixMD5     : 2BC29443904A4CC05E71AD6F892BCE80
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s -i "unlink\|rename\|rmdir")
        $finding ?? $($finding = "Check text: No results found.")

        if (
            (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+rename[\s]+|([\s]+|[,])rename([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+rename[\s]+|([\s]+|[,])rename([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+renameat[\s]+|([\s]+|[,])renameat([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+renameat[\s]+|([\s]+|[,])renameat([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+rmdir[\s]+|([\s]+|[,])rmdir([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+rmdir[\s]+|([\s]+|[,])rmdir([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+unlink[\s]+|([\s]+|[,])unlink([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+unlink[\s]+|([\s]+|[,])unlink([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+unlinkat[\s]+|([\s]+|[,])unlinkat([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
                ) -and (
                ($finding | awk '{$2=$2};1') -match [regex]'^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+unlinkat[\s]+|([\s]+|[,])unlinkat([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=(?:4294967295|-1|unset)[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$'
            )
        ) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'unlink,unlinkat,rename,renameat,rmdir' commands occur."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'unlink,unlinkat,rename,renameat,rmdir' system calls."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238315 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238315
        STIG ID    : UBTU-20-010277
        Rule ID    : SV-238315r654120_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000472-GPOS-00217
        Rule Title : The Ubuntu operating system must generate audit records for the /var/log/wtmp file.
        DiscussMD5 : 3F95598DA130A32AA1484C0772DA87A0
        CheckMD5   : 66824A7533FEB3EA3FEC4C665C916696
        FixMD5     : 55DB9DAB8905F7A6B7EE13C0CAFE88CF
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s '/var/log/wtmp')
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/var\/log\/wtmp[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records showing start and stop times for user access to the system via /var/log/wtmp."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate audit records showing start and stop times for user access to the system via /var/log/wtmp."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238316 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238316
        STIG ID    : UBTU-20-010278
        Rule ID    : SV-238316r880873_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000472-GPOS-00217
        Rule Title : The Ubuntu operating system must generate audit records for the /var/run/utmp file.
        DiscussMD5 : E0A6C8A694B3EC5EAA7AE28A3BBFF9EB
        CheckMD5   : 5E4C51FAFC3A06CCA9A4E2A58EE92136
        FixMD5     : F91BAD674B880901D5909520EC560661
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s '/var/run/utmp')
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/var\/run\/utmp[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records showing start and stop times for user access to the system via /var/run/utmp."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate audit records showing start and stop times for user access to the system via /var/run/utmp."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238317 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238317
        STIG ID    : UBTU-20-010279
        Rule ID    : SV-238317r654126_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000472-GPOS-00217
        Rule Title : The Ubuntu operating system must generate audit records for the /var/log/btmp file.
        DiscussMD5 : 3F95598DA130A32AA1484C0772DA87A0
        CheckMD5   : 36870C8CED6924E0849AB9DCE0EB8367
        FixMD5     : ECAA6AD3F47A485A90B4096FFC13649D
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s '/var/log/btmp')
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/var\/log\/btmp[\s]+)(?:-p[\s]+wa[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records showing start and stop times for user access to the system via /var/log/btmp."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate audit records showing start and stop times for user access to the system via /var/log/btmp."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238318 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238318
        STIG ID    : UBTU-20-010296
        Rule ID    : SV-238318r654129_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000477-GPOS-00222
        Rule Title : The Ubuntu operating system must generate audit records when successful/unsuccessful attempts to use modprobe command.
        DiscussMD5 : 3F95598DA130A32AA1484C0772DA87A0
        CheckMD5   : 3C7C6B2D09B70847A280A903253A6086
        FixMD5     : 8EC4D4A4CDDFC77CAD12BC6F6070131C
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s -i "/sbin/modprobe")
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/sbin\/modprobe[\s]+)(?:-p[\s]+x[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the '/sbin/modprobe' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the '/sbin/modprobe' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the '/sbin/modprobe' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238319 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238319
        STIG ID    : UBTU-20-010297
        Rule ID    : SV-238319r654132_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000477-GPOS-00222
        Rule Title : The Ubuntu operating system must generate audit records when successful/unsuccessful attempts to use the kmod command.
        DiscussMD5 : 3F95598DA130A32AA1484C0772DA87A0
        CheckMD5   : 91E2D554514560BFDAF4AA6B2D50A61E
        FixMD5     : 0C90327B0C808D52C39977C4A89C353A
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s kmod)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/bin\/kmod[\s]+)(?:-p[\s]+x[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'kmod' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'kmod' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'kmod' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238320 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238320
        STIG ID    : UBTU-20-010298
        Rule ID    : SV-238320r832956_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-OS-000477-GPOS-00222
        Rule Title : The Ubuntu operating system must generate audit records when successful/unsuccessful attempts to use the fdisk command.
        DiscussMD5 : 3F95598DA130A32AA1484C0772DA87A0
        CheckMD5   : 9841CFFE08992E0F4A1F1D4F290AA7B5
        FixMD5     : 0BC6E9946A0BA1768A45225421A436A7
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
    $finding = $(dpkg -l auditd)

    if (($finding | awk '{print $2}') -eq "auditd") {
        $finding = $(auditctl -l | grep -s fdisk)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').StartsWith("-w")) {
            if (($finding | awk '{$2=$2};1') -match [regex]'^-w[\s]+(?:\/usr\/sbin\/fdisk[\s]+)(?:-p[\s]+x[\s]+)(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$') {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system generates audit records when successful/unsuccessful attempts to use the 'fdisk' command occur."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system does not generates a correct audit record when unsuccessful does not attempt to use the 'fdisk' system call."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record when unsuccessful does not attempt to use the 'fdisk' system call."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The audit service is not installed, therefore auditctl cannot be run."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238321 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238321
        STIG ID    : UBTU-20-010300
        Rule ID    : SV-238321r853428_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-OS-000479-GPOS-00224
        Rule Title : The Ubuntu operating system must have a crontab script running weekly to offload audit events of standalone systems.
        DiscussMD5 : 00FF23A4F2024F2CDF319F03B049F332
        CheckMD5   : 17FFB6FE98E9E539422CDA4343F2D49E
        FixMD5     : 7A3D73D076B00D49678398DE92AF66ED
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
    $finding = $(ls /etc/cron.weekly)

    if ($finding.contains("audit-offload")) {
        $FindingMessage = "There is a script in the /etc/cron.weekly directory which off-loads audit data"
        $audit_offload = $(cat /etc/cron.weekly/audit-offload)
    }
    else {
        $FindingMessage = "The script file does not exist."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $audit_offload
    $FindingDetails += $(FormatFinding $finding) | Out-String

    $Status = "Open"
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238323 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238323
        STIG ID    : UBTU-20-010400
        Rule ID    : SV-238323r877399_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-OS-000027-GPOS-00008
        Rule Title : The Ubuntu operating system must limit the number of concurrent sessions to ten for all accounts and/or account types.
        DiscussMD5 : CF5180DF2E40710881A7C3934E8E5DEE
        CheckMD5   : 4E8C23C16BF371265F07E3FE0CDF3FCA
        FixMD5     : C62E7C77FFE71A43C0CD186B434C672D
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
    $finding = $(grep -i -s maxlogins /etc/security/limits.conf | grep -s '^*')
    $finding ?? $($finding = "Check text: No results found.")

    if (($finding | awk '{$2=$2};1').split(" ")[4] -le 10) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system limits the number of concurrent sessions to ten for all accounts and/or account types."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not limit the number of concurrent sessions to ten for all accounts and/or account types."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238324 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238324
        STIG ID    : UBTU-20-010403
        Rule ID    : SV-238324r832959_rule
        CCI ID     : CCI-000067
        Rule Name  : SRG-OS-000032-GPOS-00013
        Rule Title : The Ubuntu operating system must monitor remote access methods.
        DiscussMD5 : 27AAB29D7F9EE60062BDF28C7D9271A3
        CheckMD5   : CBC0060D763EB8E0FB5108B9E976D679
        FixMD5     : 33628455A6C6C37A26CD45983E0D485E
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
    $finding = $(grep -s -E -r '^(auth,authpriv\.\*|daemon\.\*)' /etc/rsyslog.*)

    if ($finding) {
        $better_finding_1 = $(grep -s -E -r '^(auth,authpriv\.*)' /etc/rsyslog.* | awk '{$2=$2};1')
        if (!($better_finding_1)) { $better_finding_1 = "Check text: No results found." }
        else{
            $better_finding_1_path = ($better_finding_1).split(":")[0]
        }
        $better_finding_2 = $(grep -s -E -r '^daemon\.*' /etc/rsyslog.*) | awk '{$2=$2};1'
        if (!($better_finding_2)) { $better_finding_2 = "Check text: No results found." }
        else {
            $better_finding_2_path = ($better_finding_2).split(":")[0]
        }
    }
    else {
        $Finding = "Check text: No results found."
    }

    if (($better_finding_1 -eq "$($better_finding_1_path):auth,authpriv.* /var/log/auth.log") -and ($better_finding_2 -eq "$($better_finding_2_path):daemon.* /var/log/messages")) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system monitors all remote access methods."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not monitor all remote access methods."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238325 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238325
        STIG ID    : UBTU-20-010404
        Rule ID    : SV-238325r654150_rule
        CCI ID     : CCI-000803
        Rule Name  : SRG-OS-000120-GPOS-00061
        Rule Title : The Ubuntu operating system must encrypt all stored passwords with a FIPS 140-2 approved cryptographic hashing algorithm.
        DiscussMD5 : 362BFA65936DD923B7EC8631E28BA5D3
        CheckMD5   : 261A1032368F8D1EFA48DECF14112D1E
        FixMD5     : DF1628A5D447BE05FE7D278D5C3EA06A
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
    $finding = $(grep -s -i ^[[:blank:]]*encrypt_method /etc/login.defs)
    $finding ?? $($finding = "Check text: No results found.")

    If (($Finding | awk '{$2=$2};1').ToUpper() -eq "ENCRYPT_METHOD SHA512") {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system encrypts all stored passwords with a FIPS 140-2 approved cryptographic hashing algorithm."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not encrypt all stored passwords with a FIPS 140-2 approved cryptographic hashing algorithm."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238326 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238326
        STIG ID    : UBTU-20-010405
        Rule ID    : SV-238326r877396_rule
        CCI ID     : CCI-000197
        Rule Name  : SRG-OS-000074-GPOS-00042
        Rule Title : The Ubuntu operating system must not have the telnet package installed.
        DiscussMD5 : 362BFA65936DD923B7EC8631E28BA5D3
        CheckMD5   : 11A1902A19D700DDDEF9816CFF2E78A7
        FixMD5     : D12B2804B3220315EC07435AF11AF144
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
    $finding = $(dpkg -l | grep -s telnetd)

    if (($finding | awk '{print $2}') -eq "telnetd") {
        $Status = "Open"
        $FindingMessage = "The telnet daemon is installed on the Ubuntu operating system."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The telnet daemon is not installed on the Ubuntu operating system."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238327 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238327
        STIG ID    : UBTU-20-010406
        Rule ID    : SV-238327r654156_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-OS-000095-GPOS-00049
        Rule Title : The Ubuntu operating system must not have the rsh-server package installed.
        DiscussMD5 : E16296521E676B2423E98E83F764F864
        CheckMD5   : 8DDC444B55853DE2591AE3896BFF525B
        FixMD5     : 0A56469C81E5B66CDBA639A7FF455053
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
    $finding = $(dpkg -l | grep -s rsh-server)

    if (($finding | awk '{print $2}') -match "rsh-server") {
        $Status = "Open"
        $FindingMessage = "The rsh-server package is installed."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The rsh-server package is not installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238328 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238328
        STIG ID    : UBTU-20-010407
        Rule ID    : SV-238328r654159_rule
        CCI ID     : CCI-000382
        Rule Name  : SRG-OS-000096-GPOS-00050
        Rule Title : The Ubuntu operating system must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.
        DiscussMD5 : 854635EDEEB3969946568A22F7A6FF23
        CheckMD5   : 8F85346A7FD3FCD16F74EAF57DBFE187
        FixMD5     : C3B7A4DB1890D32012B77C5E4AB28DAA
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
    $finding = $(dpkg -l | grep -s ufw)

    if (($finding | awk '{print $2}') -eq "ufw") {
        $finding = $(ufw show raw)

        $Status = "Not_Reviewed"
        $FindingMessage = "Verify the Ubuntu operating system is configured to prohibit or restrict the use of functions, ports, protocols, and/or services as defined in the Ports, Protocols, and Services Management (PPSM) Category Assignments List (CAL) and vulnerability assessments."
    }
    else{
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system is not configured to prohibit or restrict the use of functions, ports, protocols, and/or services as defined in the Ports, Protocols, and Services Management (PPSM) Category Assignments List (CAL) and vulnerability assessments."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238329 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238329
        STIG ID    : UBTU-20-010408
        Rule ID    : SV-238329r654162_rule
        CCI ID     : CCI-000770
        Rule Name  : SRG-OS-000109-GPOS-00056
        Rule Title : The Ubuntu operating system must prevent direct login into the root account.
        DiscussMD5 : 223D49A77A2FB6EBFB84008FCC8791E9
        CheckMD5   : C5E75014CFA49D4A41810999FFD09792
        FixMD5     : 0F75D0298B8F036A006013F1C477F255
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
    $finding = $(passwd -S root)

    if (($finding | awk '{print $2}') -eq "L") {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system prevents direct logins to the root account."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not prevent direct logins to the root account."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238330 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238330
        STIG ID    : UBTU-20-010409
        Rule ID    : SV-238330r928525_rule
        CCI ID     : CCI-000795
        Rule Name  : SRG-OS-000118-GPOS-00060
        Rule Title : The Ubuntu operating system must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.
        DiscussMD5 : 9EDEED8E29745F5AAADCF38481BCAA4B
        CheckMD5   : FF1A0FB23B242B67A575EBEF169492DE
        FixMD5     : ED29447F9651388DA93E1E0318F37A39
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
    $finding = $(grep -s -i ^[[:blank:]]*INACTIVE /etc/default/useradd)
    $finding ?? $($finding = "Check text: No results found.")

    if (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -in 1..35) {
        $Status = "NotAFinding"
        $FindingMessage = "The account identifiers (individuals, groups, roles, and devices) are disabled after 35 days of inactivity."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The account identifiers (individuals, groups, roles, and devices) are not disabled after 35 days of inactivity."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238331 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238331
        STIG ID    : UBTU-20-010410
        Rule ID    : SV-238331r902885_rule
        CCI ID     : CCI-001682
        Rule Name  : SRG-OS-000123-GPOS-00064
        Rule Title : The Ubuntu operating system must automatically expire temporary accounts within 72 hours.
        DiscussMD5 : 7015EA016FCA2564C66EDAB54535E910
        CheckMD5   : B1C0DC1ECBB65F2BAFBBC9900C539F3F
        FixMD5     : D18D5707AD33C593F9E6BF994EF78831
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
    $user_list = $(awk -F: '{print $1}' /etc/passwd)
    $user_list | ForEach-Object {
        $user_info = $(chage -l $_ | grep -s expires)
        $finding = $_ + "`r`n" + $user_info[0] + "`r`n" + $user_info[1] + "`r`n" + $user_info[2]
        $FindingDetails += $(FormatFinding $finding) | Out-String }

    $Status = "Not_Reviewed"
    $FindingMessage = "Verify the Ubuntu operating system expires emergency accounts within 72 hours or less."

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails = , $FindingMessage + $FindingDetails   | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238332 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238332
        STIG ID    : UBTU-20-010411
        Rule ID    : SV-238332r654171_rule
        CCI ID     : CCI-001090
        Rule Name  : SRG-OS-000138-GPOS-00069
        Rule Title : The Ubuntu operating system must set a sticky bit on all public directories to prevent unauthorized and unintended information transferred via shared system resources.
        DiscussMD5 : B0DB0BC1DD3AEF96805AAB59B4D1C03D
        CheckMD5   : B60ACB5A92C25CD074890CA47D9BA06C
        FixMD5     : FAFF080EBCE45E3B9CF4AFCD031B91BB
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
    $finding = $(df -Tl | awk '(NR>1 && $2!="devtmpfs" && $2!="tmpfs" ){print $7}' | xargs -I% find "%" -xdev -not -path "/sys/*" -not -path "/proc/*" -not -path "/run/*" -type d -perm -002 ! -perm -1000)

    if ($Finding) {
        $Status = "Open"
        $FindingMessage = "The below files do not have their sticky bit set."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The below files have their sticky bit set."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238333 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238333
        STIG ID    : UBTU-20-010412
        Rule ID    : SV-238333r654174_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-OS-000142-GPOS-00071
        Rule Title : The Ubuntu operating system must be configured to use TCP syncookies.
        DiscussMD5 : E76F95B92ECC562C0FC313CA6E192143
        CheckMD5   : 13F2621887717850778CE421F1B30CBF
        FixMD5     : B872AE4F7377D5ED470B847E308F2614
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
    $finding = $(sysctl net.ipv4.tcp_syncookies)
    $finding ?? $($finding = "Check text: No results found.")
    $finding_2 = ""

    if ((($Finding.Tolower()).StartsWith("net.ipv4.tcp_syncookies")) -and ((($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 1))) {
        $finding_2 = $(grep -s -i net.ipv4.tcp_syncookies /etc/sysctl.conf /etc/sysctl.d/* | grep -s -v '#')
        if ($finding_2) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system is configured to use TCP syncookies."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system is configured to use TCP syncookies but the value is not saved."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system is not configured to use TCP syncookies."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238334 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238334
        STIG ID    : UBTU-20-010413
        Rule ID    : SV-238334r654177_rule
        CCI ID     : CCI-001190
        Rule Name  : SRG-OS-000184-GPOS-00078
        Rule Title : The Ubuntu operating system must disable kernel core dumps so that it can fail to a secure state if system initialization fails, shutdown fails or aborts fail.
        DiscussMD5 : 82F90B2D2B8346DED7240F4AEFD9184C
        CheckMD5   : 518BCB935FBC29B9333BAB1FAC03A47F
        FixMD5     : D61F3A89559C49C5553D7E0FE5B355E0
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
    $finding = $(systemctl is-active kdump.service)

    if ($Finding -eq "inactive") {
        $Status = "NotAFinding"
        $FindingMessage = "Kernel core dumps are disabled."
    }
    else {
        $Status = "Not_Reviewed"
        $FindingMessage = "The 'kdump' service is active. Ask the System Administrator if the use of the service is required and documented with the Information System Security Officer (ISSO)."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238335 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238335
        STIG ID    : UBTU-20-010414
        Rule ID    : SV-238335r951548_rule
        CCI ID     : CCI-001199, CCI-002475, CCI-002476
        Rule Name  : SRG-OS-000185-GPOS-00079
        Rule Title : Ubuntu operating systems handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.
        DiscussMD5 : 6B2E5A63C7A21F4558A8BA57E8713601
        CheckMD5   : 7BC24E621447DC9CB52FDA1E479056F1
        FixMD5     : F9EEDB2E91ACA5C1109341CC3B1518C5
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
    $finding = $(fdisk -l)

    if (Test-Path /etc/crypttab){
        $better_finding = $(blkid | grep -s $(cat /etc/crypttab | awk '{print $2}').replace("UUID=", ""))
        $correct_message_count = 0

        $better_finding | ForEach-Object {
            If ($_ -match "crypto_LUKS") {
                $correct_message_count++
            }
        }
        if ($correct_message_count -eq $better_finding.count) {
            $Status = "NotAFinding"
            $FindingMessage = "The system partitions are all encrypted"
        }
        else {
            $Status = "Open"
            $FindingMessage = "The system partitions are not all encrypted.  A partition other than the boot partition or pseudo file systems (such as /proc or /sys) is not listed"
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The system partitions are not all encrypted."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238336 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238336
        STIG ID    : UBTU-20-010415
        Rule ID    : SV-238336r939261_rule
        CCI ID     : CCI-001233
        Rule Name  : SRG-OS-000191-GPOS-00080
        Rule Title : The Ubuntu operating system must deploy Endpoint Security for Linux Threat Prevention (ENSLTP).
        DiscussMD5 : A8BF9FF6C5A6B5FE48B5E40A6C28AB53
        CheckMD5   : 9E09648A7D1D3697D85FE27E547120A5
        FixMD5     : C75F3C288AC0F2E270398C1EFE9BE461
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
    $finding = $(dpkg -l | grep -s mcafeetp)
    $finding_2 = ""

    if (($finding | awk '{print $2}') -eq "mcafeetp") {
        $finding_2 = $(/opt/McAfee/ens/tp/init/mfetpd-control.sh status)

        if ($finding_2 -match "Active: active"){
            $Status = "NotAFinding"
            $FindingMessage = "The Endpoint Security for Linux Threat Prevention (ENSLTP) 10.6+ package is installed and the service is running."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Endpoint Security for Linux Threat Prevention (ENSLTP) package is installed but the service is not running."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Endpoint Security for Linux Threat Prevention (ENSLTP) package is not installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238337 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238337
        STIG ID    : UBTU-20-010416
        Rule ID    : SV-238337r880876_rule
        CCI ID     : CCI-001312
        Rule Name  : SRG-OS-000205-GPOS-00083
        Rule Title : The Ubuntu operating system must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.
        DiscussMD5 : 7A6BA1BDB4E31F3546DC89C1C346C2A4
        CheckMD5   : AC1C8564BEB8ACBF1D00D99C565B05D3
        FixMD5     : CDD5D500BC7C61AB17A29A4EF1F79D78
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
    $command = @'
#!/bin/sh

find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec stat -c "%n %a" {} \;
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    if ($Finding) {
        $Status = "Open"
        $FindingMessage += "The below files do not have their permissions set to 640 or more."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage += "The below files have their permissions set to 640 or more."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238338 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238338
        STIG ID    : UBTU-20-010417
        Rule ID    : SV-238338r654189_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : The Ubuntu operating system must configure the /var/log directory to be group-owned by syslog.
        DiscussMD5 : CA2576C21937F89199088A150A2B2878
        CheckMD5   : C23B7B1AFFD672CF0B07DF944877AC0F
        FixMD5     : 78AEBF9E2D39F8C73FD0F40E1F83BCFF
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
    $finding = $(stat -c "%n %G" /var/log)

    if ($finding -eq "/var/log syslog") {
        $Status = "NotAFinding"
        $FindingMessage = "The /var/log directory is group owned by syslog."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The /var/log directory is not group owned by syslog."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238339 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238339
        STIG ID    : UBTU-20-010418
        Rule ID    : SV-238339r654192_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : The Ubuntu operating system must configure the /var/log directory to be owned by root.
        DiscussMD5 : CA2576C21937F89199088A150A2B2878
        CheckMD5   : 539D4B9C8CD3D29B043B65E0D319CB23
        FixMD5     : 44D7309D06E97206BA7408A3CD5D9C76
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
    $finding = $(stat -c "%n %U" /var/log)

    if ($finding -eq "/var/log root") {
        $Status = "NotAFinding"
        $FindingMessage = "The /var/log directory is owned by root."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The /var/log directory is not owned by root."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238340 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238340
        STIG ID    : UBTU-20-010419
        Rule ID    : SV-238340r880879_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : The Ubuntu operating system must configure the /var/log directory to have mode "0755" or less permissive.
        DiscussMD5 : E2CBCFDA0C4AFF443AC18A12F2E5EF4C
        CheckMD5   : 8CA9DBE94E3C18D810F1DEFCBF02C17C
        FixMD5     : 239477BC05A41F843482ABC36C85FD37
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
    $finding = $(dpkg -l | grep -s rsyslog)

    if (($finding | awk '{print $2}') -eq "rsyslog") {
        $finding = $(stat -c "%n %a" /var/log)
        $finding ?? $($finding = "Check text: No results found.")

        if (($finding | awk '{$2=$2};1').split(" ")[1] -le 755) {
            $Status = "NotAFinding"
            $FindingMessage = "The mode of the /var/log directory is '755' or more (more permissive)."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The mode of the /var/log directory is less than '755' (less permissive)."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The rsyslog package is not installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238341 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238341
        STIG ID    : UBTU-20-010420
        Rule ID    : SV-238341r654198_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : The Ubuntu operating system must configure the /var/log/syslog file to be group-owned by adm.
        DiscussMD5 : CA2576C21937F89199088A150A2B2878
        CheckMD5   : 3B684BBACEC195B80F3E3A815195D663
        FixMD5     : F05782F732BC457999B9C195977A513A
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
    $finding = $(stat -c "%n %G" /var/log/syslog)

    if ($finding -eq "/var/log/syslog adm") {
        $Status = "NotAFinding"
        $FindingMessage = "The /var/log/syslog file is group-owned by adm."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The /var/log/syslog file is not group-owned by adm."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238342 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238342
        STIG ID    : UBTU-20-010421
        Rule ID    : SV-238342r654201_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : The Ubuntu operating system must configure /var/log/syslog file to be owned by syslog.
        DiscussMD5 : CA2576C21937F89199088A150A2B2878
        CheckMD5   : 3393D45290AB4B708392B65B3F653B71
        FixMD5     : 662724F6386E61CF35B410F8E380FF29
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
    $finding = $(stat -c "%n %U" /var/log/syslog)

    if ($finding -eq "/var/log/syslog syslog") {
        $Status = "NotAFinding"
        $FindingMessage = "The /var/log/syslog file is owned by syslog."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The /var/log/syslog file is owned by syslog."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238343 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238343
        STIG ID    : UBTU-20-010422
        Rule ID    : SV-238343r654204_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : The Ubuntu operating system must configure /var/log/syslog file with mode 0640 or less permissive.
        DiscussMD5 : CA2576C21937F89199088A150A2B2878
        CheckMD5   : 0554E11BC6560186F1D367CA77465B3E
        FixMD5     : 708DC202FDDE9A84424FB05CB9B02836
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
    $finding = $(stat -c "%n %a" /var/log/syslog)

    if ($finding) {
        if ($(CheckPermissions -FindPath "/var/log/syslog" -MinPerms 640) -eq $True){
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system configures the /var/log/syslog file with mode '0640' or more (less permissive)."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system configures the /var/log/syslog file with mode '0640' (more permissive)."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system in missing the /var/log/syslog file."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238344 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238344
        STIG ID    : UBTU-20-010423
        Rule ID    : SV-238344r654207_rule
        CCI ID     : CCI-001495
        Rule Name  : SRG-OS-000258-GPOS-00099
        Rule Title : The Ubuntu operating system must have directories that contain system commands set to a mode of 0755 or less permissive.
        DiscussMD5 : D582A4700E63A5909DDC992B4AC84EC2
        CheckMD5   : 14578F1BAB804BE6BD0509B259C62819
        FixMD5     : 35F83B7384EF98EF2F6A31A41AF9413E
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
    $command = @'
#!/bin/sh

find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -xdev -perm /022 -type d -exec stat -c "%n %a" '{}' \;
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    $correct_message_count = 0

    $finding | ForEach-Object {
        if (($finding | awk '{$2=$2};1').split(" ")[1] -le 755) {
            $correct_message_count++
        }
    }

    if ($correct_message_count -eq $finding.count) {
        $Status = "NotAFinding"
        $FindingMessage = "The system commands directories have mode 0755 or less permissive:"
    }
    else {
        $Status = "Open"
        $FindingMessage = "The system commands directories do not have mode 0755 or less permissive:"
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "/bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin"
    $FindingMessage += "`r`n"
    $FindingMessage += "The below directories (if any) do not have mode 0755 or less permissive."
    $FindingDetails += $FindingMessage  | Out-String
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238345 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238345
        STIG ID    : UBTU-20-010424
        Rule ID    : SV-238345r654210_rule
        CCI ID     : CCI-001495
        Rule Name  : SRG-OS-000258-GPOS-00099
        Rule Title : The Ubuntu operating system must have directories that contain system commands owned by root.
        DiscussMD5 : D582A4700E63A5909DDC992B4AC84EC2
        CheckMD5   : 431EA1B6F43740BADF35DAD1B21D1F2C
        FixMD5     : 0A27FE96D5DF45815358C7CCA1447561
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
    $command = @'
#!/bin/sh

find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -xdev ! -user root -type d -exec stat -c "%n %U" '{}' \;
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    If ($finding) {
        $Status = "Open"
        $FindingMessage = "The system commands directories are not owned by root:"
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The system commands directories are owned by root:"
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "/bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin"
    $FindingMessage += "`r`n"
    $FindingMessage += "The below directories (if any) are not owned by root."
    $FindingDetails += $FindingMessage  | Out-String
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238346 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238346
        STIG ID    : UBTU-20-010425
        Rule ID    : SV-238346r654213_rule
        CCI ID     : CCI-001495
        Rule Name  : SRG-OS-000258-GPOS-00099
        Rule Title : The Ubuntu operating system must have directories that contain system commands group-owned by root.
        DiscussMD5 : D582A4700E63A5909DDC992B4AC84EC2
        CheckMD5   : C6D75F40B16C9A52B55D6E58DFDE6082
        FixMD5     : 56D362ACE8957083E1511664A15DA7A8
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
    $command = @'
#!/bin/sh

find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -xdev ! -group root -type d -exec stat -c "%n %G" '{}' \;
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    If ($finding) {
        $Status = "Open"
        $FindingMessage = "The system commands directories are not group-owned by root:"
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The system commands directories are group-owned by root:"
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "/bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin"
    $FindingMessage += "`r`n"
    $FindingMessage += "The below directories (if any) are not group-owned by root."
    $FindingDetails += $FindingMessage  | Out-String
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238347 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238347
        STIG ID    : UBTU-20-010426
        Rule ID    : SV-238347r654216_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : The Ubuntu operating system library files must have mode 0755 or less permissive.
        DiscussMD5 : BCD24B1E190CA063D8D458E2B53C7196
        CheckMD5   : AA57EB3F3D1828FDB6DFBB8E426FA6E4
        FixMD5     : F85B8BAFB99DA382621CAB2DB2439185
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
    $command = @'
#!/bin/sh

find /lib /lib64 /usr/lib -xdev -perm /022 -type f -exec stat -c "%n %a" '{}' \;
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    $correct_message_count = 0

    $finding | ForEach-Object {
        if (($_ | awk '{$2=$2};1').split(" ")[1] -le 755) {
            $correct_message_count++
        }
    }

    if ($correct_message_count -eq $finding.count) {
        $Status = "NotAFinding"
        $FindingMessage = "The system-wide shared library files contained in the directories '/lib', '/lib64' and '/usr/lib' have mode '0755' or less permissive."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The system-wide shared library files contained in the directories '/lib', '/lib64' and '/usr/lib' do not have mode '0755' or less permissive."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "The below files (if any) do not have their permissions set to 755 or more."
    $FindingDetails += $FindingMessage  | Out-String
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238348 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238348
        STIG ID    : UBTU-20-010427
        Rule ID    : SV-238348r654219_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : The Ubuntu operating system library directories must have mode 0755 or less permissive.
        DiscussMD5 : BCD24B1E190CA063D8D458E2B53C7196
        CheckMD5   : 79FA6FCFE0BB69E2B772ACD481D98F18
        FixMD5     : 2E8B12E2137DFD872D0611341E16B7B4
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
    $command = @'
#!/bin/sh

find /lib /lib64 /usr/lib -xdev -perm /022 -type d -exec stat -c "%n %a" '{}' \;
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    $correct_message_count = 0

    $finding | ForEach-Object {
        if (($finding | awk '{$2=$2};1').split(" ")[1] -le 755) {
            $correct_message_count++
        }
    }

    if ($correct_message_count -eq $finding.count) {
        $Status = "NotAFinding"
        $FindingMessage = "The system-wide shared library directories '/lib', '/lib64' and '/usr/lib' have mode '0755' or less permissive."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The system-wide shared library directories '/lib', '/lib64' and '/usr/lib' do not have mode '0755' or less permissive."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "The below directories (if any) do not have their permissions set to 755 or more."
    $FindingDetails += $FindingMessage  | Out-String
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238349 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238349
        STIG ID    : UBTU-20-010428
        Rule ID    : SV-238349r654222_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : The Ubuntu operating system library files must be owned by root.
        DiscussMD5 : BCD24B1E190CA063D8D458E2B53C7196
        CheckMD5   : 8F22DC829E7F04B476B33D60488DB8CE
        FixMD5     : 5C2B369989596F2717BE54394F166813
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
    $command = @'
#!/bin/sh

find /lib /usr/lib /lib64 -xdev ! -user root -type f -exec stat -c "%n %U" '{}' \;
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    if ($finding) {
        $Status = "Open"
        $FindingMessage = "The system-wide shared library files contained in the directories '/lib', '/lib64' and '/usr/lib' are not owned by root."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The system-wide shared library files contained in the directories '/lib', '/lib64' and '/usr/lib' are owned by root."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "The below files (if any) are not owned by root."
    $FindingDetails += $FindingMessage  | Out-String
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238350 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238350
        STIG ID    : UBTU-20-010429
        Rule ID    : SV-238350r654225_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : The Ubuntu operating system library directories must be owned by root.
        DiscussMD5 : BCD24B1E190CA063D8D458E2B53C7196
        CheckMD5   : 5293749FA809A8EA2E0D0A38D15ED604
        FixMD5     : D5478F38423A011AFA91F0CC88A0E9C8
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
    $command = @'
#!/bin/sh

find /lib /usr/lib /lib64 -xdev ! -user root -type d -exec stat -c "%n %U" '{}' \;
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    if ($finding) {
        $Status = "Open"
        $FindingMessage = "The system-wide shared library directories '/lib', '/lib64' and '/usr/lib' are not owned by root."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The system-wide shared library directories '/lib', '/lib64' and '/usr/lib' are owned by root."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "The below files (if any) are not owned by root."
    $FindingDetails += $FindingMessage  | Out-String
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238351 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238351
        STIG ID    : UBTU-20-010430
        Rule ID    : SV-238351r832962_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : The Ubuntu operating system library files must be group-owned by root or a system account.
        DiscussMD5 : BCD24B1E190CA063D8D458E2B53C7196
        CheckMD5   : 811BCAB113CF8F0142CCE1E387DB9439
        FixMD5     : 1A83C8C4C6415BDC5938B7282B663112
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
    $command = @'
#!/bin/sh

find /lib /usr/lib /lib64 -xdev ! -group root -type f -exec stat -c "%n %G" '{}' \;
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    if ($finding) {
        $Status = "Open"
        $FindingMessage = "The system-wide library files contained in the directories '/lib', '/lib64' and '/usr/lib' are not group-owned by root."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The system-wide library files contained in the directories '/lib', '/lib64' and '/usr/lib' are group-owned by root."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "The below files (if any) are not group-owned by root."
    $FindingDetails += $FindingMessage  | Out-String
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238352 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238352
        STIG ID    : UBTU-20-010431
        Rule ID    : SV-238352r654231_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : The Ubuntu operating system library directories must be group-owned by root.
        DiscussMD5 : BCD24B1E190CA063D8D458E2B53C7196
        CheckMD5   : 442D52E7E6F721F0255B3C763D52291F
        FixMD5     : 91675EDAA86B4E9544917DBB737630B2
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
    $command = @'
#!/bin/sh

find /lib /usr/lib /lib64 -xdev ! -group root -type d -exec stat -c "%n %G" '{}' \;
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    if ($finding) {
        $Status = "Open"
        $FindingMessage = "The system-wide library directories '/lib', '/lib64' and '/usr/lib' are not group-owned by root."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The system-wide library directories '/lib', '/lib64' and '/usr/lib' are group-owned by root."
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "The below directories (if any) are not group-owned by root."
    $FindingDetails += $FindingMessage  | Out-String
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238353 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238353
        STIG ID    : UBTU-20-010432
        Rule ID    : SV-238353r654234_rule
        CCI ID     : CCI-001665
        Rule Name  : SRG-OS-000269-GPOS-00103
        Rule Title : The Ubuntu operating system must be configured to preserve log records from failure events.
        DiscussMD5 : 91819B56744A0B92292AD2DE6CAE3E8C
        CheckMD5   : C9E36C8C2E78C07AA5212DCC2A6AB98A
        FixMD5     : FEF7B75CC0AE16D79FCE88CF77E7DB2E
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
    $finding = $(dpkg -l | grep -s rsyslog)
    $finding_2 = ""
    $finding_3 = ""

    if (($finding | awk '{print $2}') -eq "rsyslog") {
        $FindingMessage = "The log service is installed properly"
        $finding_2 = $(systemctl is-enabled rsyslog)
        if ($finding_2 -eq "enabled") {
            $FindingMessage += "`r`n"
            $FindingMessage += "The log service is enabled."
            $finding_3 = $(systemctl is-active rsyslog)
            if ($finding_3 -eq "active") {
                $Status = "NotAFinding"
                $FindingMessage += "`r`n"
                $FindingMessage += "The log service is properly running and active on the system."
            }
            else {
                $Status = "Open"
                $FindingMessage += "`r`n"
                $FindingMessage += "The log service is not properly running and active on the system."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage += "`r`n"
            $FindingMessage += "The log service is not enabled."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The rsyslog package is not installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238354 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238354
        STIG ID    : UBTU-20-010433
        Rule ID    : SV-238354r853429_rule
        CCI ID     : CCI-002314
        Rule Name  : SRG-OS-000297-GPOS-00115
        Rule Title : The Ubuntu operating system must have an application firewall installed in order to control remote access methods.
        DiscussMD5 : 4249E220B20B236F5ED79403784303E5
        CheckMD5   : 398D2650DA48A351F288F975E56AC06E
        FixMD5     : 11946F40322FB4867CC9F9F32BC984E4
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
    $finding = $(dpkg -l | grep -s ufw)

    if (($finding | awk '{print $2}') -eq "ufw") {
        $Status = "NotAFinding"
        $FindingMessage = "The Uncomplicated Firewall is installed."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Uncomplicated Firewall is not installed."
        $FindingMessage += "`r`n"
        $FindingMessage += "The 'ufw' package is not installed.  Is another application firewall is installed?"
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238355 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238355
        STIG ID    : UBTU-20-010434
        Rule ID    : SV-238355r853430_rule
        CCI ID     : CCI-002314
        Rule Name  : SRG-OS-000297-GPOS-00115
        Rule Title : The Ubuntu operating system must enable and run the uncomplicated firewall(ufw).
        DiscussMD5 : 4249E220B20B236F5ED79403784303E5
        CheckMD5   : A6DF11047DCE7784DF4025A35A870AFD
        FixMD5     : 4682991F728E15E95FAF720E34194B51
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
    $finding = $(systemctl is-enabled ufw)
    $finding_2 = ""

    if ($finding -eq "enabled") {
        $finding_2 = $(systemctl is-active ufw)
        if ($finding_2 -eq "active") {
            $Status = "NotAFinding"
            $FindingMessage = "The Uncomplicated Firewall is enabled and active on the system."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Uncomplicated Firewall is enabled but not active on the system."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Uncomplicated Firewall is neither enabled nor active on the system."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238356 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238356
        STIG ID    : UBTU-20-010435
        Rule ID    : SV-238356r877038_rule
        CCI ID     : CCI-001891
        Rule Name  : SRG-OS-000355-GPOS-00143
        Rule Title : The Ubuntu operating system must, for networked systems, compare internal information system clocks at least every 24 hours with a server which is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, or a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).
        DiscussMD5 : EFB9BD28A1128E9CF87800AF30516941
        CheckMD5   : A8154C70EBAFAE991CDBF9A098A5FA20
        FixMD5     : 3308231EA3E6598C7E64A11CCD5986A9
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
    $finding = $(grep -s maxpoll /etc/chrony/chrony.conf)
    $finding ?? $($finding = "Check text: No results found.")
    $finding_2 = ""
    $found = 0

    $finding | Foreach-Object {
        $maxpoll = $($_ | grep -s -oP '(?<=maxpoll )[^ ]*')
        if (($_.ToLower()).startswith("server") -and ($maxpoll -le "16")) {
            $found++
        }
    }

    if ($found -eq $finding.count) {
        $finding_2 = $(grep -s -i server /etc/chrony/chrony.conf)
        if ($finding_2) {
            $Status = "Not_Reviewed"
            $FindingMessage = "Verify that the 'chrony.conf' file is configured to an authoritative DoD time source."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The 'chrony.conf' file is not configured to an authoritative time source."
        }
    }
    else {
        $finding_2 -eq ""
        $Status = "Open"
        $FindingMessage = "The system clock is not configured to compare the system clock at least every 24 hours to the authoritative time source."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238357 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238357
        STIG ID    : UBTU-20-010436
        Rule ID    : SV-238357r853432_rule
        CCI ID     : CCI-002046
        Rule Name  : SRG-OS-000356-GPOS-00144
        Rule Title : The Ubuntu operating system must synchronize internal information system clocks to the authoritative time source when the time difference is greater than one second.
        DiscussMD5 : C4E209DB154F2E6EDD1A6DF99B2D0F99
        CheckMD5   : 3386A80281BB75BB44C6776D7BB79EA0
        FixMD5     : 9AC7E5C3402EE24E32340B1E1D90966D
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
    $finding = $(grep -s -i ^[[:blank:]]*makestep /etc/chrony/chrony.conf)
    $finding ?? $($finding = "Check text: No results found.")

    if ((($finding | awk '{$2=$2};1').replace("makestep ", "")) -eq "1 -1") {
        $Status = "NotAFinding"
        $FindingMessage = "The operating system synchronizes internal system clocks to the authoritative time source when the time difference is greater than one second."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The operating system does not synchronize internal system clocks to the authoritative time source when the time difference is greater than one second."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238359 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238359
        STIG ID    : UBTU-20-010438
        Rule ID    : SV-238359r877463_rule
        CCI ID     : CCI-001749
        Rule Name  : SRG-OS-000366-GPOS-00153
        Rule Title : The Ubuntu operating system's Advance Package Tool (APT) must be configured to prevent the installation of patches, service packs, device drivers, or Ubuntu operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization.
        DiscussMD5 : CCD906922108B11C3C4C217872E107CA
        CheckMD5   : 3C90966E1B68A2CF4C63B1148FB4C37E
        FixMD5     : C7781CFCC3B8CC651FD82EBCEB63A855
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
    $finding = $(grep -s -i ^[[:blank:]]*AllowUnauthenticated /etc/apt/apt.conf.d/*)
    $finding ?? $($finding = "Check text: No results found.")
    $incorrect_message_count = 0

    $finding | ForEach-Object { if ($_.Contains('APT::Get::AllowUnauthenticated "true"')) {
            $incorrect_message_count++
        } }
    if ($incorrect_message_count -gt 0) {
        $Status = "Open"
        $FindingMessage = "At least one of the files returned from the command with 'AllowUnauthenticated' set to 'true'"
        $FindingMessage += "`r`n"
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The 'AllowUnauthenticated' variable is not set at all or set to 'false'"
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238360 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238360
        STIG ID    : UBTU-20-010439
        Rule ID    : SV-238360r853435_rule
        CCI ID     : CCI-001764, CCI-001774, CCI-002165, CCI-002235
        Rule Name  : SRG-OS-000368-GPOS-00154
        Rule Title : The Ubuntu operating system must be configured to use AppArmor.
        DiscussMD5 : 0244083B0F8037AC7174AF6637EEE169
        CheckMD5   : D2011373CA049E30B4BCD96D64A009B4
        FixMD5     : E4E7C69768E420B094846AEC2560B5FF
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
    $finding = $(dpkg -l | grep -s -i apparmor)
    $finding_2 = ""
    $finding_3 = ""

    if (($finding | awk '{print $2}') -match "apparmor") {
        $finding_2 = $(systemctl is-active apparmor.service)
        if ($finding_2 -eq "active") {
            $finding_3 = $(systemctl is-enabled apparmor.service)
            if ($finding_3 -eq "enabled") {
                $Status = "NotAFinding"
                $FindingMessage = "The operating system prevents program execution in accordance with local policies."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The operating system does not prevent program execution in accordance with local policies."
                $FindingMessage += "`r`n"
                $FindingMessage += "Apparmor.service is not enabled."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system does not prevent program execution in accordance with local policies."
            $FindingMessage += "`r`n"
            $FindingMessage += "Apparmor.service is not active."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The operating system does not prevent program execution in accordance with local policies."
        $FindingMessage += "`r`n"
        $FindingMessage += "AppArmor is not installed."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238362 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238362
        STIG ID    : UBTU-20-010441
        Rule ID    : SV-238362r853437_rule
        CCI ID     : CCI-002007
        Rule Name  : SRG-OS-000383-GPOS-00166
        Rule Title : The Ubuntu operating system must be configured such that Pluggable Authentication Module (PAM) prohibits the use of cached authentications after one day.
        DiscussMD5 : CC1503EB4AC6C661B16A41A973BC66E1
        CheckMD5   : D70AA1600FCE50D9A6A417CAF7AF5831
        FixMD5     : 1F1B4B10FC7C2C407AA7DCCD812DE138
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
    $finding = $(grep -s -i ^[[:blank:]]*offline_credentials_expiration /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf)
    $finding ?? $($finding = "Check text: No results found.")

    if ($Finding -match "/etc/sssd/conf.d"){$finding = $Finding.split(":")[1]}

    if (($finding | awk '{$2=$2};1').replace(" ", "").split("=") -eq 1) {
        $Status = "NotAFinding"
        $FindingMessage = "PAM prohibits the use of cached authentications after one day."
    }
    else {
        $Status = "Open"
        $FindingMessage = "PAM does not prohibit the use of cached authentications after one day."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238363 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238363
        STIG ID    : UBTU-20-010442
        Rule ID    : SV-238363r880881_rule
        CCI ID     : CCI-002450
        Rule Name  : SRG-OS-000396-GPOS-00176
        Rule Title : The Ubuntu operating system must implement NIST FIPS-validated cryptography to protect classified information and for the following: To provision digital signatures, to generate cryptographic hashes, and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.
        DiscussMD5 : 3946DF09C6EE47BF4DB54B4780912235
        CheckMD5   : 10AFD9DEE441862F3BD98EBCF33776A5
        FixMD5     : 502A2AD5DCF666747305DED76BEDE668
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
    $finding = $(cat /proc/sys/crypto/fips_enabled)

    if ($finding -eq "1") {
        $Status = "NotAFinding"
        $FindingMessage = "The system is configured to run in FIPS mode."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The system is not configured to run in FIPS mode."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238364 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238364
        STIG ID    : UBTU-20-010443
        Rule ID    : SV-238364r880902_rule
        CCI ID     : CCI-002470
        Rule Name  : SRG-OS-000403-GPOS-00182
        Rule Title : The Ubuntu operating system must use DoD PKI-established certificate authorities for verification of the establishment of protected sessions.
        DiscussMD5 : 2BD80CF4E9B5ECDFC15536BB4D98FFF3
        CheckMD5   : 3D113544587C0632B897624BFDD919BC
        FixMD5     : B1304050C077E7DBCDD5BCA8BC043419
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
    $finding = $(ls -l /etc/ssl/certs)

    $Status = "Not_Reviewed"
    $FindingMessage = "Verify the directory containing the root certificates for the Ubuntu operating system only contains certificate files for DoD PKI-established certificate authorities by iterating over all files in the '/etc/ssl/certs' directory and checking if, at least one, has the subject matching 'DOD ROOT CA'."

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238367 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238367
        STIG ID    : UBTU-20-010446
        Rule ID    : SV-238367r853444_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-OS-000420-GPOS-00186
        Rule Title : The Ubuntu operating system must configure the uncomplicated firewall to rate-limit impacted network interfaces.
        DiscussMD5 : 053868BCE7526EF6317108A8CB47667B
        CheckMD5   : 0596711588D3CA13696BE2513D547D77
        FixMD5     : 0B1E8A63A912AEDCBD9694A85E05F9C2
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
    $finding = $(dpkg -l | grep -s ufw)

    if (($finding | awk '{print $2}') -eq "ufw") {
        $finding = $(ufw show raw)

        $Status = "Not_Reviewed"
        $FindingMessage = "Verify an application firewall is configured to rate limit any connection to the system."
    }
    else{
        $Status = "Open"
        $FindingMessage = "An application firewall is not configured to rate limit any connection to the system."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238368 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238368
        STIG ID    : UBTU-20-010447
        Rule ID    : SV-238368r880910_rule
        CCI ID     : CCI-002824
        Rule Name  : SRG-OS-000433-GPOS-00192
        Rule Title : The Ubuntu operating system must implement nonexecutable data to protect its memory from unauthorized code execution.
        DiscussMD5 : 6BC4AFAD2808D5D622BB5721B427F8F3
        CheckMD5   : 454AF9CC8573FB98EF2BF68DACC8A1A0
        FixMD5     : 896E2F7B23B8C03B8B0441D3E0D704D0
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
    $finding = $(dmesg | grep -s -i "execute disable")
    $finding ?? $($finding = "Check text: No results found.")
    $finding_2 = ""

    if ($finding -match "NX (Execute Disable) protection: active" ) {
        $Status = "NotAFinding"
        $FindingMessage = "The NX (no-execution) bit flag is set on the system."
    }
    else {
        $finding_2 = $(grep -s flags /proc/cpuinfo | grep -s -w nx | Sort-Object -u)
        $finding_2 ?? $($finding_2 = "Check text: No results found.")

        if ($Finding_2.contains("nx")) {
            $Status = "NotAFinding"
            $FindingMessage = "The NX (no-execution) bit flag is set on the system."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The NX (no-execution) bit flag is not set on the system."
        }
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238369 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238369
        STIG ID    : UBTU-20-010448
        Rule ID    : SV-238369r853446_rule
        CCI ID     : CCI-002824
        Rule Name  : SRG-OS-000433-GPOS-00193
        Rule Title : The Ubuntu operating system must implement address space layout randomization to protect its memory from unauthorized code execution.
        DiscussMD5 : 8781C5D207773EFF173D4C19E7919A6F
        CheckMD5   : B923A28114A6B1D6E8E923F70B5AD7F5
        FixMD5     : F3A2F765C20CCE0F93206303E38D6DB3
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
    $finding = $(sysctl kernel.randomize_va_space)
    $finding_2 = ""
    $finding_3 = ""

    if ((($Finding.ToLower()).StartsWith("kernel.randomize_va_space")) -and (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 2)) {
        $finding_2 = $(cat /proc/sys/kernel/randomize_va_space)

        if ($Finding_2 -eq 2) {
            $finding_3 = $(egrep -s -R "^kernel.randomize_va_space=[^2]" /etc/sysctl.conf /etc/sysctl.d)

            if ($finding_3) {
                $status = "Open"
                $FindingMessage = "The Ubuntu operating system does not implement address space layout randomization (ASLR)."
                $FindingMessage += "`r`n"
                $FindingMessage += "The saved value of the kernel.randomize_va_space variable is different from 2."
            }
            else {
                $status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system implements address space layout randomization (ASLR)."
                $FindingMessage += "`r`n"
                $FindingMessage += "The saved value of the kernel.randomize_va_space variable is not different from 2."
            }
        }
        else {
            $status = "Open"
            $FindingMessage = "The Ubuntu operating system does not implement address space layout randomization (ASLR)."
            $FindingMessage += "`r`n"
            $FindingMessage += "The kernel parameter randomize_va_space is not set to 2."
        }
    }
    else {
        $status = "Open"
        $FindingMessage = "The Ubuntu operating system does not implement address space layout randomization (ASLR)."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238370 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238370
        STIG ID    : UBTU-20-010449
        Rule ID    : SV-238370r853447_rule
        CCI ID     : CCI-002617
        Rule Name  : SRG-OS-000437-GPOS-00194
        Rule Title : The Ubuntu operating system must be configured so that Advance Package Tool (APT) removes all software components after updated versions have been installed.
        DiscussMD5 : 1664F2CB47698D309E1F3C0682B43A4C
        CheckMD5   : 88BDCE4DBA7479FA0035880911DF025B
        FixMD5     : 1D70CD196796F4C97BF2F6E5D2A28F02
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
    $finding = $(grep -s -i remove-unused /etc/apt/apt.conf.d/50unattended-upgrades)
    $finding ?? $($finding = "Check text: No results found.")

    if (($finding.Contains('Unattended-Upgrade::Remove-Unused-Dependencies "true";')) -and ($finding.Contains('Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";'))) {
        $Status = "NotAFinding"
        $FindingMessage = "APT is configured to remove all software components after updating."
    }
    else {
        $Status = "Open"
        $FindingMessage = "APT is not configured to remove all software components after updating."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238371 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238371
        STIG ID    : UBTU-20-010450
        Rule ID    : SV-238371r880913_rule
        CCI ID     : CCI-002696
        Rule Name  : SRG-OS-000445-GPOS-00199
        Rule Title : The Ubuntu operating system must use a file integrity tool to verify correct operation of all security functions.
        DiscussMD5 : 06B3D07774C75B9368AF9D4AC165240C
        CheckMD5   : 223A4059910E07F3EEF67BE8729F485A
        FixMD5     : 48D18C12A36C9166A5A69122EF7B5DA8
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
    $finding = $(dpkg -l | grep -s aide)

    if (($finding | awk '{print $2}') -eq "aide") {
        $finding = $(aide.wrapper --check)

        if ($finding -eq "Couldn't open file /var/lib/aide/aide.db for reading"){
            $Status = "Open"
            $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) is installed but has not been initialized."
        }
        else{
            $Status = "NotAFinding"
            $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) is installed and verifies the correct operation of all security functions."
        }
    }
    else {
        $Status = "Not_Reviewed"
        $FindingMessage = "AIDE is not installed. Ask the System Administrator how file integrity checks are performed on the system."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238372 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238372
        STIG ID    : UBTU-20-010451
        Rule ID    : SV-238372r853449_rule
        CCI ID     : CCI-002702
        Rule Name  : SRG-OS-000447-GPOS-00201
        Rule Title : The Ubuntu operating system must notify designated personnel if baseline configurations are changed in an unauthorized manner. The file integrity tool must notify the System Administrator when changes to the baseline configuration or anomalies in the operation of any security functions are discovered.
        DiscussMD5 : 58904103CFABAD46D71A07098F33A1C5
        CheckMD5   : 85F2E4B76E6B8C0D2C87A038FB58DF69
        FixMD5     : 5804817E8CFABFC0B976E1A38D263CC6
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
    $finding = $(grep -s -i ^[[:blank:]]*SILENTREPORTS /etc/default/aide)

    if ($finding){
        if ((($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1]).ToLower() -eq "no") {
            $Status = "NotAFinding"
            $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) notifies the system administrator when anomalies in the operation of any security functions are discovered."
        }
        else {
            $Status = "Open"
            $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) does not notify the system administrator when anomalies in the operation of any security functions are discovered."
        }
    }
    else{
        $Status = "Open"
        $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) does not notify the system administrator when anomalies in the operation of any security functions are discovered."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238373 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238373
        STIG ID    : UBTU-20-010453
        Rule ID    : SV-238373r858539_rule
        CCI ID     : CCI-000052
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Ubuntu operating system must display the date and time of the last successful account logon upon logon.
        DiscussMD5 : 158A53226988CC51ED8F1B3E23D8E523
        CheckMD5   : 4DF00FFB46E6A0BE5A41578F87945EA0
        FixMD5     : 82E152D32B18B39904C35166F8072DBF
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
    $finding = $(grep -i -s pam_lastlog /etc/pam.d/login | grep -v "^#")
    $finding ?? $($finding = "Check text: No results found.")

    if (($finding -match "required") -and ($finding -notmatch "silent")) {
        $Status = "NotAFinding"
        $FindingMessage = "'pam_lastlog' is used and not silent."
    }
    else {
        $Status = "Open"
        $FindingMessage = "'pam_lastlog' is missing from the '/etc/pam.d/login' file, is not 'required', or the 'silent' option is present."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238374 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238374
        STIG ID    : UBTU-20-010454
        Rule ID    : SV-238374r654297_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00232
        Rule Title : The Ubuntu operating system must have an application firewall enabled.
        DiscussMD5 : 83B939E9FAE26D0BDBB46182BCD0D01B
        CheckMD5   : C367D38E9B2895D6DC39A78E6896D42D
        FixMD5     : A090AE943C9551B19C2662F250F1EF93
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
    $finding = $(systemctl status ufw.service | grep -s -i "active:")

    if ($finding -match "inactve") {
        $Status = "Open"
        $FindingMessage = "The Uncomplicated Firewall is neither enabled nor active on the system."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The Uncomplicated Firewall is enabled and active on the system."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238376 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238376
        STIG ID    : UBTU-20-010456
        Rule ID    : SV-238376r654303_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : The Ubuntu operating system must have system commands set to a mode of 0755 or less permissive.
        DiscussMD5 : 04D119D53DAF4296011F17C72D7C8283
        CheckMD5   : 3CC087F2746DCFF82C1A15C8C423EC15
        FixMD5     : E130FE7F21DE9452E4DC92D005DBEEA1
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
    $command = @'
#!/bin/sh

find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -xdev -perm /022 -type f -exec stat -c "%n %a" '{}' \;
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    $correct_message_count = 0

    $finding | ForEach-Object {
        if (($finding | awk '{$2=$2};1').split(" ")[1] -le 755) {
            $correct_message_count++
        }
    }

    if ($correct_message_count -eq $finding.count) {
        $Status = "NotAFinding"
        $FindingMessage = "The system commands contained in the following directories have mode 0755 or less permissive:"
    }
    else {
        $Status = "Open"
        $FindingMessage = "The system commands contained in the following directories do not have mode 0755 or less permissive:"
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "/bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin"
    $FindingMessage += "`r`n"
    $FindingMessage += "The below files (if any) do not have mode 0755 or less permissive."
    $FindingDetails += $FindingMessage  | Out-String
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238377 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238377
        STIG ID    : UBTU-20-010457
        Rule ID    : SV-238377r832968_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : The Ubuntu operating system must have system commands owned by root or a system account.
        DiscussMD5 : 04D119D53DAF4296011F17C72D7C8283
        CheckMD5   : 866002EFAEE8DFDB64ECA427F63D2AE1
        FixMD5     : 210985B82BCDE3E9DFD1C0FC13F6D90A
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
    $command = @'
#!/bin/sh

find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -xdev ! -user root -type f -exec stat -c "%n %U" '{}' \;
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    If ($finding) {
        $Status = "Open"
        $FindingMessage = "The system commands contained in the following directories are not owned by root:"
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The system commands contained in the following directories are owned by root:"
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "/bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin"
    $FindingMessage += "`r`n"
    $FindingMessage += "The below files (if any) are not owned by root."
    $FindingDetails += $FindingMessage  | Out-String
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238378 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238378
        STIG ID    : UBTU-20-010458
        Rule ID    : SV-238378r832971_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : The Ubuntu operating system must have system commands group-owned by root or a system account.
        DiscussMD5 : 04D119D53DAF4296011F17C72D7C8283
        CheckMD5   : 321CDD6CEFCD076A07D4F7E063BCB9AF
        FixMD5     : A9B54A7F6DB2B450D7D730DA0D7CD1DF
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
    $command = @'
#!/bin/sh

find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -xdev ! -group root -type f -exec stat -c "%n %G" '{}' \;
'@
    $temp_file = $(mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    If ($finding) {
        $Status = "Open"
        $FindingMessage = "The system commands contained in the following directories are not group-owned by root:"
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The system commands contained in the following directories are group-owned by root:"
    }

    $FindingMessage += "`r`n"
    $FindingMessage += "/bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin"
    $FindingMessage += "`r`n"
    $FindingMessage += "The below files (if any) are not group-owned by root."
    $FindingDetails += $FindingMessage  | Out-String
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238379 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238379
        STIG ID    : UBTU-20-010459
        Rule ID    : SV-238379r654312_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Ubuntu operating system must disable the x86 Ctrl-Alt-Delete key sequence if a graphical user interface is installed.
        DiscussMD5 : 61C10053D406013548766BA3039950D9
        CheckMD5   : 80FED23294D2CC5CB7900343FBF7D03E
        FixMD5     : 06B360C193733EDC53DABE1F53C6E6A8
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
    $finding = $(grep -s -iR ^logout /etc/dconf/db/local.d/)

    if ($finding) {
        if ((($finding | awk '{$2=$2};1').split(":")[1]).replace(" ", "").StartsWith("logout=")) {
            if ($finding.split("=")[1] -in ("''", """")) {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system is not configured to reboot the system when Ctrl-Alt-Delete is pressed when using a graphical user interface."
            }
            else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system is configured to reboot the system when Ctrl-Alt-Delete is pressed when using a graphical user interface."
                $FindingMessage += "The 'logout' key is bound to an action."
            }
        }
        else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system is configured to reboot the system when Ctrl-Alt-Delete is pressed when using a graphical user interface."
            $FindingMessage += "The 'logout' key is commented out."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system is configured to reboot the system when Ctrl-Alt-Delete is pressed when using a graphical user interface."
        $FindingMessage += "The 'logout' key is missing."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V238380 {
    <#
    .DESCRIPTION
        Vuln ID    : V-238380
        STIG ID    : UBTU-20-010460
        Rule ID    : SV-238380r832974_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Ubuntu operating system must disable the x86 Ctrl-Alt-Delete key sequence.
        DiscussMD5 : B088CF73E7DF2FDD87FC791E99F74F73
        CheckMD5   : CA07C739ADCEA6AC00B5458B11239964
        FixMD5     : 742D21BD5072B0772DE00F7AB6386BD9
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
    $finding = $(systemctl status ctrl-alt-del.target)

    If ($finding -match "Unit ctrl-alt-del.target is masked") {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system is not configured to reboot the system when Ctrl-Alt-Delete is pressed."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system is configured to reboot the system when Ctrl-Alt-Delete is pressed."
        $FindingMessage += "`r'`n"
        $FindingMessage += "The 'ctrl-alt-del.target' is active."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V251503 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251503
        STIG ID    : UBTU-20-010462
        Rule ID    : SV-251503r808506_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Ubuntu operating system must not have accounts configured with blank or null passwords.
        DiscussMD5 : 03C669455D5510A262E8EADA62EAF85A
        CheckMD5   : BA187F3EFC24B9453BB30EC4713EF741
        FixMD5     : 722E5FD0CC17D9BA1ED42921EEE216C6
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
    $finding = $(awk -F: '!$2 {print $1}' /etc/shadow)

    if ($finding) {
        $Status = "Open"
        $FindingMessage = "The '/etc/shadow' file contains account(s) with blank passwords."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The '/etc/shadow' file does not contain account(s) with blank passwords."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V251504 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251504
        STIG ID    : UBTU-20-010463
        Rule ID    : SV-251504r832977_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Ubuntu operating system must not allow accounts configured with blank or null passwords.
        DiscussMD5 : 03C669455D5510A262E8EADA62EAF85A
        CheckMD5   : 241D59D490287468B81C27F2CF8E6E60
        FixMD5     : 5F351915605D460989E8A73FF83755C7
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
    $finding = $(grep -s nullok /etc/pam.d/common_password)

    if ($finding) {
        $Status = "Open"
        $FindingMessage = "Null passwords can be used."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "Null passwords cannot be used."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V251505 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251505
        STIG ID    : UBTU-20-010461
        Rule ID    : SV-251505r942851_rule
        CCI ID     : CCI-001958
        Rule Name  : SRG-OS-000378-GPOS-00163
        Rule Title : The Ubuntu operating system must disable automatic mounting of Universal Serial Bus (USB) mass storage driver.
        DiscussMD5 : B550EC29A3BF0EF47BE665F3B6004911
        CheckMD5   : D355ED7AD7A59FA16DD0903AB6FA9FC9
        FixMD5     : ABAEE0192CF663E65A03C4F07ACC6231
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
    $finding = $(grep -s -r -v "^\s*#" /etc/modprobe.d/ | grep -s -i usb-storage | grep -s -i "/bin/false")
    $installusbs = $false

    if ($finding){
        If (((($Finding.ToLower()).split(":")[1]).startswith("install")) -and (((($Finding | awk '{$2=$2};1').ToLower()).split(":")[1]) -eq "install usb-storage /bin/false")){
            $installusbs = $true
            $FindingMessage = "The Ubuntu operating system disables ability to load the USB storage kernel module and disables the ability to use USB mass storage device."
        }
        else{
            $FindingMessage = "The Ubuntu operating system does not disable the ability to load the USB storage kernel module and disables the ability to use USB mass storage device."
        }
    }
    else{
        $Finding = "Check text: No results found."
    }

    $FindingMessage += "`r`n"

    $finding_2 = $(grep -s -r -v "^\s*#" /etc/modprobe.d/ | grep -s -ih usb-storage | grep -s -i "blacklist ")
    $blacklistusbs = $false

    if ($Finding_2){
        If (((($Finding_2 | awk '{$2=$2};1').ToLower()).split(":"))[1] -match "blacklist usb-storage"){
            $blacklistusbs = $True
            $FindingMessage += "The Ubuntu operating system disables USB mass storage."
        }
        else{
            $FindingMessage += "The Ubuntu operating system does not disable USB mass storage."
        }
    }
    else{
        $Finding_2 = "Check text: No results found."
    }

    if ($installusbs -and $blacklistusbs){
        $Status = "NotAFinding"
    }
    else{
        $Status = "Open"
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V252704 {
    <#
    .DESCRIPTION
        Vuln ID    : V-252704
        STIG ID    : UBTU-20-010455
        Rule ID    : SV-252704r942848_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-OS-000481-GPOS-00481
        Rule Title : The Ubuntu operating system must disable all wireless network adapters.
        DiscussMD5 : 97E3DA1F0B5F830EEC06AF70199B727B
        CheckMD5   : F459431C898988F161A4BFE6642D1D5D
        FixMD5     : E9F3C8D04DB7C23D7DBC8B380EDC4374
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
    $finding = $(ls -L -d /sys/class/net/*/wireless | xargs dirname | xargs basename)

    if ($finding) {
        $Status = "Not_Reviewed"
        $FindingMessage = "A wireless interface is configured and must be documented and approved by the Information System Security Officer (ISSO)"
    }
    else {
        $Status = "Not_Applicable"
        $FindingMessage = "This requirement is Not Applicable for systems that do not have physical wireless network radios."
    }
    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V255912 {
    <#
    .DESCRIPTION
        Vuln ID    : V-255912
        STIG ID    : UBTU-20-010045
        Rule ID    : SV-255912r951477_rule
        CCI ID     : CCI-000068
        Rule Name  : SRG-OS-000250-GPOS-00093
        Rule Title : The Ubuntu operating system SSH server must be configured to use only FIPS-validated key exchange algorithms.
        DiscussMD5 : 7FD01CCB0DC6EDC6C177CA353139F013
        CheckMD5   : E9EAB9673E7EA0A61C42DD8C30B81616
        FixMD5     : 8FEDAD393440E313A3B3FB7B0D82ADE5
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
    $finding = $(grep -s -i ^[[:blank:]]*kexalgorithms /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*)
    $finding ?? $($finding = "Check text: No results found.")
    $correct_message_count = 0

    $finding | ForEach-Object { if ((($_.split(":")[1] | awk '{$2=$2};1').replace(" ", "")).ToLower() -eq "kexalgorithmsecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256"){
        $correct_message_count++
    } }
    if ($correct_message_count -eq $finding.count) {
        $Status = "NotAFinding"
        $FindingMessage = "The SSH server is configured to use only FIPS-validated key exchange algorithms."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The SSH server is not configured to use only FIPS-validated key exchange algorithms."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V255913 {
    <#
    .DESCRIPTION
        Vuln ID    : V-255913
        STIG ID    : UBTU-20-010401
        Rule ID    : SV-255913r880908_rule
        CCI ID     : CCI-001090
        Rule Name  : SRG-OS-000138-GPOS-00069
        Rule Title : The Ubuntu operating system must restrict access to the kernel message buffer.
        DiscussMD5 : 84F6C0A2F1E04B895CE976C11AFBFBB3
        CheckMD5   : A52E3EA3A812E58158503D702FCB94C5
        FixMD5     : 50BD21B3F2A70AEA8672CEE15BC9C1D9
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
    $finding = $(sysctl kernel.dmesg_restrict)
    $finding ?? $($finding = "Check text: No results found.")

    if (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 1){
        $finding_2 = $(grep -s -i ^[[:blank:]]*kernel.dmesg_restrict /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf)
        $finding_2 ?? $($finding_2 = "Check text: No results found.")
        $foundcount = 1

        $finding_2 | Foreach-Object {
            if ((($_ | awk '{$2=$2};1').replace(" ", "")).split("=")[1] -eq 1) {
                $foundcount++
            }
        }
        if ($finding_2.count -eq $foundcount-1){
            $Status = "NotAFinding"
            $FindingMessage = "The operating system is configured to restrict access to the kernel message buffer."
        }
        else {
            $Status = "Open"
            $FindingMessage = "The operating system is not configured to restrict access to the kernel message buffer."
        }
    }
    else{
        $Status = "Open"
        $FindingMessage = "The operating system is not configured to restrict access to the kernel message buffer."
    }

    $FindingDetails += $FindingMessage  | Out-String

    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_2
    $FindingDetails += $(FormatFinding $finding) | Out-String
    $finding = $finding_3
    $FindingDetails += $(FormatFinding $finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBrbnvRAC1dty+Y
# 6NXlJQDIHUMEPd/wi5sFUOV//DbK0KCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAxEe7e1j2LBE54hJe7E39DgJrc6gGT
# cGZCRZc2Hl6urzANBgkqhkiG9w0BAQEFAASCAQB+pi1IpQe8vjkYGq5EJ9OGtHBd
# SWDpxsuY0aR+Qo5M5h9UKixsxb3Gy3YzLhUbJZwprw4Hr7k9CDOZZOv2QjdSfVER
# UHdumlrfGFMMBzKOYHMEU6B6qk8DcdAQX7G9ubUqKzVHXOqCG8ryttIf6vwCAaLC
# ReA67tGAEMid3ybYBcFMHQ2TJw6OC6GZjdYGAMCwGvWUmVhe7G+1bQFZVy1gzA63
# 18W3z/vEHqFz0QYNYqvwh5UHlHxwqa3r+L1n+CIZXt47WudChLixoJoSU+4suxbd
# jAA1yprFiISCcQkJIjf1QdMRGUXFu1lKe/rP5qUN9mk6VG8cBrpF0wySPzFt
# SIG # End signature block
