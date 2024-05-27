##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Canonical Ubuntu 16.04 LTS
# Version:  V2R3
# Class:    UNCLASSIFIED
# Updated:  5/13/2024
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function FormatFinding {
    Param(
        [parameter (Mandatory = $true, position = 0, ParameterSetName = 'finding')]
        [AllowNull()]
        $line
    )

    # insert separator line
    $FormattedFinding += "-----------------------------------------------------------------------" | Out-String

    # insert findings
    $FormattedFinding += $Finding | Out-String
    return $FormattedFinding
}

Function Get-V214939 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214939
        STIG ID    : UBTU-16-010000
        Rule ID    : SV-214939r648696_rule
        CCI ID     : CCI-001230
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Ubuntu operating system must be a vendor supported release.
        DiscussMD5 : CDB1F9503A17CBC852A0D446983C374D
        CheckMD5   : 46B3634E285D7011B581ABF4EE809902
        FixMD5     : 176E623506ECFEC2C19FB364FA4397F3
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding += Get-Content /etc/lsb-release -Raw

    $Rule = "Ubuntu 16.04.*([\s]+)LTS"

    If ($Finding -match $Rule) {
        $FindingMessage = "Check if the release is supported by the vendor using Extended Security Maintenance."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214940 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214940
        STIG ID    : UBTU-16-010010
        Rule ID    : SV-214940r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Ubuntu vendor packaged system security patches and updates must be installed and up to date.
        DiscussMD5 : 7C54501FEA9D4000FFE0A00921E909A4
        CheckMD5   : 370DB6956DC7146243D5CCE20A06ECC3
        FixMD5     : 9656AA2C29E28197B702C1C64F8EE71F
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(/usr/lib/update-notifier/apt-check --human-readable)

    If ($Finding -match "^([\s]*)0 updates are security updates.") {
        $Status = "NotAFinding"
        $FindingMessage = "All available security package updates have been installed."
    }
    Else {
        $Status = "Not_Reviewed"
        $FindingMessage = ("Check that security package updates have been performed on the system within the timeframe " +
            "that the site/program documentation requires.")
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214941 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214941
        STIG ID    : UBTU-16-010020
        Rule ID    : SV-214941r610931_rule
        CCI ID     : CCI-000048, CCI-001384, CCI-001385, CCI-001386, CCI-001387, CCI-001388
        Rule Name  : SRG-OS-000023-GPOS-00006
        Rule Title : The Ubuntu operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.
        DiscussMD5 : B34D361AE7143F0E16E5CB4E5017ECC4
        CheckMD5   : A9A2AA869BAAD50A21DCA8E9D7A18A7D
        FixMD5     : A318CAB7B68486985C68AEA20573860D
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(dpkg -l | egrep "gdm|lightdm" | awk '{print $2}')
    $Finding_2 = ""
    $Finding_3 = ""

    $Banner = ("You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized " +
        "use only.\nBy using this IS (which includes any device attached to this IS), you consent to the " +
        "following conditions:\n-The USG routinely intercepts and monitors communications on this IS for " +
        "purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and " +
        "defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations." +
        "\n-At any time, the USG may inspect and seize data stored on this IS.\n-Communications using, or data " +
        "stored on, this IS are not private, are subject to routine monitoring, interception, and search, and " +
        "may be disclosed or used for any USG-authorized purpose.\n-This IS includes security measures (e.g., " +
        "authentication and access controls) to protect USG interests--not for your personal benefit or privacy." +
        "\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative " +
        "searching or monitoring of the content of privileged communications, or work product, related to " +
        "personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. " +
        "Such communications and work product are private and confidential. See User Agreement for details.")

    $FindingMessage = ""

    If ($Finding.Contains("gdm3")) {
        $Finding_2 = $(grep banner-message-enable /etc/gdm3/greeter.dconf-defaults)

        If ($Finding_2 -eq "banner-message-enable=true") {
            # Get the part after "banner-message-text="
            $Finding_3 = $(grep banner-message-text /etc/gdm3/greeter.dconf-defaults)
            $Finding_3 = $Finding_3.split("=")
            $Finding_3 = $Finding_3[1]

            # Remove outer set of ' '
            $Finding_3 = $Finding_3.Trim("'")

            If ($Finding_3 -eq $Banner) {
                $Status = "NotAFinding"
                $FindingMessage += ("The operating system displays the exact approved Standard Mandatory DoD Notice " +
                    "and Consent Banner text.")
            }
            Else {
                $Status = "Open"
                $FindingMessage += ("The operating system does not display the exact approved Standard Mandatory DoD " +
                    "Notice and Consent Banner text.")
            }
        }
        Else {
            $Status = "Open"
            $FindingMessage = ("The operating system does not display banner text before granting local access to the " +
                "system via a graphical user logon.")
        }
    }
    Else {
        $Status = "Not_Applicable"
        $FindingMessage = "The system does not have the Gnome Graphical User Interface installed."

        If ($Finding.Contains("lightdm")) {
            $Status = "Open"
            $FindingMessage += ("The operating system is using lightdm for a Graphical User Interface; therefore the " +
                "banner text must be manually verified.")
        }
        Else {
            $FindingMessage += "The system does not have the lightdm Graphical User Interface installed."
        }
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    $FindingDetails += $Finding | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    $FindingDetails += $(grep banner-message-text /etc/gdm3/greeter.dconf-defaults) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214942 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214942
        STIG ID    : UBTU-16-010030
        Rule ID    : SV-214942r610931_rule
        CCI ID     : CCI-000048, CCI-001384, CCI-001385, CCI-001386, CCI-001387, CCI-001388
        Rule Name  : SRG-OS-000023-GPOS-00006
        Rule Title : The Ubuntu operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a command line user logon.
        DiscussMD5 : 4A6AF87EF3F157765D5E4334E53A1C98
        CheckMD5   : 4FDC9F90DA8166E39ADF0D2CDB349220
        FixMD5     : B254E4B031EF44682286828E0F114987
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -i banner /etc/ssh/sshd_config)
    $Finding_2 = ""

    $Banner = "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized " +
    "use only." +
    "\n" +
    "\n" +
    "By using this IS (which includes any device attached to this IS), you consent to the following " +
    "conditions:" +
    "\n" +
    "\n" +
    "-The USG routinely intercepts and monitors communications on this IS for purposes including, but not " +
    "limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel " +
    "misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations." +
    "\n" +
    "\n" +
    "-At any time, the USG may inspect and seize data stored on this IS." +
    "\n" +
    "\n" +
    "-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, " +
    "interception, and search, and may be disclosed or used for any USG-authorized purpose." +
    "\n" +
    "\n" +
    "-This IS includes security measures (e.g., authentication and access controls) to protect USG " +
    "interests -- not for your personal benefit or privacy." +
    "\n" +
    "\n" +
    "-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative " +
    "searching or monitoring of the content of privileged communications, or work product, related to " +
    "personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. " +
    "Such communications and work product are private and confidential. See User Agreement for details."
    $Banner_Lines = $Banner.Split('\n')

    If (($Finding -eq "banner /etc/issue") -or ($Finding -eq "Banner /etc/issue")) {
        $FindingMessage += ("The Ubuntu operating system displays a banner before granting access to the Ubuntu " +
            "operating system via a ssh logon.") | Out-String

        $Finding_2 = Get-Content /etc/issue
        $Finding_2 = $Finding_2.Trim("'")
        $Finding_2 = $Finding_2.Trim('"')
        $Finding_2_Lines = $Finding_2.Split([Environment]::NewLine)

        If ($Banner_Lines.Length -ne $Finding_2_Lines.Length) {
            $Status = "Open"
            $FindingMessage += "Number of lines does not match." | Out-String
            $FindingMessage += ("Expected banner line count: " +
                $Banner_Lines.Length +
                " " +
                "Actual banner line count: " +
                $Finding_2_Lines.Length) | Out-String
        }

        $already_added = $false

        for (($i = 0); $i -lt $Banner_Lines.Length; $i++) {
            for (($j = 0); $j -lt $Finding_2_Lines.Length; $j++) {
                If ($i -eq $j) {
                    If ($Banner_Lines[$i] -ne $Finding_2_Lines[$j]) {
                        $Status = "Open"

                        If (!($already_added)) {
                            $FindingMessage += ("The displayed banner file does not match the Standard Mandatory DoD " +
                                "Notice and Consent Banner exactly.") | Out-String
                            $already_added = $true
                        }

                        $FindingDetails += ("Expected: " + $i.ToString() + " " + $Banner_Lines[$i]) | Out-String
                        $FindingDetails += ("Actual: " + $j.ToString() + " " + $Finding_2_Lines[$j]) | Out-String
                    }
                }
            }
        }

        If ($Status -eq "Not_Reviewed") {
            $Status = "NotAFinding"
            $FindingMessage += ("The specified banner file matches the Standard Mandatory DoD Notice and Consent " +
                "Banner exactly.") | Out-String
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = ("The Ubuntu operating system does not display a banner before granting access to the " +
            "Ubuntu operating system via a ssh logon.") | Out-String
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    $FindingDetails += $Finding | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    $FindingDetails += $Finding_2 | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214943 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214943
        STIG ID    : UBTU-16-010040
        Rule ID    : SV-214943r610931_rule
        CCI ID     : CCI-000056
        Rule Name  : SRG-OS-000028-GPOS-00009
        Rule Title : The Ubuntu operating system must enable a user session lock until that user re-establishes access using established identification and authentication procedures.
        DiscussMD5 : 0B5C88BCFA9E8F895E558377983B3C25
        CheckMD5   : 1EB12C06E87DCCD6503B852F18C48AB2
        FixMD5     : 144616B8E6A520FF48BE1F06B86BDEED
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(gsettings get org.gnome.desktop.lockdown disable-lock-screen)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    If ($Finding -eq "false") {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system has a graphical user interface session lock enabled."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not have a graphical user interface session lock enabled."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214944 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214944
        STIG ID    : UBTU-16-010050
        Rule ID    : SV-214944r610931_rule
        CCI ID     : CCI-000056, CCI-000058, CCI-000060
        Rule Name  : SRG-OS-000028-GPOS-00009
        Rule Title : All users must be able to directly initiate a session lock for all connection types.
        DiscussMD5 : DFBB5C1D938D38D67875F3DACA49920F
        CheckMD5   : 26BB248BC4D42EF95A9879DD581023B3
        FixMD5     : D7E2D2FF00FE45069E02371FD1CB465B
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(dpkg -l) -match "vlock"

    If ($Finding) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system has the 'vlock' package installed."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not have the 'vlock' package installed."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214945 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214945
        STIG ID    : UBTU-16-010060
        Rule ID    : SV-214945r610931_rule
        CCI ID     : CCI-000057
        Rule Name  : SRG-OS-000029-GPOS-00010
        Rule Title : Ubuntu operating system sessions must be automatically logged out after 15 minutes of inactivity.
        DiscussMD5 : A121667451BBC79D2F1E34B134E764CF
        CheckMD5   : 27D3808D40726998C01D686B9C07D7E4
        FixMD5     : A3EB1C81D8E07E85C87834107DCDA70D
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(Get-Content /etc/profile.d/autologout.sh)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    $TMOUT = $($Finding | awk '{$2=$2};1' | grep "=").Trim()
    $readonly = $(($Finding | awk '{$2=$2};1')[2])
    $export = $($Finding | awk '{$2=$2};1')[3]

    If (($TMOUT -eq "TMOUT=900") -And ($readonly -eq "readonly TMOUT") -And ($export -eq "export TMOUT")) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system initiates a session logout after a 15-minute period of inactivity."
    }
    elseif (($Finding | awk '{$2=$2};1').replace(" ", "").Split("=")[1] -gt 900) {
        $Status = "Open"
        $FindingMessage = ("The Ubuntu operating system initiates a session logout after greater than a 15-minute " +
            "period of inactivity.")
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not initiate a session logout."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $TMOUT | Out-String
    $FindingDetails += $readonly | Out-String
    $FindingDetails += $export | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214946 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214946
        STIG ID    : UBTU-16-010070
        Rule ID    : SV-214946r610931_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-OS-000027-GPOS-00008
        Rule Title : The Ubuntu operating system must limit the number of concurrent sessions to ten for all accounts and/or account types.
        DiscussMD5 : FC02729F202D09AB4C0CE3E4E8F7B5F8
        CheckMD5   : 9852FE927564E8ECE31180995E44FD9C
        FixMD5     : 680206F668B361E60D566A902A714DD7
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep maxlogins /etc/security/limits.conf | grep -v '^#')

    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    $Number = $($Finding | tr -dc '0-9')

    If ((($Finding | awk '{$2=$2};1').StartsWith("* hard maxlogins")) -And ($Number -le 10)) {
        $Status = "NotAFinding"
        $FindingMessage = ("The Ubuntu operating system limits the number of concurrent sessions to ten for all " +
            "accounts and/or account types.")
    }
    Else {
        $Status = "Open"
        $FindingMessage = ("The Ubuntu operating system does not limit the number of concurrent sessions to ten for " +
            "all accounts and/or account types.")
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    $Finding = $(grep maxlogins /etc/security/limits.conf)
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214947 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214947
        STIG ID    : UBTU-16-010080
        Rule ID    : SV-214947r610931_rule
        CCI ID     : CCI-000770
        Rule Name  : SRG-OS-000109-GPOS-00056
        Rule Title : The Ubuntu operating system must prevent direct login into the root account.
        DiscussMD5 : D222DB8AAA11B27DB58BE43F3023620E
        CheckMD5   : 1D257C653A99C8C6D54E983625C84A04
        FixMD5     : C17168C7AC8609DBE641D4B1A306E915
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(passwd -S root)

    if (($Finding | awk '{print $2}') -eq "L") {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system prevents direct logins to the root account."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not prevent direct logins to the root account."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214948 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214948
        STIG ID    : UBTU-16-010099
        Rule ID    : SV-214948r610931_rule
        CCI ID     : CCI-000192, CCI-000193, CCI-000194, CCI-000195, CCI-000200, CCI-000205, CCI-001619
        Rule Name  : SRG-OS-000069-GPOS-00037
        Rule Title : The Ubuntu operating system must be configured so that when passwords are changed or new passwords are established, pwquality must be used.
        DiscussMD5 : 4AF4C1E3A5017E0922F67CCAEF89849A
        CheckMD5   : 6DDD6F88D645CD367FA08C73D501E6DC
        FixMD5     : 3AAF63190D9F16C33823E58B466982C7
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(dpkg -l | grep libpam-pwquality)
    $Finding_Lines = $Finding.Split([Environment]::NewLine)

    If ($Finding) {
        $FindingMessage = "The Ubuntu operating system has the libpam-pwquality package installed "
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not have the libpam-pwquality package installed "
    }

    $Finding_2 = Get-Content /etc/pam.d/common-password
    $Finding_2_Lines = $Finding_2.Split([Environment]::NewLine)

    $TempLine = ""

    foreach ($Line in $Finding_2_Lines) {
        If ($Line -match 'pam_pwquality.so' -And !($Line -match '#')) {
            $TempLine += $Line | Out-String
        }
    }

    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    If ($TempLine) {
        $retry = $TempLine.Split('=')[1]
        $retry = $retry.Trim()

        If ($retry -eq 0 -Or $retry -gt 3) {
            $Status = "Open"
            $FindingMessage += "but is not configured corectly." | Out-String
        }
        Else {
            $FindingMessage += "and is configured correctly." | Out-String
        }
    }
    Else {
        $Status = "Open"
        $FindingDetails += ("The command did not return an uncommented line containing the value " +
            "pwquality.so.") | Out-String
    }

    If ($Status -eq "Not_Reviewed") {
        $Status = "NotAFinding"
    }

    $FindingDetails += $FindingMessage | Out-String

    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    foreach ($Line in $Finding_Lines) {
        $FindingDetails += $Line | Out-String
    }
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    $FindingDetails += $TempLine | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214949 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214949
        STIG ID    : UBTU-16-010100
        Rule ID    : SV-214949r610931_rule
        CCI ID     : CCI-000192
        Rule Name  : SRG-OS-000069-GPOS-00037
        Rule Title : The Ubuntu operating system must enforce password complexity by requiring that at least one upper-case character be used.
        DiscussMD5 : A03E0F71B34FF20373CAC8129EEFF97C
        CheckMD5   : 65B3F1EA72A592B9AEAADB56403575FB
        FixMD5     : 6DC0AC03B1E0A503A6FD8D329E5DF349
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = Get-Content /etc/security/pwquality.conf
    $Lines = $Lines.Split([Environment]::NewLine)

    If ($Lines -eq "") {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not enforce password complexity by requiring that at least one upper-case character be used."
    }

    $Finding = ""
    $rule = '^ucredit([\s]*)=([\s]*)-1$'

    foreach ($Line in $Lines) {
        $Line = $Line.Trim()

        If ($Line -match $rule) {
            $Finding = $Line
        }
    }

    If ($Finding -ne "") {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system enforces password complexity by requiring that at least one upper-case character be used."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not enforce password complexity by requiring that at least one upper-case character be used."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    If ($Status -eq "Open") {
        $FindingDetails += "Missing:" | Out-String
        $FindingDetails += "ucredit=-1" | Out-String
    }
    Else {
        $FindingDetails += $Finding
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214950 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214950
        STIG ID    : UBTU-16-010110
        Rule ID    : SV-214950r610931_rule
        CCI ID     : CCI-000193
        Rule Name  : SRG-OS-000070-GPOS-00038
        Rule Title : The Ubuntu operating system must enforce password complexity by requiring that at least one lower-case character be used.
        DiscussMD5 : A03E0F71B34FF20373CAC8129EEFF97C
        CheckMD5   : AFD19C4750D1D024AE06E87F6D75A156
        FixMD5     : D8087372ACEE432AB6E1EAFE879C98BA
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = Get-Content /etc/security/pwquality.conf
    $Lines = $Lines.Split([Environment]::NewLine)

    If ($Lines -eq "") {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not enforce password complexity by requiring that at least one lower-case character be used."
    }

    $Finding = ""
    $rule = '^lcredit([\s]*)=([\s]*)-1$'

    foreach ($Line in $Lines) {
        $Line = $Line.Trim()

        If ($Line -match $rule) {
            $Finding = $Line
        }
    }

    If ($Finding -ne "") {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system enforces password complexity by requiring that at least one lower-case character be used."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not enforce password complexity by requiring that at least one lower-case character be used."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    If ($Status -eq "Open") {
        $FindingDetails += "Missing:" | Out-String
        $FindingDetails += "lcredit=-1" | Out-String
    }
    Else {
        $FindingDetails += $Finding
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214951 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214951
        STIG ID    : UBTU-16-010120
        Rule ID    : SV-214951r610931_rule
        CCI ID     : CCI-000194
        Rule Name  : SRG-OS-000071-GPOS-00039
        Rule Title : The Ubuntu operating system must enforce password complexity by requiring that at least one numeric character be used.
        DiscussMD5 : A03E0F71B34FF20373CAC8129EEFF97C
        CheckMD5   : E8205C964758F5CC23055954C98817F7
        FixMD5     : D819ACE3F3973D3FCBEE2F0E7EFF68C5
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -i "dcredit" /etc/security/pwquality.conf)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    If ((($Finding | awk '{$2=$2};1').replace(" ", "").StartsWith("dcredit=")) -And (($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq -1)) {
        $Status = "NotAFinding"
        $FindingMessage = ("The Ubuntu operating system enforces password complexity by requiring that at least one " +
            "numeric character be used.")
    }
    Else {
        $Status = "Open"
        $FindingMessage = ("The Ubuntu operating system does not enforce password complexity by requiring that at " +
            "least one numeric character be used.")
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214952 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214952
        STIG ID    : UBTU-16-010130
        Rule ID    : SV-214952r610931_rule
        CCI ID     : CCI-001619
        Rule Name  : SRG-OS-000266-GPOS-00101
        Rule Title : All passwords must contain at least one special character.
        DiscussMD5 : 3EAF5B3CC0EA7AA2AF1BD54142F650EF
        CheckMD5   : 2E7A3D704CC89612874BED6688A18056
        FixMD5     : B4830A016A38D1E5AD2E2B0EF8FB65B4
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -i "ocredit" /etc/security/pwquality.conf)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    If ((($Finding | awk '{$2=$2};1').replace(" ", "").StartsWith("ocredit=")) -And (($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq -1)) {
        $Status = "NotAFinding"
        $FindingMessage = "The field 'ocredit' is set in the '/etc/security/pwquality.conf'."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The field 'ocredit' is not set in the '/etc/security/pwquality.conf'."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214953 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214953
        STIG ID    : UBTU-16-010140
        Rule ID    : SV-214953r610931_rule
        CCI ID     : CCI-000195
        Rule Name  : SRG-OS-000072-GPOS-00040
        Rule Title : The Ubuntu operating system must require the change of at least 8 characters when passwords are changed.
        DiscussMD5 : 083BD62480CAEEDC08C62895CEBB35E6
        CheckMD5   : 1D2BB3C8E5D1FF85F322D7B0767959A6
        FixMD5     : 499D1C3BBC719FCD6308057F70FBC2D6
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -i "difok" /etc/security/pwquality.conf)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    If ((($Finding | awk '{$2=$2};1').replace(" ", "").StartsWith("difok=")) -And (($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -ge 8)) {
        $Status = "NotAFinding"
        $FindingMessage = ("The Ubuntu operating system requires the change of at least 8 characters when passwords " +
            "are changed.")
    }
    Else {
        $Status = "Open"
        $FindingMessage = ("The Ubuntu operating system does not require the change of at least 8 characters when " +
            "passwords are changed.")
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214954 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214954
        STIG ID    : UBTU-16-010150
        Rule ID    : SV-214954r610931_rule
        CCI ID     : CCI-000196, CCI-000803
        Rule Name  : SRG-OS-000073-GPOS-00041
        Rule Title : The Ubuntu operating system must encrypt all stored passwords with a FIPS 140-2 approved cryptographic hashing algorithm.
        DiscussMD5 : DA7F527B6C7F661ADFAA30662B624643
        CheckMD5   : EA4084A2A328FFE410744E6C96F984EC
        FixMD5     : 5E7B79B83533CA716870B21B513439A4
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(Get-Content /etc/login.defs | grep -i "crypt" | grep -i "^encrypt_method")
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    If ($Finding.ToUpper() -eq "ENCRYPT_METHOD SHA512") {
        $Status = "NotAFinding"
        $FindingMessage = ("The Ubuntu operating system encrypts all stored passwords with a FIPS 140-2 approved " +
            "cryptographic hashing algorithm.")
    }
    Else {
        $Status = "Open"
        $FindingMessage = ("The Ubuntu operating system does not encrypt all stored passwords with a FIPS 140-2 " +
            "approved cryptographic hashing algorithm.")
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    $Finding = $(Get-Content /etc/login.defs | grep -i crypt)
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214955 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214955
        STIG ID    : UBTU-16-010160
        Rule ID    : SV-214955r610931_rule
        CCI ID     : CCI-000196, CCI-000803
        Rule Name  : SRG-OS-000073-GPOS-00041
        Rule Title : The Ubuntu operating system must employ a FIPS 140-2 approved cryptographic hashing algorithms for all stored passwords.
        DiscussMD5 : 141176EF73D1EB2286DD2094DD4CB90B
        CheckMD5   : 9A7F203848F2E7628D5B1EE642D0CA3A
        FixMD5     : BB8888832B7E845FB3E24DB23A61D65F
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Passwords = $(cut -d: -f2 /etc/shadow)
    $TempDetails = ""

    foreach ($Password in $Passwords) {
        If ($Password.Contains("*") -Or $Password.Contains("!")) {
            # This contains invalid characters for cryptographic processing.
            # This means it is not an interactive user account.
        }
        Else {
            If (!($Password.Contains("$6"))) {
                $Status = "Open"
                $FindingMessage = ("The Ubuntu operating system does not encrypt all stored passwords with a FIPS " +
                    "140-2 approved cryptographic hashing algorithm.")
            }

            $TempDetails += $Password | Out-String
        }
    }

    If ($Status -eq "Not_Reviewed") {
        $Status = "NotAFinding"
        $FindingMessage = ("The Ubuntu operating system encrypts all stored passwords with a FIPS 140-2 approved " +
            "cryptographic hashing algorithm.")
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $TempDetails
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214956 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214956
        STIG ID    : UBTU-16-010170
        Rule ID    : SV-214956r610931_rule
        CCI ID     : CCI-000196, CCI-000803
        Rule Name  : SRG-OS-000073-GPOS-00041
        Rule Title : The Ubuntu operating system must employ FIPS 140-2 approved cryptographic hashing algorithms for all created passwords.
        DiscussMD5 : 141176EF73D1EB2286DD2094DD4CB90B
        CheckMD5   : C78901D67910C752B2F8CD39743AE677
        FixMD5     : 73B5BC76C37C38748C53FE83C7862FAA
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep rounds /etc/pam.d/common-password | grep -v "^#")
    $FindingMessage = ""

    If (!($Finding)) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results."
    }
    Else {
        $Finding_Split = $Finding.Split(' ')
    }

    foreach ($Word in $Finding_Split) {
        $Word = $Word.Trim()

        If ($Word.Contains("rounds")) {
            $Number = $Word.Split('=')
            $Number = $Number.Trim()

            If ($Number -lt 5000) {
                $Status = "Open"
                $FindingMessage = ("The Ubuntu operating system does not encrypt all stored passwords with a FIPS " +
                    "140-2 approved cryptographic hashing algorithm.")
            }
        }
    }

    If ($Status -eq "Not_Reviewed") {
        $Status = "NotAFinding"
        $FindingMessage = ("The Ubuntu operating system encrypts all stored passwords with a FIPS 140-2 approved " +
            "cryptographic hashing algorithm.")
    }

    $FindingDetails += $FindingMessage | Out-String

    # It was here commented out, this if statement block.
    If ($Finding) {
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        $FindingDetails += $Finding_Split
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214957 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214957
        STIG ID    : UBTU-16-010180
        Rule ID    : SV-214957r610931_rule
        CCI ID     : CCI-000803
        Rule Name  : SRG-OS-000120-GPOS-00061
        Rule Title : The pam_unix.so module must use a FIPS 140-2 approved cryptographic hashing algorithm for system authentication.
        DiscussMD5 : AC7F4E3B9BDF3C9FC830E28A40335441
        CheckMD5   : 8770B3FD284BC52C255E52ED5CD07368
        FixMD5     : B77F1287694E976AE8C3F9DF683EB2AC
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep password /etc/pam.d/common-password | grep pam_unix)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }
    $Finding_2 = ""

    If ((($Finding | Where-Object { !($_.StartsWith("#")) }).ToLower().StartsWith("password")) -And ($Finding.ToLower() -match "sha512")) {
        $Finding_2 = $(grep -i "encrypt_method" /etc/login.defs)
        $better_finding_2 = $(grep -i "^encrypt_method" /etc/login.defs)
        If ($better_finding_2.ToUpper().StartsWith("ENCRYPT_METHOD") -And (($better_finding_2 | awk '{$2=$2};1').Split(" ")[1].ToUpper() -eq "SHA512")) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system encrypts all stored passwords with a FIPS 140-2 approved cryptographic hashing algorithm."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not encrypt all stored passwords with a FIPS 140-2 approved cryptographic hashing algorithm."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "Encrypted passwords stored in /etc/shadow do not use a strong cryptographic hash."
    }

    $FindingDetails += $FindingMessage | Out-String

    $FindingDetails += $(FormatFinding $Finding) | Out-String
    $Finding = $Finding_2
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214958 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214958
        STIG ID    : UBTU-16-010200
        Rule ID    : SV-214958r610931_rule
        CCI ID     : CCI-001682
        Rule Name  : SRG-OS-000123-GPOS-00064
        Rule Title : Emergency administrator accounts must never be automatically removed or disabled.
        DiscussMD5 : EF6ED2C964D7B0AFEBD6638E9287A61E
        CheckMD5   : 2FC1C07426D606F0D29292D8A307A283
        FixMD5     : 8FB2695652768A6E3A93496B6EBFF6F6
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = $(chage -l root)
    $Lines = $Lines.Split([Environment]::NewLine)

    $rule = "^Password([\s]+)expires([\s]*):"

    foreach ($Line in $Lines) {
        If ($Line -match $rule) {
            If ($Line -match $rule_never) {
                $FindingDetails += "root account password never expires." | Out-String
            }
            Else {
                $Status = "Open"
                $FindingDetails += "root account password expires." | Out-String
            }

            $FindingDetails += "-----------------------------------------------------------------------" | Out-String
            $FindingDetails += $Line | Out-String
        }
    }

    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $rule = "^Account([\s]+)expires([\s]*):"

    foreach ($Line in $Lines) {
        If ($Line -match $rule) {
            If ($Line -match $rule_never) {
                $FindingDetails += "root account never expires." | Out-String
            }
            Else {
                $Status = "Open"
                $FindingDetails += "root account expires." | Out-String
            }

            $FindingDetails += "-----------------------------------------------------------------------" | Out-String
            $FindingDetails += $Line
        }
    }

    If ($Status -eq "Not_Reviewed") {
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

Function Get-V214959 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214959
        STIG ID    : UBTU-16-010210
        Rule ID    : SV-214959r610931_rule
        CCI ID     : CCI-000198
        Rule Name  : SRG-OS-000075-GPOS-00043
        Rule Title : Passwords for new users must have a 24 hours/1 day minimum password lifetime restriction.
        DiscussMD5 : C2BA91E7DF2AFA3F2BA2D0D3960066F7
        CheckMD5   : FA0C50417E6FDD085ECF3DF7E5A9E7C1
        FixMD5     : 51FBF5EA2545A3CFF8446FAF572DAC35
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -i pass_min_days /etc/login.defs)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    If ((($Finding | awk '{$2=$2};1').Split(" ").ToUpper()[0].StartsWith("PASS_MIN_DAYS")) -And (($Finding | awk '{$2=$2};1').Split(" ").ToUpper()[1] -ge 1)) {
        $Status = "Open"
        $FindingMessage = ("The Ubuntu operating system does not enforce a 24 hours/1 day minimum password lifetime " +
            "for new user accounts.")
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = ("The Ubuntu operating system enforces a 24 hours/1 day minimum password lifetime for new " +
            "user accounts.")
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214960 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214960
        STIG ID    : UBTU-16-010220
        Rule ID    : SV-214960r610931_rule
        CCI ID     : CCI-000199
        Rule Name  : SRG-OS-000076-GPOS-00044
        Rule Title : Passwords for new users must have a 60-day maximum password lifetime restriction.
        DiscussMD5 : 4BD693AFA3869A20BBE7820A54A65568
        CheckMD5   : 024949479E9ED89BB913683767077544
        FixMD5     : BF1E849C044D019B5D0ECF061469D23C
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -i pass_max_days /etc/login.defs)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    If ((($Finding | awk '{$2=$2};1').Split(" ").ToUpper()[0].StartsWith("PASS_MAX_DAYS")) -And (($Finding | awk '{$2=$2};1').Split(" ").ToUpper()[1] -ge 60)) {
        $Status = "Open"
        $FindingMessage = ("The Ubuntu operating system does not enforce a 60-day maximum password lifetime for new " +
            "user accounts.")
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system enforces a 60-day maximum password lifetime for new user accounts."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214961 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214961
        STIG ID    : UBTU-16-010230
        Rule ID    : SV-214961r610931_rule
        CCI ID     : CCI-000200
        Rule Name  : SRG-OS-000077-GPOS-00045
        Rule Title : Passwords must be prohibited from reuse for a minimum of five generations.
        DiscussMD5 : A976781B96235477C414C7A75D78EBEB
        CheckMD5   : C754955D629CDAEB36F149158F981426
        FixMD5     : 8D0F29A078B3AB39DB903A89CADF926B
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -i remember /etc/pam.d/common-password)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }
    $remember_line = (($Finding | awk '{$2=$2};1').split(" ") | grep -i remember)
    If (!($remember_line)) {
        $remember_line = $Finding
    }

    If (($Finding.ToLower().StartsWith("password")) -And ($remember_line.replace(" ", "").Split("=")[1] -ge 5)) {
        $Status = "NotAFinding"
        $FindingMessage = ("The Ubuntu operating system prevents passwords from being reused for a minimum of five " +
            "generations.")
    }
    Else {
        $Status = "Open"
        $FindingMessage = ("The Ubuntu operating system does not prevent passwords from being reused for a minimum of " +
            "five generations.")
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214962 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214962
        STIG ID    : UBTU-16-010240
        Rule ID    : SV-214962r610931_rule
        CCI ID     : CCI-000205
        Rule Name  : SRG-OS-000078-GPOS-00046
        Rule Title : Passwords must have a minimum of 15-characters.
        DiscussMD5 : 3305E27B7B82D2EA1009E5472608FA03
        CheckMD5   : 28E0C418A8A47BC84E93B40BA3AFA7E0
        FixMD5     : 20554287580CFD7B40192E8FE65F22FE
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -i minlen /etc/security/pwquality.conf)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    If (($Finding.ToLower().StartsWith("minlen")) -And (($Finding | awk '{$2=$2};1').replace(" ", "").Split("=")[1] -ge 15)) {
        $Status = "NotAFinding"
        $FindingMessage = "The pwquality configuration file enforces a minimum 15-character password length."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The pwquality configuration file does not enforce a minimum 15-character password length."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214963 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214963
        STIG ID    : UBTU-16-010250
        Rule ID    : SV-214963r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Ubuntu operating system must not be configured to allow blank or null passwords.
        DiscussMD5 : DB15477EC9B7A4D555400F5FB215F2B3
        CheckMD5   : 1D50F52FC052D8C6647304AFD5CF21FE
        FixMD5     : 058BA33AE7C28762157B4358CE7A3F52
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep pam_unix.so /etc/pam.d/* | grep nullok*)

    If ($Finding) {
        $Status = "Open"
        $FindingMessage = "Null passwords can be used."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "Null passwords cannot be used."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214964 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214964
        STIG ID    : UBTU-16-010260
        Rule ID    : SV-214964r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00225
        Rule Title : The Ubuntu operating system must prevent the use of dictionary words for passwords.
        DiscussMD5 : DE702766778E02CC88D158F8D9703B41
        CheckMD5   : DC8A5155A5A27EE5695F6255222433CD
        FixMD5     : 6B9A72B33F3CD9FF21F1900C90C76689
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep dictcheck /etc/security/pwquality.conf)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    If ($Finding.replace(" ", "") -eq "dictcheck=1") {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system uses the cracklib library to prevent the use of dictionary words."
    }
    Else {
        $Status = "Open"
        $FindingMessage = ("The Ubuntu operating system does not use the cracklib library to prevent the use of " +
            "dictionary words.")
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214965 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214965
        STIG ID    : UBTU-16-010270
        Rule ID    : SV-214965r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00225
        Rule Title : The passwd command must be configured to prevent the use of dictionary words as passwords.
        DiscussMD5 : DE702766778E02CC88D158F8D9703B41
        CheckMD5   : 4180D3F768B6BB6B2758EF9A82599864
        FixMD5     : 310AD3B70AB37AA19A73351B7ABF98DE
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    # Note: does not check if line is commented out.
    $Lines = Get-Content /etc/pam.d/passwd
    $Finding = $Lines -match "common-password"

    If ($Finding -ne "") {
        $Status = "NotAFinding"
        $FindingDetails = "The 'passwd' command uses the common-password option." | Out-String
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String

        $FindingDetails += $Finding
    }
    Else {
        $Status = "Open"
        $FindingDetails += "The 'passwd' command does not use the common-password option." | Out-String
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String

        $FindingDetails += "Missing:" | Out-String
        $FindingDetails += "@ include common-password"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214966 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214966
        STIG ID    : UBTU-16-010280
        Rule ID    : SV-214966r610931_rule
        CCI ID     : CCI-000795
        Rule Name  : SRG-OS-000118-GPOS-00060
        Rule Title : Account identifiers (individuals, groups, roles, and devices) must disabled after 35 days of inactivity.
        DiscussMD5 : 3ADECC35A6F5D3D3E44B34A81576CAD9
        CheckMD5   : 64208B7DD871E03B2CE4D4B41FBB6CA1
        FixMD5     : 17711CA4250AD525110A08B3B851E639
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep INACTIVE /etc/default/useradd)
    $better_finding = $(grep ^INACTIVE /etc/default/useradd)
    If (!($Finding) -And !($better_finding)) {
        $Finding = "Check text did not return results."
    }

    If ((($Finding.ToUpper()).StartsWith("INACTIVE")) -And ((($better_finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -in 1..35))) {
        $Status = "NotAFinding"
        $FindingMessage = "The account identifiers (individuals, groups, roles, and devices) are disabled after 35 days of inactivity."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The account identifiers (individuals, groups, roles, and devices) are not disabled after 35 days of inactivity."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214967 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214967
        STIG ID    : UBTU-16-010290
        Rule ID    : SV-214967r610931_rule
        CCI ID     : CCI-000044, CCI-002238
        Rule Name  : SRG-OS-000021-GPOS-00005
        Rule Title : The Ubuntu operating system must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts.
        DiscussMD5 : 97535DE64FF5CF25F542274BC33565A9
        CheckMD5   : D0ECDC5B8EC1BB7177038295A63C3D6A
        FixMD5     : C3C66D185E779E00AD4A02DB1F3469EF
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep pam_tally2 /etc/pam.d/common-auth)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    $login_attempts = ($Finding | awk '{$2=$2};1').split(" ")

    If ($login_attempts[3] -eq "onerr=fail") {
        $FindingMessage = "Ubuntu operating system locks an account after unsuccessful login attempts." | Out-String
        If ($login_attempts[4].split("=")[1] -le "3") {
            $Status = "NotAFinding"
            $FindingMessage += "Ubuntu operating system locks an account after three or less unsuccessful login attempts."
        }
        Else {
            $Status = "Open"
            $FindingMessage += "Ubuntu operating system locks an account after more than three unsuccessful login attempts."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "Ubuntu operating system does not lock account after three unsuccessful login attempts."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214968 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214968
        STIG ID    : UBTU-16-010291
        Rule ID    : SV-214968r610931_rule
        CCI ID     : CCI-002238
        Rule Name  : SRG-OS-000329-GPOS-00128
        Rule Title : Accounts on the Ubuntu operating system that are subject to three unsuccessful logon attempts within 15 minutes must be locked for the maximum configurable period.
        DiscussMD5 : E62FD69391F2A982BA761018B37B8CB6
        CheckMD5   : D48C00B501D89C74B850FF23D64A9687
        FixMD5     : 06F601930C51BE69EE6367831A6AFA78
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = $(Get-Content /etc/pam.d/password-auth -Raw) + $(Get-Content /etc/pam.d/system-auth -Raw)
    $Lines = $Lines.Split([Environment]::NewLine)

    $finding_auth_required = ""
    $finding_auth_die = ""
    $finding_account_required = ""

    $TempDetails = ""

    $rule_auth_required = '^([\s]*)auth([\s]+)required([\s]+)pam_faillock.so([\s]+)preauth([\s]+)silent([\s]+)audit([\s]+)deny=3([\s]+)even_deny_root_fail_interval=900([\s]+)unlock_time=900([\s]*)$'
    $rule_auth_die = '^([\s]*)auth([\s]+)\[default=die\]([\s]+)pam_faillock.so([\s]+)authfail([\s]+)audit([\s]+)deny=3([\s]+)even_deny_root_fail_interval=900([\s]+)unlock_time=900([\s]*)$'
    $rule_account_required = '^([\s]*)account([\s]+)required([\s]+)pam_faillock.so([\s]*)$'

    foreach ($Line in $Lines) {
        $Line = $Line.Trim()

        If ($Line -match $rule_auth_required) {
            $finding_auth_required = $Line
            $TempDetails += $finding_auth_required | Out-String
        }

        If ($Line -match $rule_auth_die) {
            $finding_auth_die = $Line
            $TempDetails += $finding_auth_die | Out-String
        }

        If ($Line -match $rule_account_required) {
            $finding_account_required = $Line
            $TempDetails += $finding_account_required | Out-String
        }
    }

    If ($finding_auth_required -And $finding_auth_die -And $finding_account_required) {
        $Status = "NotAFinding"
        $FindingMessage = ("The Ubuntu operating system is automatically locked for the maximum configurable period " +
            "when three unsuccessful login attempts are made within 15 minutes.")
    }
    Else {
        $Status = "Open"
        $FindingMessage = ("The Ubuntu operating system is not automatically locked for the maximum configurable " +
            "period when three unsuccessful login attempts are made within 15 minutes.")
    }

    $FindingDetails += $FindingMessage | Out-String

    If ($TempDetails -ne "") {
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        $FindingDetails += $TempDetails

        If ($Status -eq "Open") {
            $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        }
    }
    Else {
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    }

    If ($Status -eq "Open") {
        $FindingDetails += "Missing:" | Out-String

        If ($finding_auth_required -eq "") {
            $FindingDetails += "auth required pam_faillock.so preauth silent audit deny=3 even_deny_root_fail_interval=900 unlock_time=900" | Out-String
        }
        If ($finding_auth_die -eq "") {
            $FindingDetails += "auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root_fail_interval=900 unlock_time=900" | Out-String
        }
        If ($finding_account_required -eq "") {
            $FindingDetails += "account required pam_faillock.so" | Out-String
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

Function Get-V214969 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214969
        STIG ID    : UBTU-16-010300
        Rule ID    : SV-214969r610931_rule
        CCI ID     : CCI-002038
        Rule Name  : SRG-OS-000373-GPOS-00156
        Rule Title : The Ubuntu operating system must require users to re-authenticate for privilege escalation and changing roles.
        DiscussMD5 : 4B6F31466A4983858312B7D3010F63D9
        CheckMD5   : 083BA651B96A99B657F8AC6369837D49
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
    $Finding = $(egrep -i '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/*)
    $uncommented_count = 0

    $Finding | ForEach-Object { If ($_.StartsWith("#") -eq $False) {
            $uncommented_count++
        }
    }
    If ($uncommented_count -gt 0) {
        $Status = "Open"
        $FindingMessage = "The '/etc/sudoers' file has occurrences of 'NOPASSWD' or '!authenticate'."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The '/etc/sudoers' file has no occurrences of 'NOPASSWD' or '!authenticate'."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214970 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214970
        STIG ID    : UBTU-16-010310
        Rule ID    : SV-214970r610931_rule
        CCI ID     : CCI-000016
        Rule Name  : SRG-OS-000002-GPOS-00002
        Rule Title : Temporary user accounts must be provisioned with an expiration time of 72 hours or less.
        DiscussMD5 : A565EFA9C54C06FEC67E2C7D082FAF4E
        CheckMD5   : DE22343117D74A333EE54AEA967A8471
        FixMD5     : F929E83B262648E29AC5A7ABAF596BEE
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        $user_info = $(chage -l $_ | grep expires)
        $Finding = ($_ + [System.Environment]::NewLine +
            $user_info[0] + [System.Environment]::NewLine +
            $user_info[1] + [System.Environment]::NewLine +
            $user_info[2])
        $FindingDetails += $(FormatFinding $Finding) | Out-String
    }

    $Status = "Not_Reviewed"
    $FindingMessage = "Verify the Ubuntu operating system expires temporary user accounts within 72 hours or less."

    $FindingDetails += $FindingMessage | Out-String
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

Function Get-V214971 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214971
        STIG ID    : UBTU-16-010320
        Rule ID    : SV-214971r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00226
        Rule Title : The Ubuntu operating system must enforce a delay of at least 4 seconds between logon prompts following a failed logon attempt.
        DiscussMD5 : 7C22D07C283ABAC40CC9DD2E8DC76D89
        CheckMD5   : 4EB42E212C9B9AD5D41C840FEAB0C739
        FixMD5     : D0E4538FF793EE8EE164F1B68DECAEC9
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep pam_faildelay /etc/pam.d/common-auth*)

    If (($Finding | awk '{$2=$2};1') -match "auth required pam_faildelay.so delay=") {
        If ($Finding.split("=")[1] -ge 4000000) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system enforces a delay of at least 4 seconds between logon prompts."
        }
        Else {
            $Status = "Open"
            $FindingMessage += ("The Ubuntu operating system enforces a delay of less than 4 seconds between logon " +
                "prompts following a failed logon attempt.")
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = ("The Ubuntu operating system does not enforce a delay between logon prompts following a " +
            "failed logon attempt.")
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    $Finding = $(grep --no-filename pam_faildelay /etc/pam.d/common-auth*)
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214972 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214972
        STIG ID    : UBTU-16-010330
        Rule ID    : SV-214972r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00229
        Rule Title : Unattended or automatic login via the Graphical User Interface must not be allowed.
        DiscussMD5 : A54F06A419728C948532186EF87EC314
        CheckMD5   : E6DA1D07D3EB73D7DC239ED110A4393E
        FixMD5     : 5DEE40B91FADA37F0858672A5A8CB3B8
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = ""
    $TempDetails = ""

    Try {
        $Lines += $(Get-Content /etc/lightdm/lightdm.conf -Raw)
    }
    Catch {
    }

    Try {
        $Lines += $(Get-Content /etc/lightdm.d/*.conf -Raw)
    }
    Catch {
    }

    $Lines = $Lines.Split([Environment]::NewLine)

    $rule = '^([\s]*)autologin'

    foreach ($Line in $Lines) {
        $Line = $Line.Trim()

        If ($Line -match $rule) {
            $TempDetails += $Line | Out-String
        }
    }

    If ($TempDetails) {
        $Status = "Open"
        $FindingMessage = "Unattended or automatic login is enabled."
        $FindingDetails += $FindingMessage | Out-String
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        $FindingDetails += $TempDetails
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "Unattended or automatic login is disabled."
    }

    $FindingDetails += $FindingMessage
    $FindingDetails += $TempDetails
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214973 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214973
        STIG ID    : UBTU-16-010340
        Rule ID    : SV-214973r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Ubuntu operating system must display the date and time of the last successful account logon upon logon.
        DiscussMD5 : FA4CECDCE2C9B08407C8BD4ABFCFFEF7
        CheckMD5   : AE59E2755DED501D19C0AE1DEDAC8159
        FixMD5     : C56ED7A6CF42341693999A07E7AA124B
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep pam_lastlog /etc/pam.d/login)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    If (($Finding | awk '{$2=$2};1') -like "session required pam_lastlog.so showfailed") {
        $Status = "NotAFinding"
        $FindingMessage = "'pam_lastlog' is used and not silent."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "'pam_lastlog' is missing from the '/etc/pam.d/login' file, is not 'required', or the 'silent' option is present."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214974 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214974
        STIG ID    : UBTU-16-010350
        Rule ID    : SV-214974r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : There must be no .shosts files on the Ubuntu operating system.
        DiscussMD5 : C89D2B4233D2845625D04DFE34D44007
        CheckMD5   : 8C003B378B8F66544C28162E9EF86466
        FixMD5     : 4C1E88E12E8620281B15E8AE69528DC1
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        $Lines = ""
        $Lines += $(Get-Content /*.shosts)

        $Status = "Open"
        $FindingMessage = "At least one '.shosts' file was found."
    }
    Catch {
        $Status = "NotAFinding"
        $FindingMessage = "No '.shosts' file was found."
    }

    $FindingDetails += $FindingMessage
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214975 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214975
        STIG ID    : UBTU-16-010360
        Rule ID    : SV-214975r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : There must be no shosts.equiv files on the Ubuntu operating system.
        DiscussMD5 : 030814A6F495056B537102C6D4C6BA83
        CheckMD5   : E2F5061AD21FB07A96525B6A8E00521C
        FixMD5     : BAD977ECCB90A96CB10F6769B84380ED
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = $(find / -name shosts.equiv)

    If ($Lines) {
        $Status = "Open"

        $FindingMessage = "A 'shosts.equiv' file was found."
        $FindingDetails += $FindingMessage | Out-String
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String

        $FindingDetails += $Lines
    }
    Else {
        $Status = "NotAFinding"

        $FindingMessage = "No 'shosts.equiv' file was found."
        $FindingDetails += $FindingMessage
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214976 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214976
        STIG ID    : UBTU-16-010370
        Rule ID    : SV-214976r610931_rule
        CCI ID     : CCI-002450
        Rule Name  : SRG-OS-000396-GPOS-00176
        Rule Title : The Ubuntu operating system must implement NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.
        DiscussMD5 : 294926C8A61FB9AEEF6E607FE23E4C9F
        CheckMD5   : 2A6A4FCCCD5D13645899F61DF1839235
        FixMD5     : 4A7F35E46BE5C0CFCE05595BDF304F18
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -i 1 /proc/sys/crypto/fips_enabled)

    If ($Finding -eq "1") {
        $Status = "NotAFinding"
        $FindingMessage = "The system is configured to run in FIPS mode."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The system is not configured to run in FIPS mode."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214977 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214977
        STIG ID    : UBTU-16-010380
        Rule ID    : SV-214977r610931_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-OS-000080-GPOS-00048
        Rule Title : Ubuntu operating systems booted with a BIOS must require authentication upon booting into single-user and maintenance modes.
        DiscussMD5 : 542EB0188EA33B8D9F79B01E6C28CED4
        CheckMD5   : CE72617A407759FE7A40A93F85C7C7AB
        FixMD5     : 9BA4D288C82C5D9DC460C3E755ED3536
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

    If ($Finding) {
        $Status = "Not_Applicable"
        $FindingMessage = "This is only applicable on systems that use a basic Input/Output System BIOS."
    }
    Else {
        $Finding = $(grep password /boot/grub/grub.cfg)

        If ($Finding -match "password_pbkdf2 root grub.pbkdf2.sha512.10000.") {
            $Status = "NotAFinding"
            $FindingMessage = "The root password entry does begin with 'password_pbkdf2'"
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The root password entry does not begin with 'password_pbkdf2'"
        }
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214978 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214978
        STIG ID    : UBTU-16-010390
        Rule ID    : SV-214978r610931_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-OS-000080-GPOS-00048
        Rule Title : Ubuntu operating systems booted with United Extensible Firmware Interface (UEFI) implemented must require authentication upon booting into single-user mode and maintenance.
        DiscussMD5 : 542EB0188EA33B8D9F79B01E6C28CED4
        CheckMD5   : C488CBBE2AE002A9CE8EBF55BB8CD7FC
        FixMD5     : 6B8AC293F68A7EB2662D436146CFD14C
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

    If ($Finding) {
        $Finding = $(grep password /boot/efi/EFI/ubuntu/grub.cfg)

        If ($Finding -match "^password_pbkdf2") {
            $Status = "NotAFinding"
            $FindingMessage = "The root password entry does begin with 'password_pbkdf2'."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The root password entry does not begin with 'password_pbkdf2'."
        }
    }
    Else {
        $Status = "Not_Applicable"
        $FindingMessage += "This is only applicable on Ubuntu operating systems that use UEFI."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214979 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214979
        STIG ID    : UBTU-16-010400
        Rule ID    : SV-214979r610931_rule
        CCI ID     : CCI-001199, CCI-002475, CCI-002476
        Rule Name  : SRG-OS-000185-GPOS-00079
        Rule Title : All persistent disk partitions must implement cryptographic mechanisms to prevent unauthorized disclosure or modification of all information that requires at rest protection.
        DiscussMD5 : CDA0312A08E588CDF4E910D52C378C75
        CheckMD5   : 7F0E08ADBE7249755C9FE9D8AC3085D3
        FixMD5     : 05AD7E4A467395A7AA8B942978C8581A
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(Test-Path /etc/crypttab)

    If ($Finding) {
        $Status = "Not_Reviewed"
        $FindingMessage = "Check that the system partitions are all encrypted."
    }
    Else {
        $Status = "Open"
        $FindingMessage = ("The system partitions are not all encrypted.  A partition other than the boot partition " +
            "or pseudo file systems (such as /proc or /sys) is not listed")
    }

    $FindingDetails += $FindingMessage | Out-String

    If ($Finding) {
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        $FindingDetails += $(Get-Content /etc/crypttab)
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214980 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214980
        STIG ID    : UBTU-16-010410
        Rule ID    : SV-214980r610931_rule
        CCI ID     : CCI-001090
        Rule Name  : SRG-OS-000138-GPOS-00069
        Rule Title : All public directories must be owned by root to prevent unauthorized and unintended information transferred via shared system resources.
        DiscussMD5 : E51114DDF4084E627CE2A6AF9C67D641
        CheckMD5   : 10E3C9D820A3DB0FD6D16E6F0B869DD0
        FixMD5     : 761A02BE276A6D9FCD93A936B36BD2F2
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $TempDetails = ""

    $command = @'
#!/bin/sh
find / -type d -perm -0002 -exec ls -lLd {} \;
'@
    Write-Output $command > /tmp/command
    $Findings = $(sh /tmp/command)
    Remove-Item /tmp/command

    foreach ($Finding in $Findings) {
        If ($Finding -And !($Finding -match '^\s*$')) {
            $GroupOwner = $Finding.Split(' ')[2]

            If ($GroupOwner -ne "root") {
                $Status = "Open"
                $TempDetails += $Finding | Out-String
            }
        }
    }

    If ($Status -eq "Not_Reviewed") {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system configures the audit tools to be group owned by root to prevent any unauthorized access, deletion, or modification."
    }
    Else {
        $FindingMessage = "The Ubuntu operating system does not configure all of the audit tools to be group owned by root to prevent any unauthorized access, deletion, or modification."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    $FindingDetails += $TempDetails
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214981 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214981
        STIG ID    : UBTU-16-010420
        Rule ID    : SV-214981r610931_rule
        CCI ID     : CCI-001090
        Rule Name  : SRG-OS-000138-GPOS-00069
        Rule Title : All world-writable directories must be group-owned by root, sys, bin, or an application group.
        DiscussMD5 : 1512BF5E4A7B1EE24F8F80E1AD7A945C
        CheckMD5   : 04BEAC84DAFF896F9369DDE96B7C754D
        FixMD5     : 5498B8648A88DCC7F8038C26B7EBF04B
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Owners = stat -c "%U" $(find / -type d -perm -0002)
    $Owners = $Owners.Split([Environment]::NewLine)

    foreach ($Owner in $Owners) {
        If (!($Owner -match 'root') -And !($Owner -match 'sys') -And !($Owner -match 'bin')) {
            # We don't know whether the directory is owned by an application group associated with the directory.
            # This is why Status is Not_Reviewed, rather than Open.
            $Status = "Not_Reviewed"

            # It would be helpful to also know what the file is, not just owner.
            $FindingDetails += $Owner | Out-String
        }
    }

    If ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingMessage = "No world-writable directory was found which is not owned by root, sys, or bin."
        $FindingDetails += $FindingMessage
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214982 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214982
        STIG ID    : UBTU-16-010500
        Rule ID    : SV-214982r610931_rule
        CCI ID     : CCI-002696
        Rule Name  : SRG-OS-000445-GPOS-00199
        Rule Title : A file integrity tool must be installed to verify correct operation of all security functions in the Ubuntu operating system.
        DiscussMD5 : 193701593DBE03679445BFA2C4E4A566
        CheckMD5   : A73B00907DC1750012AE16DF1C4FCD3B
        FixMD5     : 521BE528C945F1E2E2025A132FEA4D19
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(dpkg -l | grep aide)

    If (($Finding | awk '{print $2}') -eq "aide") {
        $Status = "NotAFinding"
        $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) is installed and verifies the correct operation of all security functions."
    }
    Else {
        $Status = "Not_Reviewed"
        $FindingMessage = "AIDE is not installed. Ask the System Administrator how file integrity checks are performed on the system."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214983 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214983
        STIG ID    : UBTU-16-010510
        Rule ID    : SV-214983r610931_rule
        CCI ID     : CCI-002699
        Rule Name  : SRG-OS-000446-GPOS-00200
        Rule Title : The file integrity tool must perform verification of the correct operation of security functions: upon system start-up and/or restart; upon command by a user with privileged access; and/or every 30 days.
        DiscussMD5 : 71863D9EC5D7ACA0CE936C3273EB11F4
        CheckMD5   : BEB9E43EAD1DE6C34BDA9BB2438B374C
        FixMD5     : 4F916828DD930A375228DE4D9D84937E
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(ls -al /etc/cron.daily/aide)

    If ($Finding) {
        $Status = "NotAFinding"
        $FindingMessage = ("Advanced Intrusion Detection Environment (AIDE) performs a verification of the operation " +
                           "of security functions every 30 days.")
    }
    Else {
        $Status = "Not_Reviewed"
        $FindingMessage = ("Check if Advanced Intrusion Detection Environment (AIDE) performs a verification of the " +
                           "operation of security functions every 30 days.")
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214984 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214984
        STIG ID    : UBTU-16-010520
        Rule ID    : SV-214984r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The file integrity tool must be configured to verify Access Control Lists (ACLs).
        DiscussMD5 : CD3ED55D58532108E6184EE7E6277113
        CheckMD5   : 18D3F178D520C60B5919FED9C8835E1B
        FixMD5     : D2FAE5E41A3C6129499F56109BDD43F3
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = Get-Content /etc/aide/aide.conf
    $Lines = $Lines.Split([Environment]::NewLine)

    foreach ($Line in $Lines) {
        If (!($Line -match 'acl') -And !($Line -match '^([\s]*)#') -And !($Line -match '=') -And !($Line -match '^([\s]*)$')) {
            # Lines which contain 'acl', are commented out, have an equals sign, or are all whitespace are valid lines.
            $Status = "Open"

            If (!($FindingDetails)) {
                $FindingDetails += "/etc/aide/aide.conf has a line(s) which does not use the 'acl' rule:" | Out-String
            }

            $FindingDetails += $Line | Out-String
            $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        }
    }

    If ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingMessage = "The 'acl' rule is being used on all selection lines by /etc/aide/aide.conf."
        $FindingDetails += $FindingMessage
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214985 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214985
        STIG ID    : UBTU-16-010530
        Rule ID    : SV-214985r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The file integrity tool must be configured to verify extended attributes.
        DiscussMD5 : 3C3763C3B3E32A6278BD032C2BF03E68
        CheckMD5   : 831AC027CC17A12990FFF932414536CA
        FixMD5     : 285E85F967F0011F021553CC608170CF
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(dpkg -l | grep aide)

    If (($Finding | awk '{print $2}') -eq "aide") {
        $Status = "NotAFinding"
        $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) is installed and verifies the correct operation of all security functions."
    }
    Else {
        $Status = "Not_Reviewed"
        $FindingMessage = "AIDE is not installed. Ask the System Administrator how file integrity checks are performed on the system."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214986 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214986
        STIG ID    : UBTU-16-010540
        Rule ID    : SV-214986r610931_rule
        CCI ID     : CCI-001744, CCI-002702
        Rule Name  : SRG-OS-000363-GPOS-00150
        Rule Title : The file integrity tool must notify the system administrator when changes to the baseline configuration or anomalies in the operation of any security functions are discovered.
        DiscussMD5 : 323AFC9EA1DC1C2D09C67AB1F73D61FE
        CheckMD5   : 8BE650D5493C39D74086F33DA2A93DCB
        FixMD5     : 15D12882A5621195953086E6610F53FE
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep SILENTREPORTS /etc/default/aide)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    If (($Finding.StartsWith("SILENTREPORTS")) -And ((($Finding | awk '{$2=$2};1').replace(" ", "").split("="))[1] -eq "no")) {
        $Status = "NotAFinding"
        $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) notifies the system administrator when anomalies in the operation of any security functions are discovered."
    }
    Else {
        $Status = "Not_Reviewed"
        $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) does not notify the system administrator when anomalies in the operation of any security functions are discovered."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214987 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214987
        STIG ID    : UBTU-16-010550
        Rule ID    : SV-214987r610931_rule
        CCI ID     : CCI-001496
        Rule Name  : SRG-OS-000278-GPOS-00108
        Rule Title : The Ubuntu operating system must use cryptographic mechanisms to protect the integrity of audit tools.
        DiscussMD5 : 445D43050109AFE929C8BE4574323E8B
        CheckMD5   : 65695790E3154EDC0F41AB4E8362B966
        FixMD5     : 529BBD059D3517DAA58F1C316A22D3CF
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(egrep '(\/sbin\/(audit|au))' /etc/aide/aide.conf)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }
    $audit_tools = @("/sbin/auditctl", "/sbin/aureport", "/sbin/ausearch", "/sbin/autrace", "/sbin/auditd", "/sbin/audispd", "/sbin/augenrules")
    $missing_audit_tools = @()
    $correct_message_count = 0

    $audit_tools | ForEach-Object {
        If ($Finding -match $_) {
            $correct_message_count++
        }
        Else {
            $missing_audit_tools += $_
        }
    }

    If ($correct_message_count -eq 7) {
        $Status = "NotAFinding"
        $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) is properly configured to use cryptographic mechanisms to protect the integrity of audit tools."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "Advanced Intrusion Detection Environment (AIDE) is not properly configured to use cryptographic mechanisms to protect the integrity of audit tools." | Out-String
        $FindingMEssage += "Missing audit tools - $missing_audit_tools"
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214988 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214988
        STIG ID    : UBTU-16-010560
        Rule ID    : SV-214988r610931_rule
        CCI ID     : CCI-001749
        Rule Name  : SRG-OS-000366-GPOS-00153
        Rule Title : Advance package Tool (APT) must be configured to prevent the installation of patches, service packs, device drivers, or Ubuntu operating system components without verification they have been digitally signed using a certificate that is recognized and approved by the organization.
        DiscussMD5 : 0B02CA5F77FA3196947FD8910D7206F0
        CheckMD5   : 0F922F296A6641D159E8FD766FDBA861
        FixMD5     : 28FC8AD076E81BFC3B35A84B0CA7E5B9
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep AllowUnauthenticated /etc/apt/apt.conf.d/*)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }
    $incorrect_message_count = 0

    $Finding | ForEach-Object { If ($_.Contains('APT::Get::AllowUnauthenticated "true"')) {
            $incorrect_message_count++
        } }
    If ($incorrect_message_count -gt 0) {
        $Status = "Open"
        $FindingMessage = "At least one of the files returned from the command with 'AllowUnauthenticated' set to 'true'" | Out-String
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The 'AllowUnauthenticated' variable is not set at all or set to 'false'"
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214989 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214989
        STIG ID    : UBTU-16-010570
        Rule ID    : SV-214989r610931_rule
        CCI ID     : CCI-002617
        Rule Name  : SRG-OS-000437-GPOS-00194
        Rule Title : Advance package Tool (APT) must remove all software components after updated versions have been installed.
        DiscussMD5 : 1664F2CB47698D309E1F3C0682B43A4C
        CheckMD5   : 230AB5A86A57B717309C2C9579F37149
        FixMD5     : 8F1EACE0C04782A5C796548C8D6B7B63
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -i remove-unused /etc/apt/apt.conf.d/50unattended-upgrades)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    If ($Finding.Contains('Unattended-Upgrade::Remove-Unused-Dependencies "true";')) {
        $Status = "NotAFinding"
        $FindingMessage = "APT is configured to remove all software components after updating."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "APT is not configured to remove all software components after updating."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214990 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214990
        STIG ID    : UBTU-16-010580
        Rule ID    : SV-214990r610931_rule
        CCI ID     : CCI-001958
        Rule Name  : SRG-OS-000378-GPOS-00163
        Rule Title : Automatic mounting of Universal Serial Bus (USB) mass storage driver must be disabled.
        DiscussMD5 : B550EC29A3BF0EF47BE665F3B6004911
        CheckMD5   : EB70CC8BE453667B9A59E5FDBDAC90C6
        FixMD5     : 480AC4B017528FED1B535E9B10E82695
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep usb-storage /etc/modprobe.d/* | grep "/bin/true")
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    #/etc/modprobe.d/blacklist.conf:install usb-storage /bin/true

    If (($Finding | grep "install") -And ($Finding | grep "install usb-storage /bin/true")) {
        $Finding_2 = $(grep usb-storage /etc/modprobe.d/* | grep -i "blacklist")
        If (!($Finding_2)) {
            $Finding_2 = "Check text did not return results."
        }

        If (($Finding_2 | grep "blacklist") -And ($Finding_2 | grep "blacklist usb-storage")) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system disables ability to load the USB storage kernel module and disables the ability to use USB mass storage device."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system disables ability to load the USB storage kernel module but does not disable the ability to use USB mass storage device."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system neither disables ability to load the USB storage kernel module nor disables the ability to use USB mass storage device."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214991 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214991
        STIG ID    : UBTU-16-010590
        Rule ID    : SV-214991r610931_rule
        CCI ID     : CCI-000366, CCI-000778, CCI-001958
        Rule Name  : SRG-OS-000114-GPOS-00059
        Rule Title : File system automounter must be disabled unless required.
        DiscussMD5 : D7F9710ADCBA4C85065CC4964359EDEA
        CheckMD5   : F5CE2203C26741000E3856F724B5B01B
        FixMD5     : 02C794DFC391798DEDB79592ADD7E76A
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(systemctl status autofs)

    If ($Finding -match "Active: active") {
        $Status = "Not_Reviewed"
        $FindingMessage = "Check if 'autofs' status being set to active is documented with ISSO as an operational requirement."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "'autofs' status is inactive."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214992 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214992
        STIG ID    : UBTU-16-010600
        Rule ID    : SV-214992r610931_rule
        CCI ID     : CCI-002165, CCI-002235
        Rule Name  : SRG-OS-000312-GPOS-00122
        Rule Title : Pam_Apparmor must be configured to allow system administrators to pass information to any other Ubuntu operating system administrator or user, change security attributes, and to confine all non-privileged users from executing functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.
        DiscussMD5 : CAADAD51B49C2A4A306819D604E69E76
        CheckMD5   : 16F741BDC79F6A1183839DF410121D0E
        FixMD5     : F814C1951D7429D337803DC73EA8B0C1
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(dpkg -l | grep -i apparmor)
    $Finding_2 = ""

    If ($Finding) {
        $Finding_2 = $(systemctl status apparmor.service | grep -i active)
        If ($Finding_2 -match "Active: active") {
            $Status = "NotAFinding"
            $FindingMessage = ("The Ubuntu operating system is configured to allow system administrators to pass " +
                "information to any other Ubuntu operating system administrator or user.")
        }
        Else {
            $Status = "Open"
            $FindingMessage = ("The Ubuntu operating system is not configured to allow system administrators to pass " +
                "information to any other Ubuntu operating system administrator or user.")
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = ("The Ubuntu operating system is not configured to allow system administrators to pass " +
            "information to any other Ubuntu operating system administrator or user.")
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    $FindingDetails += $Finding | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    $FindingDetails += $Finding_2 | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214993 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214993
        STIG ID    : UBTU-16-010610
        Rule ID    : SV-214993r610931_rule
        CCI ID     : CCI-001764, CCI-001774
        Rule Name  : SRG-OS-000368-GPOS-00154
        Rule Title : The Apparmor module must be configured to employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs and limit the ability of non-privileged users to grant other users direct access to the contents of their home directories/folders.
        DiscussMD5 : BB7812F66825683543AEF82D33F9DDBD
        CheckMD5   : 56B8961DF233A886A80E3E3042FEC053
        FixMD5     : C2416434E86EFD4C8B3CDC23E253971A
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(apparmor_status)

    $Status = "Not_Reviewed"
    $FindingMessage = "Verify that the Ubuntu operating system is configured to employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs and access to user home directories."

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214994 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214994
        STIG ID    : UBTU-16-010630
        Rule ID    : SV-214994r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The x86 Ctrl-Alt-Delete key sequence must be disabled.
        DiscussMD5 : 30605CBC6163AD42F3D692B9C1EAD76E
        CheckMD5   : BC8E6197025E2E0CD6CC835E8F58494C
        FixMD5     : C4FD10F912CB7517206345BBF97B5DD8
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(systemctl status ctrl-alt-del.target)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    If ($Finding -match "inactive") {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system is not configured to reboot the system when Ctrl-Alt-Delete is pressed."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system is configured to reboot the system when Ctrl-Alt-Delete is pressed."
        $FindingMessage += "The 'ctrl-alt-del.target' is active."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214995 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214995
        STIG ID    : UBTU-16-010631
        Rule ID    : SV-214995r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The x86 Ctrl-Alt-Delete key sequence in the Ubuntu operating system must be disabled if a Graphical User Interface is installed.
        DiscussMD5 : 5E6A800D9E4713A9D3F2AF9D56876A36
        CheckMD5   : 80FED23294D2CC5CB7900343FBF7D03E
        FixMD5     : 06158198C39D7B096F2AFC2851BEBEC2
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep logout /etc/dconf/db/local.d/*)
    $LHS = $Finding -Split '='[0]
    $LHS = $LHS.Trim()

    If ($Finding) {
        If ($LHS -eq 'logout') {
            If ($Finding.split("=")[1] -in ("''", """")) {
                $Status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system is not configured to reboot the system when Ctrl-Alt-Delete is pressed when using a graphical user interface."
            }
            Else {
                $Status = "Open"
                $FindingMessage = "The Ubuntu operating system is configured to reboot the system when Ctrl-Alt-Delete is pressed when using a graphical user interface."
                $FindingMessage += "The 'logout' key is bound to an action."
            }
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system is configured to reboot the system when Ctrl-Alt-Delete is pressed when using a graphical user interface."
            $FindingMessage += "The 'logout' key is commented out."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system is configured to reboot the system when Ctrl-Alt-Delete is pressed when using a graphical user interface."
        $FindingMessage += "The 'logout' key is missing."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214996 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214996
        STIG ID    : UBTU-16-010640
        Rule ID    : SV-214996r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00228
        Rule Title : Default permissions must be defined in such a way that all authenticated users can only read and modify their own files.
        DiscussMD5 : 118F410ACCBA0FE68E7A2B605B30D976
        CheckMD5   : 0D6085B3631610912C06A147FC255FA2
        FixMD5     : 6E7443C4A5EEA4B74C738E3FFC5E9222
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -i "umask" /etc/login.defs)
    $better_finding = $(grep -i "^umask" /etc/login.defs)

    If ((($better_finding | awk '{$2=$2};1').ToUpper()).StartsWith("UMASK") -And (($better_finding | awk '{$2=$2};1').split(" ")[1] -eq "077")) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system defines default permissions for all authenticated users in such a way that the user can only read and modify their own files."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not define default permissions for all authenticated users in such a way that the user can only read and modify their own files."
        If ((($better_finding | awk '{$2=$2};1').split(" ")[1] -eq "000")) {
            $SeverityOverride = "CAT_I"
            $Justification = "The 'UMASK' variable is set to '000, therefore this is a finding with the severity raised to a CAT I."
            $FindingMessage += "`r`n"
            $FindingMessage += $Justification
        }
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214997 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214997
        STIG ID    : UBTU-16-010650
        Rule ID    : SV-214997r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Ubuntu operating system must not have unnecessary accounts.
        DiscussMD5 : 87F341C683B2C4E16FE9C23BC608CB8F
        CheckMD5   : 35F08D661D1925C3ED9549A9165C98CB
        FixMD5     : 91BFE978A182BB1B71B7DA17527C934B
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $FindingMessage = "Check if all accounts on the system are necessary."
    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    $Accounts = $(more /etc/passwd)
    $Accounts = $Accounts.Split([Environment]::NewLine)

    foreach ($Account in $Accounts) {
        $FindingDetails += $Account | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214998 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214998
        STIG ID    : UBTU-16-010660
        Rule ID    : SV-214998r610931_rule
        CCI ID     : CCI-000764, CCI-000804, CCI-001084
        Rule Name  : SRG-OS-000104-GPOS-00051
        Rule Title : Duplicate User IDs (UIDs) must not exist for interactive users.
        DiscussMD5 : 04E6717A26373E3554AA8D59DD6D6124
        CheckMD5   : C8C2B6B906799A9BF5B34D5D57E8341F
        FixMD5     : BB9553333C7FA20B9758E285637C8E8C
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd)

    If ($Finding) {
        $Status = "Not_Reviewed"
        $FindingMessage = "The Ubuntu operating system may contains duplicate User IDs (UIDs) for interactive users."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system contains no duplicate User IDs (UIDs) for interactive users."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214999 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214999
        STIG ID    : UBTU-16-010670
        Rule ID    : SV-214999r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The root account must be the only account having unrestricted access to the system.
        DiscussMD5 : FA7D5BC37918CC976534B73E3079F5FC
        CheckMD5   : 2BD08500F728DCDDEF61825ACD398CFC
        FixMD5     : 2E268E2C7A57933D20E7618C926B926D
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Findings = $(awk -F: '$3 == 0 {print $1}' /etc/passwd)
    $Findings = $Findings.Split([Environment]::NewLine)

    foreach ($Finding in $Findings) {
        If (!($Finding -match '^root$')) {
            $Status = "Open"
            $FindingDetails += "An account other than root has a UID of '0': "
            $FindingDetails += $Finding | Out-String
        }
    }

    If (!($FindingDetails)) {
        $Status = "NotAFinding"
        $FindingDetails += "No account other than root has a UID of '0'." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215001 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215001
        STIG ID    : UBTU-16-010690
        Rule ID    : SV-215001r610931_rule
        CCI ID     : CCI-002007
        Rule Name  : SRG-OS-000383-GPOS-00166
        Rule Title : Pluggable Authentication Module (PAM) must prohibit the use of cached authentications after one day.
        DiscussMD5 : CC1503EB4AC6C661B16A41A973BC66E1
        CheckMD5   : 00B38CE1B6F5D15E1FFA2AACFB975A03
        FixMD5     : D018C031C459B98F992C86A0CB2F918B
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -i "timestamp_timeout" /etc/pam.d/*)

    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    If ($Finding | grep "86400") {
        $Status = "NotAFinding"
        $FindingMessage = "PAM prohibits the use of cached authentications after one day."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "PAM does not prohibit the use of cached authentications after one day."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215002 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215002
        STIG ID    : UBTU-16-010700
        Rule ID    : SV-215002r610931_rule
        CCI ID     : CCI-002165
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : All files and directories must have a valid owner.
        DiscussMD5 : 6987FB57B2BB10CB6FF66395EDAF6244
        CheckMD5   : FA4727355775999DC4C7A49C0DA48AD5
        FixMD5     : A551E94306AE735DAA5AC4247FFE2917
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Findings = $(find / -nouser)

    If ($Findings) {
        $Status = "Open"
        $FindingMessage = "File(s) on the system which have no assigned user:"
        $FindingDetails += $FindingMessage | Out-String

        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        $FindingDetails += $Findings
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "No files on the system have no assigned user."
        $FindingDetails += $FindingMessage | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215003 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215003
        STIG ID    : UBTU-16-010710
        Rule ID    : SV-215003r610931_rule
        CCI ID     : CCI-002165
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : All files and directories must have a valid group owner.
        DiscussMD5 : 687411069F405446AC69423E983CCE38
        CheckMD5   : 9198785846C02CED71596E24D87198D7
        FixMD5     : 9F90E4D7DF488D249CA9368C10C953EA
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Findings = $(find / -nogroup)

    If ($Findings) {
        $Status = "Open"
        $FindingMessage = "File(s) on the system which have no assigned group:"
        $FindingDetails += $FindingMessage | Out-String

        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        $FindingDetails += $Findings
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "No files on the system have no assigned group."
        $FindingDetails += $FindingMessage | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215004 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215004
        STIG ID    : UBTU-16-010720
        Rule ID    : SV-215004r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : All local interactive users must have a home directory assigned in the /etc/passwd file.
        DiscussMD5 : 3AA09904685FB108BD0BA0E171F3525A
        CheckMD5   : 8915ADF9C67B3E27FB5EA28B83E386F2
        FixMD5     : 7409B9ED99BEA74CDEB15BFE4CE8EE6F
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    # I will use UID >= 1000 as a proxy for interactive users.
    # It may be desirable to use an answer file to customize a list of interactive users and feed that to this check.
    $Finding = $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6}' /etc/passwd)
    $found = 0

    $Finding | ForEach-Object {
        If ($Finding_2 -like ($_.split(":")[0])) {
            $found++
        }
    }

    If ($found -eq 0) {
        $Status = "NotAFinding"
        $FindingMessage = ("The assigned home directory of all local interactive users on the Ubuntu operating system " +
            "exists.")
    }
    Else {
        $Status = "Open"
        $FindingMessage = ("The assigned home directory of all local interactive users on the Ubuntu operating system " +
            "does not exist.")
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215005 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215005
        STIG ID    : UBTU-16-010730
        Rule ID    : SV-215005r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : All local interactive user accounts, upon creation, must be assigned a home directory.
        DiscussMD5 : 3AA09904685FB108BD0BA0E171F3525A
        CheckMD5   : 679D715E8BF56E84D40F3E1CF7B6EDC6
        FixMD5     : 09E16FDE48C08D59CEF45BA29D2309D3
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -i create_home /etc/login.defs)

    If ($Finding -match '^([\s]*)CREATE_HOME([\s]+)yes([\s]*)$') {
        $Status = "NotAFinding"
        $FindingMessage = "The value for 'CREATE_HOME' parameter is set to 'yes'."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The value for 'CREATE_HOME' parameter is not set to 'yes'."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215006 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215006
        STIG ID    : UBTU-16-010740
        Rule ID    : SV-215006r648699_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : All local interactive user home directories defined in the /etc/passwd file must exist.
        DiscussMD5 : 9FA712EB1B0E8019C663B57A91AFAADA
        CheckMD5   : F3D66513EFB1BC888C9B5B89FAB4EEC7
        FixMD5     : 804CEF9A68062C283B47092981B00BF9
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6}' /etc/passwd)
    $Finding_2 = $(pwck -r)
    $found = 0

    $Finding | ForEach-Object {
        If ($Finding_2 -like ($_.split(":")[0])) {
            $found++
        }
    }

    If ($found -eq 0) {
        $Status = "NotAFinding"
        $FindingMessage = ("The assigned home directory of all local interactive users on the Ubuntu operating system " +
            "exists.")
    }
    Else {
        $Status = "Open"
        $FindingMessage = ("The assigned home directory of all local interactive users on the Ubuntu operating system " +
            "does not exist.")
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215007 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215007
        STIG ID    : UBTU-16-010750
        Rule ID    : SV-215007r648702_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : All local interactive user home directories must have mode 0750 or less permissive.
        DiscussMD5 : 2DD626D9CC5555C42ADDC5153DC50680
        CheckMD5   : E7C622D0560F331AB5DB7ED636F671DB
        FixMD5     : 46CD7F342BB93E3D85B3DBE68F1A09FF
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Dirs = $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd)
    $TempDetails = ""
    $count_invalid = 0

    foreach ($Dir in $Dirs) {
        $Perm = $(stat -c '%a' $Dir)

        If ($Perm -gt 750) {
            $count_invalid += 1
        }

        $TempDetails += ($Dir + " " + $Perm) | Out-String
    }

    If ($count_invalid -gt 0) {
        $Status = "Open"
        $FindingMessage = ("The assigned home directory of " + $count_invalid + " interactive users do not have a " +
            "mode of '0750' or less permissive.")
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The assigned home directory of all local interactive users have a mode of '0750' or less permissive."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    $FindingDetails += $TempDetails
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215008 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215008
        STIG ID    : UBTU-16-010760
        Rule ID    : SV-215008r648705_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : All local interactive user home directories must be group-owned by the home directory owners primary group.
        DiscussMD5 : 8E80142120C11B7EE81E7B5F4EBB4360
        CheckMD5   : 4AF18F121A2F3896B7DA6DCC876BCFE8
        FixMD5     : 59F15189338E370C7DF774EE6CC552CC
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd))
    $Found = 0

    $Finding | ForEach-Object {
        if (($_ | awk '{$2=$2};1').split(" ")[3] -ne $_.split("/")[-1]) {
            $Found++
        }
    }

    if ($Found -eq 0) {
        $Status = "NotAFinding"
        $FindingMessage = "The assigned home directory of all local interactive are group owned by the interactive user."
    }
    else {
        $Status = "Open"
        $FindingMessage = ("The assigned home directory of all local interactive are not group owned by the " +
                           "interactive user.")
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215009 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215009
        STIG ID    : UBTU-16-010770
        Rule ID    : SV-215009r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : All local initialization files must have mode 0740 or less permissive.
        DiscussMD5 : 98A43D410D98F1B43AF7B80565A9881E
        CheckMD5   : 236916CA570BF91C860D129A5153C51E
        FixMD5     : F7C39A326D3085A9EF32C083520B1944
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Command = @'
#!/bin/sh
stat -c "%a %n" /home/*/.*
'@

    Write-Output $Command > /tmp/command
    $Findings = $(sh /tmp/command)
    $Findings = $Findings.Split([Environment]::NewLine)
    $TempDetails = ""

    foreach ($Finding in $Findings) {
        $Path = $Finding.Split(' ')[1]

        If ([System.IO.File]::Exists($Path)) {
            $Permission = $Finding.Split(' ')[0]

            If (!($Permission -match '^\d+$')) {
                $Status = "Open"
            }

            If ($Permission -gt 0740) {
                $Status = "Open"
                $FindingMessage = "Local initialization file(s) were found with a mode more permissive than '0740'."
            }

            $TempDetails += $Finding | Out-String
        }
    }

    If ($Status -eq "Not_Reviewed") {
        $Status = "NotAFinding"
        $FindingMessage = "No local initialization file was found with a mode more permissive than '0740'."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $TempDetails
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215010 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215010
        STIG ID    : UBTU-16-010780
        Rule ID    : SV-215010r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : All local interactive user initialization files executable search paths must contain only paths that resolve to the system default or the users home directory.
        DiscussMD5 : C3F6EAE49C91F0EE11F9A8FCF10DC942
        CheckMD5   : 08D20556ADD8A224F805D7B9387049FD
        FixMD5     : 2DAF224C09F4B624D5865B5FDB7991F8
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Dirs = $(awk -F: '($3>=1000)&&($1!="nobody"){print $6}' /etc/passwd)
    $Dirs = $Dirs.Split([Environment]::NewLine)

    $FindingMessage = ("Check for file references inside these files if they are local interactive user " +
                       "initialization files.")
    $TempDetails = ""
    $Printed = @{}

    foreach ($Dir in $Dirs) {
        If ([System.IO.Directory]::Exists($Dir)) {
            $Dir = (Resolve-Path $Dir).Path

            $DirSummary = Get-ChildItem -Path $Dir -Hidden -File -Recurse | Where-Object {! $_.PSIsContainer}

            foreach ($File in $DirSummary) {
                $Contents = $(Get-Content $File)
                $Contents = $Contents -replace '\s+', ' '
                $Words = $Contents -split ' '

                foreach ($Word in $Words) {
                    If ([System.IO.File]::Exists($Word)) {
                        If(!($Printed[$Word])) {
                            If(!($Printed[$Dir])) {
                                $TempDetails += ($Dir + ':') | Out-String
                                $Printed[$Dir] = $true
                            }

                            $TempDetails += ($Word + " referenced in " + $File) | Out-String
                            $Printed[$Word] = $true
                        }
                    }
                }
            }

            If ($Printed[$Dir]) {
                $TempDetails += "-----------------------------------------------------------------------" | Out-String
            }
        }
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $TempDetails
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215011 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215011
        STIG ID    : UBTU-16-010790
        Rule ID    : SV-215011r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Local initialization files must not execute world-writable programs.
        DiscussMD5 : 4B9F76A575A401D0FF142AA78A42FF4A
        CheckMD5   : 264D43E5E1AACD9E5C2C6E693A587331
        FixMD5     : E8DA43D1D102622B6D29F7EFB63B73D0
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    # Get list of local init files
    $LocalInitFiles = @() # Empty array

    $Findings = $(sh test.sh)
    $Findings = $Findings.Split([Environment]::NewLine)

    foreach ($Finding in $Findings) {
        $Path = $Finding.Split(' ')[1]

        If ([System.IO.File]::Exists($Path)) {
            $LocalInitFiles += $Path
        }
    }

    # Check against world writable files list
    $Paths = $(sh get-world-writable-files.sh)

    foreach ($Path in $Paths) {
        $Path = $Path.Split(' ')[8]

        foreach ($LocalInitFile in $LocalInitFiles) {
            If ($Path -eq $LocalInitFile) {
                $Status = "Open"
                $FindingMessage += "A local initialization file(s) is world writable: " + $Path | Out-String
            }
        }
    }

    If ($Status -eq "Not_Reviewed") {
        $Status = "NotAFinding"
        $FindingMessage = "No local initialization files are world writable."
    }

    $FindingDetails += $FindingMessage | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215012 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215012
        STIG ID    : UBTU-16-010800
        Rule ID    : SV-215012r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : File systems that contain user home directories must be mounted to prevent files with the setuid and setguid bit set from being executed.
        DiscussMD5 : 8A105788660A1C0A6A4294BA8D0EEC57
        CheckMD5   : 1BE532DD6A4E074B4B05CEF673EB24C0
        FixMD5     : 0CA88ED0F7690B6A9A12B5258E4D33EE
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Dirs = $(awk -F: '($3>=1000)&&($1!="nobody"){print $6}' /etc/passwd)
    $fstab = $(more /etc/fstab)

    foreach ($Dir in $Dirs) {
        If ([System.IO.Directory]::Exists($Dir)) {
            # This path represents a real directory

            If ($Dir -eq '/') {
                # A separate file system has not been created for this home dir
                continue
            }

            If ($fstab -match $Dir) {
                $FindingMessage += ("Check if 'nosuid' option is set for " + $Dir + ".") | Out-String
            }
        }
    }

    If ($FindingMessage) {
        $FindingDetails += $FindingMessage
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        $FindingDetails += $fstab
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "No file system found in '/etc/fstab' refers to the user home directory file system and does not have the 'nosuid' option set."
        $FindingDetails += $FindingMessage | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215013 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215013
        STIG ID    : UBTU-16-010810
        Rule ID    : SV-215013r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : File systems that are used with removable media must be mounted to prevent files with the setuid and setguid bit set from being executed.
        DiscussMD5 : CDE7D26E3CE594E1AB9BAF7A4ADF5240
        CheckMD5   : 1F08FE0F775DD004373E1755AE20AA95
        FixMD5     : F2C2209A06F494FA3404C7E32A66D946
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    # I make an assumption that all removable media will contain 'usb' in the file system name.

    $Lines = $(more /etc/fstab)
    $TempDetails = ""

    foreach ($Line in $Lines) {
        If ($Line -match "^([\s]*)#") {
            # This line is a comment
            continue
        }
        If (!($Line -match "nosuid") -And $Line -match "usb") {
            # 'nosuid' option is not set and file system is removable media (usb)
            $Status = "Open"
            $TempDetails += $Line | Out-String
        }
    }

    If ($Status -eq "Not_Reviewed") {
        $Status = "NotAFinding"
        $FindingMessage = "No file systems were found which refer to removable media and do not have 'nosuid' option set."
        $FindingDetails += $FindingMessage
    }
    Else {
        $FindingMessage = "File system(s) were found which refer to removable media and do not have 'nosuid' option set."
        $FindingDetails += $FindingMessage | Out-String

        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        $FindingDetails += $TempDetails
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215014 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215014
        STIG ID    : UBTU-16-010820
        Rule ID    : SV-215014r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : File systems that are being imported via Network File System (NFS) must be mounted to prevent files with the setuid and setguid bit set from being executed.
        DiscussMD5 : CDE7D26E3CE594E1AB9BAF7A4ADF5240
        CheckMD5   : F1BEB4BE562A8A519FB179692BCD1BF9
        FixMD5     : 5770EDAB0920B78941FB67A5685902E5
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = $(more /etc/fstab)
    $TempDetails = ""

    foreach ($Line in $Lines) {
        If ($Line -match "^([\s]*)#") {
            # This line is a comment
            continue
        }
        If (!($Line -match "nosuid") -And $Line -match "nfs") {
            # 'nosuid' option is not set and file system refers to NFS
            $Status = "Open"
            $TempDetails += $Line | Out-String
        }
    }

    If ($Status -eq "Not_Reviewed") {
        $Status = "NotAFinding"
        $FindingMessage = "No file systems were found which refer to NFS and do not have 'nosuid' option set."
        $FindingDetails += $FindingMessage
    }
    Else {
        $FindingMessage = "File system(s) were found which refer to NFS and do not have 'nosuid' option set."
        $FindingDetails += $FindingMessage | Out-String

        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        $FindingDetails += $TempDetails
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215015 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215015
        STIG ID    : UBTU-16-010830
        Rule ID    : SV-215015r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : File systems that are being imported via Network File System (NFS) must be mounted to prevent binary files from being executed.
        DiscussMD5 : 8F0685C4A4782A720C216BC066974206
        CheckMD5   : A7D82CC415E4FC9535D587D3B95D2E3E
        FixMD5     : 8DAFAE5AF75639BB4E77105E6BC5AF58
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = $(more /etc/fstab)
    $TempDetails = ""

    foreach ($Line in $Lines) {
        If ($Line -match "^([\s]*)#") {
            # This line is a comment
            continue
        }
        If (!($Line -match "noexec") -And $Line -match "nfs") {
            # 'noexec' option is not set and file system refers to NFS
            $Status = "Open"
            $TempDetails += $Line | Out-String
        }
    }

    If ($Status -eq "Not_Reviewed") {
        $Status = "NotAFinding"
        $FindingMessage = "No file systems were found which refer to NFS and do not have 'noexec' option set."
        $FindingDetails += $FindingMessage
    }
    Else {
        $FindingMessage = "File system(s) were found which refer to NFS and do not have 'noexec' option set.
							Check with ISSO."
        $FindingDetails += $FindingMessage | Out-String

        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        $FindingDetails += $TempDetails
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215016 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215016
        STIG ID    : UBTU-16-010900
        Rule ID    : SV-215016r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Kernel core dumps must be disabled unless needed.
        DiscussMD5 : 82F90B2D2B8346DED7240F4AEFD9184C
        CheckMD5   : 274971FA8F027437EE182BD0D8DBA6B3
        FixMD5     : 21EF67DB499260D047F85926442B27BB
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(systemctl is-active kdump.service)

    If ($Finding -eq "inactive") {
        $Status = "NotAFinding"
        $FindingMessage = "Kernel core dumps are disabled."
    }
    Else {
        $Status = "Not_Reviewed"
        $FindingMessage = "The 'kdump' service is active. Ask the System Administrator if the use of the service is required and documented with the Information System Security Officer (ISSO)."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215017 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215017
        STIG ID    : UBTU-16-010910
        Rule ID    : SV-215017r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : A separate file system must be used for user home directories (such as /home or an equivalent).
        DiscussMD5 : 05D0C45DA2A2828180AE5C13C23E9CB5
        CheckMD5   : A6CB1912988C06CF65A1FC57377E12A1
        FixMD5     : E3BEEC1126EE8C5B7952ECF7C44EB9E1
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Dirs = $(awk -F: '($3>=1000)&&($1!="nobody"){print $6}' /etc/passwd)
    $Parents = @()

    $fstab = Get-Content /etc/fstab
    $fstab = $fstab.Split([Environment]::NewLine)

    # Build list of parent directories
    foreach ($Dir in $Dirs) {
        If (!([System.IO.Directory]::Exists($Dir))) {
            # This home directory does not exist
            continue
        }

        $Parent = (Get-Item $Dir).Parent.FullName

        $match_found = $false

        foreach ($CurrParent in $Parents) {
            If ($CurrParent -eq $Parent) {
                $match_found = $true
            }
        }

        If (!($match_found)) {
            $Parents += $Parent
        }
    }

    foreach ($Parent in $Parents) {
        $match_found = $false

        foreach ($Line in $fstab) {
            If ($Parent -match $Line) {
                $match_found = $true
                $FindingDetails += ($Parent + " has an entry in /etc/fstab.") | Out-String
                $FindingDetails += "-----------------------------------------------------------------------" | Out-String
            }
        }

        If (!($match_found)) {
            $Status = "Open"
            $FindingDetails += ($Parent + " does not have an entry in /etc/fstab.") | Out-String
            $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        }
    }

    If ($Status -eq "Not_Reviewed") {
        $Status = "NotAFinding"
        $FindingDetails += "No home directory does not have an entry in /etc/fstab."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215018 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215018
        STIG ID    : UBTU-16-010920
        Rule ID    : SV-215018r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Ubuntu operating system must use a separate file system for /var.
        DiscussMD5 : 05D0C45DA2A2828180AE5C13C23E9CB5
        CheckMD5   : 8DC26B74C1F342A020402D1F7870BA16
        FixMD5     : B42664DFECC08EEC56397615518DF32C
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $fstab = Get-Content /etc/fstab
    $fstab = $fstab.Split([Environment]::NewLine)

    foreach ($Line in $fstab) {
        If ($Line -match '/var') {
            $Status = "NotAFinding"
            $FindingMessage = "'/var' has an entry in /etc/fstab."
        }
    }

    If ($Status -eq "Not_Reviewed") {
        $Status = "Open"
        $FindingMessage = "'/var' does not have an entry in /etc/fstab."
    }

    $FindingDetails += $FindingMessage
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215019 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215019
        STIG ID    : UBTU-16-010930
        Rule ID    : SV-215019r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Ubuntu operating system must use a separate file system for the system audit data path.
        DiscussMD5 : 05D0C45DA2A2828180AE5C13C23E9CB5
        CheckMD5   : F04038DE67B77F78DB23037DAF38C7D4
        FixMD5     : 7FB25FFEE55B3486F573A9FAFB178030
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    # /var/log/audit is assumed to be the system audit data path.
    $fstab = Get-Content /etc/fstab
    $fstab = $fstab.Split([Environment]::NewLine)

    foreach ($Line in $fstab) {
        If ($Line -match '/var/log/audit') {
            $Status = "NotAFinding"
            $FindingMessage = "'/var/log/audit' has an entry in /etc/fstab."
        }
    }

    If ($Status -eq "Not_Reviewed") {
        $Status = "Open"
        $FindingMessage = "'/var/log/audit' does not have an entry in /etc/fstab."
    }

    $FindingDetails += $FindingMessage
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215020 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215020
        STIG ID    : UBTU-16-010940
        Rule ID    : SV-215020r610931_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : The /var/log directory must be group-owned by syslog.
        DiscussMD5 : B4C84599B379F5BD2370FE79E209471E
        CheckMD5   : 016460F5FEB0E44D7F0E8BA78AE7DF3F
        FixMD5     : 23B10A93984B5B58D5313A75AB44452A
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(stat -c "%n %G" /var/log)

    If ($Finding -eq "/var/log syslog") {
        $Status = "NotAFinding"
        $FindingMessage = "The /var/log directory is group owned by syslog."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The /var/log directory is not group owned by syslog."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215021 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215021
        STIG ID    : UBTU-16-010950
        Rule ID    : SV-215021r610931_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : The /var/log directory must be owned by root.
        DiscussMD5 : B4C84599B379F5BD2370FE79E209471E
        CheckMD5   : DAB229F6B8BBC22C072ED5A1C9C01DF5
        FixMD5     : 22C1EFF15C23A014C8CA9C530432662A
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(stat -c "%n %U" /var/log)

    if ($Finding -eq "/var/log root") {
        $Status = "NotAFinding"
        $FindingMessage = "The /var/log directory is owned by root."
    }
    else {
        $Status = "Open"
        $FindingMessage = "The /var/log directory is not owned by root."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215022 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215022
        STIG ID    : UBTU-16-010960
        Rule ID    : SV-215022r610931_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : The /var/log directory must have mode 0770 or less permissive.
        DiscussMD5 : B4C84599B379F5BD2370FE79E209471E
        CheckMD5   : 692FD8161DC2FF805D8AB6A2B875DDE9
        FixMD5     : 3C8E0BCAE48FCF9D48C411AA91F0B9A2
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(stat -c "%n %a" /var/log)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    If (($Finding | awk '{$2=$2};1').split(" ")[1] -le 770) {
        $Status = "NotAFinding"
        $FindingMessage = "The mode of the /var/log directory is '770' or less (less permissive)."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The mode of the /var/log directory is greater than '770' (more permissive)."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215023 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215023
        STIG ID    : UBTU-16-010970
        Rule ID    : SV-215023r610931_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : The /var/log/syslog file must be group-owned by adm.
        DiscussMD5 : B4C84599B379F5BD2370FE79E209471E
        CheckMD5   : 7F628BD1B116955AD2F238A5298EDBF0
        FixMD5     : FD27EB522005AC638AA2C5BD8485D1B9
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(stat -c "%n %G" /var/log/syslog)

    If ($Finding -eq "/var/log/syslog adm") {
        $Status = "NotAFinding"
        $FindingMessage = "The /var/log/syslog file is group-owned by adm."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The /var/log/syslog file is not group-owned by adm."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215024 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215024
        STIG ID    : UBTU-16-010980
        Rule ID    : SV-215024r610931_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : The /var/log/syslog file must be owned by syslog.
        DiscussMD5 : B4C84599B379F5BD2370FE79E209471E
        CheckMD5   : 4EF0CAAF436F4D90D5A7C03A14B41933
        FixMD5     : B5D672357355DCBDE58906A7B336B98A
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(stat -c "%n %U" /var/log/syslog)

    If ($Finding -eq "/var/log/syslog syslog") {
        $Status = "NotAFinding"
        $FindingMessage = "The /var/log/syslog file is owned by syslog."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The /var/log/syslog file is owned by syslog."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215025 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215025
        STIG ID    : UBTU-16-010990
        Rule ID    : SV-215025r610931_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : The /var/log/syslog file must have mode 0640 or less permissive.
        DiscussMD5 : B4C84599B379F5BD2370FE79E209471E
        CheckMD5   : ED3242A552A956D22E0001B3D7AFE58F
        FixMD5     : A29815E7334F0A3F03515FCCA14A1FF5
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(stat -c "%n %a" /var/log/syslog)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    If (($Finding | awk '{$2=$2};1').split(" ")[1] -le 640) {
        $Status = "NotAFinding"
        $FindingMessage = ("The Ubuntu operating system configures the /var/log/syslog file with mode '0640' or less " +
            "(less permissive).")
    }
    Else {
        $Status = "Open"
        $FindingMessage = ("The Ubuntu operating system configures the /var/log/syslog file with mode '0640' or " +
            "greater (more permissive).")
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215026 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215026
        STIG ID    : UBTU-16-011000
        Rule ID    : SV-215026r610931_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : Library files must have mode 0755 or less permissive.
        DiscussMD5 : A58894C112903F603BDEBF1C49B33DC7
        CheckMD5   : 94CD598F3B0B2F667419FA3C64C9A128
        FixMD5     : E6AAF27B8BADEFA530AD5CC26CFCA829
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

find /lib /lib64 /usr/lib -perm /022 -type f -exec stat -c "%n %a" '{}' \;
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    $correct_message_count = 0

    $Finding | ForEach-Object {
        If (($_ | awk '{$2=$2};1').split(" ")[1] -le 755) {
            $correct_message_count++
        }
    }

    If ($correct_message_count -eq $Finding.count) {
        $Status = "NotAFinding"
        $FindingMessage = ("The system-wide shared library files contained in the directories '/lib', '/lib64' and " +
            "'/usr/lib' have mode '0755' or less permissive.")
    }
    Else {
        $Status = "Open"
        $FindingMessage = ("The system-wide shared library files contained in the directories '/lib', '/lib64' and " +
            "'/usr/lib' do not have mode '0755' or less permissive.")
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215027 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215027
        STIG ID    : UBTU-16-011010
        Rule ID    : SV-215027r610931_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : Library files must be owned by root.
        DiscussMD5 : A58894C112903F603BDEBF1C49B33DC7
        CheckMD5   : 574733E1C58EC2CD5A6E102E93527A9B
        FixMD5     : AC0C0B248F8B257515D6369FF78F6CB2
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

find /lib /usr/lib /lib64 ! -user root -type f -exec stat -c "%n %U" '{}' \;
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    If ($Finding) {
        $Status = "Open"
        $FindingMessage = "The system-wide shared library files contained in the directories '/lib', '/lib64' and '/usr/lib' are not owned by root." | Out-String
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The system-wide shared library files contained in the directories '/lib', '/lib64' and '/usr/lib' are owned by root." | Out-String
    }

    $FindingMessage += "The below files (if any) are not owned by root."
    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215028 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215028
        STIG ID    : UBTU-16-011020
        Rule ID    : SV-215028r610931_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : Library files must be group-owned by root.
        DiscussMD5 : A58894C112903F603BDEBF1C49B33DC7
        CheckMD5   : DF3DEA6E5B500B563197206C4919F57C
        FixMD5     : 54E53946A0D5DE673C7851515574E042
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

find /lib /usr/lib /lib64 ! -group root -type f -exec stat -c "%n %G" '{}' \;
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    If ($Finding) {
        $Status = "Open"
        $FindingMessage = "The system-wide library files contained in the directories '/lib', '/lib64' and '/usr/lib' are not group-owned by root." | Out-String
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The system-wide library files contained in the directories '/lib', '/lib64' and '/usr/lib' are group-owned by root." | Out-String
    }

    $FindingMessage += "The below files (if any) are not group-owned by root."
    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215029 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215029
        STIG ID    : UBTU-16-011030
        Rule ID    : SV-215029r610931_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : System commands must have mode 0755 or less permissive.
        DiscussMD5 : A58894C112903F603BDEBF1C49B33DC7
        CheckMD5   : 99ECD64DE3416B8F5A7275AA24E7467B
        FixMD5     : FA74724061397AA250206095F756F13A
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c "%n %a" '{}' \;
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    $correct_message_count = 0

    $Finding | ForEach-Object {
        If (($Finding | awk '{$2=$2};1').split(" ")[1] -le 755) {
            $correct_message_count++
        }
    }

    If ($correct_message_count -eq $Finding.count) {
        $Status = "NotAFinding"
        $FindingMessage = "The system commands contained in the following directories have mode 0755 or less permissive:" | Out-String
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The system commands contained in the following directories do not have mode 0755 or less permissive:" | Out-String
    }

    $FindingMessage += "/bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin" | Out-String
    $FindingMessage += "The below files (if any) do not have mode 0755 or less permissive."
    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215030 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215030
        STIG ID    : UBTU-16-011040
        Rule ID    : SV-215030r610931_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : System commands must be owned by root.
        DiscussMD5 : A58894C112903F603BDEBF1C49B33DC7
        CheckMD5   : 786401716A879F844B7443A0E52BF05A
        FixMD5     : E732B124EA28F4ADA046EC63CA3B1D33
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c "%n %U" '{}' \;
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    If ($Finding) {
        $Status = "Open"
        $FindingMessage = "The system commands directories are not owned by root:" | Out-String
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The system commands directories are owned by root:" | Out-String
    }

    $FindingMessage += "/bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin" | Out-String
    $FindingMessage += "The below directories (if any) are not owned by root."
    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215031 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215031
        STIG ID    : UBTU-16-011050
        Rule ID    : SV-215031r610931_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-OS-000259-GPOS-00100
        Rule Title : System commands must be group-owned by root.
        DiscussMD5 : A58894C112903F603BDEBF1C49B33DC7
        CheckMD5   : 2F7D337911F597D6638E31CE96E0B740
        FixMD5     : D0DE104A238D092483676B5AA8C2D718
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type f -exec stat -c "%n %G" '{}' \;
'@
    $temp_file = $(umask 0077; mktemp /tmp/command.XXXXXX || $false)
    if ($temp_file) {
        Write-Output $command > $temp_file
        $finding = $(sh $temp_file)
        Remove-Item $temp_file
    }
    else {
        $finding = "Unable to create temp file to process check."
    }

    If ($Finding) {
        $Status = "Open"
        $FindingMessage = "The system commands contained in the following directories are not group-owned by root:" | Out-String
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The system commands contained in the following directories are group-owned by root:" | Out-String
    }

    $FindingMessage += "/bin, /sbin, /usr/bin, /usr/sbin, /usr/local/bin, /usr/local/sbin" | Out-String
    $FindingMessage += "The below files (if any) are not group-owned by root." | Out-String
    $FindingDetails += $FindingMessage
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215032 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215032
        STIG ID    : UBTU-16-020000
        Rule ID    : SV-215032r610931_rule
        CCI ID     : CCI-000130, CCI-000131, CCI-000132, CCI-000133, CCI-000134, CCI-000135, CCI-000154, CCI-000158, CCI-000172, CCI-001464, CCI-001487, CCI-001814, CCI-001875, CCI-001876, CCI-001877, CCI-001878, CCI-001880, CCI-001914, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Audit records must contain information to establish what type of events occurred, the source of events, where events occurred, and the outcome of events.
        DiscussMD5 : 1D30C1C799EE0B500C496924EE4535BF
        CheckMD5   : 4F956BA14EF67383DA42D6E6292A5D42
        FixMD5     : 50E0673E503B6510A09015C5FF27C925
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(systemctl is-active auditd.service)

    If ($Finding -eq "active") {
        $Status = "NotAFinding"
        $FindingMessage = "The audit service is configured to produce audit records."
    }
    Else {
        $Status = "Open"
        $Finding_2 = $(dpkg -l | grep auditd)

        If ($Finding_2) {
            $FindingMessage = "The audit service is installed but not enabled."
        }
        Else {
            $FindingMessage = "The audit service is not installed."
        }
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String

    If ($Finding_2) {
        $FindingDetails += $(FormatFinding $Finding_2) | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215033 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215033
        STIG ID    : UBTU-16-020010
        Rule ID    : SV-215033r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The auditd service must be running in the Ubuntu operating system.
        DiscussMD5 : 9B66C924A599BF62F0215043C909FCCC
        CheckMD5   : 365DCFAFF2D8A8951B915D3DE12A95AA
        FixMD5     : FB59B6A42D848BE2914CF90AC8A48C5E
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(service auditd status)

    If ($Finding | grep " active") {
        $Status = "NotAFinding"
        $FindingMessage = "The audit service is active."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The audit service is not active."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215034 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215034
        STIG ID    : UBTU-16-020020
        Rule ID    : SV-215034r610931_rule
        CCI ID     : CCI-001849
        Rule Name  : SRG-OS-000341-GPOS-00132
        Rule Title : The Ubuntu operating system must allocate audit record storage capacity to store at least one weeks worth of audit records, when audit records are not immediately sent to a central audit record storage facility.
        DiscussMD5 : B0480C18EA2C6FE3B2CC413ECC398E4A
        CheckMD5   : 6211F7E660F87628E0CE596CA66B870B
        FixMD5     : 4E4C75EBE0BEF79A31ED9E18B4FB6949
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    # As recommended in check-text, I assume 10G (10 gigabytes) as the space requirement.

    # Find location of audit log file
    $Lines = Get-Content /etc/audit/auditd.conf
    $Lines = $Lines.Split([Environment]::NewLine)
    $auditLogPath = ""

    foreach ($Line in $Lines) {
        If ($Line -match 'log_file([\s]*)=') {
            $field = $Line.Split('=')[1]
            $field = $field.Trim()

            If ([System.IO.File]::Exists($field)) {
                $auditLogPath = $field
            }
        }
    }

    # Get directory of audit log file
    $Dir = (Get-Item $LogPath).Directory.FullName

    # Get size of audit log directory partition
    $Findings = $(df --block-size=1G $Dir)
    $Findings = $Findings.Split([Environment]::NewLine)
    $Available = 0

    foreach ($Finding in $Findings) {
        $Finding = $Finding -replace '\s+', ' '
        $Finding = $Finding.Split(' ')[3]

        If ($Finding -match '^\d+$') {
            $Available = $Finding
        }
    }

    If ($Fraction -ge 10) {
        $Status = "NotAFinding"
        $FindingMessage = ($Available + " is available for the partition for audit records.")
    }
    Else {
        $Status = "Open"
        $FindingMessage = ($Available + "G is available for the partition for audit records." +
            "This is less than the recommended 10G minimum.")
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    foreach ($Line in $Lines) {
        $FindingDetails += $Line | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215035 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215035
        STIG ID    : UBTU-16-020021
        Rule ID    : SV-215035r610931_rule
        CCI ID     : CCI-001855
        Rule Name  : SRG-OS-000343-GPOS-00134
        Rule Title : The Ubuntu operating system must notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity.
        DiscussMD5 : C35E588D648DBEA54FD4365AD7137DF5
        CheckMD5   : 84C4225039842D5074D72FCCB17AACC5
        FixMD5     : 440BDFC166301911EC0DAC83817EF825
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep ^space_left_action /etc/audit/auditd.conf)
    $finding_2 = $(grep "^space_left " /etc/audit/auditd.conf) #differentiate between space_left = and space_left_action
    $finding_3 = $(grep action_mail_acct /etc/audit/auditd.conf)

    if (!($Finding)) {
        $Finding = "Check text did not return results."
    }
    if (!($Finding_2)) {
        $Finding_2 = "Check text did not return results."
    }
    if (!($Finding_3)) {
        $Finding_3 = "Check text did not return results."
    }

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

    if ($finding_2) {
        $FindingMessage += "$finding_2 should be at least 25% of the space free in the allocated audit record storage."
    }
    else {
        $FindingMessage += "The 'space_left' parameter is missing."
    }

    $FindingDetails += $FindingMessage | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215036 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215036
        STIG ID    : UBTU-16-020030
        Rule ID    : SV-215036r610931_rule
        CCI ID     : CCI-001855
        Rule Name  : SRG-OS-000343-GPOS-00134
        Rule Title : The Ubuntu operating system must notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) via email when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity.
        DiscussMD5 : C35E588D648DBEA54FD4365AD7137DF5
        CheckMD5   : B037FB256D939BF6A7FA59889C26A635
        FixMD5     : ED8676C9FE575D58A19AC2E6691B5CED
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $space_left_action = $(grep "^space_left_action" /etc/audit/auditd.conf)
    $space_left = $(grep "^space_left " /etc/audit/auditd.conf) #differentiate between space_left = and space_left_action
    $action_mail_acct = $(grep "action_mail_acct" /etc/audit/auditd.conf)

    If (!($space_left_action)) {
        $Status = "Open"
        $FindingDetails += "Check text did not return results for 'space_left_action'." | Out-String
    }

    If (!($space_left)) {
        $Status = "Open"
        $FindingDetails += "Check text did not return results for 'space_left'." | Out-String
    }

    If (!($action_mail_acct)) {
        $Status = "Open"
        $FindingDetails = "Check text did not return results for 'action_mail_acct'."
    }
    Else {
        $action_mail_acct = $action_mail_acct.Trim()
        $field = $action_mail_acct.Split('=')[1]
        $field = $field.Trim()
    }

    switch -Wildcard ($space_left_action.ToLower()) {
        "*email" {
            $FindingDetails += "'space_left_action' is set to 'email'." | Out-String

            If ($field.contains("root")) {
                $FindingDetails += "The email address defaults to 'root'." | Out-String
            }
            ElseIf ($action_mail_acct) {
                $FindingDetails += ("The email address is '$field'. " +
                    "If the email address of the system administrator is on a remote system, " +
                    "a mail package must be available.") | Out-String
            }
        }
        "*exec" {
            $FindingDetails += ("'space_left_action' is set to 'exec'. " +
                "The system executes a designated script.") | Out-String
        }
        "*syslog" {
            $Status = "NotAFinding"
            $FindingDetails += ("'space_left_action' is set to 'syslog'. " +
                "The system logs the event, but does not generate a notification.") | Out-String
        }
    }

    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $action_mail_acct | Out-String
    $FindingDetails += $space_left_action | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215037 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215037
        STIG ID    : UBTU-16-020040
        Rule ID    : SV-215037r610931_rule
        CCI ID     : CCI-000139
        Rule Name  : SRG-OS-000046-GPOS-00022
        Rule Title : The System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) must be alerted of an audit processing failure event.
        DiscussMD5 : D7DEB737B08C0E22FAE36DD32DB4DED6
        CheckMD5   : 07D305B51631B5A59EC4185AEA1A5DA0
        FixMD5     : 4CDC6258C715E05555985FC744317729
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = $(grep "action_mail_acct" /etc/audit/auditd.conf)
    if (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    if ($finding) {
        if (($finding | awk '{$2=$2};1').StartsWith("action") -and (($finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq "root")) {
            $Status = "NotAFinding"
            $FindingMessage = "The System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) are notified in the event of an audit processing failure."
        }
    }
    else {
        $Status = "Open"
        $FindingMessage = "The System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) are not notified in the event of an audit processing failure."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215038 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215038
        STIG ID    : UBTU-16-020050
        Rule ID    : SV-215038r610931_rule
        CCI ID     : CCI-000140
        Rule Name  : SRG-OS-000047-GPOS-00023
        Rule Title : The System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) must be alerted when the audit storage volume is full.
        DiscussMD5 : 08B0722A02FF82D8EAFBA9733C32915F
        CheckMD5   : 55A7C293E3E58A9E5459727124BAD460
        FixMD5     : AD4C60DFDE370A1A461BC792D82405B7
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -iw log_file /etc/audit/auditd.conf)

    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    $dirname = dirname $Finding.replace(" ", "").split("=")[1]
    $dirname = $dirname + "/*"
    $Finding_2 = $(stat -c "%n %a" $dirname)

    If ($Finding) {
        If ((($Finding_2 | Select-String (($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] + " ")) -split (" "))[1] -le 600) {
            $Status = "NotAFinding"
            $FindingMessage = "The audit log files have a mode of '0600' or less permissive."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The audit log files do not have a mode of '0600' or less permissive."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The audit log path was not found."
    }

    $FindingDetails += $FindingMessage | Out-String

    $FindingDetails += $(FormatFinding $Finding) | Out-String
    $Finding = $Finding_2
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215039 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215039
        STIG ID    : UBTU-16-020060
        Rule ID    : SV-215039r610931_rule
        CCI ID     : CCI-000140
        Rule Name  : SRG-OS-000047-GPOS-00023
        Rule Title : The audit system must take appropriate action when the audit storage volume is full.
        DiscussMD5 : 08B0722A02FF82D8EAFBA9733C32915F
        CheckMD5   : A03C02049C021ABF208050627C5222C0
        FixMD5     : 3B95A6CE8DB7D8E847D6BE7DB51E0D3C
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep disk_full_action /etc/audit/auditd.conf)

    If ($Finding) {
        If (($Finding | awk '{$2=$2};1').StartsWith("disk") -And (($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1].ToLower() -in ("SYSLOG", "SINGLE", "HALT"))) {
            $Status = "NotAFinding"
            $FindingMessage = "The System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) are notified in the event of an audit processing failure."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) are not notified correctly in the event of an audit processing failure."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) are not notified in the event of an audit processing failure."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215040 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215040
        STIG ID    : UBTU-16-020070
        Rule ID    : SV-215040r610931_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-OS-000479-GPOS-00224
        Rule Title : The remote audit system must take appropriate action when audit storage is full.
        DiscussMD5 : 12FFD3C03701BE9B47C761E0CCB72458
        CheckMD5   : B7F32F3306C83BA478523201DE7B00DD
        FixMD5     : 5CA2EA0923228EE61D53C8508CB88086
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep disk_full_action /etc/audit/auditd.conf)

    If ($Finding) {
        If (($Finding | awk '{$2=$2};1').StartsWith("disk") -And (($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1].ToLower() -in ("SYSLOG", "SINGLE", "HALT"))) {
            $Status = "NotAFinding"
            $FindingMessage = "The System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) are notified in the event of an audit processing failure."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) are not notified correctly in the event of an audit processing failure."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) are not notified in the event of an audit processing failure."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215041 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215041
        STIG ID    : UBTU-16-020080
        Rule ID    : SV-215041r610931_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-OS-000479-GPOS-00224
        Rule Title : Off-loading audit records to another system must be authenticated.
        DiscussMD5 : 12FFD3C03701BE9B47C761E0CCB72458
        CheckMD5   : 56500EB7E9925463BF8D81AA8456C6A2
        FixMD5     : 8A22F373CA8783C81144A54EC917C91F
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -iw log_file /etc/audit/auditd.conf)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    $dirname = dirname $Finding.replace(" ", "").split("=")[1]
    $dirname = $dirname + "/*"
    $Finding_2 = $(stat -c "%n %a" $dirname)

    If ($Finding) {
        If ((($Finding_2 | Select-String (($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] + " ")) -split (" "))[1] -le 600) {
            $Status = "NotAFinding"
            $FindingMessage = "The audit log files have a mode of '0600' or less permissive."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The audit log files do not have a mode of '0600' or less permissive."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The audit log path was not found."
    }

    $FindingDetails += $FindingMessage | Out-String

    $FindingDetails += $(FormatFinding $Finding) | Out-String
    $Finding = $Finding_2
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215042 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215042
        STIG ID    : UBTU-16-020090
        Rule ID    : SV-215042r610931_rule
        CCI ID     : CCI-000162, CCI-000163, CCI-000164, CCI-001314
        Rule Name  : SRG-OS-000057-GPOS-00027
        Rule Title : Audit logs must have a mode of 0600 or less permissive to prevent unauthorized read access.
        DiscussMD5 : 2E84671810B0DB1A2411D0A04A5ADA16
        CheckMD5   : F73F7C5001E2FB3DECEF74DF21ED3DBE
        FixMD5     : A2F14EA497C0CB46B3179E4EFAFD555E
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -iw log_file /etc/audit/auditd.conf)

    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    $dirname = dirname $Finding.replace(" ", "").split("=")[1]
    $dirname = $dirname + "/*"
    $Finding_2 = $(stat -c "%n %a" $dirname)

    If ($Finding) {
        If ((($Finding_2 | Select-String (($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] + " ")) -split (" "))[1] -le 600) {
            $Status = "NotAFinding"
            $FindingMessage = "The audit log files have a mode of '0600' or less permissive."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The audit log files do not have a mode of '0600' or less permissive."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The audit log path was not found."
    }

    $FindingDetails += $FindingMessage | Out-String

    $FindingDetails += $(FormatFinding $Finding) | Out-String
    $Finding = $Finding_2
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215043 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215043
        STIG ID    : UBTU-16-020100
        Rule ID    : SV-215043r610931_rule
        CCI ID     : CCI-000162, CCI-000163, CCI-000164
        Rule Name  : SRG-OS-000057-GPOS-00027
        Rule Title : Audit log directories must have a mode of 0750 or less permissive to prevent unauthorized read access.
        DiscussMD5 : 2BA2261D2D7E3F727EEA892B3CB53AEA
        CheckMD5   : 545DDDC2FE1967F6CBB7AE8C380B6164
        FixMD5     : BF7BF8289F7E66BB372ADA9DCA9CC2D8
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -iw log_file /etc/audit/auditd.conf)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    $dirname = dirname $Finding.replace(" ", "").split("=")[1]
    $Finding_2 = $(stat -c "%n %a" $dirname)
    If ($Finding) {
        If ((($Finding_2 | Select-String (($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] + " ")) -split (" "))[1] -le 750) {
            $Status = "NotAFinding"
            $FindingMessage = "The audit log directory has a mode of '0750' or less permissive."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The audit log directory has a mode of '0750' or less permissive."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The audit log path was not found."
    }

    $FindingDetails += $FindingMessage | Out-String

    $FindingDetails += $(FormatFinding $Finding) | Out-String
    $Finding = $Finding_2
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215044 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215044
        STIG ID    : UBTU-16-020110
        Rule ID    : SV-215044r610931_rule
        CCI ID     : CCI-000162, CCI-000163, CCI-000164
        Rule Name  : SRG-OS-000057-GPOS-00027
        Rule Title : Audit logs must be owned by root to prevent unauthorized read access.
        DiscussMD5 : 2BA2261D2D7E3F727EEA892B3CB53AEA
        CheckMD5   : DD72B8135B3DC830BC2CDD06A17A1BD1
        FixMD5     : 76A277D68F74E33D8303B21B321719F4
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -iw log_file /etc/audit/auditd.conf)

    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    $dirname = dirname $Finding.replace(" ", "").split("=")[1]
    $dirname = $dirname + "/*"
    $Finding_2 = $(stat -c "%n %U" $dirname)

    If ($Finding) {
        If ((($Finding_2 | Select-String (($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] + " ")) -split (" "))[1] -eq "root") {
            $Status = "NotAFinding"
            $FindingMessage = "The audit log files are owned by 'root' account."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The audit log files are owned by 'root' account."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The audit log path was not found."
    }

    $FindingDetails += $FindingMessage | Out-String

    $FindingDetails += $(FormatFinding $Finding) | Out-String
    $Finding = $Finding_2
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215045 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215045
        STIG ID    : UBTU-16-020120
        Rule ID    : SV-215045r610931_rule
        CCI ID     : CCI-000162, CCI-000163, CCI-000164, CCI-001314
        Rule Name  : SRG-OS-000057-GPOS-00027
        Rule Title : Audit logs must be group-owned by root to prevent unauthorized read access.
        DiscussMD5 : 2E84671810B0DB1A2411D0A04A5ADA16
        CheckMD5   : 98754BD32204302AFDBC2FE659D81043
        FixMD5     : 6629DC08A0B2467DE7DF576DFABB4BED
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -iw log_file /etc/audit/auditd.conf)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    $dirname = dirname $Finding.replace(" ", "").split("=")[1]
    $dirname = $dirname + "/*"
    $Finding_2 = $(stat -c "%n %G" $dirname)
    If ($Finding) {
        If ((($Finding_2 | Select-String (($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] + " ")) -split (" "))[1] -eq "root") {
            $Status = "NotAFinding"
            $FindingMessage = "The audit log files are owned by 'root' group."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The audit log files are owned by 'root' group."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The audit log path was not found."
    }

    $FindingDetails += $FindingMessage | Out-String

    $FindingDetails += $(FormatFinding $Finding) | Out-String
    $Finding = $Finding_2
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215046 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215046
        STIG ID    : UBTU-16-020130
        Rule ID    : SV-215046r610931_rule
        CCI ID     : CCI-000162, CCI-000163, CCI-000164
        Rule Name  : SRG-OS-000057-GPOS-00027
        Rule Title : Audit log directory must be owned by root to prevent unauthorized read access.
        DiscussMD5 : 2BA2261D2D7E3F727EEA892B3CB53AEA
        CheckMD5   : F46B785321D48AA8497F6E14B7DF0DD8
        FixMD5     : 3EFBC97DBA6FB2724184A41B9162D233
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -iw log_file /etc/audit/auditd.conf)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    $dirname = dirname $Finding.replace(" ", "").split("=")[1]
    $Finding_2 = $(stat -c "%n %U" $dirname)
    If (!($Finding_2)) {
        $Finding_2 = "Check text did not return results."
    }
    If ($Finding) {
        If (($Finding_2.split(" "))[1] -eq "root") {
            $Status = "NotAFinding"
            $FindingMessage = "The audit log directory is owned by 'root' account."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The audit log directory is not owned by 'root' account."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The audit log path was not found."
    }

    $FindingDetails += $FindingMessage | Out-String

    $FindingDetails += $(FormatFinding $Finding) | Out-String
    $Finding = $Finding_2
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215047 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215047
        STIG ID    : UBTU-16-020140
        Rule ID    : SV-215047r610931_rule
        CCI ID     : CCI-000162, CCI-000163, CCI-000164
        Rule Name  : SRG-OS-000057-GPOS-00027
        Rule Title : Audit log directory must be group-owned by root to prevent unauthorized read access.
        DiscussMD5 : 2BA2261D2D7E3F727EEA892B3CB53AEA
        CheckMD5   : 87D61E8A765DA72EB29A09A81F643E58
        FixMD5     : 1AE9D149EE835DADD3C222B6C61576EB
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -iw log_file /etc/audit/auditd.conf)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    $dirname = dirname $Finding.replace(" ", "").split("=")[1]
    $Finding_2 = $(stat -c "%n %G" $dirname)
    If (!($Finding_2)) {
        $Finding_2 = "Check text did not return results."
    }
    If ($Finding) {
        If (($Finding_2.split(" "))[1] -eq "root") {
            $Status = "NotAFinding"
            $FindingMessage = "The audit log directory is owned by 'root' group."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The audit log directory is not owned by 'root' group."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The audit log path was not found."
    }

    $FindingDetails += $FindingMessage | Out-String

    $FindingDetails += $(FormatFinding $Finding) | Out-String
    $Finding = $Finding_2
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215048 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215048
        STIG ID    : UBTU-16-020150
        Rule ID    : SV-215048r610931_rule
        CCI ID     : CCI-000171
        Rule Name  : SRG-OS-000063-GPOS-00032
        Rule Title : The Ubuntu operating system must allow only the Information System Security Manager (ISSM) (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.
        DiscussMD5 : 1488C27E4AB5648A64BC001815954ABD
        CheckMD5   : 72FCF748B27601524E338C175FEE02AF
        FixMD5     : 3C195E03FB6DE5817A3FC880A9217D86
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Files = @('/etc/audit/auditd.conf', '/etc/audit/audit.rule')
    $TempDetails = ""
    $FindingDetails = ""
    $count_invalid = 0

    foreach ($File in $Files) {
        If ([System.IO.File]::Exists($File)) {
            $Perm = $(stat -c '%a' $File)

            If ($Perm -gt 640) {
                $count_invalid += 1
            }

            $TempDetails += ($File + " " + $Perm) | Out-String
        }
        Else {
            $FindingMessage += ("'" + $File + "' does not exist.") | Out-String
        }
    }

    If ($count_invalid -gt 0) {
        $Status = "Open"
        $FindingMessage += ($count_invalid + " file(s) do not have a mode of '0640' or less permissive.")
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage += "Both files have a mode of '0640' or less permissive, or do not exist."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    $FindingDetails += $TempDetails
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215049 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215049
        STIG ID    : UBTU-16-020160
        Rule ID    : SV-215049r610931_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-OS-000206-GPOS-00084
        Rule Title : The audit log files must be owned by root.
        DiscussMD5 : B4C84599B379F5BD2370FE79E209471E
        CheckMD5   : 0EEE028401308D75987356E629D4048E
        FixMD5     : 0F049264EE4473C1DB9DABF1EB925398
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -iw log_file /etc/audit/auditd.conf)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    $dirname = dirname $Finding.replace(" ", "").split("=")[1]
    $dirname = $dirname + "/*"
    $Finding_2 = $(stat -c "%n %G" $dirname)
    If ($Finding) {
        If ((($Finding_2 | Select-String (($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] + " ")) -split (" "))[1] -eq "root") {
            $Status = "NotAFinding"
            $FindingMessage = "The audit log files are owned by 'root' group."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The audit log files are owned by 'root' group."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The audit log path was not found."
    }

    $FindingDetails += $FindingMessage | Out-String

    $FindingDetails += $(FormatFinding $Finding) | Out-String
    $Finding = $Finding_2
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215050 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215050
        STIG ID    : UBTU-16-020180
        Rule ID    : SV-215050r610931_rule
        CCI ID     : CCI-001493, CCI-001494, CCI-001495
        Rule Name  : SRG-OS-000256-GPOS-00097
        Rule Title : Audit tools must have a mode of 0755 or less permissive.
        DiscussMD5 : B8609436B9680C15B83257B8AD951F02
        CheckMD5   : 787D6EE263BF41D504FD8800EC99196B
        FixMD5     : E42EE1311E6170C010570B902ABC6B60
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        $Finding = $(stat -c "%n %a" $_)
        If (!($Finding)) {
            $Finding = "Check text did not return results."
        }
        $FindingDetails += $(FormatFinding $Finding) | Out-String

        If (($Finding | awk '{$2=$2};1').split(" ")[0] -gt 755) {
            $incorrect_message_count++
        }
    }
    If ($incorrect_message_count -eq 0) {
        $Status = "NotAFinding"
        $FindingMessage = "The audit tools are protected from unauthorized access, deletion, or modification."
    }
    Else {
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

Function Get-V215051 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215051
        STIG ID    : UBTU-16-020190
        Rule ID    : SV-215051r610931_rule
        CCI ID     : CCI-001493, CCI-001494, CCI-001495
        Rule Name  : SRG-OS-000256-GPOS-00097
        Rule Title : Audit tools must be owned by root.
        DiscussMD5 : B8609436B9680C15B83257B8AD951F02
        CheckMD5   : F8123AC0E09A79186EA368061D845643
        FixMD5     : DF2721B8C98380FAFD4E4F0D0D3D9D45
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        $Finding = $(stat -c "%n %U" $_)
        $FindingDetails += $(FormatFinding $Finding) | Out-String

        If ($Finding -eq "$_ root") {
            $correct_message_count++
        }
    }
    If ($correct_message_count -eq $audit_tools.Count) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system configures the audit tools to be owned by root to prevent any unauthorized access, deletion, or modification."
    }
    Else {
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

Function Get-V215052 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215052
        STIG ID    : UBTU-16-020200
        Rule ID    : SV-215052r610931_rule
        CCI ID     : CCI-001493, CCI-001494, CCI-001495
        Rule Name  : SRG-OS-000256-GPOS-00097
        Rule Title : Audit tools must be group-owned by root.
        DiscussMD5 : B8609436B9680C15B83257B8AD951F02
        CheckMD5   : B36C72F3E3B3910423F390FE9EE1075E
        FixMD5     : B1C01A2AEB547F45D53B50DC3B40B23A
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        $Finding = $(stat -c "%n %G" $_)
        $FindingDetails += $(FormatFinding $Finding) | Out-String

        If ($Finding -eq "$_ root") {
            $correct_message_count++
        }
    }
    If ($correct_message_count -eq $audit_tools.Count) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system configures the audit tools to be group-owned by root to prevent any unauthorized access, deletion, or modification."
    }
    Else {
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

Function Get-V215053 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215053
        STIG ID    : UBTU-16-020210
        Rule ID    : SV-215053r610931_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-OS-000479-GPOS-00224
        Rule Title : The audit event multiplexor must be configured to off-load audit logs onto a different system or storage media from the system being audited.
        DiscussMD5 : 12FFD3C03701BE9B47C761E0CCB72458
        CheckMD5   : 1DD566EA13FBEF5D410DF6F570E5D151
        FixMD5     : B5D89DA998B894069524275C65E55028
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(dpkg -s audispd-plugins)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    If ($Finding.Contains("not installed")) {
        $Status = "Open"
        $FindingMessage = "Status is 'not installed', verify that another method to off-load audit logs has been implemented."
    }
    Else {
        $Finding = $(grep -i active /etc/audisp/plugins.d/au-remote.conf)

        If ($Finding -eq "active = yes") {
            $status = "NotAFinding"
            $FindingMessage = "The audit logs are off-loaded to a different system or storage media."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "How are the audit logs off-loaded to a different system or storage media?"
        }
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215054 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215054
        STIG ID    : UBTU-16-020220
        Rule ID    : SV-215054r610931_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-OS-000342-GPOS-00133
        Rule Title : The audit records must be off-loaded onto a different system or storage media from the system being audited.
        DiscussMD5 : 12FFD3C03701BE9B47C761E0CCB72458
        CheckMD5   : 0B0492FACB426E3E0687AC08DCCC411B
        FixMD5     : 025D399F44BE21350B7E1726633DC77F
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -i remote_server /etc/audisp/audisp-remote.conf)
    $Finding_2 = RemoveComment $Finding

    If (!($Finding)) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results. `"remote_server`" is not configured."
    }
    elseif (!($Finding_2)) {
        $Status = "Open"
        $FindingMessage = "The line is commented out. `"remote_server`" is not configured.\"
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "`"remote_server`" is configured."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215055 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215055
        STIG ID    : UBTU-16-020300
        Rule ID    : SV-215055r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002132, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : The Ubuntu operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd.
        DiscussMD5 : 11A932273C439A800B7C15F2FCAD6B40
        CheckMD5   : 51DBAABDBF95436DB2CEC06C9A9325C4
        FixMD5     : C40C27204C0C1A4D8660F7FA96A0A33B
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = Get-Content /etc/audit/audit.rules

    If ($null -eq $Lines) {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not generate audit records for all " +
						  "account creations, modifications, disabling, and termination events that " +
						  "affect /etc/passwd."
    }
	Else {
		$Lines = $Lines.Split([Environment]::NewLine)

		$Finding = ""
		$rule = '^-w([\s]+)/etc/passwd([\s]+)-p([\s]+)wa([\s]+)-k([\s]+)identity$'

		foreach ($Line in $Lines) {
			$Line = $Line.Trim()

			If ($Line -match $rule) {
				$Finding = $Line
			}
		}

		If ($Finding -ne "") {
			$Status = "NotAFinding"
			$FindingMessage = "The Ubuntu operating system generates audit records for all " +
							  "account creations, modifications, disabling, and termination events " +
							  "that affect /etc/passwd."
		}
		Else {
			$Status = "Open"
			$FindingMessage = "The Ubuntu operating system does not generate audit records for all " +
							  "account creations, modifications, disabling, and termination events " +
							  "that affect /etc/passwd."
		}
	}

	$FindingDetails += $FindingMessage | Out-String
	$FindingDetails += "-----------------------------------------------------------------------" | Out-String

	If ($Status -eq "Open") {
		$FindingDetails += "Missing:" | Out-String
		$FindingDetails += "-w /etc/passwd -p wa -k identity" | Out-String
	}
	Else {
		$FindingDetails += $Finding | Out-String
	}
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215056 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215056
        STIG ID    : UBTU-16-020310
        Rule ID    : SV-215056r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002132, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : The Ubuntu operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/group.
        DiscussMD5 : 11A932273C439A800B7C15F2FCAD6B40
        CheckMD5   : 58E2FE557A03D1D4BA69FD5793338F71
        FixMD5     : 37FDF4D066E3C079BB2D96140069BBAC
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = Get-Content /etc/audit/audit.rules

    If ($null -eq $Lines) {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not generate audit records for all " +
						  "account creations, modifications, disabling, and termination events that " +
						  "affect /etc/group."
    }
	Else {
		$Lines = $Lines.Split([Environment]::NewLine)

		$Finding = ""
		$rule = '^-w([\s]+)/etc/group([\s]+)-p([\s]+)wa([\s]+)-k([\s]+)identity$'

		foreach ($Line in $Lines) {
			$Line = $Line.Trim()

			If ($Line -match $rule) {
				$Finding = $Line
			}
		}

		If ($Finding -ne "") {
			$Status = "NotAFinding"
			$FindingMessage = "The Ubuntu operating system generates audit records for all account " +
							  "creations, modifications, disabling, and termination events that " +
							  "affect /etc/group."
		}
		Else {
			$Status = "Open"
			$FindingMessage = "The Ubuntu operating system does not generate audit records for all " +
							  "account creations, modifications, disabling, and termination events " +
							  "that affect /etc/group."
		}
	}

	$FindingDetails += $FindingMessage | Out-String
	$FindingDetails += "-----------------------------------------------------------------------" | Out-String

	If ($Status -eq "Open") {
		$FindingDetails += "Missing:" | Out-String
		$FindingDetails += "-w /etc/group -p wa -k identity" | Out-String
	}
	Else {
		$FindingDetails += $Finding | Out-String
	}
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215057 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215057
        STIG ID    : UBTU-16-020320
        Rule ID    : SV-215057r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002132, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : The Ubuntu operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow.
        DiscussMD5 : 11A932273C439A800B7C15F2FCAD6B40
        CheckMD5   : 237E4C3C16B470EDBB468C56A6187FBF
        FixMD5     : 221F7BC91FCA66E543D3EDF3077C54BA
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = Get-Content /etc/audit/audit.rules

    If ($null -eq $Lines) {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not generate audit records for all " +
						  "account creations, modifications, disabling, and termination events that " +
						  "affect /etc/gshadow."
    }
	Else {
		$Lines = $Lines.Split([Environment]::NewLine)

		$Finding = ""
		$Rule = '-w([\s]+)/etc/gshadow([\s]+)-p([\s]+)wa([\s]+)-k([\s]+)identity$'

		foreach ($Line in $Lines) {
			$Line = $Line.Trim()

			If ($Line -match $rule) {
				$Finding = $Line
			}
		}

		If ($Finding -ne "") {
			$Status = "NotAFinding"
			$FindingMessage = "The Ubuntu operating system generates audit records for all account " +
							  "creations, modifications, disabling, and termination events that " +
							  "affect /etc/gshadow."
		}
		Else {
			$Status = "Open"
			$FindingMessage = "The Ubuntu operating system does not generate audit records for all " +
							  "account creations, modifications, disabling, and termination events " +
							  "that affect /etc/gshadow."
		}
	}

	$FindingDetails += $FindingMessage | Out-String
	$FindingDetails += "-----------------------------------------------------------------------" | Out-String

	If ($Status -eq "Open") {
		$FindingDetails += "Missing:" | Out-String
		$FindingDetails += "-w /etc/gshadow -p wa -k identity" | Out-String
	}
	Else {
		$FindingDetails += $Finding | Out-String
	}
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215058 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215058
        STIG ID    : UBTU-16-020330
        Rule ID    : SV-215058r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002132, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : The Ubuntu operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow.
        DiscussMD5 : 11A932273C439A800B7C15F2FCAD6B40
        CheckMD5   : C9C8709F9713AD821E157C88CEEE385D
        FixMD5     : 943FB0D9CA1166031058B796058A8FF0
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = Get-Content /etc/audit/audit.rules

    If ($null -eq $Lines) {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not generate audit records for all " +
						  "account creations, modifications, disabling, and termination events that " +
						  "affect /etc/shadow."
    }
	Else {
		$Lines = $Lines.Split([Environment]::NewLine)

		$Finding = ""
		$Rule = '-w([\s]+)/etc/shadow([\s]+)-p([\s]+)wa([\s]+)-k([\s]+)identity$'

		foreach ($Line in $Lines) {
			$Line = $Line.Trim()

			If ($Line -match $rule) {
				$Finding = $Line
			}
		}

		If ($Finding -ne "") {
			$Status = "NotAFinding"
			$FindingMessage = "The Ubuntu operating system generates audit records for all account " +
							  "creations, modifications, disabling, and termination events that " +
							  "affect /etc/shadow."
		}
		Else {
			$Status = "Open"
			$FindingMessage = "The Ubuntu operating system does not generate audit records for all " +
							  "account creations, modifications, disabling, and termination events " +
							  "that affect /etc/shadow."
		}
	}

	$FindingDetails += $FindingMessage | Out-String
	$FindingDetails += "-----------------------------------------------------------------------" | Out-String

	If ($Status -eq "Open") {
		$FindingDetails += "Missing:" | Out-String
		$FindingDetails += "-w /etc/shadow -p wa -k identity" | Out-String
	}
	Else {
		$FindingDetails += $Finding | Out-String
	}
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215059 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215059
        STIG ID    : UBTU-16-020340
        Rule ID    : SV-215059r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002132, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : The Ubuntu operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/security/opasswd.
        DiscussMD5 : 11A932273C439A800B7C15F2FCAD6B40
        CheckMD5   : 687E06BEC032BE4076606832EBD2961B
        FixMD5     : 2DEB0120D62AA4C27547ED752079D242
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = Get-Content /etc/audit/audit.rules

    If ($null -eq $Lines) {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not generate audit records for all " +
						  "account creations, modifications, disabling, and termination events that " +
						  "affect /etc/security/opasswd."
    }
	Else {
		$Lines = $Lines.Split([Environment]::NewLine)

		$Finding = ""
		$Rule = '-w([\s]+)/etc/security/opasswd([\s]+)-p([\s]+)wa([\s]+)-k([\s]+)identity$'

		foreach ($Line in $Lines) {
			$Line = $Line.Trim()

			If ($Line -match $rule) {
				$Finding = $Line
			}
		}

		If ($Finding -ne "") {
			$Status = "NotAFinding"
			$FindingMessage = "The Ubuntu operating system generates audit records for all account " +
							  "creations, modifications, disabling, and termination events that " +
							  "affect /etc/security/opasswd."
		}
		Else {
			$Status = "Open"
			$FindingMessage = "The Ubuntu operating system does not generate audit records for all " +
							  "account creations, modifications, disabling, and termination events " +
							  "that affect /etc/security/opasswd."
		}
	}

	$FindingDetails += $FindingMessage | Out-String
	$FindingDetails += "-----------------------------------------------------------------------" | Out-String

	If ($Status -eq "Open") {
		$FindingDetails += "Missing:" | Out-String
		$FindingDetails += "-w /etc/security/opasswd -p wa -k identity" | Out-String
	}
	Else {
		$FindingDetails += $Finding | Out-String
	}
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215060 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215060
        STIG ID    : UBTU-16-020350
        Rule ID    : SV-215060r610931_rule
        CCI ID     : CCI-002233, CCI-002234
        Rule Name  : SRG-OS-000326-GPOS-00126
        Rule Title : The audit system must be configured to audit the execution of privileged functions and prevent all software from executing at higher privilege levels than users executing the software.
        DiscussMD5 : 73CA88E5279D16F8E4D953D69661B94D
        CheckMD5   : E494556D23A9D8F51EB8370CA0ADF929
        FixMD5     : D449A4C4A926EF237E5009124E058BBD
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = Get-Content /etc/audit/audit.rules

	$finding_b32_user = ""
	$finding_b64_user = ""
	$finding_b32_group = ""
	$finding_b64_group = ""

    If ($null -eq $Lines) {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not generate an audit record for " +
						  "successful/unsuccessful uses of the 'execve' system call."

		$FindingDetails += $FindingMessage | Out-String
		$FindingDetails += "-----------------------------------------------------------------------" | Out-String
    }
	Else {
		$Lines = $Lines.Split([Environment]::NewLine)

		$TempDetails = ""

		$b32_user = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)execve([\s]+)' +
					'-C([\s]+)uid!=euid([\s]+)-F([\s]+)euid=0([\s]+)-F([\s]+)key=execpriv$'

		$b64_user = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)execve([\s]+)' +
					'-C([\s]+)uid!=euid([\s]+)-F([\s]+)euid=0([\s]+)-F([\s]+)key=execpriv$'

		$b32_group = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)execve([\s]+)' +
					 '-C([\s]+)gid!=egid([\s]+)-F([\s]+)egid=0([\s]+)-F([\s]+)key=execpriv$'

		$b64_group = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)execve([\s]+)' +
					 '-C([\s]+)gid!=egid([\s]+)-F([\s]+)egid=0([\s]+)-F([\s]+)key=execpriv$'

		foreach ($Line in $Lines) {
			$Line = $Line.Trim()

			If ($Line -match $b32_user) {
				$finding_b32_user = $Line
				$TempDetails += $finding_b32_user | Out-String
			}
			ElseIf ($Line -match $b64_user) {
				$finding_b64_user = $Line
				$TempDetails += $finding_b64_user | Out-String
			}
			ElseIf ($Line -match $b32_group) {
				$finding_b32_group = $Line
				$TempDetails += $finding_b32_group | Out-String
			}
			ElseIf ($Line -match $b64_group) {
				$finding_b64_group = $Line
				$TempDetails += $finding_b64_group | Out-String
			}
		}

		If ($finding_b32_user -And $finding_b64_user -And $finding_b32_group -And $finding_b64_group) {
			$Status = "NotAFinding"
			$FindingMessage = "The Ubuntu operating system generates an audit record for " +
							  "successful/unsuccessful uses of the 'execve' system call."
		}
		Else {
			$Status = "Open"
			$FindingMessage = "The Ubuntu operating system does not generate all required audit " +
							  "records when successful/unsuccessful attempts to use the 'execve' " +
							  "command occur."
		}

		$FindingDetails += $FindingMessage | Out-String

		If ($TempDetails -ne "") {
			$FindingDetails += "-----------------------------------------------------------------------" | Out-String
			$FindingDetails += $TempDetails

			If ($Status -eq "Open") {
				$FindingDetails += "---------------------------------------------------------------------" | Out-String
			}
		}
		Else {
			$FindingDetails += "-----------------------------------------------------------------------" | Out-String
		}
	}

	If ($Status -eq "Open") {
		$FindingDetails += "Missing:" | Out-String

		If ($finding_b32_user -eq "") {
			$FindingDetails += "-a always,exit -F arch=b32 -S execve -C uid!=euid -F " +
							   "key=execpriv" | Out-String
		}
		If ($finding_b64_user -eq "") {
			$FindingDetails += "-a always,exit -F arch=b64 -S execve -C uid!=euid -F " +
							   "key=execpriv" | Out-String
		}
		If ($finding_b32_group -eq "") {
			$FindingDetails += "-a always,exit -F arch=b32 -S execve -C gid!=egid -F " +
							   "key=execpriv" | Out-String
		}
		If ($finding_b64_group -eq "") {
			$FindingDetails += "-a always,exit -F arch=b64 -S execve -C gid!=egid -F " +
							   "key=execpriv" | Out-String
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

Function Get-V215061 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215061
        STIG ID    : UBTU-16-020360
        Rule ID    : SV-215061r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the su command must generate an audit record.
        DiscussMD5 : F63204E6E90E19AFE100A735676B0D4F
        CheckMD5   : F16B598BCAF89BB379334959A0440573
        FixMD5     : E09B0820E104D78B216597D08CE33655
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = Get-Content /etc/audit/audit.rules

    If ($null -eq $Lines) {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not generate an audit record for " +
                          "successful/unsuccessful uses of the 'su' command."
    }
	Else {
		$Lines = $Lines.Split([Environment]::NewLine)

		$Finding = ""
        $Rule = '^-a([\s]+)always,exit([\s]+)-F([\s]+)path=/bin/su([\s]+)-F([\s]+)perm=x([\s]+)' +
                '-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)' +
                'privileged-priv_change$'

		foreach ($Line in $Lines) {
			$Line = $Line.Trim()

			If ($Line -match $rule) {
				$Finding = $Line
			}
		}

		If ($Finding -ne "") {
			$Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system generates an audit record for " +
                              "successful/unsuccessful uses of the 'su' command."
		}
		Else {
			$Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record for " +
                              "successful/unsuccessful uses of the 'su' command."
		}
	}

	$FindingDetails += $FindingMessage | Out-String
	$FindingDetails += "-----------------------------------------------------------------------" | Out-String

	If ($Status -eq "Open") {
		$FindingDetails += "Missing:" | Out-String

        $FindingDetails = '-a always,exit -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 ' +
                          '-k privileged-priv_change'
	}
	Else {
		$FindingDetails += $Finding | Out-String
	}
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215062 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215062
        STIG ID    : UBTU-16-020370
        Rule ID    : SV-215062r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the chfn command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : 2AC85D250A0E34A1F17A6286DC42C802
        FixMD5     : 9A44F6CA7B0E26B1C585D99E3E22A525
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = Get-Content /etc/audit/audit.rules

    $FindingDetails += "random text inserted here to test"

    If ($null -eq $Lines) {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not generate an audit record for " +
                          "successful/unsuccessful uses of the 'chfn' command."
    }
	Else {
		$Lines = $Lines.Split([Environment]::NewLine)

		$Finding = ""
        $Rule = '^-a([\s]+)always,exit([\s]+)-F([\s]+)path=/usr/bin/chfn([\s]+)-F([\s]+)perm=x([\s]+)' +
                '-F([\s]+)auid>=500([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)privileged-chfn$'

		foreach ($Line in $Lines) {
			$Line = $Line.Trim()

			If ($Line -match $rule) {
				$Finding = $Line
			}
		}

		If ($Finding -ne "") {
			$Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system generates an audit record for " +
                              "successful/unsuccessful uses of the 'chfn' command."
		}
		Else {
			$Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record for " +
                              "successful/unsuccessful uses of the 'chfn' command."
		}
	}

	$FindingDetails += $FindingMessage | Out-String
	$FindingDetails += "-----------------------------------------------------------------------" | Out-String

	If ($Status -eq "Open") {
		$FindingDetails += "Missing:" | Out-String

        $FindingDetails += '-a always,exit -F path=/usr/bin/chfn -F perm=x -F auid>=1000 ' +
                           '-F auid!=4294967295 -k privileged-chfn'
	}
	Else {
		$FindingDetails += $Finding | Out-String
	}
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215063 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215063
        STIG ID    : UBTU-16-020380
        Rule ID    : SV-215063r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the mount command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : 2ED371A55A24FB6B91C938E017FAC863
        FixMD5     : 203C4DE7A72BBBE63D3FB78F23EAD82F
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = Get-Content /etc/audit/audit.rules

	$finding_b32 = ""
	$finding_b64 = ""
	$finding_Path = ""

    If ($null -eq $Lines) {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not generate an audit record for " +
						  "successful/unsuccessful uses of the 'mount' system call."

		$FindingDetails += $FindingMessage | Out-String
		$FindingDetails += "-----------------------------------------------------------------------" | Out-String
    }
	Else {
		$Lines = $Lines.Split([Environment]::NewLine)
		$TempDetails = ""

        $b32 = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)mount([\s]+)-F([\s]+)' +
               'auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)privileged-mount$'

        $b64 = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)mount([\s]+)-F([\s]+)' +
               'auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)privileged-mount$'

        $Path = '^-a([\s]+)always,exit([\s]+)-F([\s]+)path=/bin/mount([\s]+)-F([\s]+)auid>=1000([\s]+)' +
                '-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)privileged-mount$'

		foreach ($Line in $Lines) {
			$Line = $Line.Trim()

			If ($Line -match $b32) {
				$finding_b32 = $Line
				$TempDetails += $finding_b32 | Out-String
			}
			ElseIf ($Line -match $b64) {
				$finding_b64 = $Line
				$TempDetails += $finding_b64 | Out-String
			}
			ElseIf ($Line -match $Path) {
				$finding_Path = $Line
				$TempDetails += $finding_Path | Out-String
			}
		}

		If ($finding_b32 -And $finding_b64 -And $finding_Path) {
			$Status = "NotAFinding"
			$FindingMessage = "The Ubuntu operating system generates an audit record for " +
							  "successful/unsuccessful uses of the 'mount' system call."
		}
		Else {
			$Status = "Open"
			$FindingMessage = "The Ubuntu operating system does not generate all required audit " +
							  "records when successful/unsuccessful attempts to use the 'mount' " +
							  "system call occur."
		}

		$FindingDetails += $FindingMessage | Out-String

		If ($TempDetails -ne "") {
			$FindingDetails += "-----------------------------------------------------------------------" | Out-String
			$FindingDetails += $TempDetails

			If ($Status -eq "Open") {
				$FindingDetails += "---------------------------------------------------------------------" | Out-String
			}
		}
		Else {
			$FindingDetails += "-----------------------------------------------------------------------" | Out-String
		}
	}

	If ($Status -eq "Open") {
		$FindingDetails += "Missing:" | Out-String

		If ($finding_b32 -eq "") {
		    $FindingDetails += "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 " +
							   "-k privileged-mount" | Out-String
		}
		If ($finding_b64 -eq "") {
		    $FindingDetails += "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 " +
							   "-k privileged-mount" | Out-String
		}
		If ($finding_Path -eq "") {
		    $FindingDetails += "-a always,exit -F path=/bin/mount -F auid>=1000 -F auid!=4294967295 " +
							   "-k privileged-mount" | Out-String
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

Function Get-V215064 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215064
        STIG ID    : UBTU-16-020390
        Rule ID    : SV-215064r610931_rule
        CCI ID     : CCI-000135, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000042-GPOS-00020
        Rule Title : Successful/unsuccessful uses of the umount command must generate an audit record.
        DiscussMD5 : 495657B16F70FEDD13B7488446FBD9B9
        CheckMD5   : 1767C4B345CB56CBD38A894ED4310697
        FixMD5     : C9B876FB141895729716B2742D6A9EF6
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep umount /etc/audit/audit.rules)

    If (!($Finding)) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results. The Ubuntu operating system does not " +
                          "generate an audit record for successful/unsuccessful uses of the umount " +
                          "command."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system generates an audit record for " +
                          "successful/unsuccessful uses of the umount command."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215065 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215065
        STIG ID    : UBTU-16-020400
        Rule ID    : SV-215065r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the ssh-agent command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : 48B7B06260892CA58A11FB4CDC44C1CF
        FixMD5     : BD1EB98FB1D8604A7CC0D1FB4C4E3906
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep ssh-agent /etc/audit/audit.rules)

    If (!($Finding)) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results. The Ubuntu operating system does not " +
                          "generate an audit record for successful/unsuccessful uses of the ssh-agent " +
                          "command."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system generates an audit record for " +
                          "successful/unsuccessful uses of the ssh-agent command."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215066 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215066
        STIG ID    : UBTU-16-020410
        Rule ID    : SV-215066r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the ssh-keysign command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : ED4B421C07F4B7D7A711972537FF3259
        FixMD5     : 634E745E8C70098C7940916AE4BC0C74
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep ssh-keysign /etc/audit/audit.rules)

    If (!($Finding)) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results. The Ubuntu operating system does not " +
                          "generate an audit record for successful/unsuccessful uses of the ssh-keysign" +
                          "command."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system generates an audit record for " +
                          "successful/unsuccessful uses of the ssh-keysign command."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215067 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215067
        STIG ID    : UBTU-16-020450
        Rule ID    : SV-215067r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : The audit system must be configured to audit any usage of the kmod command.
        DiscussMD5 : 419215E99CD3835EF7B0DA8F6DA5C4DF
        CheckMD5   : 9D658732FF1BB73127C6AE3CD87BAAA5
        FixMD5     : 1D3437774359F187292BABCA26469FF3
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep "/bin/kmod" /etc/audit/audit.rules)

    If (!($Finding)) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results. The Ubuntu operating system does not " +
                          "generate an audit record for successful/unsuccessful uses of the module " +
                          "management program kmod."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system generates an audit record for " +
                          "successful/unsuccessful uses of the module management program kmod."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215068 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215068
        STIG ID    : UBTU-16-020460
        Rule ID    : SV-215068r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : The audit system must be configured to audit any usage of the setxattr system call.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : 235EEB7F5BA48870CFA430A4732EEA64
        FixMD5     : 89CFF89290D1AA41E6750CEA25249431
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = Get-Content /etc/audit/audit.rules

    $finding_b32_big = ""
    $finding_b64_big = ""
    $finding_b32_0 = ""
    $finding_b64_0 = ""

    If ($null -eq $Lines) {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not generate an audit record for " +
						  "successful/unsuccessful uses of the 'setxattr' system call."

		$FindingDetails += $FindingMessage | Out-String
		$FindingDetails += "-----------------------------------------------------------------------" | Out-String
    }
	Else {
		$Lines = $Lines.Split([Environment]::NewLine)
		$TempDetails = ""

        $b32_big = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)setxattr([\s]+)' +
                   '-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_mod$'

        $b64_big = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)setxattr([\s]+)' +
                   '-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_mod$'

        $b32_0 = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)setxattr([\s]+)' +
                 '-F([\s]+)auid=0([\s]+)-k([\s]+)perm_mod$'

        $b64_0 = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)setxattr([\s]+)' +
                 '-F([\s]+)auid=0([\s]+)-k([\s]+)perm_mod$'

		foreach ($Line in $Lines) {
			$Line = $Line.Trim()

			If ($Line -match $b32_big) {
				$finding_b32_big = $Line
				$TempDetails += $finding_b32_big | Out-String
			}
			ElseIf ($Line -match $b64_big) {
				$finding_b64_big = $Line
				$TempDetails += $finding_b64_big | Out-String
			}
			ElseIf ($Line -match $b32_0) {
				$finding_b32_0 = $Line
				$TempDetails += $finding_b32_0 | Out-String
			}
			ElseIf ($Line -match $b64_0) {
				$finding_b64_0 = $Line
				$TempDetails += $finding_b64_0 | Out-String
			}
		}

		If ($finding_b32_big -And $finding_b64_big -And $finding_b32_0 -And $finding_b64_0) {
			$Status = "NotAFinding"
			$FindingMessage = "The Ubuntu operating system generates an audit record for " +
							  "successful/unsuccessful uses of the 'setxattr' system call."
		}
		Else {
			$Status = "Open"
			$FindingMessage = "The Ubuntu operating system does not generate all required audit " +
							  "records when successful/unsuccessful attempts to use the 'setxattr' " +
							  "system call occur."
		}

		$FindingDetails += $FindingMessage | Out-String

		If ($TempDetails -ne "") {
			$FindingDetails += "-----------------------------------------------------------------------" | Out-String
			$FindingDetails += $TempDetails

			If ($Status -eq "Open") {
				$FindingDetails += "---------------------------------------------------------------------" | Out-String
			}
		}
		Else {
			$FindingDetails += "-----------------------------------------------------------------------" | Out-String
		}
	}

	If ($Status -eq "Open") {
		$FindingDetails += "Missing:" | Out-String

		If ($finding_b32_big -eq "") {
		    $FindingDetails += "-a always,exit -F arch=b32 -S setxattr -F auid>=1000 -F " +
                               "auid!=4294967295 -k perm_mod" | Out-String
		}
		If ($finding_b64_big -eq "") {
		    $FindingDetails += "-a always,exit -F arch=b64 -S setxattr -F auid>=1000 -F " +
                               "auid!=4294967295 -k perm_mod" | Out-String
		}
		If ($finding_b32_0 -eq "") {
		    $FindingDetails += "-a always,exit -F arch=b32 -S setxattr -F auid=0 -F " +
                               "auid!=4294967295 -k perm_mod" | Out-String
		}
		If ($finding_b64_0 -eq "") {
		    $FindingDetails += "-a always,exit -F arch=b64 -S setxattr -F auid=0 -F " +
                               "auid!=4294967295 -k perm_mod" | Out-String
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

Function Get-V215069 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215069
        STIG ID    : UBTU-16-020470
        Rule ID    : SV-215069r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : The audit system must be configured to audit any usage of the lsetxattr system call.
        DiscussMD5 : BEEE6A197F41E62DB335A63D16A3EABB
        CheckMD5   : 7C18FD488E227CCF07DAA11F881595C4
        FixMD5     : B787553A771F193B712B029C1552C91D
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = Get-Content /etc/audit/audit.rules

    $finding_b32_big = ""
    $finding_b64_big = ""
    $finding_b32_0 = ""
    $finding_b64_0 = ""

    If ($null -eq $Lines) {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not generate an audit record for " +
						  "successful/unsuccessful uses of the 'lsetxattr' system call."

		$FindingDetails += $FindingMessage | Out-String
		$FindingDetails += "-----------------------------------------------------------------------" | Out-String
    }
	Else {
		$Lines = $Lines.Split([Environment]::NewLine)
		$TempDetails = ""

        $b32_big = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)lsetxattr([\s]+)' +
                   '-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_mod$'

        $b64_big = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)lsetxattr([\s]+)' +
                   '-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_mod$'

        $b32_0 = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)lsetxattr([\s]+)' +
                 '-F([\s]+)auid=0([\s]+)-k([\s]+)perm_mod$'

        $b64_0 = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)lsetxattr([\s]+)' +
                 '-F([\s]+)auid=0([\s]+)-k([\s]+)perm_mod$'

		foreach ($Line in $Lines) {
			$Line = $Line.Trim()

			If ($Line -match $b32_big) {
				$finding_b32_big = $Line
				$TempDetails += $finding_b32_big | Out-String
			}
			ElseIf ($Line -match $b64_big) {
				$finding_b64_big = $Line
				$TempDetails += $finding_b64_big | Out-String
			}
			ElseIf ($Line -match $b32_0) {
				$finding_b32_0 = $Line
				$TempDetails += $finding_b32_0 | Out-String
			}
			ElseIf ($Line -match $b64_0) {
				$finding_b64_0 = $Line
				$TempDetails += $finding_b64_0 | Out-String
			}
		}

		If ($finding_b32_big -And $finding_b64_big -And $finding_b32_0 -And $finding_b64_0) {
			$Status = "NotAFinding"
			$FindingMessage = "The Ubuntu operating system generates an audit record for " +
							  "successful/unsuccessful uses of the 'lsetxattr' system call."
		}
		Else {
			$Status = "Open"
			$FindingMessage = "The Ubuntu operating system does not generate all required audit " +
							  "records when successful/unsuccessful attempts to use the 'lsetxattr' " +
							  "system call occur."
		}

		$FindingDetails += $FindingMessage | Out-String

		If ($TempDetails -ne "") {
			$FindingDetails += "-----------------------------------------------------------------------" | Out-String
			$FindingDetails += $TempDetails

			If ($Status -eq "Open") {
				$FindingDetails += "---------------------------------------------------------------------" | Out-String
			}
		}
		Else {
			$FindingDetails += "-----------------------------------------------------------------------" | Out-String
		}
	}

	If ($Status -eq "Open") {
		$FindingDetails += "Missing:" | Out-String

		If ($finding_b32_big -eq "") {
		    $FindingDetails += "-a always,exit -F arch=b32 -S lsetxattr -F auid>=1000 -F " +
                               "auid!=4294967295 -k perm_mod" | Out-String
		}
		If ($finding_b64_big -eq "") {
		    $FindingDetails += "-a always,exit -F arch=b64 -S lsetxattr -F auid>=1000 -F " +
                               "auid!=4294967295 -k perm_mod" | Out-String
		}
		If ($finding_b32_0 -eq "") {
		    $FindingDetails += "-a always,exit -F arch=b32 -S lsetxattr -F auid=0 -F " +
                               "auid!=4294967295 -k perm_mod" | Out-String
		}
		If ($finding_b64_0 -eq "") {
		    $FindingDetails += "-a always,exit -F arch=b64 -S lsetxattr -F auid=0 -F " +
                               "auid!=4294967295 -k perm_mod" | Out-String
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

Function Get-V215070 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215070
        STIG ID    : UBTU-16-020480
        Rule ID    : SV-215070r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : The audit system must be configured to audit any usage of the fsetxattr system call.
        DiscussMD5 : BEEE6A197F41E62DB335A63D16A3EABB
        CheckMD5   : 27F0E81DB62361F54F8AFD019B83AB73
        FixMD5     : CF1AEC63412F19149E6269AFB4093848
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = Get-Content /etc/audit/audit.rules

    $finding_b32_big = ""
    $finding_b64_big = ""
    $finding_b32_0 = ""
    $finding_b64_0 = ""

    If ($null -eq $Lines) {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not generate an audit record for " +
						  "successful/unsuccessful uses of the 'fsetxattr' system call."

		$FindingDetails += $FindingMessage | Out-String
		$FindingDetails += "-----------------------------------------------------------------------" | Out-String
    }
	Else {
		$Lines = $Lines.Split([Environment]::NewLine)
		$TempDetails = ""

        $b32_big = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)fsetxattr([\s]+)' +
                   '-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_mod$'

        $b64_big = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)fsetxattr([\s]+)' +
                   '-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_mod$'

        $b32_0 = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)fsetxattr([\s]+)' +
                 '-F([\s]+)auid=0([\s]+)-k([\s]+)perm_mod$'

        $b64_0 = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)fsetxattr([\s]+)' +
                 '-F([\s]+)auid=0([\s]+)-k([\s]+)perm_mod$'

		foreach ($Line in $Lines) {
			$Line = $Line.Trim()

			If ($Line -match $b32_big) {
				$finding_b32_big = $Line
				$TempDetails += $finding_b32_big | Out-String
			}
			ElseIf ($Line -match $b64_big) {
				$finding_b64_big = $Line
				$TempDetails += $finding_b64_big | Out-String
			}
			ElseIf ($Line -match $b32_0) {
				$finding_b32_0 = $Line
				$TempDetails += $finding_b32_0 | Out-String
			}
			ElseIf ($Line -match $b64_0) {
				$finding_b64_0 = $Line
				$TempDetails += $finding_b64_0 | Out-String
			}
		}

		If ($finding_b32_big -And $finding_b64_big -And $finding_b32_0 -And $finding_b64_0) {
			$Status = "NotAFinding"
			$FindingMessage = "The Ubuntu operating system generates an audit record for " +
							  "successful/unsuccessful uses of the 'fsetxattr' system call."
		}
		Else {
			$Status = "Open"
			$FindingMessage = "The Ubuntu operating system does not generate all required audit " +
							  "records when successful/unsuccessful attempts to use the 'fsetxattr' " +
							  "system call occur."
		}

		$FindingDetails += $FindingMessage | Out-String

		If ($TempDetails -ne "") {
			$FindingDetails += "-----------------------------------------------------------------------" | Out-String
			$FindingDetails += $TempDetails

			If ($Status -eq "Open") {
				$FindingDetails += "---------------------------------------------------------------------" | Out-String
			}
		}
		Else {
			$FindingDetails += "-----------------------------------------------------------------------" | Out-String
		}
	}

	If ($Status -eq "Open") {
		$FindingDetails += "Missing:" | Out-String

		If ($finding_b32_big -eq "") {
		    $FindingDetails += "-a always,exit -F arch=b32 -S fsetxattr -F auid>=1000 -F " +
                               "auid!=4294967295 -k perm_mod" | Out-String
		}
		If ($finding_b64_big -eq "") {
		    $FindingDetails += "-a always,exit -F arch=b64 -S fsetxattr -F auid>=1000 -F " +
                               "auid!=4294967295 -k perm_mod" | Out-String
		}
		If ($finding_b32_0 -eq "") {
		    $FindingDetails += "-a always,exit -F arch=b32 -S fsetxattr -F auid=0 -F " +
                               "auid!=4294967295 -k perm_mod" | Out-String
		}
		If ($finding_b64_0 -eq "") {
		    $FindingDetails += "-a always,exit -F arch=b64 -S fsetxattr -F auid=0 -F " +
                               "auid!=4294967295 -k perm_mod" | Out-String
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

Function Get-V215071 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215071
        STIG ID    : UBTU-16-020490
        Rule ID    : SV-215071r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : The audit system must be configured to audit any usage of the removexattr system call.
        DiscussMD5 : BEEE6A197F41E62DB335A63D16A3EABB
        CheckMD5   : D27A8F96CF3A4B6A8B1F70068C1B4347
        FixMD5     : C348DB2F93B4A9460FA5EF8C9B5E37CA
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = Get-Content /etc/audit/audit.rules

    $finding_b32_big = ""
    $finding_b64_big = ""
    $finding_b32_0 = ""
    $finding_b64_0 = ""

    If ($null -eq $Lines) {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not generate an audit record for " +
						  "successful/unsuccessful uses of the 'removexattr' system call."

		$FindingDetails += $FindingMessage | Out-String
		$FindingDetails += "-----------------------------------------------------------------------" | Out-String
    }
	Else {
		$Lines = $Lines.Split([Environment]::NewLine)
		$TempDetails = ""

        $b32_big = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)removexattr([\s]+)' +
                   '-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_mod$'

        $b64_big = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)removexattr([\s]+)' +
                   '-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_mod$'

        $b32_0 = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)removexattr([\s]+)' +
                 '-F([\s]+)auid=0([\s]+)-k([\s]+)perm_mod$'

        $b64_0 = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)removexattr([\s]+)' +
                 '-F([\s]+)auid=0([\s]+)-k([\s]+)perm_mod$'

		foreach ($Line in $Lines) {
			$Line = $Line.Trim()

			If ($Line -match $b32_big) {
				$finding_b32_big = $Line
				$TempDetails += $finding_b32_big | Out-String
			}
			ElseIf ($Line -match $b64_big) {
				$finding_b64_big = $Line
				$TempDetails += $finding_b64_big | Out-String
			}
			ElseIf ($Line -match $b32_0) {
				$finding_b32_0 = $Line
				$TempDetails += $finding_b32_0 | Out-String
			}
			ElseIf ($Line -match $b64_0) {
				$finding_b64_0 = $Line
				$TempDetails += $finding_b64_0 | Out-String
			}
		}

		If ($finding_b32_big -And $finding_b64_big -And $finding_b32_0 -And $finding_b64_0) {
			$Status = "NotAFinding"
			$FindingMessage = "The Ubuntu operating system generates an audit record for " +
							  "successful/unsuccessful uses of the 'removexattr' system call."
		}
		Else {
			$Status = "Open"
			$FindingMessage = "The Ubuntu operating system does not generate all required audit " +
							  "records when successful/unsuccessful attempts to use the 'removexattr' " +
							  "system call occur."
		}

		$FindingDetails += $FindingMessage | Out-String

		If ($TempDetails -ne "") {
			$FindingDetails += "-----------------------------------------------------------------------" | Out-String
			$FindingDetails += $TempDetails

			If ($Status -eq "Open") {
				$FindingDetails += "---------------------------------------------------------------------" | Out-String
			}
		}
		Else {
			$FindingDetails += "-----------------------------------------------------------------------" | Out-String
		}
	}

	If ($Status -eq "Open") {
		$FindingDetails += "Missing:" | Out-String

		If ($finding_b32_big -eq "") {
		    $FindingDetails += "-a always,exit -F arch=b32 -S removexattr -F auid>=1000 -F " +
                               "auid!=4294967295 -k perm_mod" | Out-String
		}
		If ($finding_b64_big -eq "") {
		    $FindingDetails += "-a always,exit -F arch=b64 -S removexattr -F auid>=1000 -F " +
                               "auid!=4294967295 -k perm_mod" | Out-String
		}
		If ($finding_b32_0 -eq "") {
		    $FindingDetails += "-a always,exit -F arch=b32 -S removexattr -F auid=0 -F " +
                               "auid!=4294967295 -k perm_mod" | Out-String
		}
		If ($finding_b64_0 -eq "") {
		    $FindingDetails += "-a always,exit -F arch=b64 -S removexattr -F auid=0 -F " +
                               "auid!=4294967295 -k perm_mod" | Out-String
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

Function Get-V215072 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215072
        STIG ID    : UBTU-16-020500
        Rule ID    : SV-215072r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : The audit system must be configured to audit any usage of the lremovexattr system call.
        DiscussMD5 : BEEE6A197F41E62DB335A63D16A3EABB
        CheckMD5   : 87B61183EDE17AE3AC279D119B027E30
        FixMD5     : EE290464B583BBCD8055FFF3F761E935
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = Get-Content /etc/audit/audit.rules

    $finding_b32_big = ""
    $finding_b64_big = ""
    $finding_b32_0 = ""
    $finding_b64_0 = ""

    If ($null -eq $Lines) {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not generate an audit record for " +
						  "successful/unsuccessful uses of the 'lremovexattr' system call."

		$FindingDetails += $FindingMessage | Out-String
		$FindingDetails += "-----------------------------------------------------------------------" | Out-String
    }
	Else {
		$Lines = $Lines.Split([Environment]::NewLine)
		$TempDetails = ""

        $b32_big = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)lremovexattr([\s]+)' +
                   '-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_mod$'

        $b64_big = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)lremovexattr([\s]+)' +
                   '-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_mod$'

        $b32_0 = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)lremovexattr([\s]+)' +
                 '-F([\s]+)auid=0([\s]+)-k([\s]+)perm_mod$'

        $b64_0 = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)lremovexattr([\s]+)' +
                 '-F([\s]+)auid=0([\s]+)-k([\s]+)perm_mod$'

		foreach ($Line in $Lines) {
			$Line = $Line.Trim()

			If ($Line -match $b32_big) {
				$finding_b32_big = $Line
				$TempDetails += $finding_b32_big | Out-String
			}
			ElseIf ($Line -match $b64_big) {
				$finding_b64_big = $Line
				$TempDetails += $finding_b64_big | Out-String
			}
			ElseIf ($Line -match $b32_0) {
				$finding_b32_0 = $Line
				$TempDetails += $finding_b32_0 | Out-String
			}
			ElseIf ($Line -match $b64_0) {
				$finding_b64_0 = $Line
				$TempDetails += $finding_b64_0 | Out-String
			}
		}

		If ($finding_b32_big -And $finding_b64_big -And $finding_b32_0 -And $finding_b64_0) {
			$Status = "NotAFinding"
			$FindingMessage = "The Ubuntu operating system generates an audit record for " +
							  "successful/unsuccessful uses of the 'lremovexattr' system call."
		}
		Else {
			$Status = "Open"
			$FindingMessage = "The Ubuntu operating system does not generate all required audit " +
							  "records when successful/unsuccessful attempts to use the 'lremovexattr' " +
							  "system call occur."
		}

		$FindingDetails += $FindingMessage | Out-String

		If ($TempDetails -ne "") {
			$FindingDetails += "-----------------------------------------------------------------------" | Out-String
			$FindingDetails += $TempDetails

			If ($Status -eq "Open") {
				$FindingDetails += "---------------------------------------------------------------------" | Out-String
			}
		}
		Else {
			$FindingDetails += "-----------------------------------------------------------------------" | Out-String
		}
	}

	If ($Status -eq "Open") {
		$FindingDetails += "Missing:" | Out-String

		If ($finding_b32_big -eq "") {
		    $FindingDetails += "-a always,exit -F arch=b32 -S lremovexattr -F auid>=1000 -F " +
                               "auid!=4294967295 -k perm_mod" | Out-String
		}
		If ($finding_b64_big -eq "") {
		    $FindingDetails += "-a always,exit -F arch=b64 -S lremovexattr -F auid>=1000 -F " +
                               "auid!=4294967295 -k perm_mod" | Out-String
		}
		If ($finding_b32_0 -eq "") {
		    $FindingDetails += "-a always,exit -F arch=b32 -S lremovexattr -F auid=0 -F " +
                               "auid!=4294967295 -k perm_mod" | Out-String
		}
		If ($finding_b64_0 -eq "") {
		    $FindingDetails += "-a always,exit -F arch=b64 -S lremovexattr -F auid=0 -F " +
                               "auid!=4294967295 -k perm_mod" | Out-String
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

Function Get-V215073 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215073
        STIG ID    : UBTU-16-020510
        Rule ID    : SV-215073r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : The audit system must be configured to audit any usage of the fremovexattr system call.
        DiscussMD5 : BEEE6A197F41E62DB335A63D16A3EABB
        CheckMD5   : F1809851F8417A9BF3FF7B5B36013B13
        FixMD5     : F4EF99850166435F59E8C844CAA030D9
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = Get-Content /etc/audit/audit.rules

    $finding_b32_big = ""
    $finding_b64_big = ""
    $finding_b32_0 = ""
    $finding_b64_0 = ""

    If ($null -eq $Lines) {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not generate an audit record for " +
						  "successful/unsuccessful uses of the 'fremovexattr' system call."

		$FindingDetails += $FindingMessage | Out-String
		$FindingDetails += "-----------------------------------------------------------------------" | Out-String
    }
	Else {
		$Lines = $Lines.Split([Environment]::NewLine)
		$TempDetails = ""

        $b32_big = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)fremovexattr([\s]+)' +
                   '-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_mod$'

        $b64_big = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)fremovexattr([\s]+)' +
                   '-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_mod$'

        $b32_0 = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)fremovexattr([\s]+)' +
                 '-F([\s]+)auid=0([\s]+)-k([\s]+)perm_mod$'

        $b64_0 = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)fremovexattr([\s]+)' +
                 '-F([\s]+)auid=0([\s]+)-k([\s]+)perm_mod$'

		foreach ($Line in $Lines) {
			$Line = $Line.Trim()

			If ($Line -match $b32_big) {
				$finding_b32_big = $Line
				$TempDetails += $finding_b32_big | Out-String
			}
			ElseIf ($Line -match $b64_big) {
				$finding_b64_big = $Line
				$TempDetails += $finding_b64_big | Out-String
			}
			ElseIf ($Line -match $b32_0) {
				$finding_b32_0 = $Line
				$TempDetails += $finding_b32_0 | Out-String
			}
			ElseIf ($Line -match $b64_0) {
				$finding_b64_0 = $Line
				$TempDetails += $finding_b64_0 | Out-String
			}
		}

		If ($finding_b32_big -And $finding_b64_big -And $finding_b32_0 -And $finding_b64_0) {
			$Status = "NotAFinding"
			$FindingMessage = "The Ubuntu operating system generates an audit record for " +
							  "successful/unsuccessful uses of the 'fremovexattr' system call."
		}
		Else {
			$Status = "Open"
			$FindingMessage = "The Ubuntu operating system does not generate all required audit " +
							  "records when successful/unsuccessful attempts to use the 'fremovexattr' " +
							  "system call occur."
		}

		$FindingDetails += $FindingMessage | Out-String

		If ($TempDetails -ne "") {
			$FindingDetails += "-----------------------------------------------------------------------" | Out-String
			$FindingDetails += $TempDetails

			If ($Status -eq "Open") {
				$FindingDetails += "---------------------------------------------------------------------" | Out-String
			}
		}
		Else {
			$FindingDetails += "-----------------------------------------------------------------------" | Out-String
		}
	}

	If ($Status -eq "Open") {
		$FindingDetails += "Missing:" | Out-String

		If ($finding_b32_big -eq "") {
		    $FindingDetails += "-a always,exit -F arch=b32 -S fremovexattr -F auid>=1000 -F " +
                               "auid!=4294967295 -k perm_mod" | Out-String
		}
		If ($finding_b64_big -eq "") {
		    $FindingDetails += "-a always,exit -F arch=b64 -S fremovexattr -F auid>=1000 -F " +
                               "auid!=4294967295 -k perm_mod" | Out-String
		}
		If ($finding_b32_0 -eq "") {
		    $FindingDetails += "-a always,exit -F arch=b32 -S fremovexattr -F auid=0 -F " +
                               "auid!=4294967295 -k perm_mod" | Out-String
		}
		If ($finding_b64_0 -eq "") {
		    $FindingDetails += "-a always,exit -F arch=b64 -S fremovexattr -F auid=0 -F " +
                               "auid!=4294967295 -k perm_mod" | Out-String
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

Function Get-V215074 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215074
        STIG ID    : UBTU-16-020520
        Rule ID    : SV-215074r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the chown command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : 87C8C4987176C4285C93E3E1F85E3C2D
        FixMD5     : 5A1B709656FF14D622FAF038CB0A64E5
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep chown /etc/audit/audit.rules)

    If (!($Finding)) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results. The Ubuntu operating system does not " +
                          "generate an audit record for successful/unsuccessful uses of the command " +
                          "chown."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system generates an audit record for " +
                          "successful/unsuccessful uses of the command chown."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215075 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215075
        STIG ID    : UBTU-16-020530
        Rule ID    : SV-215075r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the fchown command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : 45DDD1CDD239F3FA4598759C15B494AB
        FixMD5     : 9E266E3CFA256912DAA5975483C34FE8
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep fchown /etc/audit/audit.rules)

    If (!($Finding)) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results. The Ubuntu operating system does not " +
                          "generate an audit record for successful/unsuccessful uses of the command " +
                          "fchown."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system generates an audit record for " +
                          "successful/unsuccessful uses of the command fchown."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215076 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215076
        STIG ID    : UBTU-16-020540
        Rule ID    : SV-215076r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the fchownat command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : 311EB8A4B63E2FB642A63DFD91356F19
        FixMD5     : 9DA1AF7A564A82D60406AACFD8825E82
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -w fchownat /etc/audit/audit.rules)
    $Finding_2 = RemoveComment $Finding

    If (!($Finding)) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the fchownat command."
    }
    elseif (!($Finding_2)) {
        $Status = "Open"
        $FindingMessage = "The line is commented out. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the fchownat command."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system generates an audit record for successful/unsuccessful uses of the fchownat command."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215077 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215077
        STIG ID    : UBTU-16-020550
        Rule ID    : SV-215077r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the lchown command must generate an audit record.
        DiscussMD5 : FB83F06D1EBBA02B6187ACFC387AFABB
        CheckMD5   : 48C9DA5E893D7E4ADB29024BC7FF4B77
        FixMD5     : 1F80CDFE5A87EC3FCA2EE45DE57CF446
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -w lchown /etc/audit/audit.rules)
    $Finding_2 = RemoveComment $Finding

    If (!($Finding)) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the lchown command."
    }
    elseif (!($Finding_2)) {
        $Status = "Open"
        $FindingMessage = "The line is commented out. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the lchown command."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system generates an audit record for successful/unsuccessful uses of the lchown command."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215078 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215078
        STIG ID    : UBTU-16-020560
        Rule ID    : SV-215078r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the chmod command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : 1EE0DBD1562220B5BD76353F910FE539
        FixMD5     : 2380A5BD550C89462F870E6E96460EEE
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -w chmod /etc/audit/audit.rules)

    If (!($Finding)) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the chmod command."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system generates an audit record for successful/unsuccessful uses of the chmod command."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215079 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215079
        STIG ID    : UBTU-16-020570
        Rule ID    : SV-215079r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the fchmod command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : C157CD696031FE0F14B97BCD0F1D1B5B
        FixMD5     : 60E5658AADA9C1F174586C1C930E1E85
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -w fchmod /etc/audit/audit.rules)

    If (!($Finding)) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the fchmod command."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system generates an audit record for successful/unsuccessful uses of the fchmod command."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215080 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215080
        STIG ID    : UBTU-16-020580
        Rule ID    : SV-215080r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the fchmodat command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : 3CCF2A62A1FC1D1C9C9C7CF855380F2D
        FixMD5     : 728C60DFF4044527AC566C05958E2F8D
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -w fchmodat /etc/audit/audit.rules)

    If (!($Finding)) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the fchmodat command."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system generates an audit record for successful/unsuccessful uses of the fchmodat command."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215081 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215081
        STIG ID    : UBTU-16-020590
        Rule ID    : SV-215081r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the open command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : 7EFFADBEE2D0812CFB6AD3B154A0BAB6
        FixMD5     : D1D6BE5A5D1EABD7DA7FD156F3C4664D
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Findings = Get-Content /etc/audit/audit.rules

    If ($null -eq $Findings) {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the 'open' command."
    }
    Else {
        $Findings = $Findings.Split([Environment]::NewLine)

        $finding_b32_eperm = ""
        $finding_b64_eperm = ""
        $finding_b32_eacces = ""
        $finding_b64_eacces = ""

        $TempDetails = ""

        $b32_eperm = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)open([\s]+)-F([\s]+)exit=-EPERM([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_access$'

        $b64_eperm = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)open([\s]+)-F([\s]+)exit=-EPERM([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_access$'

        $b32_eacces = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)open([\s]+)-F([\s]+)exit=-EACCES([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_access$'

        $b64_eacces = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)open([\s]+)-F([\s]+)exit=-EACCES([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_access$'

        foreach ($Finding in $Findings) {
            $Finding = $Finding.Trim()

            If ($Finding -match $b32_eperm) {
                $finding_b32_eperm = $Finding
                $TempDetails += $finding_b32_eperm | Out-String
            }
            ElseIf ($Finding -match $b64_eperm) {
                $finding_b64_eperm = $Finding
                $TempDetails += $finding_b64_eperm | Out-String
            }
            ElseIf ($Finding -match $b32_eacces) {
                $finding_b32_eacces = $Finding
                $TempDetails += $finding_b32_eacces | Out-String
            }
            ElseIf ($Finding -match $b64_eacces) {
                $finding_b64_eacces = $Finding
                $TempDetails += $finding_b64_eacces | Out-String
            }
        }

        If ($finding_b32_eperm -And $finding_b64_eperm -And $finding_b32_eacces -And $finding_b64_eacces) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system generates an audit record for successful/unsuccessful uses of the 'open' command."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the 'open' command."
        }

        $FindingDetails += $FindingMessage | Out-String


        If ($TempDetails -ne "") {
            $FindingDetails += "-----------------------------------------------------------------------" | Out-String
            $FindingDetails += $TempDetails

            If ($Status -eq "Open") {
                $FindingDetails += "-----------------------------------------------------------------------" | Out-String
            }
        }
        Else {
            $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        }

        If ($Status -eq "Open") {
            $FindingDetails += "Missing:" | Out-String

            If ($finding_b32_eperm -eq "") {
                $FindingDetails += "-a always,exit -F arch=b32 -S open -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access" | Out-String
            }
            If ($finding_b64_eperm -eq "") {
                $FindingDetails += "-a always,exit -F arch=b64 -S open -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access" | Out-String
            }
            If ($finding_b32_eacces -eq "") {
                $FindingDetails += "-a always,exit -F arch=b32 -S open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access" | Out-String
            }
            If ($finding_b64_eacces -eq "") {
                $FindingDetails += "-a always,exit -F arch=b64 -S open -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access" | Out-String
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

Function Get-V215082 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215082
        STIG ID    : UBTU-16-020600
        Rule ID    : SV-215082r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the truncate command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : 7FAF7A595C12CF9C1D5094330614B73B
        FixMD5     : B8FA6851E8CFE51BAE7761021E9E6ED4
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Findings = Get-Content /etc/audit/audit.rules

    If ($null -eq $Findings) {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the 'truncate' command."
    }
    Else {
        $Findings = $Findings.Split([Environment]::NewLine)

        $finding_b32_eperm = ""
        $finding_b64_eperm = ""
        $finding_b32_eacces = ""
        $finding_b64_eacces = ""

        $TempDetails = ""

        $b32_eperm = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)truncate([\s]+)-F([\s]+)exit=-EPERM([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_access$'

        $b64_eperm = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)truncate([\s]+)-F([\s]+)exit=-EPERM([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_access$'

        $b32_eacces = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)truncate([\s]+)-F([\s]+)exit=-EACCES([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_access$'

        $b64_eacces = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)truncate([\s]+)-F([\s]+)exit=-EACCES([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_access$'

        foreach ($Finding in $Findings) {
            $Finding = $Finding.Trim()

            If ($Finding -match $b32_eperm) {
                $finding_b32_eperm = $Finding
                $TempDetails += $finding_b32_eperm | Out-String
            }
            ElseIf ($Finding -match $b64_eperm) {
                $finding_b64_eperm = $Finding
                $TempDetails += $finding_b64_eperm | Out-String
            }
            ElseIf ($Finding -match $b32_eacces) {
                $finding_b32_eacces = $Finding
                $TempDetails += $finding_b32_eacces | Out-String
            }
            ElseIf ($Finding -match $b64_eacces) {
                $finding_b64_eacces = $Finding
                $TempDetails += $finding_b64_eacces | Out-String
            }
        }

        If ($finding_b32_eperm -And $finding_b64_eperm -And $finding_b32_eacces -And $finding_b64_eacces) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system generates an audit record for successful/unsuccessful uses of the 'truncate' command."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the 'truncate' command."
        }

        $FindingDetails += $FindingMessage | Out-String

        If ($TempDetails -ne "") {
            $FindingDetails += "-----------------------------------------------------------------------" | Out-String
            $FindingDetails += $TempDetails

            If ($Status -eq "Open") {
                $FindingDetails += "-----------------------------------------------------------------------" | Out-String
            }
        }
        Else {
            $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        }

        If ($Status -eq "Open") {
            $FindingDetails += "Missing:" | Out-String

            If ($finding_b32_eperm -eq "") {
                $FindingDetails += "-a always,exit -F arch=b32 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access" | Out-String
            }
            If ($finding_b64_eperm -eq "") {
                $FindingDetails += "-a always,exit -F arch=b64 -S truncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access" | Out-String
            }
            If ($finding_b32_eacces -eq "") {
                $FindingDetails += "-a always,exit -F arch=b32 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access" | Out-String
            }
            If ($finding_b64_eacces -eq "") {
                $FindingDetails += "-a always,exit -F arch=b64 -S truncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access" | Out-String
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

Function Get-V215083 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215083
        STIG ID    : UBTU-16-020610
        Rule ID    : SV-215083r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the ftruncate command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : C05A63F4FAB5CB74093F8AF1D0E8AB6A
        FixMD5     : 7E4CA125C865181081D3FBBB0AE99739
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Findings = Get-Content /etc/audit/audit.rules

    If ($null -eq $Findings) {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the 'ftruncate' command."
        $FindingDetails += $FindingMessage | Out-String
    }
    Else {
        $Findings = $Findings.Split([Environment]::NewLine)

        $finding_b32_eperm = ""
        $finding_b64_eperm = ""
        $finding_b32_eacces = ""
        $finding_b64_eacces = ""

        $TempDetails = ""

        $b32_eperm = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)ftruncate([\s]+)-F([\s]+)exit=-EPERM([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_access$'

        $b64_eperm = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)ftruncate([\s]+)-F([\s]+)exit=-EPERM([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_access$'

        $b32_eacces = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)ftruncate([\s]+)-F([\s]+)exit=-EACCES([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_access$'

        $b64_eacces = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)ftruncate([\s]+)-F([\s]+)exit=-EACCES([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_access$'

        foreach ($Finding in $Findings) {
            $Finding = $Finding.Trim()

            If ($Finding -match $b32_eperm) {
                $finding_b32_eperm = $Finding
                $TempDetails += $finding_b32_eperm | Out-String
            }
            ElseIf ($Finding -match $b64_eperm) {
                $finding_b64_eperm = $Finding
                $TempDetails += $finding_b64_eperm | Out-String
            }
            ElseIf ($Finding -match $b32_eacces) {
                $finding_b32_eacces = $Finding
                $TempDetails += $finding_b32_eacces | Out-String
            }
            ElseIf ($Finding -match $b64_eacces) {
                $finding_b64_eacces = $Finding
                $TempDetails += $finding_b64_eacces | Out-String
            }
        }

        If ($finding_b32_eperm -And $finding_b64_eperm -And $finding_b32_eacces -And $finding_b64_eacces) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system generates an audit record for successful/unsuccessful uses of the 'ftruncate' command."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the 'ftruncate' command."
        }

        $FindingDetails += $FindingMessage | Out-String

        If ($TempDetails -ne "") {
            $FindingDetails += "-----------------------------------------------------------------------" | Out-String
            $FindingDetails += $TempDetails

            If ($Status -eq "Open") {
                $FindingDetails += "-----------------------------------------------------------------------" | Out-String
            }
        }
        Else {
            $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        }

        If ($Status -eq "Open") {
            $FindingDetails += "Missing:" | Out-String

            If ($finding_b32_eperm -eq "") {
                $FindingDetails += "-a always,exit -F arch=b32 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access" | Out-String
            }
            If ($finding_b64_eperm -eq "") {
                $FindingDetails += "-a always,exit -F arch=b64 -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access" | Out-String
            }
            If ($finding_b32_eacces -eq "") {
                $FindingDetails += "-a always,exit -F arch=b32 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access" | Out-String
            }
            If ($finding_b64_eacces -eq "") {
                $FindingDetails += "-a always,exit -F arch=b64 -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access" | Out-String
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

Function Get-V215084 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215084
        STIG ID    : UBTU-16-020620
        Rule ID    : SV-215084r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the creat command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : CA5F68E277DA59B262E077C0C195AFBC
        FixMD5     : D5D722562A9E0DA6BA6F0B677E4A1F10
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Findings = Get-Content /etc/audit/audit.rules

    If ($null -eq $Findings) {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the 'creat' command."
        $FindingDetails += $FindingMessage | Out-String
    }
    Else {
        $Findings = $Findings.Split([Environment]::NewLine)

        $finding_b32_eperm = ""
        $finding_b64_eperm = ""
        $finding_b32_eacces = ""
        $finding_b64_eacces = ""

        $TempDetails = ""

        $b32_eperm = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)creat([\s]+)-F([\s]+)exit=-EPERM([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_access$'

        $b64_eperm = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)creat([\s]+)-F([\s]+)exit=-EPERM([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_access$'

        $b32_eacces = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)creat([\s]+)-F([\s]+)exit=-EACCES([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_access$'

        $b64_eacces = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)creat([\s]+)-F([\s]+)exit=-EACCES([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_access$'

        foreach ($Finding in $Findings) {
            $Finding = $Finding.Trim()

            If ($Finding -match $b32_eperm) {
                $finding_b32_eperm = $Finding
                $TempDetails += $finding_b32_eperm | Out-String
            }
            ElseIf ($Finding -match $b64_eperm) {
                $finding_b64_eperm = $Finding
                $TempDetails += $finding_b64_eperm | Out-String
            }
            ElseIf ($Finding -match $b32_eacces) {
                $finding_b32_eacces = $Finding
                $TempDetails += $finding_b32_eacces | Out-String
            }
            ElseIf ($Finding -match $b64_eacces) {
                $finding_b64_eacces = $Finding
                $TempDetails += $finding_b64_eacces | Out-String
            }
        }

        If ($finding_b32_eperm -And $finding_b64_eperm -And $finding_b32_eacces -And $finding_b64_eacces) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system generates an audit record for successful/unsuccessful uses of the 'creat' command."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the 'creat' command."
        }

        $FindingDetails += $FindingMessage | Out-String


        If ($TempDetails -ne "") {
            $FindingDetails += "-----------------------------------------------------------------------" | Out-String
            $FindingDetails += $TempDetails

            If ($Status -eq "Open") {
                $FindingDetails += "-----------------------------------------------------------------------" | Out-String
            }
        }
        Else {
            $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        }

        If ($Status -eq "Open") {
            $FindingDetails += "Missing:" | Out-String

            If ($finding_b32_eperm -eq "") {
                $FindingDetails += "-a always,exit -F arch=b32 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access" | Out-String
            }
            If ($finding_b64_eperm -eq "") {
                $FindingDetails += "-a always,exit -F arch=b64 -S creat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access" | Out-String
            }
            If ($finding_b32_eacces -eq "") {
                $FindingDetails += "-a always,exit -F arch=b32 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access" | Out-String
            }
            If ($finding_b64_eacces -eq "") {
                $FindingDetails += "-a always,exit -F arch=b64 -S creat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access" | Out-String
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

Function Get-V215085 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215085
        STIG ID    : UBTU-16-020630
        Rule ID    : SV-215085r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the openat command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : E12960C6C255039FCE60ADC74DA7D25D
        FixMD5     : AD96711B7EF892549CC00DAF69B73964
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Findings = Get-Content /etc/audit/audit.rules

    If ($null -eq $Findings) {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the 'openat' command."
    }
    Else {
        $Findings = $Findings.Split([Environment]::NewLine)

        $finding_b32_eperm = ""
        $finding_b64_eperm = ""
        $finding_b32_eacces = ""
        $finding_b64_eacces = ""

        $TempDetails = ""

        $b32_eperm = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)openat([\s]+)-F([\s]+)exit=-EPERM([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_access$'

        $b64_eperm = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)openat([\s]+)-F([\s]+)exit=-EPERM([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_access$'

        $b32_eacces = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)openat([\s]+)-F([\s]+)exit=-EACCES([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_access$'

        $b64_eacces = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)openat([\s]+)-F([\s]+)exit=-EACCES([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_access$'

        foreach ($Finding in $Findings) {
            $Finding = $Finding.Trim()

            If ($Finding -match $b32_eperm) {
                $finding_b32_eperm = $Finding
                $TempDetails += $finding_b32_eperm | Out-String
            }
            ElseIf ($Finding -match $b64_eperm) {
                $finding_b64_eperm = $Finding
                $TempDetails += $finding_b64_eperm | Out-String
            }
            ElseIf ($Finding -match $b32_eacces) {
                $finding_b32_eacces = $Finding
                $TempDetails += $finding_b32_eacces | Out-String
            }
            ElseIf ($Finding -match $b64_eacces) {
                $finding_b64_eacces = $Finding
                $TempDetails += $finding_b64_eacces | Out-String
            }
        }

        If ($finding_b32_eperm -And $finding_b64_eperm -And $finding_b32_eacces -And $finding_b64_eacces) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system generates an audit record for successful/unsuccessful uses of the 'openat' command."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the 'openat' command."
        }

        $FindingDetails += $FindingMessage | Out-String

        If ($TempDetails -ne "") {
            $FindingDetails += "-----------------------------------------------------------------------" | Out-String
            $FindingDetails += $TempDetails

            If ($Status -eq "Open") {
                $FindingDetails += "-----------------------------------------------------------------------" | Out-String
            }
        }
        Else {
            $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        }

        If ($Status -eq "Open") {
            $FindingDetails += "Missing:" | Out-String

            If ($finding_b32_eperm -eq "") {
                $FindingDetails += "-a always,exit -F arch=b32 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access" | Out-String
            }
            If ($finding_b64_eperm -eq "") {
                $FindingDetails += "-a always,exit -F arch=b64 -S openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access" | Out-String
            }
            If ($finding_b32_eacces -eq "") {
                $FindingDetails += "-a always,exit -F arch=b32 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access" | Out-String
            }
            If ($finding_b64_eacces -eq "") {
                $FindingDetails += "-a always,exit -F arch=b64 -S openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access" | Out-String
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

Function Get-V215086 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215086
        STIG ID    : UBTU-16-020640
        Rule ID    : SV-215086r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the open_by_handle_at command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : 1A475F1549A571822906046F699E5E5D
        FixMD5     : 5CEB388EB640AE65898A031A32BDC980
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Findings = Get-Content /etc/audit/audit.rules

    If ($null -eq $Findings) {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the 'open_by_handle_at' command."
    }
    Else {
        $Findings = $Findings.Split([Environment]::NewLine)

        $finding_b32_eperm = ""
        $finding_b64_eperm = ""
        $finding_b32_eacces = ""
        $finding_b64_eacces = ""

        $TempDetails = ""

        $b32_eperm = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)open_by_handle_at([\s]+)-F([\s]+)exit=-EPERM([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_access$'

        $b64_eperm = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)open_by_handle_at([\s]+)-F([\s]+)exit=-EPERM([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_access$'

        $b32_eacces = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)open_by_handle_at([\s]+)-F([\s]+)exit=-EACCES([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_access$'

        $b64_eacces = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)open_by_handle_at([\s]+)-F([\s]+)exit=-EACCES([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)perm_access$'

        foreach ($Finding in $Findings) {
            $Finding = $Finding.Trim()

            If ($Finding -match $b32_eperm) {
                $finding_b32_eperm = $Finding
                $TempDetails += $finding_b32_eperm | Out-String
            }
            ElseIf ($Finding -match $b64_eperm) {
                $finding_b64_eperm = $Finding
                $TempDetails += $finding_b64_eperm | Out-String
            }
            ElseIf ($Finding -match $b32_eacces) {
                $finding_b32_eacces = $Finding
                $TempDetails += $finding_b32_eacces | Out-String
            }
            ElseIf ($Finding -match $b64_eacces) {
                $finding_b64_eacces = $Finding
                $TempDetails += $finding_b64_eacces | Out-String
            }
        }

        If ($finding_b32_eperm -And $finding_b64_eperm -And $finding_b32_eacces -And $finding_b64_eacces) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system generates an audit record for successful/unsuccessful uses of the 'open_by_handle_at' command."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the 'open_by_handle_at' command."
        }

        $FindingDetails += $FindingMessage | Out-String

        If ($TempDetails -ne "") {
            $FindingDetails += "-----------------------------------------------------------------------" | Out-String
            $FindingDetails += $TempDetails

            If ($Status -eq "Open") {
                $FindingDetails += "-----------------------------------------------------------------------" | Out-String
            }
        }
        Else {
            $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        }

        If ($Status -eq "Open") {
            $FindingDetails += "Missing:" | Out-String

            If ($finding_b32_eperm -eq "") {
                $FindingDetails += "-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access" | Out-String
            }
            If ($finding_b64_eperm -eq "") {
                $FindingDetails += "-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k perm_access" | Out-String
            }
            If ($finding_b32_eacces -eq "") {
                $FindingDetails += "-a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access" | Out-String
            }
            If ($finding_b64_eacces -eq "") {
                $FindingDetails += "-a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k perm_access" | Out-String
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

Function Get-V215087 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215087
        STIG ID    : UBTU-16-020650
        Rule ID    : SV-215087r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the sudo command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : 5BCE5E12143BB85A9B3C2D71AF6C2A81
        FixMD5     : EEA5F391031F87C2089E2FD05B712825
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -w sudo /etc/audit/audit.rules)
    $Finding_2 = RemoveComment $Finding

    If (!($Finding)) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the sudo command."
    }
    elseif (!($Finding_2)) {
        $Status = "Open"
        $FindingMessage = "The line is commented out. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the sudo command."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system generates an audit record for successful/unsuccessful uses of the sudo command."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215089 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215089
        STIG ID    : UBTU-16-020670
        Rule ID    : SV-215089r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the chsh command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : F9196752B158CF440799B5F0DCCC4458
        FixMD5     : E2F739B104E6097F6AA6BEC41062BED2
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = Get-Content /etc/audit/audit.rules

    If ($null -eq $Lines) {
        $Status = "Open"
        $FindingMessage = ("Check text did not return results. The Ubuntu operating system does not generate an audit " +
            "record for successful/unsuccessful uses of the 'chsh' command.")
    }
    Else {
        $Lines = $Lines.Split([Environment]::NewLine)
        $Finding = ""

        $Rule = ('^-a([\s]+)always,exit([\s]+)-F([\s]+)path=/usr/bin/chsh([\s]+)-F([\s]+)perm=x([\s]+)-F([\s]+)auid>=1000' +
            '([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)priv_cmd$')

        foreach ($Line in $Lines) {
            $Line = $Line.Trim()

            If ($Line -match $Rule) {
                $Status = "NotAFinding"
                $Finding = $Line
            }
        }

        If ($Status -eq "NotAFinding") {
            $FindingMessage = ("The Ubuntu operating system generates an audit record for successful/unsuccessful uses " +
                "of the 'chsh' command.")
            $FindingDetails += $FindingMessage | Out-String
            $FindingDetails += "-----------------------------------------------------------------------" | Out-String
            $FindingDetails += $Finding
        }
        Else {
            $Status = "Open"
            $FindingMessage = ("The Ubuntu operating system does not generate an audit record for successful/unsuccessful " +
                "uses of the 'chsh' command.")
            $FindingDetails += $FindingMessage | Out-String
            $FindingDetails += "-----------------------------------------------------------------------" | Out-String
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

Function Get-V215090 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215090
        STIG ID    : UBTU-16-020680
        Rule ID    : SV-215090r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the newgrp command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : 2BCFA7EF905B8564B5F8E5D9640A72EC
        FixMD5     : 73FC48C813D169BC16ED2E25923B43D7
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = Get-Content /etc/audit/audit.rules

    If ($null -eq $Lines) {
        $Status = "Open"
        $FindingMessage = ("Check text did not return results. The Ubuntu operating system does not generate an audit " +
            "record for successful/unsuccessful uses of the 'newgrp' command.")
    }
    Else {
        $Lines = $Lines.Split([Environment]::NewLine)

        $Finding = ""

        $Rule = ('^-a([\s]+)always,exit([\s]+)-F([\s]+)path=/usr/bin/newgrp([\s]+)-F([\s]+)perm=x([\s]+)-F([\s]+)auid>=1000' +
            '([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)priv_cmd$')

        foreach ($Line in $Lines) {
            $Line = $Line.Trim()

            If ($Line -match $Rule) {
                $Status = "NotAFinding"
                $Finding = $Line
            }
        }

        If ($Status -eq "NotAFinding") {
            $FindingMessage = ("The Ubuntu operating system generates an audit record for successful/unsuccessful uses " +
                "of the 'newgrp' command.")
            $FindingDetails += $FindingMessage | Out-String
            $FindingDetails += "-----------------------------------------------------------------------" | Out-String
            $FindingDetails += $Finding
        }
        Else {
            $Status = "Open"
            $FindingMessage = ("The Ubuntu operating system does not generate an audit record for successful/unsuccessful " +
                "uses of the 'newgrp' command.")
            $FindingDetails += $FindingMessage | Out-String
            $FindingDetails += "-----------------------------------------------------------------------" | Out-String
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

Function Get-V215091 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215091
        STIG ID    : UBTU-16-020690
        Rule ID    : SV-215091r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the chcon command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : 401DADB45FE63DF2EF82CCE97DA83ED7
        FixMD5     : 73B49B69E4A1DD8AE17A65199AF1769B
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -w chcon /etc/audit/audit.rules)
    $Finding_2 = RemoveComment $Finding

    If (!($Finding)) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the chcon command."
    }
    elseif (!($Finding_2)) {
        $Status = "Open"
        $FindingMessage = "The line is commented out. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the chcon command."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system generates an audit record for successful/unsuccessful uses of the chcon command."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215092 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215092
        STIG ID    : UBTU-16-020700
        Rule ID    : SV-215092r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the apparmor_parser command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : 253120EEA3104A361109F9A095EDFEEE
        FixMD5     : C3F2EA00880F4287A46B0098C26E38C8
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -w apparmor_parser /etc/audit/audit.rules)
    $Finding_2 = RemoveComment $Finding

    If (!($Finding)) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the apparmor_parser command."
    }
    elseif (!($Finding_2)) {
        $Status = "Open"
        $FindingMessage = "The line is commented out. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the apparmor_parser command."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system generates an audit record for successful/unsuccessful uses of the apparmor_parser command."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215093 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215093
        STIG ID    : UBTU-16-020710
        Rule ID    : SV-215093r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the setfacl command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : FB0F99348F50C472563DB3A4C3615C36
        FixMD5     : B76C82E9F5F6C4F03B32AD716D1F2C36
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -w setfacl /etc/audit/audit.rules)
    $Finding_2 = RemoveComment $Finding

    If (!($Finding)) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the setfacl command."
    }
    elseif (!($Finding_2)) {
        $Status = "Open"
        $FindingMessage = "The line is commented out. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the setfacl command."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system generates an audit record for successful/unsuccessful uses of the setfacl command."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215094 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215094
        STIG ID    : UBTU-16-020720
        Rule ID    : SV-215094r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the chacl command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : 9D6B7CDD89E1711D13BB4A69C5340D75
        FixMD5     : DD8E084CA3283BE8FF3472721E8DF6DE
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -w chacl /etc/audit/audit.rules)
    $Finding_2 = RemoveComment $Finding

    If (!($Finding)) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the chacl command."
    }
    elseif (!($Finding_2)) {
        $Status = "Open"
        $FindingMessage = "The line is commented out. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the chacl command."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system generates an audit record for successful/unsuccessful uses of the chacl command."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215095 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215095
        STIG ID    : UBTU-16-020730
        Rule ID    : SV-215095r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful modifications to the tallylog file must generate an audit record.
        DiscussMD5 : 899D5F75AB62251118EC95A3BD56E089
        CheckMD5   : BDA0B2CBCE3F46034BADF1F691DA7DAB
        FixMD5     : 64E4F3EB071D9009BD93E93BB5DC307C
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -w tallylog /etc/audit/audit.rules)
    $Finding_2 = RemoveComment $Finding

    If (!($Finding)) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the tallylog command."
    }
    elseif (!($Finding_2)) {
        $Status = "Open"
        $FindingMessage = "The line is commented out. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the tallylog command."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system generates an audit record for successful/unsuccessful uses of the tallylog command."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215096 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215096
        STIG ID    : UBTU-16-020740
        Rule ID    : SV-215096r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful modifications to the faillog file must generate an audit record.
        DiscussMD5 : 899D5F75AB62251118EC95A3BD56E089
        CheckMD5   : A0C2E9462C2BC2EF55D132D50A372604
        FixMD5     : 8E3081CCD7F13B8DE0E80842EAC0339F
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -w faillog /etc/audit/audit.rules)
    $Finding_2 = RemoveComment $Finding

    If (!($Finding)) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the faillog command."
    }
    elseif (!($Finding_2)) {
        $Status = "Open"
        $FindingMessage = "The line is commented out. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the faillog command."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system generates an audit record for successful/unsuccessful uses of the faillog command."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215097 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215097
        STIG ID    : UBTU-16-020750
        Rule ID    : SV-215097r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful modifications to the lastlog file must generate an audit record.
        DiscussMD5 : 899D5F75AB62251118EC95A3BD56E089
        CheckMD5   : 85378877F8C6A84A32626F46DBBF1C1B
        FixMD5     : 76D2143C2F701E1B076058280631CE8A
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -w lastlog /etc/audit/audit.rules)
    $Finding_2 = RemoveComment $Finding

    If (!($Finding)) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the lastlog command."
    }
    elseif (!($Finding_2)) {
        $Status = "Open"
        $FindingMessage = "The line is commented out. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the lastlog command."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system generates an audit record for successful/unsuccessful uses of the lastlog command."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215098 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215098
        STIG ID    : UBTU-16-020760
        Rule ID    : SV-215098r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the passwd command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : E03B545583035289D9493DAD2C2EA576
        FixMD5     : 3C75B4F9F4F9AE727025F333647C4EAA
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -w passwd /etc/audit/audit.rules)
    $Finding_2 = RemoveComment $Finding

    If (!($Finding)) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the passwd command."
    }
    elseif (!($Finding_2)) {
        $Status = "Open"
        $FindingMessage = "The line is commented out. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the passwd command."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system generates an audit record for successful/unsuccessful uses of the passwd command."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215099 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215099
        STIG ID    : UBTU-16-020770
        Rule ID    : SV-215099r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the unix_update command must generate an audit record.
        DiscussMD5 : B366793B9D5565887227EAACC365C7E7
        CheckMD5   : CDDEE955CAC817D966B69326B159D6C8
        FixMD5     : 6192B93825E947BCE034F486AE7021CA
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -w unix_update /etc/audit/audit.rules)
    $Finding_2 = RemoveComment $Finding

    If (!($Finding)) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the unix_update command."
    }
    elseif (!($Finding_2)) {
        $Status = "Open"
        $FindingMessage = "The line is commented out. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the unix_update command."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system generates an audit record for successful/unsuccessful uses of the unix_update command."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215100 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215100
        STIG ID    : UBTU-16-020780
        Rule ID    : SV-215100r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the gpasswd command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : D035F4F1E9680E10B9BAA210DEF32A85
        FixMD5     : DFC4A2C7FB510D2DDD77ED1D628A78EC
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -w gpasswd /etc/audit/audit.rules)
    $Finding_2 = RemoveComment $Finding

    If (!($Finding)) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the gpasswd command."
    }
    elseif (!($Finding_2)) {
        $Status = "Open"
        $FindingMessage = "The line is commented out. The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the gpasswd command."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system generates an audit record for successful/unsuccessful uses of the gpasswd command."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215101 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215101
        STIG ID    : UBTU-16-020790
        Rule ID    : SV-215101r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the chage command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : 96D2617E37306EA537658541930F353C
        FixMD5     : 40B37CBAD6E557D9F24A02B7E77295C8
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -w chage /etc/audit/audit.rules)

    If (!($Finding)) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results. The Ubuntu operating system does not " +
                          "generate an audit record for successful/unsuccessful uses of the " +
                          "chage command."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system generates audit records for " +
                          "successful/unsuccessful uses of the chage command."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215102 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215102
        STIG ID    : UBTU-16-020800
        Rule ID    : SV-215102r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the usermod command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : C203196D51D2090E9AA121D0F315FA1A
        FixMD5     : 20BB265CDF9FE742D61A31177DDD0C17
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -w usermod /etc/audit/audit.rules)

    If (!($Finding)) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results. The Ubuntu operating system does not " +
                          "generate an audit record for successful/unsuccessful uses of the " +
                          "usermod command."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system generates audit records for " +
                          "successful/unsuccessful uses of the usermod command."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215103 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215103
        STIG ID    : UBTU-16-020810
        Rule ID    : SV-215103r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the crontab command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : C10CE727CBE69E983F4310E83899C8EA
        FixMD5     : 825369E130CF9B2C0960F1C32DF4935F
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -w crontab /etc/audit/audit.rules)

    If (!($Finding)) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results. The Ubuntu operating system does not " +
                          "generate an audit record for successful/unsuccessful uses of the " +
                          "crontab command."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system generates audit records for " +
                          "successful/unsuccessful uses of the crontab command."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215104 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215104
        STIG ID    : UBTU-16-020820
        Rule ID    : SV-215104r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the pam_timestamp_check command must generate an audit record.
        DiscussMD5 : 5BB81017B94724C97F2DAF34D0FC0036
        CheckMD5   : DBC34745FDFD7F6EA830C6B52DDCDD9C
        FixMD5     : 2686F8B33A2B1D0448E8A154895E6134
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -w pam_timestamp_check /etc/audit/audit.rules)

    If (!($Finding)) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results. The Ubuntu operating system does not " +
                          "generate an audit record for successful/unsuccessful uses of the " +
                          "pam_timestamp_check command."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system generates audit records for " +
                          "successful/unsuccessful uses of the pam_timestamp_check command."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215105 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215105
        STIG ID    : UBTU-16-020830
        Rule ID    : SV-215105r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the init_module command must generate an audit record.
        DiscussMD5 : D1398E318F80B0A14DF11C1080AF353D
        CheckMD5   : 9CB3CBC1223184A294C45F6CA285C0DA
        FixMD5     : 49916E2F9DF4CE698C0304D5AD6342F6
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = Get-Content /etc/audit/audit.rules

    If ($null -eq $Lines) {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the 'init_module' command."
        $FindingDetails += $FindingMessage
    }
    Else {
        $Lines = $Lines.Split([Environment]::NewLine)

        $finding_b32 = ""
        $finding_b64 = ""

        $TempDetails = ""

        $b32 = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)init_module([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)module_chng$'

        $b64 = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)init_module([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)module_chng$'

        foreach ($Line in $Lines) {
            $Line = $Line.Trim()

            If ($Line -match $b32) {
                $finding_b32 = $Line
                $TempDetails += $finding_b32 | Out-String
            }
            ElseIf ($Line -match $b64) {
                $finding_b64 = $Line
                $TempDetails += $finding_b64 | Out-String
            }
        }

        If ($finding_b32 -And $finding_b64) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system generates an audit record for successful/unsuccessful uses of the 'init_module' command."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the 'init_module' command."
        }

        $FindingDetails += $FindingMessage | Out-String
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String

        If ($TempDetails -ne "") {
            $FindingDetails += $TempDetails

            If ($Status -eq "Open") {
                $FindingDetails += "-----------------------------------------------------------------------" | Out-String
            }
        }

        If ($Status -eq "Open") {
            $FindingDetails += "Missing:" | Out-String

            If ($finding_b32 -eq "") {
                $FindingDetails += "-a always,exit -F arch=b32 -S init_module -F auid>=1000 -F auid!=4294967295 -k module_chng" | Out-String
            }
            If ($finding_b64 -eq "") {
                $FindingDetails += "-a always,exit -F arch=b64 -S init_module -F auid>=1000 -F auid!=4294967295 -k module_chng" | Out-String
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

Function Get-V215106 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215106
        STIG ID    : UBTU-16-020840
        Rule ID    : SV-215106r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the finit_module command must generate an audit record.
        DiscussMD5 : D1398E318F80B0A14DF11C1080AF353D
        CheckMD5   : 3F172D1A7930BC7D0309B81D80D7652A
        FixMD5     : 0208BB41E7786488971D2B81C8921202
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = Get-Content /etc/audit/audit.rules

    If ($null -eq $Lines) {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the 'finit_module' command."
        $FindingDetails += $FindingMessage
    }
    Else {
        $Lines = $Lines.Split([Environment]::NewLine)

        $finding_b32 = ""
        $finding_b64 = ""

        $TempDetails = ""

        $b32 = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)finit_module([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)module_chng$'

        $b64 = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)finit_module([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)module_chng$'

        foreach ($Line in $Lines) {
            $Line = $Line.Trim()

            If ($Line -match $b32) {
                $finding_b32 = $Line
                $TempDetails += $finding_b32 | Out-String
            }
            ElseIf ($Line -match $b64) {
                $finding_b64 = $Line
                $TempDetails += $finding_b64 | Out-String
            }
        }

        If ($finding_b32 -And $finding_b64) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system generates an audit record for successful/unsuccessful uses of the 'finit_module' command."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the 'finit_module' command."
        }

        $FindingDetails += $FindingMessage | Out-String
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String

        If ($TempDetails -ne "") {
            $FindingDetails += $TempDetails

            If ($Status -eq "Open") {
                $FindingDetails += "-----------------------------------------------------------------------" | Out-String
            }
        }

        If ($Status -eq "Open") {
            $FindingDetails += "Missing:" | Out-String

            If ($finding_b32 -eq "") {
                $FindingDetails += "-a always,exit -F arch=b32 -S finit_module -F auid>=1000 -F auid!=4294967295 -k module_chng" | Out-String
            }
            If ($finding_b64 -eq "") {
                $FindingDetails += "-a always,exit -F arch=b64 -S finit_module -F auid>=1000 -F auid!=4294967295 -k module_chng" | Out-String
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

Function Get-V215107 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215107
        STIG ID    : UBTU-16-020850
        Rule ID    : SV-215107r610931_rule
        CCI ID     : CCI-000130, CCI-000135, CCI-000169, CCI-000172, CCI-002884
        Rule Name  : SRG-OS-000037-GPOS-00015
        Rule Title : Successful/unsuccessful uses of the delete_module command must generate an audit record.
        DiscussMD5 : D1398E318F80B0A14DF11C1080AF353D
        CheckMD5   : F8E3497D6FF14ADB03C621E28E6488A3
        FixMD5     : 59AE3553A641C04A613005C5EF7400D9
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = Get-Content /etc/audit/audit.rules

    If ($null -eq $Lines) {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the 'delete_module' command."
        $FindingDetails += $FindingMessage
    }
    Else {
        $Lines = $Lines.Split([Environment]::NewLine)

        $finding_b32 = ""
        $finding_b64 = ""

        $TempDetails = ""

        $b32 = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b32([\s]+)-S([\s]+)delete_module([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)module_chng$'

        $b64 = '^-a([\s]+)always,exit([\s]+)-F([\s]+)arch=b64([\s]+)-S([\s]+)delete_module([\s]+)-F([\s]+)auid>=1000([\s]+)-F([\s]+)auid!=4294967295([\s]+)-k([\s]+)module_chng$'

        foreach ($Line in $Lines) {
            $Line = $Line.Trim()

            If ($Line -match $b32) {
                $finding_b32 = $Line
                $TempDetails += $finding_b32 | Out-String
            }
            ElseIf ($Line -match $b64) {
                $finding_b64 = $Line
                $TempDetails += $finding_b64 | Out-String
            }
        }

        If ($finding_b32 -And $finding_b64) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system generates an audit record for successful/unsuccessful uses of the 'delete_module' command."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system does not generate an audit record for successful/unsuccessful uses of the 'delete_module' command."
        }

        $FindingDetails += $FindingMessage | Out-String
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String

        If ($TempDetails -ne "") {
            $FindingDetails += $TempDetails

            If ($Status -eq "Open") {
                $FindingDetails += "-----------------------------------------------------------------------" | Out-String
            }
        }

        If ($Status -eq "Open") {
            $FindingDetails += "Missing:" | Out-String

            If ($finding_b32 -eq "") {
                $FindingDetails += "-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=4294967295 -k module_chng" | Out-String
            }
            If ($finding_b64 -eq "") {
                $FindingDetails += "-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=4294967295 -k module_chng" | Out-String
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

Function Get-V215108 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215108
        STIG ID    : UBTU-16-030000
        Rule ID    : SV-215108r610931_rule
        CCI ID     : CCI-000197, CCI-000381
        Rule Name  : SRG-OS-000074-GPOS-00042
        Rule Title : The telnetd package must not be installed.
        DiscussMD5 : 626E5A2A2B0EA24B22B31C2A2A76BF3C
        CheckMD5   : D2223B98558D39C0A9638976263D27C1
        FixMD5     : B6A382872F3A47044F2F910DB853771D
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Findings = $(dpkg -l | awk -F ' ' '{print $2}')
    $TempDetails = ""

    foreach ($Finding in $Findings) {
        If ($Finding -match 'telnetd') {
            $Status = "Open"
            $FindingMessage = "The telnetd package is installed."
            $TempDetails += $Finding | Out-String
        }
    }

    If ($Status -eq "Not_Reviewed") {
        $Status = "NotAFinding"
        $FindingMessage = "The telnetd package is not installed."
    }

    $FindingDetails += $FindingMessage | Out-String

    If ($TempDetails) {
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        $FindingDetails += $TempDetails | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215109 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215109
        STIG ID    : UBTU-16-030010
        Rule ID    : SV-215109r610931_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-OS-000095-GPOS-00049
        Rule Title : The Network Information Service (NIS) package must not be installed.
        DiscussMD5 : 1ABD02B468296E9A5D93110E3E3D86D2
        CheckMD5   : 46F18356656C971CCA34F019F2794F78
        FixMD5     : 477371906F442E184B03CABEBD595B0C
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Findings = $(dpkg -l | awk -F ' ' '{print $2}')
    $TempDetails = ""

    foreach ($Finding in $Findings) {
        If ($Finding -match '^nis') {
            $Status = "Open"
            $FindingMessage = "The NIS package is installed."
            $TempDetails += $Finding | Out-String
        }
    }

    If ($Status -eq "Not_Reviewed") {
        $Status = "NotAFinding"
        $FindingMessage = "The NIS package is not installed."
    }

    $FindingDetails += $FindingMessage | Out-String

    If ($TempDetails) {
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        $FindingDetails += $TempDetails | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215110 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215110
        STIG ID    : UBTU-16-030020
        Rule ID    : SV-215110r610931_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-OS-000095-GPOS-00049
        Rule Title : The rsh-server package must not be installed.
        DiscussMD5 : 1E218B795BD39246F8BE9FDC99C5C11F
        CheckMD5   : C5291D17D595BD4B8EB0271CE6C47DC3
        FixMD5     : F2C78387A7AD2337850D688C27CF373E
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Findings = $(dpkg -l | awk -F ' ' '{print $2}')
    $TempDetails = ""

    foreach ($Finding in $Findings) {
        If ($Finding -match 'rsh-server') {
            $Status = "Open"
            $FindingMessage = "The rsh-server package is installed."
            $TempDetails += $Finding | Out-String
        }
    }

    If ($Status -eq "Not_Reviewed") {
        $Status = "NotAFinding"
        $FindingMessage = "The rsh-server package is not installed."
    }

    $FindingDetails += $FindingMessage | Out-String

    If ($TempDetails) {
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        $FindingDetails += $TempDetails | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215111 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215111
        STIG ID    : UBTU-16-030030
        Rule ID    : SV-215111r610931_rule
        CCI ID     : CCI-002314
        Rule Name  : SRG-OS-000297-GPOS-00115
        Rule Title : An application firewall must be installed.
        DiscussMD5 : E06B6D5CC97280CD4742719B5351D12B
        CheckMD5   : ABF70741BDB65F4995C9D98A7EDCF1DD
        FixMD5     : E2E93EF633FF37A9372F68062567AA38
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Findings = $(dpkg -l | awk -F ' ' '{print $2}')
    $TempDetails = ""

    foreach ($Finding in $Findings) {
        If ($Finding -match 'ufw') {
            $Status = "NotAFinding"
            $FindingMessage = "The ufw package is installed."
            $TempDetails += $Finding | Out-String
        }
    }

    If ($Status -eq "Not_Reviewed") {
        $FindingMessage = "The ufw package is not installed."
    }

    $FindingDetails += $FindingMessage | Out-String

    If ($TempDetails) {
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        $FindingDetails += $TempDetails | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215112 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215112
        STIG ID    : UBTU-16-030040
        Rule ID    : SV-215112r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00232
        Rule Title : An application firewall must be enabled on the system.
        DiscussMD5 : 83B939E9FAE26D0BDBB46182BCD0D01B
        CheckMD5   : 5BB37643DADC63718432042529757AF0
        FixMD5     : AED5675E1458FCE15B8CAE8DB929C79D
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(systemctl is-enabled ufw)
    $Finding_2 = ""

    If ($Finding -eq "enabled") {
        $Finding_2 = $(systemctl is-active ufw)
        If ($Finding_2 -eq "active") {
            $Status = "NotAFinding"
            $FindingMessage = "The Uncomplicated Firewall is enabled and active on the system."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The Uncomplicated Firewall is enabled but not active on the system."
        }
    }
    Else {
        # Not_Reviewed because user should check for another application firewall
        $Status = "Not_Reviewed"
        $FindingMessage = "The Uncomplicated Firewall is neither enabled nor active on the system."
    }

    $FindingDetails += $FindingMessage | Out-String

    If ($Finding) {
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        $FindingDetails += $Finding | Out-String
    }

    If ($Finding_2) {
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        $FindingDetails += $Finding_2 | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215114 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215114
        STIG ID    : UBTU-16-030060
        Rule ID    : SV-215114r610931_rule
        CCI ID     : CCI-000382
        Rule Name  : SRG-OS-000096-GPOS-00050
        Rule Title : The Ubuntu operating system must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management (PPSM) Category Assignments List (CAL) and vulnerability assessments.
        DiscussMD5 : 00F3B146F49A97244EBFCEEEB267A6F5
        CheckMD5   : 18BFDD7CF6BE774D41D95CD2ECFEEE13
        FixMD5     : 7390CFA034D24E9AEB6D740D1B74683B
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Status = "Not_Reviewed"
    $FindingMessage = ("Verify the Ubuntu operating system is configured to prohibit or restrict the use of " +
        "functions, ports, protocols, and/or services as defined in the Ports, Protocols, and Services " +
        "Management (PPSM) Category Assignments List (CAL) and vulnerability assessments.")

    $FindingDetails += $FindingMessage | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215115 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215115
        STIG ID    : UBTU-16-030070
        Rule ID    : SV-215115r610931_rule
        CCI ID     : CCI-001090
        Rule Name  : SRG-OS-000138-GPOS-00069
        Rule Title : A sticky bit must be set on all public directories to prevent unauthorized and unintended information transferred via shared system resources.
        DiscussMD5 : E51114DDF4084E627CE2A6AF9C67D641
        CheckMD5   : B31E23ABA25640440DD29B5E0FA9C08A
        FixMD5     : 2EC442639EA2FEB4A8D37AB668DC5557
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Command = @'
#!/bin/sh
find / -type d \( -perm -0002 -a ! -perm -1000 \)
'@
    Write-Output $Command > /tmp/command
    $Dirs = $(sh /tmp/command)
    Remove-Item /tmp/command

    If ($Dirs) {
        $Status = "Open"
        $FindingMessage = "The below directories do not have their sticky bit set."
    }
    else {
        $Status = "NotAFinding"
        $FindingMessage = "The below directories have their sticky bit set."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    $Dirs = $Dirs.Split([Environment]::NewLine)

    foreach ($Dir in $Dirs) {
        $FindingDetails += $Dir | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215116 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215116
        STIG ID    : UBTU-16-030100
        Rule ID    : SV-215116r610931_rule
        CCI ID     : CCI-001891
        Rule Name  : SRG-OS-000355-GPOS-00143
        Rule Title : The Ubuntu operating system must compare internal information system clocks at least every 24 hours with a server which is synchronized to an authoritative time source, such as the United States Naval Observatory (USNO) time servers, or a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).
        DiscussMD5 : CBAAE5399D8412E73C7DBFCB535650E0
        CheckMD5   : 2B88D328FE816FEAC3BF3AF9DC396B1E
        FixMD5     : BEF7E68596DA2620B9A656A4F48FFF10
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $FindingDetails += "If the system is not networked this item is Not Applicable." | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    # Check that 'Chrony' is active and loaded.
    $Finding = $(systemctl status chrony.service)

    If ($Finding -match "Active: active") {
        $FindingDetails += "'Chrony' is active." | Out-String
    }
    Else {
        $FindingDetails += "'Chrony' is not active." | Out-String
    }

    If ($Finding -match "Loaded: loaded") {
        $FindingDetails += "'Chrony' is loaded." | Out-String
    }
    Else {
        $FindingDetails += "'Chrony' is not loaded." | Out-String
    }

    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    # Check that 'server' is set to an authoritative DoD time source.
    $Lines = Get-Content /etc/chrony/chrony.conf
    $Lines = $Lines.Split([Environment]::NewLine)

    $Finding = ""
    $Finding = $Lines -match '^server*(\d)*'

    If ($Finding -ne "") {
        $FindingDetails += "'server' is set. Check that 'server' is set to an authoritative DoD time source." | Out-String
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String

        foreach ($Row in $Finding) {
            $FindingDetails += $Row | Out-String
        }
    }
    Else {
        $FindingDetails += "'server' is not set." | Out-String
    }

    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    # Check the value of 'maxpool'.
    $Lines = Get-Content /etc/chrony/chrony.conf
    $Lines = $Lines.Split([Environment]::NewLine)

    $Finding = ""
    $Finding = $Lines -match 'maxpoll'

    If ($Finding -ne "") {
        $FindingDetails += "'maxpoll' is set. Check that 'maxpoll' is set to '17'." | Out-String
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String

        foreach ($Row in $Finding) {
            $FindingDetails += $Row | Out-String
        }
    }
    Else {
        $FindingDetails += "'maxpoll' is not set." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215117 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215117
        STIG ID    : UBTU-16-030110
        Rule ID    : SV-215117r610931_rule
        CCI ID     : CCI-002046
        Rule Name  : SRG-OS-000356-GPOS-00144
        Rule Title : The Ubuntu operating system must synchronize internal information system clocks to the authoritative time source when the time difference is greater than one second.
        DiscussMD5 : A9FCC374EFD235BB39D65C9EC9FF1A80
        CheckMD5   : 932B6DB20927551AEC998A65102F3818
        FixMD5     : D98338AFAC443E4432CC474D99C28572
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep ntpdate /etc/init.d/ntpd)

    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    If ($Finding.contains("-q")) {
        $Status = "Open"
        $FindingMessage = "The '-q' option is set."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "The '-q' option is not set."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215118 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215118
        STIG ID    : UBTU-16-030120
        Rule ID    : SV-215118r610931_rule
        CCI ID     : CCI-001890
        Rule Name  : SRG-OS-000359-GPOS-00146
        Rule Title : The Ubuntu operating system must record time stamps for audit records that can be mapped to Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT).
        DiscussMD5 : 5C4D25CE89FFA1A7506EBD882B1A5E3D
        CheckMD5   : DE2E2BC4B34E7332D9CF466E7260039B
        FixMD5     : 654FE48A5E125E7077CE5B15410BBF1F
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(timedatectl status | grep -i "time zone")
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    If (($Finding | grep "UTC") -or ($Finding | grep "GMT")) {
        $Status = "NotAFinding"
        $FindingMessage = "The time zone is configured to use Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT)."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The time zone is not configured to use Coordinated Universal Time (UTC) or Greenwich Mean Time (GMT)."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215119 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215119
        STIG ID    : UBTU-16-030130
        Rule ID    : SV-215119r610931_rule
        CCI ID     : CCI-002824
        Rule Name  : SRG-OS-000433-GPOS-00192
        Rule Title : The Ubuntu operating system must implement non-executable data to protect its memory from unauthorized code execution.
        DiscussMD5 : 082A672A62F928AE4C66922A6503DF52
        CheckMD5   : 100438456321EDAAA153998AB3BFBED4
        FixMD5     : 587B3D4A41FB16FA14B609C8432B9D61
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(dmesg | grep -i "execute disable")
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }
    $Finding_2 = ""

    If ($Finding -like "NX (Execute Disable) protection: active" ) {
        $Status = "NotAFinding"
        $FindingMessage = "The NX (no-execution) bit flag is set on the system."
    }
    Else {
        $Finding_2 = $(grep flags /proc/cpuinfo | grep -w nx | Sort-Object -u)
        If (!($Finding_2)) {
            $Finding_2 = "Check text did not return results."
        }

        If ($Finding_2.contains("nx")) {
            $Status = "NotAFinding"
            $FindingMessage = "The NX (no-execution) bit flag is set on the system."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The NX (no-execution) bit flag is not set on the system."
        }
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    $Finding = $Finding_2
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215120 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215120
        STIG ID    : UBTU-16-030140
        Rule ID    : SV-215120r610931_rule
        CCI ID     : CCI-002824
        Rule Name  : SRG-OS-000433-GPOS-00193
        Rule Title : The Ubuntu operating system must implement address space layout randomization to protect its memory from unauthorized code execution.
        DiscussMD5 : 082A672A62F928AE4C66922A6503DF52
        CheckMD5   : 5711C4BE141C61F8919766515AD3B51B
        FixMD5     : 5751C595464A67834A68443F9E27620B
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(sysctl kernel.randomize_va_space)
    $Finding_2 = ""
    $Finding_3 = ""

    If ((($Finding.ToLower()).StartsWith("kernel.randomize_va_space")) -And (($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 2)) {
        $Finding_2 = $(Get-Content /proc/sys/kernel/randomize_va_space)

        If ($Finding_2 -eq 2) {
            $Finding_3 = $(egrep -R "^kernel.randomize_va_space=[^2]" /etc/sysctl.conf /etc/sysctl.d)

            If ($Finding_3) {
                $status = "Open"
                $FindingMessage = "The Ubuntu operating system does not implement address space layout randomization (ASLR)." | Out-String
                $FindingMessage += "The saved value of the kernel.randomize_va_space variable is different from 2."
            }
            Else {
                $status = "NotAFinding"
                $FindingMessage = "The Ubuntu operating system implements address space layout randomization (ASLR)." | Out-String
                $FindingMessage += "The saved value of the kernel.randomize_va_space variable is not different from 2."
            }
        }
        Else {
            $status = "Open"
            $FindingMessage = "The Ubuntu operating system does not implement address space layout randomization (ASLR)." | Out-String
            $FindingMessage += "The kernel parameter randomize_va_space is not set to 2."
        }
    }
    Else {
        $status = "Open"
        $FindingMessage = "The Ubuntu operating system does not implement address space layout randomization (ASLR)."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    $Finding = $Finding_2
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    $Finding = $Finding_3
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215121 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215121
        STIG ID    : UBTU-16-030200
        Rule ID    : SV-215121r610931_rule
        CCI ID     : CCI-001941, CCI-001942
        Rule Name  : SRG-OS-000112-GPOS-00057
        Rule Title : The Ubuntu operating system must enforce SSHv2 for network access to all accounts.
        DiscussMD5 : 58E3B5EE3E690B19A29B2908A968C5E5
        CheckMD5   : 413B8ADD9F04FDE6679580C07EE40628
        FixMD5     : 50FCC49F64B035E159877269D904AE16
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = $(grep -i protocol /etc/ssh/sshd_config)
    $Lines = $Lines.Split([Environment]::NewLine)

    If (!($Lines)) {
        $FindingMessage = "Check text did not return results."
    }

    foreach ($Line in $Lines) {
        $Line = $Line.Trim()
        $Line = $Line -replace '\s+', ' '

        If ($Line -match '#') {
            continue
        }

        If ((($Line.ToLower()).StartsWith("protocol")) -And $Line.split(" ")[1] -eq 2) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system enforces SSH protocol 2 for network access."
        }
    }

    If ($Status -eq "Not_Reviewed") {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not enforce SSH protocol 2 for network access."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Lines | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215122 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215122
        STIG ID    : UBTU-16-030210
        Rule ID    : SV-215122r610931_rule
        CCI ID     : CCI-000048
        Rule Name  : SRG-OS-000023-GPOS-00006
        Rule Title : The Ubuntu operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a ssh logon and the user must acknowledge the usage conditions and take explicit actions to log on for further access.
        DiscussMD5 : 4A6AF87EF3F157765D5E4334E53A1C98
        CheckMD5   : C20E28A45849E4E58BFE3FD9504BAF38
        FixMD5     : CDE009A973D1EF7C4CF1209910DFA0AA
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    # In this implementation, empty lines consisting of whitespace in the banner are ignored.

    $Finding = $(grep -i banner /etc/ssh/sshd_config)
    $Finding_2 = ""
    $FindingMessage = ""

    $Expected = @("You are accessing a U.S. Government (USG) Information System (IS) that is provided for " +
        "USG-authorized use only.",

        "By using this IS (which includes any device attached to this IS), you consent to the " +
        "following conditions:",

        "-The USG routinely intercepts and monitors communications on this IS for purposes including, " +
        "but not limited to, penetration testing, COMSEC monitoring, network operations and defense, " +
        "personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.",

        "-At any time, the USG may inspect and seize data stored on this IS.",

        "-Communications using, or data stored on, this IS are not private, are subject to routine " +
        "monitoring, interception, and search, and may be disclosed or used for any USG-authorized " +
        "purpose.",

        "-This IS includes security measures (e.g., authentication and access controls) to protect USG " +
        "interests--not for your personal benefit or privacy.",

        "-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI " +
        "investigative searching or monitoring of the content of privileged communications, or work " +
        "product, related to personal representation or services by attorneys, psychotherapists, or " +
        "clergy, and their assistants. Such communications and work product are private and " +
        "confidential. See User Agreement for details."
    )

    If (($Finding -eq "banner /etc/issue") -or ($Finding -eq "Banner /etc/issue")) {
        $FindingMessage += ("The Ubuntu operating system displays a banner before granting access to the Ubuntu " +
            "operating system via a ssh logon.") | Out-String

        $Finding_2 = Get-Content /etc/issue
        $Finding_2 = $Finding_2.Split([Environment]::NewLine)

        for (($i = 0); $i -lt $Finding_2.Length; $i++) {
            If (!($Line -match '^\s*$')) {
                If ($Finding_2[$i] -ne $Expected[$i]) {
                    $Status = "Open"
                    $FindingDetails += "Mismatch" | Out-String
                    $FindingDetails += ("Finding_2[i]: " + $Finding_2[$i]) | Out-String
                    $FindingDetails += ("Expected[i]: " + $Expected[$i]) | Out-String
                }
            }
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage += ("The Ubuntu operating system does not display a banner before granting access to the " +
            "Ubuntu operating system via a ssh logon.") | Out-String
    }

    If ($Status -eq "Not_Reviewed") {
        $Status = "NotAFinding"
        $FindingMessage += ("The displayed banner file matches the Standard Mandatory DoD Notice and Consent " +
            "Banner.") | Out-String
    }
    Else {
        $FindingMessage += ("The specified banner file does not match the Standard Mandatory DoD Notice and " +
            "Consent Banner.") | Out-String
    }

    $FindingDetails += $FindingMessage
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    $FindingDetails += $Finding | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    $FindingDetails += $Finding_2 | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215123 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215123
        STIG ID    : UBTU-16-030220
        Rule ID    : SV-215123r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Ubuntu operating system must not permit direct logons to the root account using remote access via SSH.
        DiscussMD5 : D2D029A109763FD6C12A7D7FF8ABE078
        CheckMD5   : 1D72DB3C9870D78430BA3B2A40786433
        FixMD5     : 2B1AC87DFCC7538D2B2F19FA1A4CE601
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = Get-Content /etc/ssh/sshd_config
    $Lines = $Lines.Split([Environment]::NewLine)

    If ($Lines -eq "") {
        $Status = "Open"
        $FindingMessage = "Direct logons to the root account using remote access via SSH are permitted."
    }

    $Finding = ""
    $rule = '^PermitRootLogin([\s]+)no$'

    foreach ($Line in $Lines) {
        $Line = $Line.Trim()

        If ($Line -match $rule) {
            $Finding = $Line
        }
    }

    If ($Finding -ne "") {
        $Status = "NotAFinding"
        $FindingMessage = "Direct logons to the root account using remote access via SSH are not permitted."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "Direct logons to the root account using remote access via SSH are permitted."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    If ($Status -eq "Open") {
        $FindingDetails += "Missing:" | Out-String
        $FindingDetails += "PermitRootLogin no"
    }
    Else {
        $FindingDetails += $Finding | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215124 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215124
        STIG ID    : UBTU-16-030230
        Rule ID    : SV-215124r610931_rule
        CCI ID     : CCI-000068
        Rule Name  : SRG-OS-000033-GPOS-00014
        Rule Title : The Ubuntu operating system must implement DoD-approved encryption to protect the confidentiality of SSH connections.
        DiscussMD5 : E7652926B71200469C926CB212FC24B6
        CheckMD5   : 265BEC711655D250003CEEA231622896
        FixMD5     : 841D72A0FAC335E8F743A55E1C3129C6
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -E '^Ciphers ' /etc/ssh/sshd_config)

    If ($Finding) {
        $Ciphers = (($Finding).replace("Ciphers", "").replace("ciphers", "") | awk '{$2=$2};1').replace(" ", "").split(",")
        $correct_message_count = 0

        $Ciphers | ForEach-Object {
            If (($_.ToLower()) -eq "aes128-ctr") {
                $correct_message_count += 1
            }
            ElseIf (($_.ToLower()) -eq "aes192-ctr") {
                $correct_message_count += 1
            }
            ElseIf (($_.ToLower()) -eq "aes256-ctr") {
                $correct_message_count += 1
            }
        }

        If ($correct_message_count -eq $Ciphers.count) {
            $Status = "NotAFinding"
            $FindingMessage = "The SSH daemon is configured to only implement DoD-approved encryption."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The SSH daemon is configured to use Ciphers, but not implement DoD-approved encryption."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The SSH daemon is not configured to only implement DoD-approved encryption."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215125 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215125
        STIG ID    : UBTU-16-030240
        Rule ID    : SV-215125r610931_rule
        CCI ID     : CCI-001453, CCI-002890, CCI-003123
        Rule Name  : SRG-OS-000250-GPOS-00093
        Rule Title : The SSH daemon must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms.
        DiscussMD5 : A02B6876A78819C052DC72F0F2FA252E
        CheckMD5   : 1924DD9BA88DB27F7B27C428DAA35210
        FixMD5     : 411CC28315EBC0E08354CFE0374F22CA
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Lines = Get-Content /etc/ssh/sshd_config
    $Lines = $Lines.Split([Environment]::NewLine)

    $Rule = "MACs([\s]+)hmac-sha2-512,hmac-sha2-256"
    $TempDetails = ""
    $Finding = ""

    foreach ($Line in $Lines) {
        $Line = $Line.Trim()

        If ($Line -match $Rule) {
            $Finding = $Line
            $TempDetails += $Finding | Out-String
        }
    }

    If ($Finding) {
        $Status = "NotAFinding"
    }
    Else {
        $Status = "Open"
    }

    If ($Status -eq "NotAFinding") {
        $FindingMessage = ("The Ubuntu operating system configures the SSH daemon to only use Message Authentication " +
            "Codes (MACs) that employ FIPS 140-2 approved ciphers.")
    }
    ElseIf ($Status -eq "Open") {
        $FindingMessage = ("The Ubuntu operating system does not configure the SSH daemon to only use Message " +
            "Authentication Codes (MACs) that employ FIPS 140-2 approved ciphers.")
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215126 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215126
        STIG ID    : UBTU-16-030250
        Rule ID    : SV-215126r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00229
        Rule Title : The Ubuntu operating system must be configured so that the SSH daemon does not allow authentication using an empty password.
        DiscussMD5 : A54F06A419728C948532186EF87EC314
        CheckMD5   : F58F701112FC67852B12591A3F2F0E8A
        FixMD5     : F4F9AA2CE875EC7774F3FF9BD2EA83F7
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(egrep '(Permit(.*?)(Passwords|Environment))' /etc/ssh/sshd_config)
    $PE_correct_message = $false
    $PU_correct_message = $false

    If ($Finding) {
        $PermitEmpty = $(grep PermitEmpty /etc/ssh/sshd_config)
        $PermitUser = $(grep PermitUser /etc/ssh/sshd_config)

        If ($PermitEmpty) {
            If (($PermitEmpty.StartsWith("Permit")) -and (($PermitEmpty | awk '{$2=$2};1').split(" ").ToLower() -eq "no")) {
                $PE_correct_message = $true
            }
        }
        If ($PermitUser) {
            If (($PermitUser.StartsWith("Permit")) -and (($PermitUser | awk '{$2=$2};1').split(" ").ToLower() -eq "no")) {
                $PU_correct_message = $true
            }
        }

        If (($PE_correct_message) -and ($PU_correct_message)) {
            $Status = "NotAFinding"
            $FindingMessage = "Unattended or automatic login via ssh is disabled."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "Unattended or automatic login via ssh is not disabled."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "Unattended or automatic login via ssh is not disabled."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215127 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215127
        STIG ID    : UBTU-16-030251
        Rule ID    : SV-215127r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00229
        Rule Title : The Ubuntu operating system must not allow users to override SSH environment variables.
        DiscussMD5 : A54F06A419728C948532186EF87EC314
        CheckMD5   : 60FBD89EFDD8A552F08C46971F701180
        FixMD5     : 4B653242E05E9FE10A7D4BC07DDA75E9
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -i permituserenvironment /etc/ssh/sshd_config)
    $PE_correct_message = $false
    $PU_correct_message = $false

    If ($Finding) {
        $PermitEmpty = $(grep PermitEmpty /etc/ssh/sshd_config)
        $PermitUser = $(grep PermitUser /etc/ssh/sshd_config)

        If ($PermitEmpty) {
            If (($PermitEmpty.StartsWith("Permit")) -And (($PermitEmpty | awk '{$2=$2};1').split(" ").ToLower() -eq "no")) {
                $PE_correct_message = $true
            }
        }
        If ($PermitUser) {
            If (($PermitUser.StartsWith("Permit")) -And (($PermitUser | awk '{$2=$2};1').split(" ").ToLower() -eq "no")) {
                $PU_correct_message = $true
            }
        }

        If (($PE_correct_message) -And ($PU_correct_message)) {
            $Status = "NotAFinding"
            $FindingMessage = "Unattended or automatic login via ssh is disabled."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "Unattended or automatic login via ssh is not disabled."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "Unattended or automatic login via ssh is not disabled."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215128 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215128
        STIG ID    : UBTU-16-030260
        Rule ID    : SV-215128r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The system must display the date and time of the last successful account logon upon an SSH logon.
        DiscussMD5 : 0A43BF522D99C44EA70013CAD71E8C7F
        CheckMD5   : D6DFCEBB2AEBC10766FA671512A2C657
        FixMD5     : C9F672AFD44650C0A98EA0C4C50E9E7E
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep PrintLastLog /etc/ssh/sshd_config)

    If (!($Finding)) {
        $FindingMessage = "Check text did not return results."
    }

    If (($Finding.StartsWith("PrintLastLog")) -And ((($Finding | awk '{$2=$2};1').split(" "))[1]).ToLower() -eq "yes") {
        $Status = "NotAFinding"
        $FindingMessage = "The system displays the date and time of the last successful account logon upon an SSH logon."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The system does not display the date and time of the last successful account logon upon an SSH logon."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215129 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215129
        STIG ID    : UBTU-16-030270
        Rule ID    : SV-215129r610931_rule
        CCI ID     : CCI-000879, CCI-001133, CCI-002361
        Rule Name  : SRG-OS-000163-GPOS-00072
        Rule Title : The Ubuntu operating system must be configured so that all network connections associated with SSH traffic are terminated at the end of the session or after 10 minutes of inactivity, except to fulfill documented and validated mission requirements.
        DiscussMD5 : 0F9AFA1DACD1A14ED16A5764F63C6753
        CheckMD5   : 456B27C6739EB7F06DA74700E825B8DD
        FixMD5     : 7B7076425CFBBB732BCD3BE92C1FA57D
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -i clientalive /etc/ssh/sshd_config)

    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    If ((($Finding.ToLower()).StartsWith("ClientAliveInterval")) -And ((($Finding | awk '{$2=$2};1').split(" "))[1]).ToLower() -le 600) {
        $Status = "NotAFinding"
        $FindingMessage = "All network connections associated with SSH traffic are automatically terminated at the end of the session or after 10 minutes of inactivity."
    }
    Else {
        $Status = "Not_Reviewed"
        $FindingMessage = "All network connections associated with SSH traffic are not automatically terminated at the end of the session or after 10 minutes of inactivity. Check if documented with ISSO as an operational requirement."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215130 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215130
        STIG ID    : UBTU-16-030271
        Rule ID    : SV-215130r610931_rule
        CCI ID     : CCI-000879, CCI-001133, CCI-002361
        Rule Name  : SRG-OS-000163-GPOS-00072
        Rule Title : The Ubuntu operating system must be configured so that all network connections associated with SSH traffic terminate after a period of inactivity.
        DiscussMD5 : 0F9AFA1DACD1A14ED16A5764F63C6753
        CheckMD5   : F643141A9B4E8352008899E84F0E196C
        FixMD5     : 61011A834D65E211161B40EE753EFF46
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -i clientalivecountmax /etc/ssh/sshd_config)

    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    If ((($Finding.ToLower()).StartsWith("clientalivecountmax")) -And ((($Finding | awk '{$2=$2};1').split(" "))[1]).ToLower() -eq 0) {
        $Status = "NotAFinding"
        $FindingMessage = "All network connections associated with SSH traffic automatically terminate after a period of inactivity."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "All network connections associated with SSH traffic automatically do not terminate after a period of inactivity."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215131 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215131
        STIG ID    : UBTU-16-030300
        Rule ID    : SV-215131r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The SSH daemon must not allow authentication using known hosts authentication.
        DiscussMD5 : 93AAB83A770E43EEC36B15CE3A5EC2AF
        CheckMD5   : F13D0D8EEA14759AFC9E14AB3024064F
        FixMD5     : BBC7A4A77171516AD919ABE37A4C2066
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep IgnoreUserKnownHosts /etc/ssh/sshd_config)
    $Finding2 = RemoveComment $Finding

    If (!($Finding)) {
        $Status = "Open"
        $Finding = "Check text did not return results."
    }
    elseif ($Finding -And !($Finding2)) {
        $Status = "Open"
        $Finding = "Check text returned a commented line."
    }
    elseif (((($Finding | awk '{$2=$2};1').split(" "))[1]).ToLower() -eq "yes") {
        $Status = "NotAFinding"
        $FindingMessage = "The SSH daemon does not allow authentication using known hosts authentication."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The SSH daemon allows authentication using known hosts authentication."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215132 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215132
        STIG ID    : UBTU-16-030310
        Rule ID    : SV-215132r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The SSH public host key files must have mode 0644 or less permissive.
        DiscussMD5 : 0051DB8F916936C64EA65CCAB04840C5
        CheckMD5   : 9D2B735A2DC8B632A1180CC3C87FB39E
        FixMD5     : DC8E01802E2C787D009BE62D3E63E07F
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Modes = $(stat -c "%a" /etc/ssh/*.pub)
    $Modes = $Modes.Split([Environment]::NewLine)

    foreach ($Mode in $Modes) {
        If ($Mode -gt 644) {
            $Status = "Open"
        }
    }

    If ($Status -eq "Not_Reviewed") {
        $Status = "NotAFinding"
        $FindingMessage = ("The Ubuntu operating system does not have public host key files with a mode more " +
            "permissive than 0644.")
    }
    Else {
        $FindingMessage = "The Ubuntu operating system has public host key files with a mode more permissive than 0644."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    $Lines = $(stat -c "%n %a" /etc/ssh/*.pub)
    $Lines = $Lines.Split([Environment]::NewLine)

    foreach ($Line in $Lines) {
        $FindingDetails += $Line | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215133 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215133
        STIG ID    : UBTU-16-030320
        Rule ID    : SV-215133r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The SSH private host key files must have mode 0600 or less permissive.
        DiscussMD5 : 78BA7207DDC6180C202A0E083B9A2619
        CheckMD5   : 416A5CBFD9CB141B1D3EB51AD862B033
        FixMD5     : D2D0C689C4915D9ED505A24AC7835171
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Modes = $(stat -c "%a" /etc/ssh/ssh_host*key)
    $Modes = $Modes.Split([Environment]::NewLine)

    foreach ($Mode in $Modes) {
        If ($Mode -gt 600) {
            $Status = "Open"
        }
    }

    If ($Status -eq "Not_Reviewed") {
        $Status = "NotAFinding"
        $FindingMessage = ("The Ubuntu operating system does not have private host key files with a mode more " +
            "permissive than 0600.")
    }
    Else {
        $FindingMessage = "The Ubuntu operating system has private host key files with a mode more permissive than 0600."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    $Lines = $(stat -c "%n %a" /etc/ssh/ssh_host*key)
    $Lines = $Lines.Split([Environment]::NewLine)

    foreach ($Line in $Lines) {
        $FindingDetails += $Line | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215134 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215134
        STIG ID    : UBTU-16-030330
        Rule ID    : SV-215134r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The SSH daemon must perform strict mode checking of home directory configuration files.
        DiscussMD5 : 94786D14FB7147428AA4433803DBC542
        CheckMD5   : 870C0E6B2464D70AE4875D6A07354AF7
        FixMD5     : EAD4975E2824197D1F61DD00F23C6541
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep StrictModes /etc/ssh/sshd_config)
    $Finding2 = RemoveComment $Finding

    If (!($Finding)) {
        $Status = "Open"
        $Finding = "Check text did not return results."
    }
    elseif ($Finding -And !($Finding2)) {
        $Status = "Open"
        $Finding = "Check text returned a commented line."
    }
    elseif (((($Finding | awk '{$2=$2};1').split(" "))[1]).ToLower() -eq "yes") {
        $Status = "NotAFinding"
        $FindingMessage = "The SSH daemon performs strict mode checking of home directory configuration files."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The SSH daemon does not perform strict mode checking of home directory configuration files."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215135 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215135
        STIG ID    : UBTU-16-030340
        Rule ID    : SV-215135r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The SSH daemon must use privilege separation.
        DiscussMD5 : CF2E4E280EFC0D68C26CDF1E857EEA0C
        CheckMD5   : AA5319716CDE22E69FB016D03F98D97C
        FixMD5     : E7A27856A9C13AF88FB1D79F584BB6C2
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep UsePrivilegeSeparation /etc/ssh/sshd_config)
    $Finding2 = RemoveComment $Finding

    If (!($Finding)) {
        $Status = "Open"
        $Finding = "Check text did not return results."
    }
    elseif ($Finding -And !($Finding2)) {
        $Status = "Open"
        $Finding = "Check text returned a commented line."
    }
    elseif (((($Finding | awk '{$2=$2};1').split(" "))[1]).ToLower() -eq "yes") {
        $Status = "NotAFinding"
        $FindingMessage = "The SSH daemon uses privilege separation."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The SSH daemon does not use privilege separation."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215136 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215136
        STIG ID    : UBTU-16-030350
        Rule ID    : SV-215136r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The SSH daemon must not allow compression or must only allow compression after successful authentication.
        DiscussMD5 : 54E2FB5CE03710525252F0E06E57E053
        CheckMD5   : 953EA24028AB26A71D5D46423CD77758
        FixMD5     : 5AA6A269CB130D30661A0F9CFE3AFD8D
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep Compression /etc/ssh/sshd_config)

    If (!($Finding)) {
        $Status = "Open"
        $Finding = "Check text did not return results."
    }
    ElseIf (((($Finding | awk '{$2=$2};1').split(" "))[1]).ToLower() -eq "no") {
        $Status = "NotAFinding"
        $FindingMessage = "Compression is disabled."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "Compression is not disabled."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215137 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215137
        STIG ID    : UBTU-16-030400
        Rule ID    : SV-215137r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Ubuntu operating system must be configured so that remote X connections are disabled unless to fulfill documented and validated mission requirements.
        DiscussMD5 : F7482390B15DAC1396163EA5B8DDF704
        CheckMD5   : 99E1132EE31E15C3334E01D4EF1F56A0
        FixMD5     : 12CDCAC66F396AB4887CB46BB811278E
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -i x11forwarding /etc/ssh/sshd_config | grep -v "^#")

    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    $RHS = $Finding.split(" ")[1]

    If ($RHS -eq "yes") {
        $Status = "Not_Reviewed"
        $FindingMessage = "X11Forwarding is enabled."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "X11Forwarding is not enabled."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215138 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215138
        STIG ID    : UBTU-16-030410
        Rule ID    : SV-215138r610931_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-OS-000420-GPOS-00186
        Rule Title : An application firewall must protect against or limit the effects of Denial of Service (DoS) attacks by ensuring the Ubuntu operating system is implementing rate-limiting measures on impacted network interfaces.
        DiscussMD5 : 5F0EEF5F8CFD7D84A3BE05868222DD9E
        CheckMD5   : B3F598B48E1CDCC09FF5C1CA30A70920
        FixMD5     : 3CD7E64A391D8C7A43AE67DA5A1E7210
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Findings = $(dpkg -l | awk -F ' ' '{print $2}')
    $Finding = ""

    foreach ($Finding in $Findings) {
        If ($Finding -match 'ufw') {
            $Status = "NotAFinding"
        }
    }

    If ($Status -eq "NotAFinding") {
        # ufw is installed
        $Finding = $(ufw show raw)
    }

    $Status = "Not_Reviewed"
    $FindingMessage = "Verify an application firewall is configured to rate limit any connection to the system."

    $FindingDetails += $FindingMessage | Out-String

    If ($Finding) {
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        $FindingDetails += $Finding | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215139 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215139
        STIG ID    : UBTU-16-030420
        Rule ID    : SV-215139r610931_rule
        CCI ID     : CCI-002418, CCI-002420, CCI-002421, CCI-002422
        Rule Name  : SRG-OS-000423-GPOS-00187
        Rule Title : All networked systems must have and implement SSH to protect the confidentiality and integrity of transmitted and received information, as well as information during preparation for transmission.
        DiscussMD5 : 7F8A1FA1ABA8C819FA861BE3FB4B0F5A
        CheckMD5   : 5D27375C012D682D48EE0856BACF9E94
        FixMD5     : F827DD90E52E77FD3615CEA24783C55E
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(dpkg -l | grep openssh)
    $Finding_2 = ""

    If (($Finding | awk '{print $2}').contains("openssh-server")) {
        $Finding_2 = $(systemctl status sshd.service | egrep -i "(active|loaded)")

        If ($Finding_2 -match "Loaded: loaded") {
            If ($Finding_2 -match "Active: active") {
                $Status = "NotAFinding"
                $FindingMessage = "The ssh package is installed and the 'sshd.service' is loaded and active."
            }
            Else {
                $Status = "Open"
                $FindingMessage = "The ssh package is installed but the 'sshd.service' is not active."
            }
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The ssh package is installed but the 'sshd.service' is not loaded."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The ssh package is not installed."
    }
    $FindingDetails += $FindingMessage | Out-String

    $FindingDetails += $(FormatFinding $Finding) | Out-String
    $Finding = $Finding_2
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215140 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215140
        STIG ID    : UBTU-16-030430
        Rule ID    : SV-215140r610931_rule
        CCI ID     : CCI-001851
        Rule Name  : SRG-OS-000479-GPOS-00224
        Rule Title : The audit system must take appropriate action when the network cannot be used to off-load audit records.
        DiscussMD5 : 12FFD3C03701BE9B47C761E0CCB72458
        CheckMD5   : 60268935C04E65E83D3753EBB0096B64
        FixMD5     : 88E6E0717EF6E0B5BFE9B0D4FD81E9FE
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -iw "network_failure" /etc/audisp/audisp-remote.conf)
    $Finding2 = RemoveComment $Finding

    if ($null -eq $Finding -And $null -eq $Finding2) {
        $Status = "Open"
        $FindingMessage = "The audit system does not take appropriate action when the network cannot be used to off-load audit records. The line is commented out."
    }
    elseif ($null -eq $Finding) {
        $Status = "Open"
        $FindingMessage = "Check text did not return results."
    }
    elseif ($Finding2.Contains("syslog") -or $Finding2.Contains("single") -or $Finding2.Contains("halt")) {
        $Status = "NotAFinding"
        $FindingMessage = "The audit system takes appropriate action when the network cannot be used to off-load audit records."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The audit system does not take appropriate action when the network cannot be used to off-load audit records."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215141 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215141
        STIG ID    : UBTU-16-030450
        Rule ID    : SV-215141r610931_rule
        CCI ID     : CCI-000067
        Rule Name  : SRG-OS-000032-GPOS-00013
        Rule Title : All remote access methods must be monitored.
        DiscussMD5 : 4EA785D3418C126806E56AA6202B2453
        CheckMD5   : A01D5B43E28464E319109D7700041AEC
        FixMD5     : 6B69D53C03EDB1F1A31FBDF881229182
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -E -r '^(auth,authpriv\.\*|daemon\.\*)' /etc/rsyslog.*)

    If ($Finding) {
        $better_finding_1 = $(grep -E -r '^(auth,authpriv\.*)' /etc/rsyslog.* | awk '{$2=$2};1')
        If (!($better_finding_1)) {
            $better_finding_1 = "Check text did not return results."
        }
        else {
            $better_finding_1_path = ($better_finding_1).split(":")[0]
        }
        $better_finding_2 = $(grep -E -r '^daemon\.*' /etc/rsyslog.*) | awk '{$2=$2};1'
        If (!($better_finding_2)) {
            $better_finding_2 = "Check text did not return results."
        }
        Else {
            $better_finding_2_path = ($better_finding_2).split(":")[0]
        }
    }
    Else {
        $Finding = "Check text did not return results."
    }

    If (($better_finding_1 -eq "$($better_finding_1_path):auth,authpriv.* /var/log/auth.log") -And ($better_finding_2 -eq "$($better_finding_2_path):daemon.notice /var/log/messages")) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system monitors all remote access methods."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not monitor all remote access methods."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215142 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215142
        STIG ID    : UBTU-16-030460
        Rule ID    : SV-215142r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Cron logging must be implemented.
        DiscussMD5 : EF5612442518FAE73D9462D9A1266E38
        CheckMD5   : 53C95B3AACDE5C13E6CF9641CB781B3A
        FixMD5     : 7776D5765152D1E441389369BC29F3D4
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep cron /etc/rsyslog.d/50-default.conf)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    $Finding2 = $(more /etc/rsyslog.conf)

    if (!($Finding2.Contains("*.* /var/log/messages"))) {
        $Status = "NotAFinding"
        $FindingMessage = "`"rsyslog`" is configured to log cron events."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "`"rsyslog`" is not configured to log cron events."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    $FindingDetails += $(FormatFinding $Finding2) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215143 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215143
        STIG ID    : UBTU-16-030500
        Rule ID    : SV-215143r610931_rule
        CCI ID     : CCI-001443, CCI-001444, CCI-002418
        Rule Name  : SRG-OS-000299-GPOS-00117
        Rule Title : Wireless network adapters must be disabled.
        DiscussMD5 : 257FD4EE39D040DCE044C243F5C5F5F7
        CheckMD5   : 8C26300585370CC29EB01F8D5463B41F
        FixMD5     : ED453975904C7EC1F5FAA92945F4211B
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(ip a)
    $wireless = $(lshw -C Network) | Where-Object { $_ -like "wireless" }

    If ($wireless) {
        $Status = "Not_Reviewed"
        $FindingMessage = "A wireless interface is configured and must be documented and approved by the Information System Security Officer (ISSO)"
    }
    Else {
        $Status = "Not_Applicable"
        $FindingMessage = "This requirement is Not Applicable for systems that do not have physical wireless network radios."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215144 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215144
        STIG ID    : UBTU-16-030510
        Rule ID    : SV-215144r610931_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-OS-000142-GPOS-00071
        Rule Title : The Ubuntu operating system must be configured to use TCP syncookies.
        DiscussMD5 : 921AE2B537EF68FF53CCBD0BD9D8275C
        CheckMD5   : C45C058CFE53F05AC14A918DF5EB1092
        FixMD5     : 91921D9A2D61DB2674DF433F55A7AD37
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(sysctl net.ipv4.tcp_syncookies)

    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }
    $Finding_2 = ""

    If ((($Finding.Tolower()).StartsWith("net.ipv4.tcp_syncookies")) -And ((($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 1))) {
        $Finding_2 = $(grep -i net.ipv4.tcp_syncookies /etc/sysctl.conf /etc/sysctl.d/* | grep -v '#')
        If ($Finding_2) {
            $Status = "NotAFinding"
            $FindingMessage = "The Ubuntu operating system is configured to use TCP syncookies."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "The Ubuntu operating system is configured to use TCP syncookies but the value is not saved."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system is not configured to use TCP syncookies."
    }

    $FindingDetails += $FindingMessage | Out-String

    $FindingDetails += $(FormatFinding $Finding) | Out-String
    $Finding = $Finding_2
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215145 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215145
        STIG ID    : UBTU-16-030520
        Rule ID    : SV-215145r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : For Ubuntu operating systems using Domain Name Servers (DNS) resolution, at least two name servers must be configured.
        DiscussMD5 : C95AA669AE0F14A185CF765F740BC378
        CheckMD5   : 83930604D9D0DB748370B2697A2D223B
        FixMD5     : D2C430663A23DC59C3065E5CEDF8EE13
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep hosts /etc/nsswitch.conf)

    If (!($Finding)) {
        If (!([String]::IsNullOrWhiteSpace((Get-Content "/etc/resolv.conf")))) {
            $Status = "Open"
            $FindingMessage = "/etc/resolv.conf is not empty but does not contain any hosts lines."
        }
    }
    Else {
        $Finding_2 = $(grep nameserver /etc/resolv.conf)
        If (!($Finding_2)) {
            $Status = "Open"
        }
        Else {
            $Finding_2 = $Finding_2.Split([Environment]::NewLine)
            $count = 0

            foreach ($row in $Finding_2) {
                If (!($row -Match '#')) {
                    $count++
                }
            }

            if ($count -lt 2) {
                $Status = "Open"
                $FindingMessage = "Less than two lines are returned that are not commented out."
            }
            Else {
                $Status = "NotAFinding"
                $FindingMessage = "At least two lines are returned that are not commented out."
            }
        }
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    $Finding = $Finding.Split([Environment]::NewLine)
    foreach ($Line in $Finding) {
        $FindingDetails += $Line | Out-String
    }
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    foreach ($Line in $Finding_2) {
        $FindingDetails += $Line | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215146 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215146
        STIG ID    : UBTU-16-030530
        Rule ID    : SV-215146r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Ubuntu operating system must not forward Internet Protocol version 4 (IPv4) source-routed packets.
        DiscussMD5 : 9179EB0D19C941D533A72A346FE7093C
        CheckMD5   : D3919201AD471FB0AF7EFA02DDF9689E
        FixMD5     : 7906852D5551ADDF75035B8EA33014AE
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(sysctl net.ipv4.conf.all.accept_source_route)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }
    $Finding_2 = ""

    If ((($Finding.Tolower()).StartsWith("net.ipv4.conf.all.accept_source_route")) -And ((($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 0))) {
        $Finding_2 = $(grep -i net.ipv4.tcp_syncookies /etc/sysctl.conf /etc/sysctl.d/* | grep -v '#')
        If ($Finding_2) {
            $Status = "NotAFinding"
            $FindingMessage = "Internet Protocol version 4 (IPv4) source-routed packets are not forwarded."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "Internet Protocol version 4 (IPv4) source-routed packets are forwarded."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "Internet Protocol version 4 (IPv4) source-routed packets are forwarded."
    }

    $FindingDetails += $FindingMessage | Out-String

    $FindingDetails += $(FormatFinding $Finding) | Out-String
    $Finding = $Finding_2
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215147 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215147
        STIG ID    : UBTU-16-030540
        Rule ID    : SV-215147r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Ubuntu operating system must not forward Internet Protocol version 4 (IPv4) source-routed packets by default.
        DiscussMD5 : 9179EB0D19C941D533A72A346FE7093C
        CheckMD5   : 5D599D99126109DC7E276179D56DD0E0
        FixMD5     : 3405573A33738CCE86ED7FB2F3994A58
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(sysctl net.ipv4.conf.default.accept_source_route)
    $Finding = $Finding.ToLower()

    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }
    $Finding_2 = ""

    If (($Finding.StartsWith("net.ipv4.conf.default.accept_source_route")) -And ((($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 0))) {
        $Finding_2 = $(grep -i net.ipv4.tcp_syncookies /etc/sysctl.conf /etc/sysctl.d/* | grep -v '#')
        If ($Finding_2) {
            $Status = "NotAFinding"
            $FindingMessage = "Internet Protocol version 4 (IPv4) source-routed packets are not forwarded by default."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "Internet Protocol version 4 (IPv4) source-routed packets are forwarded by default."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "Internet Protocol version 4 (IPv4) source-routed packets are forwarded by default."
    }

    $FindingDetails += $FindingMessage | Out-String

    $FindingDetails += $(FormatFinding $Finding) | Out-String
    $Finding = $Finding_2
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215148 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215148
        STIG ID    : UBTU-16-030550
        Rule ID    : SV-215148r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Ubuntu operating system must not respond to Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) echoes sent to a broadcast address.
        DiscussMD5 : BE70874631D75B2BC5F6D4D18AC1896F
        CheckMD5   : 89352C2926C9CD445B4F858D2686C19D
        FixMD5     : D578DF0FD88E86EB1F6F3CA989B2807C
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(sysctl net.ipv4.icmp_echo_ignore_broadcasts)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }
    $Finding_2 = ""

    If ((($Finding.Tolower()).StartsWith("net.ipv4.icmp_echo_ignore_broadcasts")) -And ((($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 1))) {
        $Finding_2 = $(grep -i net.ipv4.tcp_syncookies /etc/sysctl.conf /etc/sysctl.d/* | grep -v '#')
        If ($Finding_2) {
            $Status = "NotAFinding"
            $FindingMessage = "Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) echoes sent to a broadcast address are not responded to."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) echoes sent to a broadcast address are responded to."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) echoes sent to a broadcast address are responded to."
    }

    $FindingDetails += $FindingMessage | Out-String

    $FindingDetails += $(FormatFinding $Finding) | Out-String
    $Finding = $Finding_2
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215149 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215149
        STIG ID    : UBTU-16-030560
        Rule ID    : SV-215149r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Ubuntu operating system must prevent Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages from being accepted.
        DiscussMD5 : 291BC64B1A09772416DA14DCDFB7E9E3
        CheckMD5   : C19866EEB95DF91AF3A4BD402090FBCD
        FixMD5     : 9391BF044DF3C4F6DB0D2F50F6257FF2
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(sysctl net.ipv4.conf.default.accept_redirects)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }
    $Finding_2 = ""

    If ((($Finding.Tolower()).StartsWith("net.ipv4.conf.default.accept_redirects")) -And ((($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 0))) {
        $Finding_2 = $(grep -i net.ipv4.tcp_syncookies /etc/sysctl.conf /etc/sysctl.d/* | grep -v '#')
        If ($Finding_2) {
            $Status = "NotAFinding"
            $FindingMessage = "Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messsages are not accepted."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messsages are accepted."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messsages are accepted."
    }

    $FindingDetails += $FindingMessage | Out-String

    $FindingDetails += $(FormatFinding $Finding) | Out-String
    $Finding = $Finding_2
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215150 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215150
        STIG ID    : UBTU-16-030570
        Rule ID    : SV-215150r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Ubuntu operating system must ignore Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages.
        DiscussMD5 : 291BC64B1A09772416DA14DCDFB7E9E3
        CheckMD5   : 7A2145BD3763FE32FDB7007AD596857B
        FixMD5     : 973F76CBF4B9F82FCB28474D73DA6CC1
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(sysctl net.ipv4.conf.all.accept_redirects)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }
    $Finding_2 = ""

    If ((($Finding.Tolower()).StartsWith("net.ipv4.conf.all.accept_redirects")) -And ((($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 0))) {
        $Finding_2 = $(grep -i net.ipv4.tcp_syncookies /etc/sysctl.conf /etc/sysctl.d/* | grep -v '#')
        If ($Finding_2) {
            $Status = "NotAFinding"
            $FindingMessage = "Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages are ignored."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages are not ignored."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages are not ignored."
    }

    $FindingDetails += $FindingMessage | Out-String

    $FindingDetails += $(FormatFinding $Finding) | Out-String
    $Finding = $Finding_2
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215151 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215151
        STIG ID    : UBTU-16-030580
        Rule ID    : SV-215151r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Ubuntu operating system must not allow interfaces to perform Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirects by default.
        DiscussMD5 : A282162854CD0178A5043B15A17AD001
        CheckMD5   : 4C2ADB588AC9D0AA320F93B86855AB12
        FixMD5     : 5B71521D28AD163508677CA7EC5DDAF5
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(sysctl net.ipv4.conf.default.send_redirects)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }
    $Finding_2 = ""

    If ((($Finding.Tolower()).StartsWith("net.ipv4.conf.default.send_redirects")) -And ((($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 0))) {
        $Finding_2 = $(grep -i net.ipv4.tcp_syncookies /etc/sysctl.conf /etc/sysctl.d/* | grep -v '#')
        If ($Finding_2) {
            $Status = "NotAFinding"
            $FindingMessage = "Interfaces are not allowed to perform Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirects."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "Interfaces are allowed to perform Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirects."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "Interfaces are allowed to perform Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirects."
    }

    $FindingDetails += $FindingMessage | Out-String

    $FindingDetails += $(FormatFinding $Finding) | Out-String
    $Finding = $Finding_2
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215152 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215152
        STIG ID    : UBTU-16-030590
        Rule ID    : SV-215152r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Ubuntu operating system must not send Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirects.
        DiscussMD5 : A282162854CD0178A5043B15A17AD001
        CheckMD5   : 365CACDC117B83379F9C77144503DFD0
        FixMD5     : B1CE6CCE0BB5DAFE262AF351920759E1
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(sysctl net.ipv4.conf.all.send_redirects)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }
    $Finding_2 = ""

    If ((($Finding.Tolower()).StartsWith("net.ipv4.conf.all.send_redirects")) -And ((($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 0))) {
        $Finding_2 = $(grep -i net.ipv4.tcp_syncookies /etc/sysctl.conf /etc/sysctl.d/* | grep -v '#')
        If ($Finding_2) {
            $Status = "NotAFinding"
            $FindingMessage = "Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirects are not sent."
        }
        Else {
            $Status = "Open"
            $FindingMessage = "Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirects are sent."
        }
    }
    Else {
        $Status = "Open"
        $FindingMessage = "Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirects are sent."
    }

    $FindingDetails += $FindingMessage | Out-String

    $FindingDetails += $(FormatFinding $Finding) | Out-String
    $Finding = $Finding_2
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215153 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215153
        STIG ID    : UBTU-16-030600
        Rule ID    : SV-215153r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Ubuntu operating system must not be performing packet forwarding unless the system is a router.
        DiscussMD5 : 65A8EAD83B669ECBA43C87CE3C146ABB
        CheckMD5   : 4FB11355D7CFDE995C7A060B88D65D2C
        FixMD5     : 0F92795A092AFCE70D38BF263EB52935
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(sysctl net.ipv4.ip_forward)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    If ((($Finding.Tolower()).StartsWith("net.ipv4.ip_forward")) -And ((($Finding | awk '{$2=$2};1').replace(" ", "").split("=")[1] -eq 0))) {
        $Status = "NotAFinding"
        $FindingMessage = "IP forwarding is disabled."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "IP forwarding is enabled."
    }

    $FindingDetails += $FindingMessage | Out-String

    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215154 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215154
        STIG ID    : UBTU-16-030610
        Rule ID    : SV-215154r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : Network interfaces must not be in promiscuous mode.
        DiscussMD5 : 40B15DDB9478835577079598CAF0D518
        CheckMD5   : 66F679EE11680D91C9C5118107739E3A
        FixMD5     : D89D8031046A190412C762A966C8AAA9
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(ip link | grep -i promisc)

    If (!($Finding)) {
        $Status = "NotAFinding"
        $FindingMessage = "No network interface was found in promiscuous mode."
    }
    Else {
        $Status = "Not_Reviewed"
        $FindingMessage = "Network interface(s) were found in promiscuous mode."
    }

    $FindingDetails += $FindingMessage | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215155 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215155
        STIG ID    : UBTU-16-030620
        Rule ID    : SV-215155r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Ubuntu operating system must be configured to prevent unrestricted mail relaying.
        DiscussMD5 : F61182AB59E5EE82BE7A93165A4441CD
        CheckMD5   : 1873E30E30346E6D49F48C93BDE24C9B
        FixMD5     : 78706B1A57F07D3F8AA908D8785D2245
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Findings = $(dpkg -l | awk -F ' ' '{print $2}')
    $TempDetails = ""
    $postfix_installed = $false

    foreach ($Finding in $Findings) {
        If ($Finding -match 'postfix') {
            $postfix_installed = $true

            $TempDetails += $Finding | Out-String
            $TempDetails += "-----------------------------------------------------------------------" | Out-String

            $Finding_2 = $(postconf -n smtpd_client_restrictions)
            $TempDetails += $Finding_2 | Out-String

            $Finding_2 = $Finding_2.Split(' ')

            foreach ($Word in $Finding_2) {
                # Delete non-letter characters from string
                $rule = '[^a-zA-Z_]'
                $Word = $Word -replace $rule, ''

                If (!($Word)) {
                    continue
                }

                If ($Word -eq 'smtpd_relay_strictions') {
                }
                ElseIf ($Word -eq 'permit_mynetworks') {
                }
                ElseIf ($Word -eq 'permit_sasl_authenticated') {
                }
                ElseIf ($Word -eq 'reject') {
                }
                Else {
                    # Invalid configuration
                    $TempDetails += ("Invalid word: " + $Word) | Out-String
                    $Status = "Open"
                }
            }
        }
    }

    If ($Status -eq "Not_Reviewed" -And $postfix_installed) {
        $Status = "NotAFinding"
        $FindingMessage = "The postfix package is installed and is correctly configured."
    }
    ElseIf ($Status -eq "Not_Reviewed") {
        $Status = "Not_Applicable"
        $FindingMessage = "The postfix package is not installed."
    }
    ElseIf ($Status -eq "Open") {
        $FindingMessage = "The postfix package is installed and is incorrectly configured."
    }

    $FindingDetails += $FindingMessage | Out-String

    If ($TempDetails) {
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        $FindingDetails += $TempDetails | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215156 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215156
        STIG ID    : UBTU-16-030700
        Rule ID    : SV-215156r610931_rule
        CCI ID     : CCI-000139
        Rule Name  : SRG-OS-000046-GPOS-00022
        Rule Title : The Information System Security Officer (ISSO) and System Administrator (SA) (at a minimum) must have mail aliases to be notified of an audit processing failure.
        DiscussMD5 : D7DEB737B08C0E22FAE36DD32DB4DED6
        CheckMD5   : 42C8D48894C1BC3EF999ABB08765A070
        FixMD5     : 498A7A0316847643D3E437928DEB2687
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep "postmaster: *root$" /etc/aliases)

    If ($Finding -And !($Finding -match '#')) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system notifies administrators in the event of an audit processing " +
						  "failure."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not notify administrators in the event of an audit " +
						  "processing failure."
    }

    $FindingDetails += $FindingMessage | Out-String

    If ($Finding) {
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        $FindingDetails += $Finding | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215157 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215157
        STIG ID    : UBTU-16-030710
        Rule ID    : SV-215157r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : A File Transfer Protocol (FTP) server package must not be installed unless needed.
        DiscussMD5 : BB380AA75C01A599AD43B801CEA01003
        CheckMD5   : 4B1C1BF39178A881260172AC61AE2124
        FixMD5     : 0F18E2AEE003A56FC30C8DEA165C77F8
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(dpkg -l | egrep -i 'ftpd' | egrep -v 'tfpd')

    If ($Finding) {
        $FindingMessage = "An ftp daemon is installed."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "An ftp daemon is not installed."
    }

    $FindingDetails += $FindingMessage | Out-String

    If ($Finding) {
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        $FindingDetails += $Finding
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215158 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215158
        STIG ID    : UBTU-16-030720
        Rule ID    : SV-215158r610931_rule
        CCI ID     : CCI-000318, CCI-000368, CCI-001812, CCI-001813, CCI-001814
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Trivial File Transfer Protocol (TFTP) server package must not be installed if not required for operational support.
        DiscussMD5 : 08E528CCF29EA80A72583D3D1B1B4D64
        CheckMD5   : 34D85CE68627CDE211BA74BAD9750F46
        FixMD5     : 54A8CA0C9CBD0D8688B162D9991EA8E9
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(dpkg -l | grep -i 'tftpd')

    If ($Finding) {
        $FindingMessage = "A TFTP package is installed."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "A TFTP package is not installed."
    }

    $FindingDetails += $FindingMessage | Out-String

    If ($Finding) {
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        $FindingDetails += $Finding
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215159 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215159
        STIG ID    : UBTU-16-030730
        Rule ID    : SV-215159r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : If the Trivial File Transfer Protocol (TFTP) server is required, the TFTP daemon must be configured to operate in secure mode.
        DiscussMD5 : 035EA21B7A0183545404DB48DB373044
        CheckMD5   : FF722A23B6037C3F2CD4269374826E8C
        FixMD5     : EB0785981F35B052D7C93F62FEFFEBF7
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(dpkg -l | grep -i 'tftpd-hpa')
    $Finding_2 = ""

    If ($Finding) {
        $FindingMessage = "A TFTP package is installed."

        $Finding_2 = $(grep TFTP_OPTIONS /etc/default/tdtpd-hpa)

        If ($Finding_2 -match '--secure') {
            $Status = "NotAFinding"
        }
        Else {
            $Status = "Open"
        }
    }
    Else {
        $Status = "Not_Applicable"
        $FindingMessage = "A TFTP package is not installed."
    }

    $FindingDetails += $FindingMessage | Out-String

    If ($Finding) {
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        $FindingDetails += $Finding | Out-String
    }

    If ($Finding_2) {
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        $FindingDetails += $Finding_2
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215160 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215160
        STIG ID    : UBTU-16-030740
        Rule ID    : SV-215160r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : An X Windows display manager must not be installed unless approved.
        DiscussMD5 : 52112F6C4BBC6BBBB7F7ED2FF42FC773
        CheckMD5   : D0136143914B746BD200D0E45795FFA4
        FixMD5     : E3E7B8DF313753A533D72419B3B7B226
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(dpkg -l | grep lightdm)

    If ($Finding) {
        $FindingMessage = "An X windows package is installed."
    }
    Else {
        $Status = "NotAFinding"
        $FindingMessage = "An X windows package is not installed."
    }

    $FindingDetails += $FindingMessage | Out-String

    If ($Finding) {
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        $FindingDetails += $Finding
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215161 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215161
        STIG ID    : UBTU-16-030800
        Rule ID    : SV-215161r610931_rule
        CCI ID     : CCI-001948, CCI-001953, CCI-001954
        Rule Name  : SRG-OS-000375-GPOS-00160
        Rule Title : The Ubuntu operating system must have the packages required for multifactor authentication to be installed.
        DiscussMD5 : DB85D9470975778DEFB0C5C9492E6665
        CheckMD5   : 3AB354BCBF0BE842203CC12F1C0F0F6F
        FixMD5     : 76675C00CF63290300A65E40564D6A97
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(dpkg -l | grep libpam-pkcs11)

    If ($Finding) {
        $Status = "NotAFinding"
        $FindingMessage = "The 'libpam-pkcs11' package is installed."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The 'libpam-pkcs11' package is not installed."
    }

    $FindingDetails += $FindingMessage | Out-String

    If ($Finding) {
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        $FindingDetails += $Finding | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215162 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215162
        STIG ID    : UBTU-16-030810
        Rule ID    : SV-215162r610931_rule
        CCI ID     : CCI-001953
        Rule Name  : SRG-OS-000376-GPOS-00161
        Rule Title : The Ubuntu operating system must accept Personal Identity Verification (PIV) credentials.
        DiscussMD5 : 7462E7E4AE986086DAE75AD399AA91AD
        CheckMD5   : A1562FE82BC4349925956ED56D865B8A
        FixMD5     : 29424D450AA725BDDB7EE16F65D533CB
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(dpkg -l | grep opensc-pkcs11)

    If ($Finding) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system accepts Personal Identity Verification (PIV) credentials."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not accept Personal Identity Verification (PIV) credentials."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215163 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215163
        STIG ID    : UBTU-16-030820
        Rule ID    : SV-215163r610931_rule
        CCI ID     : CCI-001948, CCI-001953, CCI-001954
        Rule Name  : SRG-OS-000375-GPOS-00160
        Rule Title : The Ubuntu operating system must implement certificate status checking for multifactor authentication.
        DiscussMD5 : DB85D9470975778DEFB0C5C9492E6665
        CheckMD5   : 1248308D0CA1090635234A12BB0DD59C
        FixMD5     : 76E192803C4E5AFAC0FE82FDBB4BBD5B
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ocsp_on)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    If ((($Finding.ToLower()).StartsWith("cert_policy")) -And (($Finding.ToLower()).contains("ocsp_on"))) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system implements certificate status checking for multifactor authentication."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not implement certificate status checking for multifactor authentication."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215164 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215164
        STIG ID    : UBTU-16-030830
        Rule ID    : SV-215164r610931_rule
        CCI ID     : CCI-000185, CCI-001991
        Rule Name  : SRG-OS-000066-GPOS-00034
        Rule Title : The Ubuntu operating system, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.
        DiscussMD5 : E08C494664B81656E4A56EBDE0AA9782
        CheckMD5   : 6C66AA4461B3E7F68CEA13ED9D22A7AD
        FixMD5     : D096B9895D6A7636A75A582AAC4D56DC
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ca)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    If ((($Finding.ToLower()).StartsWith("cert_policy")) -And (($Finding.ToLower()).contains("ca"))) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system is configured to use strong authenticators in the establishment of nonlocal maintenance and diagnostic maintenance."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system is not configured to use strong authenticators in the establishment of nonlocal maintenance and diagnostic maintenance."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V215165 {
    <#
    .DESCRIPTION
        Vuln ID    : V-215165
        STIG ID    : UBTU-16-030840
        Rule ID    : SV-215165r610931_rule
        CCI ID     : CCI-000765, CCI-000766, CCI-000767, CCI-000768, CCI-001948, CCI-001953, CCI-001954
        Rule Name  : SRG-OS-000105-GPOS-00052
        Rule Title : The Ubuntu operating system must implement smart card logins for multifactor authentication for access to accounts.
        DiscussMD5 : 70758E213D5AC6CBCDCA0C9B0A68D772
        CheckMD5   : 633DECA4F611B98BBE49D27756594E24
        FixMD5     : 4C337ACFB23FE82527F769A3501847F7
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep pam_pkcs11.so /etc/pam.d/common-auth)
    If (!($Finding)) {
        $Finding = "Check text did not return results."
    }

    If (($Finding.StartsWith("auth")) -And ($Finding -match "pam_pkcs11.so")) {
        $Status = "NotAFinding"
        $FindingMessage = "The Ubuntu operating system uses multifactor authentication for local access to accounts."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The Ubuntu operating system does not use multifactor authentication for local access to accounts."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += $(FormatFinding $Finding) | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V220332 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220332
        STIG ID    : UBTU-16-030900
        Rule ID    : SV-220332r610931_rule
        CCI ID     : CCI-001241
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The system must use a DoD-approved virus scan program.
        DiscussMD5 : 25B19E2935F83F9C8FC2091EA0A42EC3
        CheckMD5   : 4FA2D24A2EFC894576051E39CB18941C
        FixMD5     : DE3BEF9AA29D3DBE7E822D1D872BEA56
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(systemctl status nails)
    $Finding_2 = ""

    If ($Finding -match "Active: active") {
        $Status = "NotAFinding"
        $FindingMessage = "'nails' is active."
    }
    Else {
        $Finding_2 = $(systemctl status clamav-daemon.socket)

        If ($Finding_2 -match "Active: active") {
            $Status = "NotAFinding"
            $FindingMessage = "'nails' is not active but 'clamav-daemon.socket' is active."
        }
        Else {
            $FindingMessage = "'nails' is not active and 'clamav-daemon.socket' is not active."
        }
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    $FindingDetails += $Finding | Out-String

    If ($Finding_2) {
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        $FindingDetails += $Finding | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V220333 {
    <#
    .DESCRIPTION
        Vuln ID    : V-220333
        STIG ID    : UBTU-16-030910
        Rule ID    : SV-220333r610931_rule
        CCI ID     : CCI-001240
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The system must update the DoD-approved virus scan program every seven days or more frequently.
        DiscussMD5 : 3B806C72336FB98138C2867FBC6BF7CF
        CheckMD5   : BDD34289282F38AB71FF1C476FC93442
        FixMD5     : 53CF066753692FAD00BC11B49A08ADB8
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    # Date checking has been ommited from this implementation.
    # If desired, this functionality can be added by processing $Finding_3.
    $Finding = $(systemctl status nails)
    $Finding_2 = ""
    $Finding_3 = ""

    If ($Finding -match "Active: active") {
        $Finding_3 = $(ls -al /opt/NAI/LinuxShield/engine/dat/*.dat)
        $FindingMessage = "'nails' is active."
    }
    Else {
        $Finding_2 = $(systemctl status clamav-daemon.socket)

        If ($Finding_2 -match "Active: active") {
            $Finding_3 = $(grep -l databasedirectory /etc/clamav.conf)
            $FindingMessage = "'nails' is not active but 'clamav-daemon.socket' is active."
        }
        Else {
            $FindingMessage = "'nails' is not active and 'clamav-daemon.socket' is not active."
        }
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String

    $FindingDetails += $Finding | Out-String

    If ($Finding_2) {
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        $FindingDetails += $Finding_2 | Out-String
    }

    If ($Finding_3) {
        $FindingDetails += "-----------------------------------------------------------------------" | Out-String
        $FindingDetails += $Finding_3 | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V233624 {
    <#
    .DESCRIPTION
        Vuln ID    : V-233624
        STIG ID    : UBTU-16-030401
        Rule ID    : SV-233624r610931_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-OS-000480-GPOS-00227
        Rule Title : The Ubuntu operating system SSH daemon must prevent remote hosts from connecting to the proxy display.
        DiscussMD5 : FA989F66C162065549A2E9C6154F6848
        CheckMD5   : 15BB9971E2D6C13AF588EEAE151225DC
        FixMD5     : BAC33FE3ADB72AF0B0B142F1F498B3F5
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Finding = $(grep -i x11uselocalhost /etc/ssh/sshd_config)

    If ($Finding -match "^X11UseLocalHost([\s]+)yes$") {
        $Status = "NotAFinding"
        $FindingMessage = "The SSH daemon prevents remote hosts from connecting to the proxy display."
    }
    Else {
        $Status = "Open"
        $FindingMessage = "The SSH daemon does not prevent remote hosts from connecting to the proxy display."
    }

    $FindingDetails += $FindingMessage | Out-String
    $FindingDetails += "-----------------------------------------------------------------------" | Out-String
    $FindingDetails += $Finding | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA/yPGTS//V5l6x
# TUC2qKe10wnGdBlrQgawrO5mTqLwWqCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAvex2XKDbtWq4CkT2lU3cFJKRiZ8mF
# wnEteVMYjZnDAzANBgkqhkiG9w0BAQEFAASCAQDECQBcVY5JMvYU6FUc2IHUQXhi
# 4htGgwO4a4Ad01KuvKKxX3si7bFPSaQtJBrNmFR4IIl/G1WhVjW6k7dP0dYyfl5L
# zcdgUvA1g6xdqsWn+oW5D8HRCcCZ7wi3iWd8ZbGf8nH4SmCLOwHevBbWsR906n/x
# CxkQ0F+++DXUa4OuQcLzVx1R7T3eoYPcuOlvsvJgeqL59eCzm/TyYhmXSdK4tjm5
# oegYemBI/2Yxnkvr5pEIJrlaDf3YJ6NHUHVdIQ0g7MNRwR5TWN5HIIjU5X9ueASM
# EyKrDpGiCNPxF7gHDK5Cnyg8r3vJ3BDza09EvGHQz+UoM+vYsjOLN8ie2vd7
# SIG # End signature block
