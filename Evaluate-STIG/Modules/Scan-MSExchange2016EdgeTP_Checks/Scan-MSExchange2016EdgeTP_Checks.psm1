##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Microsoft Exchange 2016 Edge Transport Server
# Version:  V2R5
# Class:    UNCLASSIFIED
# Updated:  5/13/2024
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V221202 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221202
        STIG ID    : EX16-ED-000010
        Rule ID    : SV-221202r879511_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001
        Rule Title : Exchange must limit the Receive connector timeout.
        DiscussMD5 : 3A6A9CDC408FC53CC361A3956F39943D
        CheckMD5   : D79C736EC48461D31C9E6EBF6764646A
        FixMD5     : D8C5DB17504BD8C6C651E1A79687E732
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "ConnectionTimeout"
    $ExpectedValue = (New-TimeSpan -Minutes 5)
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ReceiveConnector -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ReceiveConnector -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting).ToString())" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting).ToString()) [Expected $($ExpectedValue.ToString())]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V221203 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221203
        STIG ID    : EX16-ED-000020
        Rule ID    : SV-221203r879530_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033
        Rule Title : Exchange servers must use approved DoD certificates.
        DiscussMD5 : A46404F0F7F8763EC7F50D9BABEF7FA5
        CheckMD5   : E2CDFBCD6170D9B039A2F3A1F4041983
        FixMD5     : A1E4AEC7D1140D9E47DF60C12BC01271
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ExchangeCertificate -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ExchangeCertificate -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        $FindingDetails += "CertificateDomains:`t$($Item.CertificateDomains -join ", ")" | Out-String
        If ($Item.Issuer -like "CN=DoD*") {
            $FindingDetails += "Issuer:`t`t`t$($Item.Issuer)" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "Issuer:`t`t`t$($Item.Issuer) [Not DoD issued]" | Out-String
        }
        $FindingDetails += "Services:`t`t`t$($Item.Services)" | Out-String
        $FindingDetails += "NotAfter:`t`t`t$($Item.NotAfter)" | Out-String
        $FindingDetails += "Thumbprint:`t`t$($Item.Thumbprint)" | Out-String
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

Function Get-V221204 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221204
        STIG ID    : EX16-ED-000030
        Rule ID    : SV-221204r879533_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-APP-000038
        Rule Title : Exchange must have accepted domains configured.
        DiscussMD5 : A8524B443A7AC0372E30A3BE2F17FC61
        CheckMD5   : 8E0C81196D3E5A7BEC7DDF398ED4D27F
        FixMD5     : 83541EC9DF181E3A5514F15210323E80
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "Default"
    $ExpectedValue = $true
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-AcceptedDomain
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-AcceptedDomain}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        ForEach ($Item in $Result) {
            If ($Item.$($Setting) -eq $ExpectedValue) {
                $FindingDetails += "$($Item.Name)" | Out-String
                $FindingDetails += "DomainName:`t$($Item.DomainName)" | Out-String
                $FindingDetails += "$($Setting):`t`t$($Item.$($Setting))" | Out-String
                $FindingDetails += "" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "$($Item.Name)" | Out-String
                $FindingDetails += "DomainName:`t$($Item.DomainName)" | Out-String
                $FindingDetails += "$($Setting):`t`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
                $FindingDetails += "" | Out-String
            }
        }
    }
    Else {
        $FindingDetails += "No Accepted Domains configured." | Out-String
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

Function Get-V221206 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221206
        STIG ID    : EX16-ED-000050
        Rule ID    : SV-221206r879533_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-APP-000038
        Rule Title : Exchange external Receive connectors must be domain secure-enabled.
        DiscussMD5 : 2A32652445C2F110A5F0979840C9C6CC
        CheckMD5   : 03C884290807ECE14E6AD3110317B4F4
        FixMD5     : 91584D0A35A25F89C57E2C874803E404
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "DomainSecureEnabled"
    $ExpectedValue = $true
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ReceiveConnector -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ReceiveConnector -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($ExpectedValue -in ($Item.$($Setting) -split (",\s*"))) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Missing $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V221207 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221207
        STIG ID    : EX16-ED-000060
        Rule ID    : SV-221207r879559_rule
        CCI ID     : CCI-000169
        Rule Name  : SRG-APP-000089
        Rule Title : The Exchange email Diagnostic log level must be set to the lowest level.
        DiscussMD5 : B10BF8289E53BAD47468C80424907243
        CheckMD5   : 4CC9C9662D56DFA4E64C0F0D5ED96ECF
        FixMD5     : CDBB57C9F68248841C6F05166849CFD4
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "EventLevel"
    $ExpectedValue = "Lowest"

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-EventLogLevel | Where-Object $Setting -NE $ExpectedValue
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-EventLogLevel | Where-Object $Setting -ne $ExpectedValue}"
        $Result = Invoke-Expression $PSCommand
    }

    If (-Not($Result)) {
        $Status = "NotAFinding"
        $FindingDetails += "All Event Log Levels configured to 'Lowest'." | Out-String
    }
    Else {
        $Status = "Open"
        ForEach ($Item in $Result) {
            $FindingDetails += "$($Item.Identity)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
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

Function Get-V221208 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221208
        STIG ID    : EX16-ED-000070
        Rule ID    : SV-221208r879559_rule
        CCI ID     : CCI-000169
        Rule Name  : SRG-APP-000089
        Rule Title : Exchange Connectivity logging must be enabled.
        DiscussMD5 : 2686005CA57567B8C789ECC308F2BEFE
        CheckMD5   : 2544FE11DEDCEE0B20C3AA9FBB36E686
        FixMD5     : 4BC914DB69FACEA034DC40775B0B56B4
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "ConnectivityLogEnabled"
    $ExpectedValue = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-TransportService -Identity $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-TransportService -Identity $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    $FindingDetails += "$($Result.Name)" | Out-String
    If ($Result.$($Setting) -eq $ExpectedValue) {
        $Status = "NotAFinding"
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V221210 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221210
        STIG ID    : EX16-ED-000090
        Rule ID    : SV-221210r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Exchange must not send Customer Experience reports to Microsoft.
        DiscussMD5 : 2C3DA62503E1E73100E5D785925B0350
        CheckMD5   : A002B9FF20AE9120F167A76D63ABC6FB
        FixMD5     : 368B432D3D3B021A647C9C53618EC3D6
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "CustomerFeedbackEnabled"
    $ExpectedValue = $false

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-OrganizationConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-OrganizationConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    $FindingDetails += "$($Result.Name)" | Out-String
    If ($Result.$($Setting) -eq $ExpectedValue) {
        $Status = "NotAFinding"
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V221212 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221212
        STIG ID    : EX16-ED-000110
        Rule ID    : SV-221212r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Exchange Send Fatal Errors to Microsoft must be disabled.
        DiscussMD5 : FCC656892161A952D886D8BA576EA11B
        CheckMD5   : C1DA38D0D7CA0E0779CBEFEB59ECE9E3
        FixMD5     : 328B1CA82E4C3EAE3C5CC041B49797E3
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "ErrorReportingEnabled"
    $ExpectedValue = $false
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ExchangeServer -Status
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ExchangeServer -Status}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V221216 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221216
        STIG ID    : EX16-ED-000150
        Rule ID    : SV-221216r879584_rule
        CCI ID     : CCI-001749
        Rule Name  : SRG-APP-000131
        Rule Title : The Exchange local machine policy must require signed scripts.
        DiscussMD5 : 0AEB844FF0B48F5DF784972A52930E03
        CheckMD5   : 1AAE5F0FA62879C1FEADBD104F9C0846
        FixMD5     : FBEB285BB912E78495AC9875BBA198C6
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "ExecutionPolicy"
    $ExpectedValue = "RemoteSigned"

    $Result = Get-ExecutionPolicy

    If ($Result -eq $ExpectedValue) {
        $Status = "NotAFinding"
        $FindingDetails += "$($Setting):`t$($Result)" | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "$($Setting):`t$($Result) [Expected $($ExpectedValue)]" | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V221217 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221217
        STIG ID    : EX16-ED-000160
        Rule ID    : SV-221217r879633_rule
        CCI ID     : CCI-001178
        Rule Name  : SRG-APP-000213
        Rule Title : Exchange Internet-facing Send connectors must specify a Smart Host.
        DiscussMD5 : 2C64C7E589CAF7CB03DF445027515708
        CheckMD5   : 13A267A67585D9368B1A7B49BF4331E0
        FixMD5     : EB3379ED8A8889AF364B9159814F1483
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Prop1 = "SmartHosts"
    $ExpectedValue1 = 1
    $Prop2 = "DNSRoutingEnabled"
    $ExpectedValue2 = $false
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-SendConnector
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-SendConnector}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        ForEach ($Item in $Result) {
            If (($Item.$($Prop1) | Measure-Object).Count -ge $ExpectedValue1 -and $Item.$($Prop2) -eq $ExpectedValue2) {
                $FindingDetails += "$($Item.Name)" | Out-String
                $FindingDetails += "$($Prop1):`t`t`t$($Item.$($Prop1) -join ', ')" | Out-String
                $FindingDetails += "$($Prop2):`t$($Item.$($Prop2))" | Out-String
                $FindingDetails += "" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "$($Item.Name)" | Out-String
                If (($Item.$($Prop1) | Measure-Object).Count -ge $ExpectedValue1) {
                    $FindingDetails += "$($Prop1):`t`t`t$($Item.$($Prop1) -join ', ')" | Out-String
                }
                Else {
                    $FindingDetails += "$($Prop1):`t`t`tNULL [Expected IP address(s)]" | Out-String
                }
                If ($Item.$($Prop2) -eq $ExpectedValue2) {
                    $FindingDetails += "$($Prop2):`t$($Item.$($Prop2)) [Expected $($ExpectedValue2)]" | Out-String
                }
                $FindingDetails += "" | Out-String
            }
        }
    }
    Else {
        $FindingDetails += "No Send Connectors are configured." | Out-String
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

Function Get-V221218 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221218
        STIG ID    : EX16-ED-000170
        Rule ID    : SV-221218r879636_rule
        CCI ID     : CCI-001184
        Rule Name  : SRG-APP-000219
        Rule Title : Exchange internal Send connectors must use domain security (mutual authentication Transport Layer Security).
        DiscussMD5 : D9B1D4C960715BD103839C47BDECB351
        CheckMD5   : 1792EC6FCAEF8832E4D19C828EA5AAC0
        FixMD5     : EE7B0647186252D11DAB35D6047FAEB0
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Prop1 = "SmartHosts"
    $ExpectedValue1 = 1
    $Prop2 = "DomainSecureEnabled"
    $ExpectedValue2 = $false
    $Prop3 = "DNSRoutingEnabled"
    $ExpectedValue3 = $false
    $Prop4 = "RequireTLS"
    $ExpectedValue4 = $true
    $Prop5 = "TlsAuthLevel"
    $ExpectedValue5 = "DomainValidation"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-SendConnector
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-SendConnector}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        ForEach ($Item in $Result) {
            If (($Item.$($Prop1) | Measure-Object).Count -lt $ExpectedValue1) {
                $FindingDetails += "$($Item.Name)" | Out-String
                $FindingDetails += "$($Prop1):`t`t`tNULL" | Out-String
                If ($Item.$($Prop2) -eq $true) {
                    $FindingDetails += "$($Prop2):`t$($Item.$($Prop2))" | Out-String
                }
                Else {
                    $Compliant = $false
                    $FindingDetails += "$($Prop2):`t$($Item.$($Prop2)) [Expected True]" | Out-String
                }
                $FindingDetails += "" | Out-String
            }
            Else {
                $FindingDetails += "$($Item.Name)" | Out-String
                $FindingDetails += "$($Prop1):`t`t`t$($Item.$($Prop1) -join ', ')" | Out-String
                # Prop2
                If ($Item.$($Prop2) -eq $ExpectedValue2) {
                    $FindingDetails += "$($Prop2):`t$($Item.$($Prop2))" | Out-String
                }
                Else {
                    $Compliant = $false
                    $FindingDetails += "$($Prop2):`t$($Item.$($Prop2)) [Expected $($ExpectedValue2)]" | Out-String
                }

                # Prop3
                If ($Item.$($Prop3) -eq $ExpectedValue3) {
                    $FindingDetails += "$($Prop3):`t$($Item.$($Prop3))" | Out-String
                }
                Else {
                    $Compliant = $false
                    $FindingDetails += "$($Prop3):`t$($Item.$($Prop3)) [Expected $($ExpectedValue3)]" | Out-String
                }

                # Prop4
                If ($Item.$($Prop4) -eq $ExpectedValue4) {
                    $FindingDetails += "$($Prop4):`t`t`t$($Item.$($Prop4))" | Out-String
                }
                Else {
                    $Compliant = $false
                    $FindingDetails += "$($Prop4):`t`t`t$($Item.$($Prop4)) [Expected $($ExpectedValue4)]" | Out-String
                }

                # Prop5
                If ($Item.$($Prop5) -eq $ExpectedValue5) {
                    $FindingDetails += "$($Prop5):`t`t`t$($Item.$($Prop5))" | Out-String
                }
                Else {
                    $Compliant = $false
                    $FindingDetails += "$($Prop5):`t`t`t$($Item.$($Prop5)) [Expected $($ExpectedValue5)]" | Out-String
                }
                $FindingDetails += "" | Out-String
            }
        }
    }
    Else {
        $FindingDetails += "No Send Connectors are configured." | Out-String
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

Function Get-V221219 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221219
        STIG ID    : EX16-ED-000180
        Rule ID    : SV-221219r879636_rule
        CCI ID     : CCI-001184
        Rule Name  : SRG-APP-000219
        Rule Title : Exchange Internet-facing Receive connectors must offer Transport Layer Security (TLS) before using basic authentication.
        DiscussMD5 : D626D3B05EE3C969F3B46809EBBCCF92
        CheckMD5   : 298E10AE9319EDD638AE2A762D6C5E10
        FixMD5     : 0804D725F9944CBDE4891242B1BCEF3A
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "AuthMechanism"
    $ExpectedValue = "Tls, BasicAuth, BasicAuthRequireTLS"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ReceiveConnector -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ReceiveConnector -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V221220 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221220
        STIG ID    : EX16-ED-000190
        Rule ID    : SV-221220r879651_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange Outbound Connection Timeout must be 10 minutes or less.
        DiscussMD5 : 6133E5ADD44568F414B29551EA60B9D3
        CheckMD5   : 965BB9AC162625979CD4927A9927F926
        FixMD5     : 3DEC88BA07122BA1A88C385FAAFE74DA
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "ConnectionInactivityTimeOut"
    $ExpectedValue = (New-TimeSpan -Minutes 10)
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-SendConnector
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-SendConnector}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        ForEach ($Item in $Result) {
            If ($Result.$($Setting) -eq $ExpectedValue) {
                $FindingDetails += "$($Item.Name)" | Out-String
                $FindingDetails += "$($Setting):`t$($Item.$($Setting).ToString())" | Out-String
                $FindingDetails += "" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "$($Item.Name)" | Out-String
                $FindingDetails += "$($Setting):`t$($Item.$($Setting).ToString()) [Expected $($ExpectedValue.ToString())]" | Out-String
                $FindingDetails += "" | Out-String
            }
        }
    }
    Else {
        $FindingDetails += "No Send Connectors are configured." | Out-String
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

Function Get-V221221 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221221
        STIG ID    : EX16-ED-000200
        Rule ID    : SV-221221r879651_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange Outbound Connection Limit per Domain Count must be controlled.
        DiscussMD5 : 31914511CAFBDE8237E406B6C0F66C68
        CheckMD5   : E576CA020893F54C62ACBCA7DB7CAD70
        FixMD5     : 4E44A0A48128F2AE903D3E66830E49F2
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "MaxPerDomainOutboundConnections"
    $ExpectedValue = "20"

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-TransportService -Identity $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-TransportService -Identity $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    $FindingDetails += "$($Result.Name)" | Out-String
    If ($Result.$($Setting) -eq $ExpectedValue) {
        $Status = "NotAFinding"
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
    }
    Else {
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V221222 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221222
        STIG ID    : EX16-ED-000230
        Rule ID    : SV-221222r879651_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange Send connector connections count must be limited.
        DiscussMD5 : 8476A7B70344F2B3FE334AEACC41884A
        CheckMD5   : 66E7FC2E1DA3004B99D730EB0D83084A
        FixMD5     : 324DD691C9FA2855F347CC36270F8435
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "MaxOutboundConnections"
    $ExpectedValue = "1000"

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-TransportService -Identity $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-TransportService -Identity $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    $FindingDetails += "$($Result.Name)" | Out-String
    If ($Result.$($Setting) -eq $ExpectedValue) {
        $Status = "NotAFinding"
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
    }
    Else {
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V221223 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221223
        STIG ID    : EX16-ED-000240
        Rule ID    : SV-221223r879651_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange message size restrictions must be controlled on Send connectors.
        DiscussMD5 : E04E0A6F630E993BC1C6F4D0B9FDF591
        CheckMD5   : 4262C0109783FB1F4A92E693EED28BB5
        FixMD5     : A8F6718BDF8EACD33D1661BEB3CE6312
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "MaxMessageSize"

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-SendConnector
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-SendConnector}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        ForEach ($Item in $Result) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "No Send Connectors are configured." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V221224 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221224
        STIG ID    : EX16-ED-000250
        Rule ID    : SV-221224r879651_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange Send connectors delivery retries must be controlled.
        DiscussMD5 : 0F6D46CA29EF879CDDC053D8721FFC16
        CheckMD5   : 8B11A63C71FC3A5DDBDC90EB1621ECD2
        FixMD5     : 59B9F5DD9E51681F68C52A46EAD5581D
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "TransientFailureRetryCount"
    $ExpectedValue = "10"

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-TransportService -Identity $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-TransportService -Identity $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    $FindingDetails += "$($Result.Name)" | Out-String
    If ($Result.$($Setting) -le $ExpectedValue) {
        $Status = "NotAFinding"
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
    }
    Else {
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V221225 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221225
        STIG ID    : EX16-ED-000260
        Rule ID    : SV-221225r879651_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange Send connectors must be clearly named.
        DiscussMD5 : 67DF70916310FB25FEC546BA1C095DBA
        CheckMD5   : 2AC7E0198015BA2810183403DE08AC0C
        FixMD5     : D6F047F66DEFD6F606D1E6BB31274F48
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "Identity"

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-SendConnector
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-SendConnector}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        ForEach ($Item in $Result) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "No Send Connectors are configured." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V221226 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221226
        STIG ID    : EX16-ED-000270
        Rule ID    : SV-221226r879651_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange Receive connector Maximum Hop Count must be 60.
        DiscussMD5 : F9D1C75F8FB7963500B7F8EF5CAB327F
        CheckMD5   : 670A3460F8EFCEE7728D295E4E802C14
        FixMD5     : F8009DDCB45C766FE3C8E09716B0C7B2
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "MaxHopCount"
    $ExpectedValue = "60"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ReceiveConnector -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ReceiveConnector -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V221227 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221227
        STIG ID    : EX16-ED-000280
        Rule ID    : SV-221227r879651_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange Receive connectors must be clearly named.
        DiscussMD5 : BAA427210337A0BE0117C4B461ED0E2F
        CheckMD5   : 22BD0731667057847D9C2FA09ED5C48C
        FixMD5     : 056320E9477AC88001D43D23A2E06429
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "Identity"

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ReceiveConnector -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ReceiveConnector -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        $FindingDetails += "$($Item.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
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

Function Get-V221228 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221228
        STIG ID    : EX16-ED-000290
        Rule ID    : SV-221228r879651_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange Receive connectors must control the number of recipients chunked on a single message.
        DiscussMD5 : FE42DBF45976427028C7AF493CB362F8
        CheckMD5   : BB5BA8F8E1495E9128363FE3EB9A5FE9
        FixMD5     : 2FAE7A4BAF8314D29454EF7C278B2B9D
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "ChunkingEnabled"
    $ExpectedValue = $true
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ReceiveConnector -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ReceiveConnector -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V221229 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221229
        STIG ID    : EX16-ED-000300
        Rule ID    : SV-221229r879651_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange Receive connectors must control the number of recipients per message.
        DiscussMD5 : 8262B45347879AFCDDD6924D3AE56FD7
        CheckMD5   : 8E685B2BBF2250071FFA934021D588DC
        FixMD5     : 96757735C32723205ED3CA646EDF654A
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "MaxRecipientsPerMessage"
    $ExpectedValue = "5000"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ReceiveConnector -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ReceiveConnector -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V221230 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221230
        STIG ID    : EX16-ED-000310
        Rule ID    : SV-221230r879651_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : The Exchange Internet Receive connector connections count must be set to default.
        DiscussMD5 : DEFCA339AF2B476D90D73F58A36CE9DC
        CheckMD5   : 7254EAF0EE2D004A71D0B49FCA744B94
        FixMD5     : 02ABC3620B7FC3A7FCA803EF9592EBD1
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "MaxInboundConnection"
    $ExpectedValue = "5000"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ReceiveConnector -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ReceiveConnector -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V221231 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221231
        STIG ID    : EX16-ED-000320
        Rule ID    : SV-221231r879651_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange Message size restrictions must be controlled on Receive connectors.
        DiscussMD5 : 56B7585F5048A1B06E4356E471537716
        CheckMD5   : AC8C0E1E4D64B9777A35296C4A2FB063
        FixMD5     : F9781CDD34A1DB0FD07D427B1664DEC6
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "MaxMessageSize"

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ReceiveConnector -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ReceiveConnector -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        $FindingDetails += "$($Item.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
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

Function Get-V221232 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221232
        STIG ID    : EX16-ED-000330
        Rule ID    : SV-221232r879653_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange messages with a blank sender field must be rejected.
        DiscussMD5 : 7D7104DF5F35EA2707531EAED1D12E6F
        CheckMD5   : E11C5F59AF8F2250FF8CCFB0B9311891
        FixMD5     : 5570A6933C9754C8F787B8135E5D67E4
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -in "Classified") {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA."
    }
    Else {
        $Setting = "Action"
        $ExpectedValue = "Reject"

        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
            $Result = Get-SenderFilterConfig
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-SenderFilterConfig}"
            $Result = Invoke-Expression $PSCommand
        }

        $FindingDetails += "$($Result.Name)" | Out-String
        If ($Result.$($Setting) -eq $ExpectedValue) {
            $Status = "NotAFinding"
            $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
        }
        Else {
            $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
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

Function Get-V221233 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221233
        STIG ID    : EX16-ED-000340
        Rule ID    : SV-221233r879653_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange messages with a blank sender field must be filtered.
        DiscussMD5 : 4E6B9FD906E7B0141E75DDD990A83DD3
        CheckMD5   : 7D5AD74B7C608D6C5327A53CDE4CF5FD
        FixMD5     : 957CD444425835EEF2A840F8CBE00C52
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -in "Classified") {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA."
    }
    Else {
        $Setting = "BlankSenderBlockingEnabled"
        $ExpectedValue = $true

        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
            $Result = Get-SenderFilterConfig
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-SenderFilterConfig}"
            $Result = Invoke-Expression $PSCommand
        }

        $FindingDetails += "$($Result.Name)" | Out-String
        If ($Result.$($Setting) -eq $ExpectedValue) {
            $Status = "NotAFinding"
            $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
        }
        Else {
            $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
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

Function Get-V221234 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221234
        STIG ID    : EX16-ED-000350
        Rule ID    : SV-221234r879653_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange filtered messages must be archived.
        DiscussMD5 : 0CAF09E8EE3C8EB9CCBCEEEBB71E66B6
        CheckMD5   : 2AFC18D0679033E05FC429CF76CE940D
        FixMD5     : 1B3E33A6A7866329CB9A934F06242266
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "QuarantineMailbox"

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ContentFilterConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ContentFilterConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result.$($Setting)) {
        $Status = "NotAFinding"
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
    }
    Else {
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`tNULL [Exepected SMTP address]" | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V221235 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221235
        STIG ID    : EX16-ED-000360
        Rule ID    : SV-221235r879653_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : The Exchange Sender filter must block unaccepted domains.
        DiscussMD5 : 20FBFC9250B6B11E0B71D490E96CB586
        CheckMD5   : 46EF70E6C5EA8B2CEBEECF7A2E206906
        FixMD5     : 62B6E6B20D52BB555E00AD8F34B4187B
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Prop1 = "BlockedDomains"
    $Prop2 = "BlockedDomainsAndSubdomains"

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-SenderFilterConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ContentFilterConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    $FindingDetails += "$($Result.Name)" | Out-String
    $FindingDetails += "$($Prop1):`t`t`t`t$($Result.$($Prop1) -join ', ')" | Out-String
    $FindingDetails += "$($Prop2):`t$($Result.$($Prop2) -join ', ')" | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V221236 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221236
        STIG ID    : EX16-ED-000370
        Rule ID    : SV-221236r879653_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange nonexistent recipients must not be blocked.
        DiscussMD5 : 22603C9F312B12FDBA595FB2F1D06E0A
        CheckMD5   : 217F4FBCC31C2ADE2B942F2E87E3683A
        FixMD5     : D12A6832DBCE5C50DDB6283F75413E07
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "RecipientValidationEnabled"
    $ExpectedValue = $false
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-RecipientFilterConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-RecipientFilterConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result.$($Setting) -eq $ExpectedValue) {
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Compliant = $false
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
        $FindingDetails += "" | Out-String
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

Function Get-V221237 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221237
        STIG ID    : EX16-ED-000380
        Rule ID    : SV-221237r879653_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : The Exchange Sender Reputation filter must be enabled.
        DiscussMD5 : D8C1596C7088C5653ACB25CCB1F9AB63
        CheckMD5   : 16A94835EC1E74E1A38A477A91FFF074
        FixMD5     : 74697A62784F7167BC2FD27412B11EE5
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "Enabled"
    $ExpectedValue = $true
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-SenderReputationConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-SenderReputationConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result.$($Setting) -eq $ExpectedValue) {
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Compliant = $false
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
        $FindingDetails += "" | Out-String
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

Function Get-V221238 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221238
        STIG ID    : EX16-ED-000390
        Rule ID    : SV-221238r879653_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : The Exchange Sender Reputation filter must identify the spam block level.
        DiscussMD5 : 1D5E15312DA0FEB89E0A03339614F988
        CheckMD5   : 4E7E4C4A2D9E6A11652BB7CCEDBC6CF6
        FixMD5     : 73061ECCF171EBE4E9EAE8CD22AC8544
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "SrlBlockThreshold"
    $ExpectedValue = 6
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-SenderReputationConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-SenderReputationConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result.$($Setting) -eq $ExpectedValue) {
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Compliant = $false
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
        $FindingDetails += "" | Out-String
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

Function Get-V221239 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221239
        STIG ID    : EX16-ED-000400
        Rule ID    : SV-221239r879653_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange Attachment filtering must remove undesirable attachments by file type.
        DiscussMD5 : E1076A93DE38404DD846A71FACC2492F
        CheckMD5   : 335273916AE0EAF16197FBFCA62B7B42
        FixMD5     : F1B6B2C001894EB61CF6481A6C30FAE3
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-AttachmentFilterEntry
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-AttachmentFilterEntry}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        ForEach ($Item in $Result) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "Type:`t$($Item.Type)" | Out-String
            $FindingDetails += "Identity:`t$($Item.Identity)" | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $FindingDetails += "No Attachment Filters are configured." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V221240 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221240
        STIG ID    : EX16-ED-000410
        Rule ID    : SV-221240r879653_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : The Exchange Spam Evaluation filter must be enabled.
        DiscussMD5 : A9D7A0A225475668A1E0B93529448036
        CheckMD5   : C80D9A9CBA864258B6102F888E48D86C
        FixMD5     : 65B6F8CC483C204CD049FA4F37CA5DC5
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "Enabled"
    $ExpectedValue = $true
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ContentFilterConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ContentFilterConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result.$($Setting) -eq $ExpectedValue) {
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Compliant = $false
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
        $FindingDetails += "" | Out-String
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

Function Get-V221241 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221241
        STIG ID    : EX16-ED-000420
        Rule ID    : SV-221241r879653_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : The Exchange Block List service provider must be identified.
        DiscussMD5 : 1E024C706B869C466AED611848B3566D
        CheckMD5   : F71429150FF17C3644E5876DE0F128EB
        FixMD5     : 482E4B33AFE363419067A55187219F3B
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Prop1 = "Name"
    $Prop2 = "GUID"
    $Prop3 = "LookupDomain"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ReceiveConnector -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ReceiveConnector -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        ForEach ($Item in $Result) {
            If ($null -ne $Result.$($Prop1) -and $null -ne $Result.$($Prop2) -and $null -ne $Result.$($Prop3)) {
                $FindingDetails += "$($Prop1):`t`t`t$($Item.$($Prop1))" | Out-String
                $FindingDetails += "$($Prop2):`t`t`t$($Item.$($Prop2))" | Out-String
                $FindingDetails += "$($Prop3):`t$($Item.$($Prop3))" | Out-String
                $FindingDetails += "" | Out-String
            }
            Else {
                $Compliant = $false
                If ($null -ne $Result.$($Prop1)) {
                    $FindingDetails += "$($Prop1):`t`t`t$($Item.$($Prop1))" | Out-String
                }
                Else {
                    $FindingDetails += "$($Prop1):`t`t`t$($Item.$($Prop1)) [Not Configured]" | Out-String
                }
                If ($null -ne $Result.$($Prop2)) {
                    $FindingDetails += "$($Prop2):`t`t`t$($Item.$($Prop2))" | Out-String
                }
                Else {
                    $FindingDetails += "$($Prop2):`t`t`t$($Item.$($Prop2)) [Not Configured]" | Out-String
                }
                If ($null -ne $Result.$($Prop3)) {
                    $FindingDetails += "$($Prop3):`t$($Item.$($Prop3))" | Out-String
                }
                Else {
                    $FindingDetails += "$($Prop3):`t$($Item.$($Prop3)) [Not Configured]" | Out-String
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
    Else {
        $Status = "Not_Applicable"
        $FindingDetails += "No service providers configured so this requirement is NA." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V221242 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221242
        STIG ID    : EX16-ED-000430
        Rule ID    : SV-221242r879653_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange messages with a malformed From address must be rejected.
        DiscussMD5 : E2BCAD00F509BEDE4EE155B6160F76CD
        CheckMD5   : E6461777DA0B4D52A9B78B2AAA838A9A
        FixMD5     : D0DB25075E2246743CD276DEACFCF53C
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "SpoofedDomainAction"
    $ExpectedValue = "Reject"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-SenderIdConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-SenderIdConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result.$($Setting) -eq $ExpectedValue) {
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Compliant = $false
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
        $FindingDetails += "" | Out-String
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

Function Get-V221243 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221243
        STIG ID    : EX16-ED-000470
        Rule ID    : SV-221243r879653_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : The Exchange Recipient filter must be enabled.
        DiscussMD5 : 41145D407731C155F4CE9DF0D90A3863
        CheckMD5   : CAD8B01815E3344A581AB3D061782693
        FixMD5     : 816D457806318D79B50336E8109A7051
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "Enabled"
    $ExpectedValue = $true
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-RecipientFilterConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-RecipientFilterConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result.$($Setting) -eq $ExpectedValue) {
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Compliant = $false
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
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

Function Get-V221244 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221244
        STIG ID    : EX16-ED-000480
        Rule ID    : SV-221244r879653_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : The Exchange tarpitting interval must be set.
        DiscussMD5 : 26B8AEA395D3F446590E542825D00DD8
        CheckMD5   : 655B63815F3A2498E820488179F284F6
        FixMD5     : EE6E44BD8D96148D318C8A4839202339
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "TarpitInterval"
    $ExpectedValue = (New-TimeSpan -Seconds 5)
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ReceiveConnector -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ReceiveConnector -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -ge $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting).ToString())" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting).ToString()) [Expected $($ExpectedValue.ToString())]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V221245 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221245
        STIG ID    : EX16-ED-000490
        Rule ID    : SV-221245r879653_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange internal Receive connectors must not allow anonymous connections.
        DiscussMD5 : C85BE3F2F97A2B1D9C462CDCE615AF1A
        CheckMD5   : BE9447215A00E5FB16F95808E85EE64A
        FixMD5     : A1A6EDB4D42655A5908D16B5F350CB2C
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "PermissionGroups"
    $ExpectedValue = "AnonymousUsers"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ReceiveConnector -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ReceiveConnector -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($ExpectedValue -notin ($Item.$($Setting) -split (",\s*"))) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Found $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V221246 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221246
        STIG ID    : EX16-ED-000500
        Rule ID    : SV-221246r879653_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange Simple Mail Transfer Protocol (SMTP) IP Allow List entries must be empty.
        DiscussMD5 : 878C813D243D7ADE9EC054972023C9E8
        CheckMD5   : 32FE69313DE627FBE0F0FCFDD80E78C0
        FixMD5     : 0793B6AE9D8E525FAF32CC2AB77E7C33
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-IPAllowListEntry -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-IPAllowListEntry -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        $Compliant = $false
        ForEach ($Item in $Result) {
            $FindingDetails += "Identity:`t$($Item.Identity)" | Out-String
            $FindingDetails += "IPRange:`t$($Item.IPRange)" | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $FindingDetails += "No entries configured in the SMTP IP Allow List." | Out-String
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

Function Get-V221247 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221247
        STIG ID    : EX16-ED-000510
        Rule ID    : SV-221247r879653_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : The Exchange Simple Mail Transfer Protocol (SMTP) IP Allow List Connection filter must be enabled.
        DiscussMD5 : 878C813D243D7ADE9EC054972023C9E8
        CheckMD5   : F478830C5CFA452319EEB31083673F28
        FixMD5     : ADEE0C2A9FC969539C09C7C14AFCD779
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "Enabled"
    $ExpectedValue = $true
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-IPAllowListConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-IPAllowListConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result.$($Setting) -eq $ExpectedValue) {
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Compliant = $false
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
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

Function Get-V221248 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221248
        STIG ID    : EX16-ED-000520
        Rule ID    : SV-221248r879653_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : The Exchange Simple Mail Transfer Protocol (SMTP) Sender filter must be enabled.
        DiscussMD5 : B7E045435CFF3667EBFFFC7E857B2158
        CheckMD5   : 32476D412F6A04C52D8AB108379A2CD7
        FixMD5     : 674C11505F79BB13311FF425D5036E73
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -in "Classified") {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA."
    }
    Else {
        $Setting = "Enabled"
        $ExpectedValue = $true
        $Compliant = $true

        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
            $Result = Get-SenderFilterConfig
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-SenderFilterConfig}"
            $Result = Invoke-Expression $PSCommand
        }

        If ($Result.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Result.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Result.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
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

Function Get-V221249 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221249
        STIG ID    : EX16-ED-000530
        Rule ID    : SV-221249r879653_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange must have antispam filtering installed.
        DiscussMD5 : 6EA27D50EC19C49E8167E7475E7B043F
        CheckMD5   : 21B743C311905513E8AC842B9647BE58
        FixMD5     : 54B6B5462636DF8CF4F00A63F58C6C5F
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ContentFilterConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ContentFilterConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        $Status = "NotAFinding"
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "Enabled:`t$($Result.Enabled)" | Out-String
    }
    Else {
        $FindingDetails += "No Content Filter is configured." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V221250 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221250
        STIG ID    : EX16-ED-000540
        Rule ID    : SV-221250r879653_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange must have antispam filtering enabled.
        DiscussMD5 : 6EA27D50EC19C49E8167E7475E7B043F
        CheckMD5   : 6BD0F95DF1250B9E7E88C720BD8D2C25
        FixMD5     : 6961D074F31AD630BFE8FD63F7CC387F
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "Enabled"
    $ExpectedValue = $true
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = New-Object System.Collections.Generic.List[System.Object]
        $Commands = @("Get-ContentFilterConfig | Select-Object Name,Enabled", "Get-SenderFilterConfig | Select-Object Name,Enabled", "Get-SenderIDConfig | Select-Object Name,Enabled", "Get-SenderReputationConfig | Select-Object Name,Enabled")
        ForEach ($Command in $Commands) {
            $Ouput = Invoke-Expression $Command
            $NewObj = [PSCustomObject]@{
                Name    = $($Ouput.Name)
                Enabled = $($Ouput.Enabled)
            }
            $Result.Add($NewObj)
        }
    }
    Else {
        $PSCommand = 'PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; $Result = New-Object System.Collections.Generic.List[System.Object]; $Commands = @("Get-ContentFilterConfig | Select-Object Name,Enabled", "Get-SenderFilterConfig | Select-Object Name,Enabled", "Get-SenderIDConfig | Select-Object Name,Enabled", "Get-SenderReputationConfig | Select-Object Name,Enabled"); ForEach ($Command in $Commands) {$Ouput = Invoke-Expression $Command; $NewObj = [PSCustomObject]@{Name = $($Ouput.Name); Enabled = $($Ouput.Enabled)}; $Result.Add($NewObj)}; Return $Result}'
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V221252 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221252
        STIG ID    : EX16-ED-000560
        Rule ID    : SV-221252r879653_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange Sender Identification Framework must be enabled.
        DiscussMD5 : 90A3C2904E3D61EBF619C95540E583E4
        CheckMD5   : D805417B0C9C09BC915BD82B607C28B0
        FixMD5     : 16C779F307D157CA6A24EDE523F859EA
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "Enabled"
    $ExpectedValue = $true
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-SenderIdConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-SenderIdConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result.$($Setting) -eq $ExpectedValue) {
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting))" | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Compliant = $false
        $FindingDetails += "$($Result.Name)" | Out-String
        $FindingDetails += "$($Setting):`t$($Result.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
        $FindingDetails += "" | Out-String
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

Function Get-V221253 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221253
        STIG ID    : EX16-ED-000570
        Rule ID    : SV-221253r879653_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange must render hyperlinks from email sources from non-.mil domains as unclickable.
        DiscussMD5 : 02BD06527905826DA17EA83EEB47B8FE
        CheckMD5   : 382AEA8821F75E6FA8B2B9A9134E0524
        FixMD5     : D1DF2314AE7882E40C2E62BF2CB534E6
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    If ($ScanType -in "Classified") {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V221256 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221256
        STIG ID    : EX16-ED-000610
        Rule ID    : SV-221256r879756_rule
        CCI ID     : CCI-001762
        Rule Name  : SRG-APP-000383
        Rule Title : Exchange services must be documented and unnecessary services must be removed or disabled.
        DiscussMD5 : 4717FAD2D62C9D78AE98DDFC56C2584B
        CheckMD5   : FA203BBA7AE2BA9EA3FEEAB7667C9AE2
        FixMD5     : 4A3DC499C534BC73A7CAF63A7C3FE187
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    ForEach ($Item in Get-Service) {
        $FindingDetails += "ServiceName:`t$($Item.Name)" | Out-String
        $FindingDetails += "Displayname:`t$($Item.DisplayName)" | Out-String
        $FindingDetails += "Status:`t`t$($Item.Status)" | Out-String
        $FindingDetails += "StartType:`t$($Item.StartType)" | Out-String
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

Function Get-V221258 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221258
        STIG ID    : EX16-ED-000630
        Rule ID    : SV-221258r879806_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-APP-000435
        Rule Title : The Exchange SMTP automated banner response must not reveal server details.
        DiscussMD5 : 96F1A14F4333D8DC18D54712D663EE92
        CheckMD5   : 7739B6D9AD1AD2D756B29306B522DC07
        FixMD5     : CABACA64EC098B0805BE0740873EB7F5
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "Banner"
    $ExpectedValue = "220 SMTP Server Ready"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ReceiveConnector -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ReceiveConnector -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V221259 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221259
        STIG ID    : EX16-ED-000660
        Rule ID    : SV-221259r879806_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000435
        Rule Title : Exchange must provide redundancy.
        DiscussMD5 : 381F3FAF974B3122C40A93319734ECC3
        CheckMD5   : 92C7E811F3C2EDB3D0ECA4B64271CF68
        FixMD5     : 58C76D4B460C70829E9E4FD48ED3C8EB
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Result = Get-TransportService
    If (($Result | Measure-Object).Count -gt 1) {
        $Status = "NotAFinding"
        $FindingDetails += "Multiple Edge servers detected." | Out-String
        $FindingDetails += "" | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "Multiple Edge servers NOT detected." | Out-String
        $FindingDetails += "" | Out-String
    }

    ForEach ($Item in $Result) {
        $FindingDetails += "$($Item.Name)" | Out-String
        $FindingDetails += "ExchangeVersion:`t$($Item.ExchangeVersion)" | Out-String
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

Function Get-V221260 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221260
        STIG ID    : EX16-ED-000670
        Rule ID    : SV-221260r879806_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-APP-000435
        Rule Title : Exchange internal Send connectors must use an authentication level.
        DiscussMD5 : 83C8E589D56DB3F7BBDE14195982BB41
        CheckMD5   : C7E15AA1024106C4957EDB7A9C6697CB
        FixMD5     : CA314BE574DDF21EB5CF3440EA63CECA
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "TlsAuthLevel"
    $ExpectedValue = "DomainValidation"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-SendConnector
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-SendConnector}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        ForEach ($Item in $Result) {
            If ($Item.$($Setting) -eq $ExpectedValue) {
                $FindingDetails += "$($Item.Name)" | Out-String
                $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
                $FindingDetails += "" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "$($Item.Name)" | Out-String
                $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
                $FindingDetails += "" | Out-String
            }
        }
    }
    Else {
        $FindingDetails += "No Send Connectors are configured." | Out-String
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

Function Get-V221261 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221261
        STIG ID    : EX16-ED-000680
        Rule ID    : SV-221261r879810_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000439
        Rule Title : Exchange internal Receive connectors must require encryption.
        DiscussMD5 : B7DACF6D9D2197D7EFEAED47CBF7ACA8
        CheckMD5   : AE54A16A643278DD51D82C24C6AF1F13
        FixMD5     : 9F51B80AA01B21F34A02108507AFDDD8
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "AuthMechanism"
    $ExpectedValue = "Tls"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ReceiveConnector -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ReceiveConnector -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "" | Out-String
        }
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

Function Get-V221262 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221262
        STIG ID    : EX16-ED-000690
        Rule ID    : SV-221262r879810_rule
        CCI ID     : CCI-002418
        Rule Name  : SRG-APP-000439
        Rule Title : Exchange internal Send connectors must require encryption.
        DiscussMD5 : 83C8E589D56DB3F7BBDE14195982BB41
        CheckMD5   : 8CE7E541179B7C898CA770B886E289DC
        FixMD5     : 5939FA4ED97011B3709DDF0DBC861CB4
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Prop1 = "TlsDomain"
    $ExpectedValue1 = 1
    $Prop2 = "DomainSecureEnabled"
    $Prop3 = "SmartHosts"
    $ExpectedValue3 = 1
    $Prop4 = "RequireTLS"
    $ExpectedValue4 = $true
    $Prop5 = "TlsAuthLevel"
    $ExpectedValue5 = "DomainValidation"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-SendConnector
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-SendConnector}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        ForEach ($Item in $Result) {
            $FindingDetails += "$($Item.Name)" | Out-String
            If ($Item.$($Prop1)) {
                $FindingDetails += "$($Prop1):`t$($Item.$($Prop1))" | Out-String
                $FindingDetails += "$($Prop2):`t$($Item.$($Prop2))" | Out-String
                If ($Item.$($Prop2) -eq $true) {
                    If (($Item.$($Prop3) | Measure-Object).Count -ge $ExpectedValue3) {
                        $FindingDetails += "$($Prop3):`t$($Item.$($Prop3))" | Out-String
                    }
                    Else {
                        $Compliant = $false
                        $FindingDetails += "$($Prop3):`t$($Item.$($Prop3)) [Expected SmartHost(s)]" | Out-String
                    }
                }
                Else {
                    $FindingDetails += "$($Prop3):`t$($Item.$($Prop3))" | Out-String
                    If (($Item.$($Prop3) | Measure-Object).Count -ge $ExpectedValue3) {
                        $FindingDetails += "$($Prop3):`t$($Item.$($Prop3) -join ', ')" | Out-String
                        If ($Item.$($Prop4) -eq $ExpectedValue4) {
                            $FindingDetails += "$($Prop4):`t$($Item.$($Prop4))" | Out-String
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "$($Prop4):`t$($Item.$($Prop4)) [Expected $($ExpectedValue4)]" | Out-String
                        }
                        If ($Item.$($Prop5) -eq $ExpectedValue5) {
                            $FindingDetails += "$($Prop5):`t$($Item.$($Prop5))" | Out-String
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "$($Prop5):`t$($Item.$($Prop5)) [Expected $($ExpectedValue5)]" | Out-String
                        }
                    }
                }
            }
            Else {
                $Compliant = $false
                $FindingDetails += "$($Prop1):`t$($Item.$($Prop1)) [Expected SMTP Domain]" | Out-String
            }
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $FindingDetails += "No Send Connectors are configured." | Out-String
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

Function Get-V221263 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221263
        STIG ID    : EX16-ED-000700
        Rule ID    : SV-221263r879827_rule
        CCI ID     : CCI-002605
        Rule Name  : SRG-APP-000456
        Rule Title : Exchange must have the most current, approved service pack installed.
        DiscussMD5 : B4DDE5F2E0481135CB1E8D7FDAAE1DA9
        CheckMD5   : 3B9985489F8CD869ADA0E96640E13810
        FixMD5     : 07A93F7338BFE978775FFDD2E54B051B
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "AdminDisplayVersion"

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-ExchangeServer -Identity $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ExchangeServer -Identity $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        $FindingDetails += "$($Item.Name)" | Out-String
        $FindingDetails += "AdminDisplayVersion:`t$($Item.$($Setting))" | Out-String
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

Function Get-V221264 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221264
        STIG ID    : EX16-ED-000720
        Rule ID    : SV-221264r879663_rule
        CCI ID     : CCI-001241
        Rule Name  : SRG-APP-000277
        Rule Title : The application must configure malicious code protection mechanisms to perform periodic scans of the information system every seven days.
        DiscussMD5 : 00A2E73A96D98EA6AABA1C2DAF236682
        CheckMD5   : 19EE631BF1AA50991617A77E34DD2A5C
        FixMD5     : AE6D2D95FAAF5312789DF48BB556F7F2
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "Malware Agent"
    $Prop = "Enabled"
    $ExpectedValue = $false

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-TransportAgent $Setting
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-TransportAgent $Setting}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        If ($Result.$($Prop) -eq $ExpectedValue) {
            $Status = "NotAFinding"
            $FindingDetails += "$($Setting)" | Out-String
            $FindingDetails += "$($Prop):`t$($Result.$($Prop))" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "$($Setting)" | Out-String
            $FindingDetails += "$($Prop):`t$($Result.$($Prop)) [Expected $($ExpectedValue)]" | Out-String
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "Transport Agent $($Setting) is not detected." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V221266 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221266
        STIG ID    : EX16-ED-000750
        Rule ID    : SV-221266r879665_rule
        CCI ID     : CCI-001243
        Rule Name  : SRG-APP-000279
        Rule Title : The application must be configured to block and quarantine malicious code upon detection, then send an immediate alert to appropriate individuals.
        DiscussMD5 : 91943E615BAE43CBCD486821FC8F5763
        CheckMD5   : 19EE631BF1AA50991617A77E34DD2A5C
        FixMD5     : AE6D2D95FAAF5312789DF48BB556F7F2
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "Malware Agent"
    $Prop = "Enabled"
    $ExpectedValue = $false

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-TransportAgent $Setting
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-TransportAgent $Setting}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        If ($Result.$($Prop) -eq $ExpectedValue) {
            $Status = "NotAFinding"
            $FindingDetails += "$($Setting)" | Out-String
            $FindingDetails += "$($Prop):`t$($Result.$($Prop))" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "$($Setting)" | Out-String
            $FindingDetails += "$($Prop):`t$($Result.$($Prop)) [Expected $($ExpectedValue)]" | Out-String
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "Transport Agent $($Setting) is not detected." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V221268 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221268
        STIG ID    : EX16-ED-002400
        Rule ID    : SV-221268r879662_rule
        CCI ID     : CCI-001240
        Rule Name  : SRG-APP-000276
        Rule Title : The application must update malicious code protection mechanisms whenever new releases are available in accordance with organizational configuration management policy and procedures.
        DiscussMD5 : 502BC45F223FA99883CD2B913343DDEE
        CheckMD5   : 19EE631BF1AA50991617A77E34DD2A5C
        FixMD5     : AE6D2D95FAAF5312789DF48BB556F7F2
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "Malware Agent"
    $Prop = "Enabled"
    $ExpectedValue = $false

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-TransportAgent $Setting
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-TransportAgent $Setting}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        If ($Result.$($Prop) -eq $ExpectedValue) {
            $Status = "NotAFinding"
            $FindingDetails += "$($Setting)" | Out-String
            $FindingDetails += "$($Prop):`t$($Result.$($Prop))" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "$($Setting)" | Out-String
            $FindingDetails += "$($Prop):`t$($Result.$($Prop)) [Expected $($ExpectedValue)]" | Out-String
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "Transport Agent $($Setting) is not detected." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V221270 {
    <#
    .DESCRIPTION
        Vuln ID    : V-221270
        STIG ID    : EX16-ED-003010
        Rule ID    : SV-221270r879664_rule
        CCI ID     : CCI-001242
        Rule Name  : SRG-APP-000278
        Rule Title : The applications built-in Malware Agent must be disabled.
        DiscussMD5 : B544D29B685BFD1E99ABD96147BC95F0
        CheckMD5   : 19EE631BF1AA50991617A77E34DD2A5C
        FixMD5     : AE6D2D95FAAF5312789DF48BB556F7F2
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "Malware Agent"
    $Prop = "Enabled"
    $ExpectedValue = $false

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-TransportAgent $Setting
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-TransportAgent $Setting}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        If ($Result.$($Prop) -eq $ExpectedValue) {
            $Status = "NotAFinding"
            $FindingDetails += "$($Setting)" | Out-String
            $FindingDetails += "$($Prop):`t$($Result.$($Prop))" | Out-String
        }
        Else {
            $Status = "Open"
            $FindingDetails += "$($Setting)" | Out-String
            $FindingDetails += "$($Prop):`t$($Result.$($Prop)) [Expected $($ExpectedValue)]" | Out-String
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails += "Transport Agent $($Setting) is not detected." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBZlZDsf3XI9S6I
# Qmn4gOqZK4LxkfhIua14zIW81q0jvqCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCly8Y4RvCFLoHWNUvSiIGDui6LIeHt
# GBp70hvIW0foDDANBgkqhkiG9w0BAQEFAASCAQC+yPB2FgUIamt7+9WbYNJpPltF
# v3QJlWqthKaNw7nCaTbZQPY2YoExLj8zBeLSzA6YxCIot8b88mLJL1jf0cHKlg90
# QPjG7m0A3Gk77Xl1223u7q3U1/IV4XrydSu6VTeK1i/8BjprJfPNPYjYfN3sUA1X
# yHq8ELCeemzYPkr1YoW45JAEDz8EK07Q04a80WgGvq1/Rvu/qbHbxtfxy0TZhYBc
# UgYPkhyyuFheDOZrO50K+o5o+sthiVEn36rCqc1xRFDSb4zK+S/Yo9mjyTbSdqq4
# 3bxjqYsCFZjs1pO/vYnua3ltlO9UaCsp6dxQWgdwykP+dsspgH3E1HmDctLe
# SIG # End signature block
