##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Microsoft Exchange 2016 Mailbox Server
# Version:  V2R6
# Class:    UNCLASSIFIED
# Updated:  5/13/2024
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V228354 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228354
        STIG ID    : EX16-MB-000010
        Rule ID    : SV-228354r879526_rule
        CCI ID     : CCI-001403
        Rule Name  : SRG-APP-000027
        Rule Title : Exchange must have Administrator audit logging enabled.
        DiscussMD5 : D7E7E59275A6D8AF333B531806FA103C
        CheckMD5   : 648795C8DE25D509BDE92E8201539856
        FixMD5     : 312C845FC8305CA68BDED52AC0E230FB
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "AdminAuditLogEnabled"
    $ExpectedValue = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-AdminAuditLogConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-AdminAuditLogConfig}"
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

Function Get-V228355 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228355
        STIG ID    : EX16-MB-000020
        Rule ID    : SV-228355r879530_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033
        Rule Title : Exchange servers must use approved DoD certificates.
        DiscussMD5 : 00E3018C97548B4E8A97398EA63D2398
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
        $FindingDetails += "CertificateDomains:`t$($Item.CertificateDomains -join ', ')" | Out-String
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

Function Get-V228356 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228356
        STIG ID    : EX16-MB-000030
        Rule ID    : SV-228356r879533_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-APP-000038
        Rule Title : Exchange auto-forwarding email to remote domains must be disabled or restricted.
        DiscussMD5 : 781AEDD37EE45AF9D481BE84E730D44A
        CheckMD5   : 8B4B81FF83911D3E4E2865FE66E2AED5
        FixMD5     : 6837C20890AC7D51DF1E1D029EB8C456
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        $Setting = "AutoForwardEnabled"
        $ExpectedValue = $false
        $Compliant = $true

        If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
            Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
            $Result = Get-RemoteDomain
        }
        Else {
            $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-RemoteDomain}"
            $Result = Invoke-Expression $PSCommand
        }

        ForEach ($Item in $Result) {
            If ($Item.$($Setting) -eq $ExpectedValue -or $Item.DomainName -like "*.mil" -or $Item.DomainName -like "*.gov") {
                $FindingDetails += "$($Item.Name)" | Out-String
                $FindingDetails += "DomainName:`t`t`t$($Item.DomainName)" | Out-String
                $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
                $FindingDetails += "" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "$($Item.Name)" | Out-String
                $FindingDetails += "DomainName:`t`t`t$($Item.DomainName)" | Out-String
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
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V228357 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228357
        STIG ID    : EX16-MB-000040
        Rule ID    : SV-228357r879559_rule
        CCI ID     : CCI-000169
        Rule Name  : SRG-APP-000089
        Rule Title : Exchange Connectivity logging must be enabled.
        DiscussMD5 : 0EE448D821E37C4C6012FCEE5E847BD4
        CheckMD5   : 288286FAD11D862851731A58FB3ACA65
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

Function Get-V228358 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228358
        STIG ID    : EX16-MB-000050
        Rule ID    : SV-228358r879559_rule
        CCI ID     : CCI-000169
        Rule Name  : SRG-APP-000089
        Rule Title : The Exchange Email Diagnostic log level must be set to the lowest level.
        DiscussMD5 : 473AE2E7526B355A2894BD3712CA6AD9
        CheckMD5   : F87E14B47B1545457BA0ED795A62F682
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

Function Get-V228359 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228359
        STIG ID    : EX16-MB-000060
        Rule ID    : SV-228359r879559_rule
        CCI ID     : CCI-000169
        Rule Name  : SRG-APP-000089
        Rule Title : Exchange Audit record parameters must be set.
        DiscussMD5 : 83253204B7665273D18878F6F3E3089C
        CheckMD5   : D5CB7F69A38FBD0F5077DE09ADE0C15B
        FixMD5     : 98AE795B73409608065A3A8ED549D71D
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "AdminAuditLogParameters"
    $ExpectedValue = '*'

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-AdminAuditLogConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-AdminAuditLogConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    $FindingDetails += "$($Result.Name)" | Out-String
    If ([String]$Result.$($Setting) -eq $ExpectedValue) {
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

Function Get-V228360 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228360
        STIG ID    : EX16-MB-000070
        Rule ID    : SV-228360r879566_rule
        CCI ID     : CCI-000133
        Rule Name  : SRG-APP-000098
        Rule Title : Exchange Circular Logging must be disabled.
        DiscussMD5 : D68666A4A2B78DA8B24A685CDC9F94FD
        CheckMD5   : 66B7731B05B32C0C7320DB537EE0E575
        FixMD5     : 191DAFA7CB15B616894C57BF4AE8CE9A
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "CircularLoggingEnabled"
    $ExpectedValue = $false
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-MailboxDatabase -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-MailboxDatabase -Server $env:COMPUTERNAME}"
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

Function Get-V228361 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228361
        STIG ID    : EX16-MB-000080
        Rule ID    : SV-228361r879566_rule
        CCI ID     : CCI-000133
        Rule Name  : SRG-APP-000098
        Rule Title : Exchange Email Subject Line logging must be disabled.
        DiscussMD5 : 5F8852602FFA87A5BCC95CAD82C29AD2
        CheckMD5   : F58309E785A54C0C3B239E8BC0AFBA6B
        FixMD5     : BBE3FE4E12799CA980DC01D350BBB64B
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "MessageTrackingLogSubjectLoggingEnabled"
    $ExpectedValue = $false

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

Function Get-V228362 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228362
        STIG ID    : EX16-MB-000090
        Rule ID    : SV-228362r879566_rule
        CCI ID     : CCI-000133
        Rule Name  : SRG-APP-000098
        Rule Title : Exchange Message Tracking Logging must be enabled.
        DiscussMD5 : 7F36F0F615CE574A4C04DFEC9E0B7365
        CheckMD5   : D2AD11BE47DE13ED1989B9BAAE024FA0
        FixMD5     : 54ADEAC74292433804612364CB32F770
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "MessageTrackingLogEnabled"
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

Function Get-V228364 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228364
        STIG ID    : EX16-MB-000110
        Rule ID    : SV-228364r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Exchange Send Fatal Errors to Microsoft must be disabled.
        DiscussMD5 : 63B8960E07BB63A37DB686C6FA09D5EA
        CheckMD5   : ACDB27FB0BE7C39624A76ACFB38589C8
        FixMD5     : 57165FCB52A52FE6239E103BCCB0E126
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V228366 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228366
        STIG ID    : EX16-MB-000130
        Rule ID    : SV-228366r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Exchange must not send Customer Experience reports to Microsoft.
        DiscussMD5 : 38EDB27CC20F4CD40717FA071A14E426
        CheckMD5   : EBC59EFE86E8BC8D8433C82C45C29C67
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

Function Get-V228370 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228370
        STIG ID    : EX16-MB-000170
        Rule ID    : SV-228370r879584_rule
        CCI ID     : CCI-001749
        Rule Name  : SRG-APP-000131
        Rule Title : Exchange Local machine policy must require signed scripts.
        DiscussMD5 : C490A31FA1E551B26D64E9FBD5B21F9C
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

Function Get-V228371 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228371
        STIG ID    : EX16-MB-000180
        Rule ID    : SV-228371r944805_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : The Exchange Internet Message Access Protocol 4 (IMAP4) service must be disabled.
        DiscussMD5 : 628AAE7521B603AA8E52767364F337C9
        CheckMD5   : 1E1F176FC553576A865F539EB3D33750
        FixMD5     : 84ACD9FEBAC4EA10E7A2A5A47C62A89E
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Service = "MSExchangeIMAP4"
    $ExpectedValue = "Disabled"

    $Result = Get-Service $Service
    If ($Result.StartType -eq $ExpectedValue) {
        $Status = "NotAFinding"
        $FindingDetails += "Service:`t`t$($Service)" | Out-String
        $FindingDetails += "StartType:`t$($Result.StartType)" | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "Service:`t`t$($Service)" | Out-String
        $FindingDetails += "StartType:`t$($Result.StartType) [Expected $($ExpectedValue)]" | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V228372 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228372
        STIG ID    : EX16-MB-000190
        Rule ID    : SV-228372r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : The Exchange Post Office Protocol 3 (POP3) service must be disabled.
        DiscussMD5 : F4556FD8432C77CD765508F3AC73F37C
        CheckMD5   : 69EAF866D0BE0264BF3C116F377126C1
        FixMD5     : 8D4742F08659B80A1041398E9B0770F0
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Service = "MSExchangePOP3"
    $ExpectedValue = "Disabled"

    $Result = Get-Service $Service
    If ($Result.StartType -eq $ExpectedValue) {
        $Status = "NotAFinding"
        $FindingDetails += "Service:`t`t$($Service)" | Out-String
        $FindingDetails += "StartType:`t$($Result.StartType)" | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "Service:`t`t$($Service)" | Out-String
        $FindingDetails += "StartType:`t$($Result.StartType) [Expected $($ExpectedValue)]" | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V228374 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228374
        STIG ID    : EX16-MB-000210
        Rule ID    : SV-228374r879633_rule
        CCI ID     : CCI-001178
        Rule Name  : SRG-APP-000213
        Rule Title : Exchange Internet-facing Send connectors must specify a Smart Host.
        DiscussMD5 : 2C64C7E589CAF7CB03DF445027515708
        CheckMD5   : B2E25071AD69862B179CF44E476D2E6C
        FixMD5     : 4A03F644C2B0E7CB90E7D76D4EF9BB3D
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
            If (($Item.$($Prop1) | Measure-Object).Count -ge $ExpectedValue1) {
                $FindingDetails += "$($Item.Name)" | Out-String
                $FindingDetails += "$($Prop1):`t$($Item.$($Prop1) -join ', ')" | Out-String
                $FindingDetails += "" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "$($Item.Name)" | Out-String
                $FindingDetails += "$($Prop1):`tNULL [Expected IP address(s)]" | Out-String
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

Function Get-V228375 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228375
        STIG ID    : EX16-MB-000220
        Rule ID    : SV-228375r879636_rule
        CCI ID     : CCI-001184
        Rule Name  : SRG-APP-000219
        Rule Title : Exchange internal Receive connectors must require encryption.
        DiscussMD5 : BF3952CADC2133546889D6360A66B25E
        CheckMD5   : 0BDA229058EFEBA02B345EF57786767F
        FixMD5     : F45D2D2BBAF373A5ECCE6BE96603AEEE
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V228376 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228376
        STIG ID    : EX16-MB-000270
        Rule ID    : SV-228376r879642_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231
        Rule Title : Exchange Mailboxes must be retained until backups are complete.
        DiscussMD5 : ABE48E3B1B6C7E3CD0DB095A2D9CFAA2
        CheckMD5   : 68F57BAD37DFF13E199A2BE9F2AAA151
        FixMD5     : DC8F4FE4BE49778BA80FC574B6956A05
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "RetainDeletedItemsUntilBackup"
    $ExpectedValue = $true
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-MailboxDatabase -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-MailboxDatabase -Server $env:COMPUTERNAME}"
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

Function Get-V228377 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228377
        STIG ID    : EX16-MB-000290
        Rule ID    : SV-228377r879642_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231
        Rule Title : Exchange email forwarding must be restricted.
        DiscussMD5 : 8ADA80BE448544A4D8F355AD0D57EFB9
        CheckMD5   : A4AB9577EC70B527022E2264074DFA05
        FixMD5     : E7FF01CF1E089AC4D150FFB2CFB3F3AF
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "ForwardingSmtpAddress"

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-Mailbox -Server $env:COMPUTERNAME | Where-Object $Setting -NE $null
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-Mailbox -Server $env:COMPUTERNAME | Where-Object $Setting -ne " + '$null}'
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
        $FindingDetails += "No mailboxes have '$($Setting)' configured." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V228378 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228378
        STIG ID    : EX16-MB-000300
        Rule ID    : SV-228378r879642_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231
        Rule Title : Exchange email-forwarding SMTP domains must be restricted.
        DiscussMD5 : 8ADA80BE448544A4D8F355AD0D57EFB9
        CheckMD5   : 3C3C550426F9EF8228B48EF00EBFE5C8
        FixMD5     : 97E00F043CF76C0F63599616B8B24CD3
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "AutoForwardEnabled"
    $ExpectedValue = $false
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-RemoteDomain
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-RemoteDomain}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "DomainName:`t`t`t$($Item.DomainName)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "DomainName:`t`t`t$($Item.DomainName)" | Out-String
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

Function Get-V228379 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228379
        STIG ID    : EX16-MB-000310
        Rule ID    : SV-228379r879650_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246
        Rule Title : Exchange Mail quota settings must not restrict receiving mail.
        DiscussMD5 : FD779F73516216588046E02DF805433A
        CheckMD5   : 65F07A1A9AFEE4DA9140D40B9F8B73EB
        FixMD5     : BFC25ADE1D5AD184D39FDF4AC31896FB
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "ProhibitSendReceiveQuota"
    $Prop1 = "IsUnlimited"
    $ExpectedValue = $true
    $Prop2 = "Value"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-MailboxDatabase -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-MailboxDatabase -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting).$($Prop1) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting)" | Out-String
            $FindingDetails += "$($Prop1):`t$($Item.$($Setting).$($Prop1))" | Out-String
            $FindingDetails += "$($Prop2):`t`t$($Item.$($Setting).$($Prop2))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "$($Setting)" | Out-String
            $FindingDetails += "$($Prop1):`t$($Item.$($Setting).$($Prop1)) [Expected $($ExpectedValue)]" | Out-String
            $FindingDetails += "$($Prop2):`t`t$($Item.$($Setting).$($Prop2))" | Out-String
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

Function Get-V228380 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228380
        STIG ID    : EX16-MB-000320
        Rule ID    : SV-228380r879650_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246
        Rule Title : Exchange Mail Quota settings must not restrict receiving mail.
        DiscussMD5 : A47139F12E409CEB7FCEF1D7FDD3C969
        CheckMD5   : 4FFBED9F33B82BD287F6912629C746A5
        FixMD5     : 63579B80E808740699AAF850DD1F8CCD
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "ProhibitSendQuota"
    $Prop1 = "IsUnlimited"
    $Prop2 = "Value"

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-MailboxDatabase -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-MailboxDatabase -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        $FindingDetails += "$($Item.Name)" | Out-String
        $FindingDetails += "$($Setting)" | Out-String
        $FindingDetails += "$($Prop1):`t$($Item.$($Setting).$($Prop1))" | Out-String
        $FindingDetails += "$($Prop2):`t`t$($Item.$($Setting).$($Prop2))" | Out-String
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

Function Get-V228381 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228381
        STIG ID    : EX16-MB-000340
        Rule ID    : SV-228381r879650_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246
        Rule Title : Exchange Mailbox Stores must mount at startup.
        DiscussMD5 : 74DFB963DDF8D858DE59F488CFD1AD84
        CheckMD5   : A5755A20B7D02F3F17984B41D83B1C3E
        FixMD5     : 984B31052F3DDD6B8D821C66B82CBF08
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "MountAtStartup"
    $ExpectedValue = $true
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-MailboxDatabase -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-MailboxDatabase -Server $env:COMPUTERNAME}"
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

Function Get-V228382 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228382
        STIG ID    : EX16-MB-000350
        Rule ID    : SV-228382r879651_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange Message size restrictions must be controlled on Receive connectors.
        DiscussMD5 : 9951ACE287E5087F8F53452E3AE6CA95
        CheckMD5   : 7D3039530965789AFD55632061986DFD
        FixMD5     : FE0A2876B23605189737FDA1FE624BE5
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V228383 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228383
        STIG ID    : EX16-MB-000360
        Rule ID    : SV-228383r879651_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange Receive connectors must control the number of recipients per message.
        DiscussMD5 : 07EE6CDB75033DF4183F3B18625EE8B7
        CheckMD5   : 36A787AAA5360167777E3A6BE6D32B13
        FixMD5     : FAE6B29082C1564A53EA4256AEDA0D78
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V228384 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228384
        STIG ID    : EX16-MB-000380
        Rule ID    : SV-228384r879651_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : The Exchange Receive Connector Maximum Hop Count must be 60.
        DiscussMD5 : 3345C3E7E4BBB138498DD57CE442DC41
        CheckMD5   : 364BC5216998A476B6BB98EED78FAEC8
        FixMD5     : 029E41641E49446C1DD0A9873EAB7029
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V228385 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228385
        STIG ID    : EX16-MB-000410
        Rule ID    : SV-228385r879651_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange Message size restrictions must be controlled on Send connectors.
        DiscussMD5 : 11A3696D32E0DFA8A45DBB30AD1BA967
        CheckMD5   : DC0FF00B5DC172B61FEEFEC8DA6C5334
        FixMD5     : C293318D4C332476852974D86508C223
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V228386 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228386
        STIG ID    : EX16-MB-000420
        Rule ID    : SV-228386r879651_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : The Exchange Send connector connections count must be limited.
        DiscussMD5 : 7586C67BD80182A7B9DAA9C00F41E5CA
        CheckMD5   : 3808CFBC8B2DD167AB0F8C6BE57C314B
        FixMD5     : 908FB0647ECCBF2B378ED3AAEDBC8C25
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V228387 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228387
        STIG ID    : EX16-MB-000430
        Rule ID    : SV-228387r879651_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : The Exchange global inbound message size must be controlled.
        DiscussMD5 : 7E8DE36238F2ECD422C43DAB21992F82
        CheckMD5   : F4CE03B061A881249F79858AB9549F13
        FixMD5     : 4E75431D0120B7E9EF2DBCE6E3DC4C6E
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "MaxReceiveSize"
    $Prop1 = "IsUnlimited"
    $ExpectedValue1 = $false
    $Prop2 = "Value"
    $ExpectedValue2 = "10 MB (10,485,760 bytes)"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-TransportConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-TransportConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result.$($Setting).$($Prop1) -eq $ExpectedValue1 -and $Result.$($Setting).$($Prop2) -eq $ExpectedValue2) {
        $FindingDetails += "$($Setting)" | Out-String
        $FindingDetails += "$($Prop1):`t$($Result.$($Setting).$($Prop1))" | Out-String
        $FindingDetails += "$($Prop2):`t`t$($Result.$($Setting).$($Prop2))" | Out-String
    }
    Else {
        $Compliant = $false
        $FindingDetails += "$($Setting)" | Out-String
        If ($Result.$($Setting).$($Prop1) -eq $ExpectedValue1) {
            $FindingDetails += "$($Prop1):`t$($Result.$($Setting).$($Prop1))" | Out-String
        }
        Else {
            $FindingDetails += "$($Prop1):`t$($Result.$($Setting).$($Prop1)) [Expected $($ExpectedValue1)]" | Out-String
        }
        If ($Result.$($Setting).$($Prop2) -eq $ExpectedValue2) {
            $FindingDetails += "$($Prop2):`t`t$($Result.$($Setting).$($Prop2))" | Out-String
        }
        Else {
            $FindingDetails += "$($Prop2):`t`t$($Result.$($Setting).$($Prop2)) [Expected $($ExpectedValue2)]" | Out-String
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

Function Get-V228388 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228388
        STIG ID    : EX16-MB-000440
        Rule ID    : SV-228388r879651_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : The Exchange global outbound message size must be controlled.
        DiscussMD5 : E97B038C95761471073229E3CF06AB0E
        CheckMD5   : 9EE5AA0D7AD5E7582D6588D21E49063B
        FixMD5     : EBF1A6A56030DDA2561A91AAF6545210
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "MaxSendSize"
    $Prop1 = "IsUnlimited"
    $ExpectedValue1 = $false
    $Prop2 = "Value"
    $ExpectedValue2 = "10 MB (10,485,760 bytes)"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-TransportConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-TransportConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result.$($Setting).$($Prop1) -eq $ExpectedValue1 -and $Result.$($Setting).$($Prop2) -eq $ExpectedValue2) {
        $FindingDetails += "$($Setting)" | Out-String
        $FindingDetails += "$($Prop1):`t$($Result.$($Setting).$($Prop1))" | Out-String
        $FindingDetails += "$($Prop2):`t`t$($Result.$($Setting).$($Prop2))" | Out-String
    }
    Else {
        $Compliant = $false
        $FindingDetails += "$($Setting)" | Out-String
        If ($Result.$($Setting).$($Prop1) -eq $ExpectedValue1) {
            $FindingDetails += "$($Prop1):`t$($Result.$($Setting).$($Prop1))" | Out-String
        }
        Else {
            $FindingDetails += "$($Prop1):`t$($Result.$($Setting).$($Prop1)) [Expected $($ExpectedValue1)]" | Out-String
        }
        If ($Result.$($Setting).$($Prop2) -eq $ExpectedValue2) {
            $FindingDetails += "$($Prop2):`t`t$($Result.$($Setting).$($Prop2))" | Out-String
        }
        Else {
            $FindingDetails += "$($Prop2):`t`t$($Result.$($Setting).$($Prop2)) [Expected $($ExpectedValue2)]" | Out-String
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

Function Get-V228389 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228389
        STIG ID    : EX16-MB-000450
        Rule ID    : SV-228389r879651_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : The Exchange Outbound Connection Limit per Domain Count must be controlled.
        DiscussMD5 : 9F70EE2A9744B9D61EA9B2EA188FA809
        CheckMD5   : A6F27712D370B6AD9B38302AB07E47FC
        FixMD5     : EB44DFA834321CCAC1D424FC826689E2
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V228390 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228390
        STIG ID    : EX16-MB-000460
        Rule ID    : SV-228390r879651_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : The Exchange Outbound Connection Timeout must be 10 minutes or less.
        DiscussMD5 : 78305918324BDE5E13AB2D602FB221BD
        CheckMD5   : BAB49485D4256518040C26D71419C185
        FixMD5     : 53EA2E035B1625027E8336C3CE80734A
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V228391 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228391
        STIG ID    : EX16-MB-000470
        Rule ID    : SV-228391r879653_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange Internal Receive connectors must not allow anonymous connections.
        DiscussMD5 : F4AD9B977A52FA57F136F27346165AF8
        CheckMD5   : 52BA0CDF90B480C4014F20E6FEFA3465
        FixMD5     : 4E0E7E530F027A524113608F7F9BE8F9
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V228392 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228392
        STIG ID    : EX16-MB-000480
        Rule ID    : SV-228392r879653_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange external/Internet-bound automated response messages must be disabled.
        DiscussMD5 : BA431295FDFC67ABC0FE1B7BE57E7000
        CheckMD5   : 9B12D8732109567F2DB12D8818B12291
        FixMD5     : 0AA255DCF0754C209B53CC7C9A78307C
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "AllowedOOFType"
    $ExpectedValue = "InternalLegacy"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-RemoteDomain
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-RemoteDomain}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "DomainName:`t`t$($Item.DomainName)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "DomainName:`t`t$($Item.DomainName)" | Out-String
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

Function Get-V228393 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228393
        STIG ID    : EX16-MB-000490
        Rule ID    : SV-228393r879653_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange must have anti-spam filtering installed.
        DiscussMD5 : ED5CD700F5971BF04DC353203620D5B0
        CheckMD5   : 8E990DBD02826B5F43E2D9402F76F88A
        FixMD5     : F035CAFFC6B024DB8EB145CDAD5D4846
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V228394 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228394
        STIG ID    : EX16-MB-000500
        Rule ID    : SV-228394r879653_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange must have anti-spam filtering enabled.
        DiscussMD5 : ED5CD700F5971BF04DC353203620D5B0
        CheckMD5   : 360A1377E5600012EB10AA8EBA2F0F53
        FixMD5     : 829D185222E22011B0E4D0742A05A25E
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V228395 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228395
        STIG ID    : EX16-MB-000510
        Rule ID    : SV-228395r879653_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange must have anti-spam filtering configured.
        DiscussMD5 : ED5CD700F5971BF04DC353203620D5B0
        CheckMD5   : 4C4370D8314EC34AA78ACC80FB0377F3
        FixMD5     : 7B9F96A89A8485A7F136E51C9FF85AB5
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "InternalSmtpServers"
    $Prop = "Expression"

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-TransportConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-TransportConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result.$($Setting)) {
        $FindingDetails += "$($Setting):" | Out-String
        ForEach ($Item in $Result) {
            $FindingDetails += "$($Prop):`t$($Item.$($Setting).$($Prop))" | Out-String
        }
    }
    Else {
        $FindingDetails += "No internal SMTP servers are configured." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V228396 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228396
        STIG ID    : EX16-MB-000520
        Rule ID    : SV-228396r879653_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange must not send automated replies to remote domains.
        DiscussMD5 : 3A66BAAEB326AEDA70EDCFA3D09681B4
        CheckMD5   : BE082A5F08E8D1B1A7B0E4167242645A
        FixMD5     : 60772515A05CDAD616C9D6CAFF352221
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "AutoReplyEnabled"
    $ExpectedValue = $false
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-RemoteDomain
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-RemoteDomain}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue -or $Item.DomainName -like "*.mil" -or $Item.DomainName -like "*.gov") {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "DomainName:`t`t$($Item.DomainName)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "DomainName:`t`t$($Item.DomainName)" | Out-String
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

Function Get-V228398 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228398
        STIG ID    : EX16-MB-000540
        Rule ID    : SV-228398r879653_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : The Exchange Global Recipient Count Limit must be set.
        DiscussMD5 : 1789B84E7CFB923B1F0467E46D1A3D7A
        CheckMD5   : 6404EF04AD7208B64B1033BB49D40611
        FixMD5     : 81883EF706569C25C92C19252D04B5FB
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "MaxRecipientEnvelopeLimit"
    $Prop1 = "IsUnlimited"
    $ExpectedValue1 = $false
    $Prop2 = "Value"
    $ExpectedValue2 = "5000"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-TransportConfig
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-TransportConfig}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result.$($Setting).$($Prop1) -eq $ExpectedValue1 -and $Result.$($Setting).$($Prop2) -eq $ExpectedValue2) {
        $FindingDetails += "$($Setting)" | Out-String
        $FindingDetails += "$($Prop1):`t$($Result.$($Setting).$($Prop1))" | Out-String
        $FindingDetails += "$($Prop2):`t`t$($Result.$($Setting).$($Prop2))" | Out-String
    }
    Else {
        $Compliant = $false
        $FindingDetails += "$($Setting)" | Out-String
        If ($Result.$($Setting).$($Prop1) -eq $ExpectedValue1) {
            $FindingDetails += "$($Prop1):`t$($Result.$($Setting).$($Prop1))" | Out-String
        }
        Else {
            $FindingDetails += "$($Prop1):`t$($Result.$($Setting).$($Prop1)) [Expected $($ExpectedValue1)]" | Out-String
        }
        If ($Result.$($Setting).$($Prop2) -eq $ExpectedValue2) {
            $FindingDetails += "$($Prop2):`t`t$($Result.$($Setting).$($Prop2))" | Out-String
        }
        Else {
            $FindingDetails += "$($Prop2):`t`t$($Result.$($Setting).$($Prop2)) [Expected $($ExpectedValue2)]" | Out-String
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

Function Get-V228399 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228399
        STIG ID    : EX16-MB-000550
        Rule ID    : SV-228399r879673_rule
        CCI ID     : CCI-002361
        Rule Name  : SRG-APP-000295
        Rule Title : The Exchange Receive connector timeout must be limited.
        DiscussMD5 : DAF8D8C3ED08AA8F007DD1422909C09B
        CheckMD5   : 808243BB4250C6D13673DDF98251B8C3
        FixMD5     : EE5372FE75DDDD308221DB810648F253
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
    $ExpectedValue = (New-TimeSpan -Minutes 10)
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

Function Get-V228403 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228403
        STIG ID    : EX16-MB-000600
        Rule ID    : SV-228403r879756_rule
        CCI ID     : CCI-001762
        Rule Name  : SRG-APP-000383
        Rule Title : Exchange services must be documented and unnecessary services must be removed or disabled.
        DiscussMD5 : B046F856D8CF878D518D94DB40F9BAB9
        CheckMD5   : 9A9921B40F9F31749DAF6F9F0A1482FC
        FixMD5     : EE2AD2FCD05B0A3F6BD68B20EFDEA006
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V228404 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228404
        STIG ID    : EX16-MB-000610
        Rule ID    : SV-228404r879764_rule
        CCI ID     : CCI-001953
        Rule Name  : SRG-APP-000391
        Rule Title : Exchange Outlook Anywhere clients must use NTLM authentication to access email.
        DiscussMD5 : 3C0CE6717B65D1592AB0D2B7B6273514
        CheckMD5   : 5D601E2AE7CC4C2F9F419D7B0718D48F
        FixMD5     : 22C52CB9501A5DB6D0DFEF6496264767
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Settings = @("InternalClientAuthenticationMethod", "ExternalClientAuthenticationMethod")
    $ExpectedValue = "Ntlm"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-OutlookAnywhere -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-OutlookAnywhere -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        ForEach ($Item in $Result) {
            $FindingDetails += "$($Item.Identity)" | Out-String
            ForEach ($Setting in $Settings) {
                If ($Item.$($Setting) -eq $ExpectedValue) {
                    $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
                }
                Else {
                    $Compliant = $false
                    $FindingDetails += "$($Setting):`t$($Item.$($Setting)) [Expected $($ExpectedValue)]" | Out-String
                }
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

Function Get-V228406 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228406
        STIG ID    : EX16-MB-000630
        Rule ID    : SV-228406r879806_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-APP-000435
        Rule Title : Exchange must not send delivery reports to remote domains.
        DiscussMD5 : 3BEECA64F085E210E785CE4BE0A2C3DC
        CheckMD5   : C6CADCEB12843C1601EFA308A6F3544E
        FixMD5     : E39A51B4F1FB5DA82AA95DDB3646457B
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "DeliveryReportEnabled"
    $ExpectedValue = $false
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-RemoteDomain
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-RemoteDomain}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "DomainName:`t`t`t$($Item.DomainName)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "DomainName:`t`t`t$($Item.DomainName)" | Out-String
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

Function Get-V228407 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228407
        STIG ID    : EX16-MB-000640
        Rule ID    : SV-228407r879806_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-APP-000435
        Rule Title : Exchange must not send nondelivery reports to remote domains.
        DiscussMD5 : 68CCE93BFDD67A75267AB0D2C3D1A4B6
        CheckMD5   : 7BD035E8766D8A758C55FB314CAFD671
        FixMD5     : 71E2EA81D7951398FDBE590529910CE5
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "NDREnabled"
    $ExpectedValue = $false
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-RemoteDomain
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-RemoteDomain}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "DomainName:`t$($Item.DomainName)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "DomainName:`t$($Item.DomainName)" | Out-String
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

Function Get-V228408 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228408
        STIG ID    : EX16-MB-000650
        Rule ID    : SV-228408r879806_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-APP-000435
        Rule Title : The Exchange SMTP automated banner response must not reveal server details.
        DiscussMD5 : E8127649D9C7F46A697DE18B569818CA
        CheckMD5   : 5D8818C5CD7E524C655FDE15A7220B43
        FixMD5     : 63EB0C6E50A4528B289BD3325B32FC7E
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V228409 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228409
        STIG ID    : EX16-MB-000660
        Rule ID    : SV-228409r879806_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-APP-000435
        Rule Title : Exchange Internal Send connectors must use an authentication level.
        DiscussMD5 : 83C8E589D56DB3F7BBDE14195982BB41
        CheckMD5   : F7B2B68C2A80C0BEAF01D8AE5F159476
        FixMD5     : 0B9B3E8EF2AC297A1DE99D855015E194
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V228410 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228410
        STIG ID    : EX16-MB-000670
        Rule ID    : SV-228410r879806_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-APP-000435
        Rule Title : Exchange must provide Mailbox databases in a highly available and redundant configuration.
        DiscussMD5 : F8418FFCFF6D4ACB6F03A03330F38E5E
        CheckMD5   : BAEC169D3092DB41890477F24C19FFF4
        FixMD5     : FC616CFF4A9B50B7B5773FD5FE769F2D
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        $Result = Get-DatabaseAvailabilityGroup
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-DatabaseAvailabilityGroup}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        ForEach ($Item in $Result) {
            $FindingDetails += "$($Item.Name)" | Out-String
            $FindingDetails += "Servers:`t`t$($Item.Servers -join ', ')" | Out-String
            $FindingDetails += "WitnessServer:`t$($Item.WitnessServer)" | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $FindingDetails += "No Database Availability Groups are configured." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V228411 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228411
        STIG ID    : EX16-MB-000680
        Rule ID    : SV-228411r879827_rule
        CCI ID     : CCI-002605
        Rule Name  : SRG-APP-000456
        Rule Title : Exchange must have the most current, approved service pack installed.
        DiscussMD5 : 43B2767E8E7AE7F68AF2391194882B58
        CheckMD5   : CD11CE525AF5D1F528677C9333B15955
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

Function Get-V228412 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228412
        STIG ID    : EX16-MB-002870
        Rule ID    : SV-228412r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : The application must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.
        DiscussMD5 : F0559F63C6C5DAECFF8DF892CD54BB9D
        CheckMD5   : 7E1C6774FCA780933E37FE409D187E2A
        FixMD5     : 0DB00C0F81ABC0CF5A5C387822942E7B
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
        $Result = Get-WebSite | Where-Object Name -NE "Exchange Back End"
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebSite | Where-Object Name -ne 'Exchange Back End'}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        ForEach ($Item in $Result) {
            $FindingDetails += "$($Item.Name)" | Out-String
            ForEach ($Binding in $Item.bindings.Collection) {
                If ($Binding.protocol -in @("http", "https")) {
                    $Port = $Binding.bindingInformation -split ":"
                    If ($Port -contains "80" -or $Port -contains "443") {
                        $FindingDetails += "Binding:`t$($Binding.protocol) ($($Binding.bindingInformation))" | Out-String
                    }
                    Else {
                        $Compliant = $false
                        $FindingDetails += "Binding:`t$($Binding.protocol) ($($Binding.bindingInformation)) [Expected port 80 or 443]" | Out-String
                    }
                }
                Else {
                    $FindingDetails += "Binding:`t$($Binding.protocol) ($($Binding.bindingInformation))" | Out-String
                }
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
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V228413 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228413
        STIG ID    : EX16-MB-002880
        Rule ID    : SV-228413r879664_rule
        CCI ID     : CCI-001242
        Rule Name  : SRG-APP-000278
        Rule Title : The applications built-in Malware Agent must be disabled.
        DiscussMD5 : 7E1B8E98E9C2DCABBC8D9AE1116C7901
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

Function Get-V228415 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228415
        STIG ID    : EX16-MB-002900
        Rule ID    : SV-228415r879519_rule
        CCI ID     : CCI-000068
        Rule Name  : SRG-APP-000014
        Rule Title : Exchange must use encryption for RPC client access.
        DiscussMD5 : 71511A0DC7125D2E9F701DDBD01D9073
        CheckMD5   : 1D82C99E54835FB0DB26C7B271052812
        FixMD5     : 110F6A03ECD8C4F121C11E631F7919DC
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "EncryptionRequired"
    $ExpectedValue = $true
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-RpcClientAccess -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-RpcClientAccess -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Server)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Server)" | Out-String
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

Function Get-V228416 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228416
        STIG ID    : EX16-MB-002910
        Rule ID    : SV-228416r879519_rule
        CCI ID     : CCI-000068
        Rule Name  : SRG-APP-000014
        Rule Title : Exchange must use encryption for Outlook Web App (OWA) access.
        DiscussMD5 : CEF23EEEDA173590AFB58AD876C1AADF
        CheckMD5   : E5851B094580235909049EFCD8B67FE7
        FixMD5     : 9E9DE29E044C1B8CF38E68B977E3787E
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Settings = @("InternalUrl", "ExternalUrl")
    $Prop = "Scheme"
    $ExpectedValue = "https"
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-OwaVirtualDirectory -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-OwaVirtualDirectory -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        ForEach ($Setting in $Settings) {
            If ($Item.$($Setting).$($Prop)) {
                If ($Item.$($Setting).$($Prop) -eq $ExpectedValue) {
                    $FindingDetails += "$($Item.Name)" | Out-String
                    $FindingDetails += "$($Setting):`t$($Item.$($Setting).AbsoluteUri)" | Out-String
                    $FindingDetails += "" | Out-String
                }
                Else {
                    $Compliant = $false
                    $FindingDetails += "$($Item.Server)" | Out-String
                    $FindingDetails += "$($Setting):`t$($Item.$($Setting).AbsoluteUri) [Expected $($ExpectedValue)]" | Out-String
                    $FindingDetails += "" | Out-String
                }
            }
            Else {
                $FindingDetails += "$($Setting) is not configured." | Out-String
                $FindingDetails += "" | Out-String
            }
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

Function Get-V228417 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228417
        STIG ID    : EX16-MB-002920
        Rule ID    : SV-228417r879519_rule
        CCI ID     : CCI-000068
        Rule Name  : SRG-APP-000014
        Rule Title : Exchange must have forms-based authentication disabled.
        DiscussMD5 : 8695CEBDA48802FB0F201ABFA4360236
        CheckMD5   : 644CCC05BF181AF352118430669B4816
        FixMD5     : 80CA73A12D630E9F865C9276A1A27BC9
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "FormsAuthentication"
    $ExpectedValue = $false
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-OwaVirtualDirectory -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-OwaVirtualDirectory -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Server)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Server)" | Out-String
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

Function Get-V228418 {
    <#
    .DESCRIPTION
        Vuln ID    : V-228418
        STIG ID    : EX16-MB-002930
        Rule ID    : SV-228418r879530_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033
        Rule Title : Exchange must have authenticated access set to Integrated Windows Authentication only.
        DiscussMD5 : A46404F0F7F8763EC7F50D9BABEF7FA5
        CheckMD5   : 2DD3A2FFB3DF1DFB65DDF920A70D4401
        FixMD5     : E0FAC9C48DE69B9DC5438BB811EE8197
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Setting = "WindowsAuthentication"
    $ExpectedValue = $true
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-OwaVirtualDirectory -Server $env:COMPUTERNAME
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-OwaVirtualDirectory -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand
    }

    ForEach ($Item in $Result) {
        If ($Item.$($Setting) -eq $ExpectedValue) {
            $FindingDetails += "$($Item.Server)" | Out-String
            $FindingDetails += "$($Setting):`t$($Item.$($Setting))" | Out-String
            $FindingDetails += "" | Out-String
        }
        Else {
            $Compliant = $false
            $FindingDetails += "$($Item.Server)" | Out-String
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

# SIG # Begin signature block
# MIIL+QYJKoZIhvcNAQcCoIIL6jCCC+YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBfQvVH2pQ8oj71
# r2C0f4Vpr0N5lrA/rRFEZs+5iMRD7KCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCMW0ovsStjgBJfdfbm3BudNcnT9b7b
# bq16Hjwgiqlx4TANBgkqhkiG9w0BAQEFAASCAQCmm2+9MVuhkhmW2yO0XG/yIcUv
# xdra9zMI9vPCE7ZezvRcbJS/nuMQNs86q4xaZz1K8YEpVG23TTCWpMpGoPpi06kr
# dtB7efwOfiKG8vK32KO65VmP8DXIR/+RwKS1xaASEsDgaj6IPjKCvrWjMQXaPCHM
# mWaV2vN+MekDQpb3jd0D8Fi72W+b19xw/9xAkg7i2157OpTe0UWCfQTqYGz9YGKI
# CAkH2Xfgn0p0YoUBYOyBF9z8AJnS0WZT9oCFXj9HCzDuWZp/OuikyLEBa2Fzdf95
# jtwNcvkZIKqzPqIZRB0ABpDqQCC4Ua1uKLYpHLwblb+QnoD2ttfyW6P/SHM4
# SIG # End signature block
