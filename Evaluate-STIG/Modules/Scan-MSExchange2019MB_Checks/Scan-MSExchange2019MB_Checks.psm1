##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Microsoft Exchange 2019 Mailbox Server
# Version:  V1R1
# Class:    UNCLASSIFIED
# Updated:  5/13/2024
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V259645 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259645
        STIG ID    : EX19-MB-000006
        Rule ID    : SV-259645r942249_rule
        CCI ID     : CCI-000068
        Rule Name  : SRG-APP-000014
        Rule Title : Exchange must use encryption for RPC client access.
        DiscussMD5 : 71511A0DC7125D2E9F701DDBD01D9073
        CheckMD5   : A3A978CE5FBBE9C3D0A23ADEE7BA26AB
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

Function Get-V259646 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259646
        STIG ID    : EX19-MB-000007
        Rule ID    : SV-259646r942252_rule
        CCI ID     : CCI-000068
        Rule Name  : SRG-APP-000014
        Rule Title : Exchange must use encryption for Outlook Web App (OWA) access.
        DiscussMD5 : 488B81D2515E73566E8773339F2460F1
        CheckMD5   : 3C24CDC592158B925FF7C0A1AA829013
        FixMD5     : EEF131CAA1A7450B59A32B4F83897F3A
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
    $OpenFinding = $false

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-OwaVirtualDirectory -Server $env:COMPUTERNAME
        $IISCerts = Get-ExchangeCertificate | Where-Object Services -Match "IIS"
        $Access = Get-WebConfigurationProperty "/system.webServer/security/access" -PsPath "IIS:\Sites\Default Web Site\owa" -Name *
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-OwaVirtualDirectory -Server $env:COMPUTERNAME}"
        $Result = Invoke-Expression $PSCommand

        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-ExchangeCertificate | Where-Object Services -match 'IIS'}"
        $IISCerts = Invoke-Expression $PSCommand

        $PSCommand = "PowerShell.exe -Command {Import-Module WebAdministration; Get-WebConfigurationProperty '/system.webServer/security/access' -PsPath 'IIS:\Sites\Default Web Site\owa' -Name *}"
        $Access = Invoke-Expression $PSCommand
    }

    $FindingDetails += "IIS Service Certificates" | Out-String
    $FindingDetails += "---------------------------" | Out-String
    If ($IISCerts) {
        # Certs must be verified manually if trusted public
        ForEach ($Cert in $IISCerts) {
            $FindingDetails += "Subject:`t`t$($Cert.Subject)" | Out-String
            $FindingDetails += "Services:`t`t$($Cert.Services)" | Out-String
            $FindingDetails += "Thumbprint:`t$($Cert.Thumbprint)" | Out-String
            $FindingDetails += "Issuer:`t`t$($Cert.Issuer)" | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $OpenFinding = $true
        $FindingDetails += "No certs associated with the IIS service. [Expected trusted public certificate]" | Out-String
        $FindingDetails += "" | Out-String
    }

    $FindingDetails += "Get-OwaVirtualDirectory" | Out-String
    $FindingDetails += "---------------------------" | Out-String
    ForEach ($Item in $Result) {
        ForEach ($Setting in $Settings) {
            If ($Item.$($Setting).$($Prop)) {
                If ($Item.$($Setting).$($Prop) -eq $ExpectedValue) {
                    $FindingDetails += "$($Item.Name)" | Out-String
                    $FindingDetails += "$($Setting):`t$($Item.$($Setting).AbsoluteUri)" | Out-String
                }
                Else {
                    $OpenFinding = $true
                    $FindingDetails += "$($Item.Server)" | Out-String
                    $FindingDetails += "$($Setting):`t$($Item.$($Setting).AbsoluteUri) [Expected $($ExpectedValue)]" | Out-String
                }
            }
            Else {
                $FindingDetails += "$($Setting):`tNot configured." | Out-String
            }
        }
        $FindingDetails += "" | Out-String
    }

    $FindingDetails += "IIS: Default Web Site/owa" | Out-String
    $FindingDetails += "---------------------------" | Out-String
    $SslFlags = $Access.sslFlags -split ","
    If ("Ssl" -in $SslFlags) {
        $FindingDetails += "Require SSL is enabled"
    }
    Else {
        $OpenFinding = $true
        $FindingDetails += "Require SSL is NOT enabled [Expected enabled]" | Out-String
    }

    If ($OpenFinding -eq $true) {
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

Function Get-V259647 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259647
        STIG ID    : EX19-MB-000008
        Rule ID    : SV-259647r942255_rule
        CCI ID     : CCI-000068
        Rule Name  : SRG-APP-000014
        Rule Title : Exchange must have forms-based authentication enabled.
        DiscussMD5 : 539D5BB02B443D0FC4DDBF9DB60DA5CB
        CheckMD5   : 93DF3F0A939D43386D95CCAF30AF5E13
        FixMD5     : DEC479DB5BAEA92499ABFFDDA96FBA43
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259648 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259648
        STIG ID    : EX19-MB-000016
        Rule ID    : SV-259648r942258_rule
        CCI ID     : CCI-001403
        Rule Name  : SRG-APP-000027
        Rule Title : Exchange must have administrator audit logging enabled.
        DiscussMD5 : 0B9CE973443039D9BC8FF4FF01A6F095
        CheckMD5   : ACEAB97F3E5DA8A3AEC1DD2B17A0CA86
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

Function Get-V259649 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259649
        STIG ID    : EX19-MB-000019
        Rule ID    : SV-259649r942261_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033
        Rule Title : Exchange servers must use approved DOD certificates.
        DiscussMD5 : 00E3018C97548B4E8A97398EA63D2398
        CheckMD5   : 7E9F5ECA0C5F0319B167C5F3DB97A5C7
        FixMD5     : 389037395E34ADEBCBE0E8E65AEAA73C
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259650 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259650
        STIG ID    : EX19-MB-000020
        Rule ID    : SV-259650r942264_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033
        Rule Title : Exchange must have authenticated access set to integrated Windows authentication only.
        DiscussMD5 : 69744F197E45EEC6FF815F8FB2AA13F9
        CheckMD5   : 39280264DA835AEF6D513C8761A68250
        FixMD5     : 9133108E81B14C27892FB2FBA39BC590
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259651 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259651
        STIG ID    : EX19-MB-000021
        Rule ID    : SV-259651r942267_rule
        CCI ID     : CCI-001368
        Rule Name  : SRG-APP-000038
        Rule Title : Exchange auto-forwarding email to remote domains must be disabled or restricted.
        DiscussMD5 : 781AEDD37EE45AF9D481BE84E730D44A
        CheckMD5   : EB3D12F604D7C50031A03899248E941A
        FixMD5     : FBEB7A63E5E5C1C53E6C9A50E3230F4F
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259652 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259652
        STIG ID    : EX19-MB-000031
        Rule ID    : SV-259652r942270_rule
        CCI ID     : CCI-000169
        Rule Name  : SRG-APP-000089
        Rule Title : Exchange connectivity logging must be enabled.
        DiscussMD5 : 61E46637BF660DCE55EE9B9357C51203
        CheckMD5   : 3B70D9D9817AA62D3B3AE5B709926A78
        FixMD5     : 6596469A090A57F389EDA53392372AE2
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259653 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259653
        STIG ID    : EX19-MB-000032
        Rule ID    : SV-259653r942273_rule
        CCI ID     : CCI-000169
        Rule Name  : SRG-APP-000089
        Rule Title : The Exchange email diagnostic log level must be set to the lowest level.
        DiscussMD5 : 3CF7E39438FAAB38DE8397935D22C1FC
        CheckMD5   : 10100E33700C3137A81924AD2BA8D22C
        FixMD5     : E29F999007A3D4C66AB25F1856B38DE3
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259654 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259654
        STIG ID    : EX19-MB-000033
        Rule ID    : SV-259654r942276_rule
        CCI ID     : CCI-000169
        Rule Name  : SRG-APP-000089
        Rule Title : Exchange audit record parameters must be set.
        DiscussMD5 : FDB443B326B6EE1314D264A5E7B989E6
        CheckMD5   : 0EE5B6389CC12B88A191E134DCA0C81B
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

Function Get-V259655 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259655
        STIG ID    : EX19-MB-000034
        Rule ID    : SV-259655r942279_rule
        CCI ID     : CCI-000171
        Rule Name  : SRG-APP-000090
        Rule Title : The RBAC role for audit log management must be defined and restricted.
        DiscussMD5 : 0C079EFDC59B9E755EBC89FC1E114098
        CheckMD5   : B28D6231D82B25D812E49AFD04E5D035
        FixMD5     : 2F24C650FE81A108C5600A420B383C9F
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $RoleGroup = "Records Management"

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-RoleGroup $RoleGroup | Get-RoleGroupMember
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-RoleGroup $RoleGroup | Get-RoleGroupMember}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        $FindingDetails += "Members of role group '$RoleGroup':" | Out-String
        $FindingDetails += "---------------------------" | Out-String
        ForEach ($Item in $Result) {
            $FindingDetails += "Name:`t`t$($Item.Name)" | Out-String
            $FindingDetails += "RecipientType:`t$($Item.RecipientType)" | Out-String
            $FindingDetails += "" | Out-String
        }
    }
    Else {
        $FindingDetails += "Role group '$RoleGroup' contains no members." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V259656 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259656
        STIG ID    : EX19-MB-000040
        Rule ID    : SV-259656r942282_rule
        CCI ID     : CCI-000133
        Rule Name  : SRG-APP-000098
        Rule Title : Exchange email subject line logging must be disabled.
        DiscussMD5 : 2F69AC9C8CE7B0243A095FD293CBA055
        CheckMD5   : C520AA44A344DEAAA6C496158DA2535D
        FixMD5     : 542CF303F934C3D612BEB8FA3EF0D762
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259657 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259657
        STIG ID    : EX19-MB-000041
        Rule ID    : SV-259657r942285_rule
        CCI ID     : CCI-000133
        Rule Name  : SRG-APP-000098
        Rule Title : Exchange message tracking logging must be enabled.
        DiscussMD5 : 7F36F0F615CE574A4C04DFEC9E0B7365
        CheckMD5   : 069382B19A7DAAD6859D6B5163C514C7
        FixMD5     : 42BD511464C690C3CBF5092A9CC6E849
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259658 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259658
        STIG ID    : EX19-MB-000042
        Rule ID    : SV-259658r942288_rule
        CCI ID     : CCI-000133
        Rule Name  : SRG-APP-000098
        Rule Title : Exchange circular logging must be disabled.
        DiscussMD5 : 74E7B537D5E2C7F1870EBE53AAECE444
        CheckMD5   : 069F42F27B804CC6BBDF06134F4DD05F
        FixMD5     : 6ECD405E931F3C67B7579903FE6BA733
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259664 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259664
        STIG ID    : EX19-MB-000061
        Rule ID    : SV-259664r942306_rule
        CCI ID     : CCI-001749
        Rule Name  : SRG-APP-000131
        Rule Title : Exchange local machine policy must require signed scripts.
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

Function Get-V259665 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259665
        STIG ID    : EX19-MB-000063
        Rule ID    : SV-259665r942309_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Exchange Send Fatal Errors to Microsoft must be disabled.
        DiscussMD5 : 132968ACA1259D45DB145DD4C1C97FFA
        CheckMD5   : CBF1BD5B89336F2880BEEF512A59D9B2
        FixMD5     : 8999916DC5884649D8D2B485257CB1AF
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259666 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259666
        STIG ID    : EX19-MB-000064
        Rule ID    : SV-259666r942312_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : Exchange must not send customer experience reports to Microsoft.
        DiscussMD5 : 1C7E8F518305485F759695743171A445
        CheckMD5   : A7F9C512402FF54FD7004E2A0B1A52D8
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

Function Get-V259667 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259667
        STIG ID    : EX19-MB-000065
        Rule ID    : SV-259667r942315_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : The Exchange Internet Message Access Protocol 4 (IMAP4) service must be disabled.
        DiscussMD5 : 5B5D6B2BD27AD04F701D57DB75122F64
        CheckMD5   : CD7647838C7EAE3354F0957A061F753C
        FixMD5     : A75CEC82E443B30CAD72E90B93D787D4
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Services = @("MSExchangeIMAPBE", "MSExchangeIMAP4")
    $ExpectedValue = "Disabled"
    $Compliant = $true

    ForEach ($Service in $Services) {
        $Result = Get-Service $Service -ErrorAction SilentlyContinue
        If ($Result) {
            If ($Result.StartType -eq $ExpectedValue) {
                $Status = "NotAFinding"
                $FindingDetails += "Service:`t`t$($Service)" | Out-String
                $FindingDetails += "StartType:`t$($Result.StartType)" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "Service:`t`t$($Service)" | Out-String
                $FindingDetails += "StartType:`t$($Result.StartType) [Expected $($ExpectedValue)]" | Out-String
            }
        }
        Else {
            $FindingDetails += "Service:`t`t$($Service) [not installed]" | Out-String
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

Function Get-V259668 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259668
        STIG ID    : EX19-MB-000066
        Rule ID    : SV-259668r942318_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141
        Rule Title : The Exchange Post Office Protocol 3 (POP3) service must be disabled.
        DiscussMD5 : 3B3B18EE26D482B3FCC9F0EDCF88F844
        CheckMD5   : 57B984FEAC9136D14C8406759AEC7932
        FixMD5     : 776DA170BABDB40EA92E8B773BD98C79
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Services = @("MSExchangePop3", "MSExchangePOP3BE")
    $ExpectedValue = "Disabled"
    $Compliant = $true

    ForEach ($Service in $Services) {
        $Result = Get-Service $Service -ErrorAction SilentlyContinue
        If ($Result) {
            If ($Result.StartType -eq $ExpectedValue) {
                $Status = "NotAFinding"
                $FindingDetails += "Service:`t`t$($Service)" | Out-String
                $FindingDetails += "StartType:`t$($Result.StartType)" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "Service:`t`t$($Service)" | Out-String
                $FindingDetails += "StartType:`t$($Result.StartType) [Expected $($ExpectedValue)]" | Out-String
            }
        }
        Else {
            $FindingDetails += "Service:`t`t$($Service) [not installed]" | Out-String
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

Function Get-V259670 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259670
        STIG ID    : EX19-MB-000106
        Rule ID    : SV-259670r942324_rule
        CCI ID     : CCI-001178
        Rule Name  : SRG-APP-000213
        Rule Title : Exchange internet-facing send connectors must specify a smart host.
        DiscussMD5 : 1316182CA20AAE2D5ABC4E41A689B1D4
        CheckMD5   : 87883C7BF92553F3E1FD0C26AF44A784
        FixMD5     : F3F2CE29B91B616720B7BBE0DBC4E3FA
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259671 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259671
        STIG ID    : EX19-MB-000115
        Rule ID    : SV-259671r942327_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231
        Rule Title : Exchange mailboxes must be retained until backups are complete.
        DiscussMD5 : ABE48E3B1B6C7E3CD0DB095A2D9CFAA2
        CheckMD5   : D3F12DBFCABF7DF867DFF4B713858788
        FixMD5     : 930EF324D497012DDDBA1872506C58D5
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259672 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259672
        STIG ID    : EX19-MB-000116
        Rule ID    : SV-259672r942330_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231
        Rule Title : Exchange email forwarding must be restricted.
        DiscussMD5 : 418F2C1FBCC2404505489E7D954EC84C
        CheckMD5   : A992C91F6732A1DCFA5D82446113DBED
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

Function Get-V259673 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259673
        STIG ID    : EX19-MB-000117
        Rule ID    : SV-259673r942333_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231
        Rule Title : Exchange email-forwarding SMTP domains must be restricted.
        DiscussMD5 : 418F2C1FBCC2404505489E7D954EC84C
        CheckMD5   : 2AE55DCFEEA0643342BA39660F0F3F5E
        FixMD5     : 53844BE530BFB6A22B25A61B5154A8DF
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259674 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259674
        STIG ID    : EX19-MB-000121
        Rule ID    : SV-259674r942336_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246
        Rule Title : Exchange mailbox stores must mount at startup.
        DiscussMD5 : AD647F7C2F3214737081919E9D452C70
        CheckMD5   : 71E6EE2BA2D1FE577998C5940572D4C7
        FixMD5     : 8830F2AB6270F967A9C6835AFF2A8CCF
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259675 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259675
        STIG ID    : EX19-MB-000122
        Rule ID    : SV-259675r942339_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246
        Rule Title : Exchange mail quota settings must not restrict receiving mail.
        DiscussMD5 : 3A44D0AECAAA41A21A4DB0D32DBF9BA5
        CheckMD5   : 4B60FE8C76CE7309F73892F4D845E35D
        FixMD5     : 465059CAAD06C73833E3FCA351EB2A58
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259676 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259676
        STIG ID    : EX19-MB-000123
        Rule ID    : SV-259676r942342_rule
        CCI ID     : CCI-001094
        Rule Name  : SRG-APP-000246
        Rule Title : Exchange mail quota settings must not restrict sending mail.
        DiscussMD5 : 83A51864E0D5F1FF807BB7CD4038F12E
        CheckMD5   : B07AC38A4EEABEBD16A1D0E8581A3203
        FixMD5     : 95690A13C94A22856A25D4F8E77D6ABD
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259677 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259677
        STIG ID    : EX19-MB-000124
        Rule ID    : SV-259677r942345_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange Message size restrictions must be controlled on Receive connectors.
        DiscussMD5 : B31AED900611513796A3D54733216CF8
        CheckMD5   : BD0F7F9B1C805C09CF394919A904A7C1
        FixMD5     : A6A651161D55ECA031C51B66E7BF811F
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259678 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259678
        STIG ID    : EX19-MB-000125
        Rule ID    : SV-259678r942348_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : The Exchange Receive Connector Maximum Hop Count must be 60.
        DiscussMD5 : 0EE78E6A2CCB39CC09E4433207C08F95
        CheckMD5   : AE9EF0136B3FB3FA25FC81EAEF3FA2AC
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

Function Get-V259679 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259679
        STIG ID    : EX19-MB-000126
        Rule ID    : SV-259679r942351_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : The Exchange send connector connections count must be limited.
        DiscussMD5 : 7586C67BD80182A7B9DAA9C00F41E5CA
        CheckMD5   : 74AE99A58CC13A6F5DE6D72E516AC33D
        FixMD5     : 027513229E29B4FFE51844CDE0F7D4B9
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259680 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259680
        STIG ID    : EX19-MB-000127
        Rule ID    : SV-259680r942354_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange receive connectors must control the number of recipients per message.
        DiscussMD5 : B3C84056E1A4AE3C023B33CB3774F59D
        CheckMD5   : 1571AA9B864D4C1897CB6D3A489E9CD9
        FixMD5     : F4596A41393AD5EAA399EC221BEF8B15
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259681 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259681
        STIG ID    : EX19-MB-000128
        Rule ID    : SV-259681r942357_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : Exchange message size restrictions must be controlled on send connectors.
        DiscussMD5 : 11A3696D32E0DFA8A45DBB30AD1BA967
        CheckMD5   : 1BBE370BAF32772A441065BB95C6EBBD
        FixMD5     : 7504F3E880C6EE18933D2C3DD1E6AA7E
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259682 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259682
        STIG ID    : EX19-MB-000129
        Rule ID    : SV-259682r942360_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : The Exchange global inbound message size must be controlled.
        DiscussMD5 : 63EB25F4E47D2C8B11D505D9AA41F4CD
        CheckMD5   : CAC361C4D7C44F6302B179C5F5871792
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

Function Get-V259683 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259683
        STIG ID    : EX19-MB-000130
        Rule ID    : SV-259683r942363_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : The Exchange global outbound message size must be controlled.
        DiscussMD5 : D8CE56A2B88B63D7C73403629CA571CA
        CheckMD5   : FB20EF56C019F8B857517B667FEB0620
        FixMD5     : F96910E606BDF604498A3046EFF67F57
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259684 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259684
        STIG ID    : EX19-MB-000131
        Rule ID    : SV-259684r942366_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : The Exchange Outbound Connection Limit per Domain Count must be controlled.
        DiscussMD5 : 9F70EE2A9744B9D61EA9B2EA188FA809
        CheckMD5   : 931793C9026211FD430ADD4509674910
        FixMD5     : 6929CC1CEE0DBECDD9D9E8A9DC47694D
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259685 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259685
        STIG ID    : EX19-MB-000132
        Rule ID    : SV-259685r942369_rule
        CCI ID     : CCI-001095
        Rule Name  : SRG-APP-000247
        Rule Title : The Exchange Outbound Connection Timeout must be 10 minutes or less.
        DiscussMD5 : 27B066CBBB47BCBE2638D78198FDAD5D
        CheckMD5   : E52688EB26844EF5EA61B942FD2F0BFB
        FixMD5     : 9F1A13487214E9C5C0E58E65E7D585C8
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259687 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259687
        STIG ID    : EX19-MB-000135
        Rule ID    : SV-259687r942375_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange internal receive connectors must not allow anonymous connections.
        DiscussMD5 : 35B5BA0C74EED45745CD96D8D5155026
        CheckMD5   : 00132BFBE933AE19FCE40E6F89C036DB
        FixMD5     : 36F06634F1EB1F7F157A230ACF009B15
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259688 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259688
        STIG ID    : EX19-MB-000136
        Rule ID    : SV-259688r942378_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange external/internet-bound automated response messages must be disabled.
        DiscussMD5 : BA431295FDFC67ABC0FE1B7BE57E7000
        CheckMD5   : 5DA3AA88C7C2C67D18B970AC761968E8
        FixMD5     : E22AC0BFA974CF7195A3837857C43469
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259689 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259689
        STIG ID    : EX19-MB-000137
        Rule ID    : SV-259689r945436_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange must have anti-spam filtering installed.
        DiscussMD5 : C40AC7B50FA42D4CEE87741FEAC70E63
        CheckMD5   : B7AF44F2EEBF67C53CA5B64868680B85
        FixMD5     : 9AA0E4EC59D2CD3B958CD7A8F33DA8E3
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259690 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259690
        STIG ID    : EX19-MB-000138
        Rule ID    : SV-259690r942384_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange must have anti-spam filtering enabled.
        DiscussMD5 : C40AC7B50FA42D4CEE87741FEAC70E63
        CheckMD5   : CA29F27361047B8A5140564BABAEAEFF
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

Function Get-V259691 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259691
        STIG ID    : EX19-MB-000139
        Rule ID    : SV-259691r945438_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange must have anti-spam filtering configured.
        DiscussMD5 : C40AC7B50FA42D4CEE87741FEAC70E63
        CheckMD5   : FB7A66E11CC2E737A49EBD50B62A88EF
        FixMD5     : 093870E22D8274CA42D6E82C22554A7B
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259692 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259692
        STIG ID    : EX19-MB-000140
        Rule ID    : SV-259692r942390_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : Exchange must not send automated replies to remote domains.
        DiscussMD5 : 3A66BAAEB326AEDA70EDCFA3D09681B4
        CheckMD5   : 77FA30FF26FC26E8926B4375B2957CE9
        FixMD5     : E8BA9E1F7CC2B3F206CFF31AF0424C92
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259693 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259693
        STIG ID    : EX19-MB-000142
        Rule ID    : SV-259693r942393_rule
        CCI ID     : CCI-001308
        Rule Name  : SRG-APP-000261
        Rule Title : The Exchange Global Recipient Count Limit must be set.
        DiscussMD5 : C31D90608706EE82EC9DF173CDC01EF6
        CheckMD5   : 5E776AB130A4DA277AB99E826CEC56CD
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

Function Get-V259694 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259694
        STIG ID    : EX19-MB-000146
        Rule ID    : SV-259694r942396_rule
        CCI ID     : CCI-001247
        Rule Name  : SRG-APP-000272
        Rule Title : Exchange anti-malware agent must be enabled and configured.
        DiscussMD5 : 676A131E84400AA9B1FA40E02DF068EA
        CheckMD5   : EEB4532FFC592DE8813D6513BDDA3E1F
        FixMD5     : 3C530BA1E6DC34B4BA877C23AEF1B5FB
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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
    $ExpectedValue = $true

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

Function Get-V259695 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259695
        STIG ID    : EX19-MB-000147
        Rule ID    : SV-259695r945440_rule
        CCI ID     : CCI-001247
        Rule Name  : SRG-APP-000272
        Rule Title : The Exchange malware scanning agent must be configured for automatic updates.
        DiscussMD5 : 9ACBB8B22C23567EE2ABCA85E81512C2
        CheckMD5   : 7773054A5625988B5BACA7488BB4138E
        FixMD5     : CD87E1004341B18657D2201F73BAD577
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Prop = "UpdateFrequency"
    $ExpectedValue = 1
    $Compliant = $true

    If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
        Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
        $Result = Get-MalwareFilteringServer
    }
    Else {
        $PSCommand = "PowerShell.exe -Command {Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn; Get-MalwareFilteringServer}"
        $Result = Invoke-Expression $PSCommand
    }

    If ($Result) {
        ForEach ($Item in $Result) {
            $FindingDetails += "Name:`t`t`t$($Item.Name)" | Out-String
            If ($Item.$($Prop) -ge $ExpectedValue) {
                $FindingDetails += "$($Prop):`t$($Item.$($Prop))" | Out-String
            }
            Else {
                $Compliant = $false
                $FindingDetails += "$($Prop):`t$($Item.$($Prop)) [Expected $($ExpectedValue)]" | Out-String
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
        $FindingDetails += "The Malware Agent is not installed so this requirement is NA." | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V259696 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259696
        STIG ID    : EX19-MB-000151
        Rule ID    : SV-259696r942402_rule
        CCI ID     : CCI-001242
        Rule Name  : SRG-APP-000278
        Rule Title : The Exchange built-in malware agent must be disabled.
        DiscussMD5 : 2F1A0EC5C6CD9A1CB9A91A10190C5EBB
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

Function Get-V259697 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259697
        STIG ID    : EX19-MB-000158
        Rule ID    : SV-259697r942405_rule
        CCI ID     : CCI-002361
        Rule Name  : SRG-APP-000295
        Rule Title : The Exchange receive connector timeout must be limited.
        DiscussMD5 : 905819C2C7F9501FC6CC6B4553E7204F
        CheckMD5   : 91C9C2FF53154B02C0D5327D2E1171D8
        FixMD5     : DE5DE1D5B4158871AF3819D03F3A59FF
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259702 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259702
        STIG ID    : EX19-MB-000198
        Rule ID    : SV-259702r942420_rule
        CCI ID     : CCI-001762
        Rule Name  : SRG-APP-000383
        Rule Title : Exchange services must be documented, and unnecessary services must be removed or disabled.
        DiscussMD5 : 5E82FE7DAF756D23CEB793178EB68249
        CheckMD5   : 2151EBE8DE683C54F38A688E6DE67799
        FixMD5     : 20BDC641107E6769AFFF9410377C7BA5
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259703 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259703
        STIG ID    : EX19-MB-000203
        Rule ID    : SV-259703r942423_rule
        CCI ID     : CCI-001953
        Rule Name  : SRG-APP-000391
        Rule Title : Exchange Outlook Anywhere clients must use NTLM authentication to access email.
        DiscussMD5 : 3C0CE6717B65D1592AB0D2B7B6273514
        CheckMD5   : 72E0478A0D8225F151E673DCCF124402
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

Function Get-V259705 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259705
        STIG ID    : EX19-MB-000230
        Rule ID    : SV-259705r942429_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-APP-000435
        Rule Title : Exchange must not send delivery reports to remote domains.
        DiscussMD5 : 3BEECA64F085E210E785CE4BE0A2C3DC
        CheckMD5   : D2B4E1C33E3D6467A71E2CFEA1A57BE2
        FixMD5     : ABA44B35910306B39F67002D4306E973
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259706 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259706
        STIG ID    : EX19-MB-000231
        Rule ID    : SV-259706r942432_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-APP-000435
        Rule Title : Exchange must not send nondelivery reports to remote domains.
        DiscussMD5 : 68CCE93BFDD67A75267AB0D2C3D1A4B6
        CheckMD5   : F63778EF2D60663C653517938D6BEC73
        FixMD5     : FE9997C9DB43BB1D62A4C8C0E434413D
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259707 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259707
        STIG ID    : EX19-MB-000232
        Rule ID    : SV-259707r942435_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-APP-000435
        Rule Title : The Exchange SMTP automated banner response must not reveal server details.
        DiscussMD5 : FF58F73AE1EEEB4F204E4A59F1AB7DC8
        CheckMD5   : B2D34CC41CC26B1427E5ABB714502733
        FixMD5     : 8151D43DFBD9BD4304EC10AF59BC3C77
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259708 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259708
        STIG ID    : EX19-MB-000233
        Rule ID    : SV-259708r942438_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-APP-000435
        Rule Title : Exchange internal send connectors must use an authentication level.
        DiscussMD5 : 4B3D8B19FF63AB32B9DBF1FB9BE1FD12
        CheckMD5   : F45CB593B03058EA92074CE56E5227C0
        FixMD5     : 9AE4DB2D74813F488E6A93D8E76AD859
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259709 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259709
        STIG ID    : EX19-MB-000234
        Rule ID    : SV-259709r942441_rule
        CCI ID     : CCI-002385
        Rule Name  : SRG-APP-000435
        Rule Title : Exchange must provide mailbox databases in a highly available and redundant configuration.
        DiscussMD5 : 04964EFEFC73A59B7A374FA220CA6093
        CheckMD5   : 50D7C6BC20D1DD48F4EA1DDD72819FBD
        FixMD5     : 073CA0152EDE1C52923401F7A033E8FC
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259710 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259710
        STIG ID    : EX19-MB-000236
        Rule ID    : SV-259710r942444_rule
        CCI ID     : CCI-001184, CCI-002418
        Rule Name  : SRG-APP-000439
        Rule Title : The application must protect the confidentiality and integrity of transmitted information.
        DiscussMD5 : 712B4E3987C0266AF4297923BB308AB2
        CheckMD5   : 62BA0FB033AE79594784644E6B2F88FB
        FixMD5     : 6C1811859ECB6BB041616E46D3419B91
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259711 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259711
        STIG ID    : EX19-MB-000244
        Rule ID    : SV-259711r942447_rule
        CCI ID     : CCI-002605
        Rule Name  : SRG-APP-000456
        Rule Title : Exchange must have the most current, approved Cumulative Update installed.
        DiscussMD5 : 0ADC55FDDEA1BD20D1A8FFF9E5564C97
        CheckMD5   : C4E653002769554337BEF17A99F4FBC0
        FixMD5     : 64BCAE91743DB32D28290588D1573580
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

Function Get-V259712 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259712
        STIG ID    : EX19-MB-000283
        Rule ID    : SV-259712r942450_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : Exchange must be configured in accordance with the security configuration settings based on DOD security configuration or implementation guidance, including STIGs, NSA configuration guides, CTOs, and DTMs.
        DiscussMD5 : 0FEA821257ECFDC213E3E7886FD9C598
        CheckMD5   : 4710F582E576BEE7BA9C2B5B4EF7C9D3
        FixMD5     : CA0590F388CCCF3D238883BFFE05343E
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
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

# SIG # Begin signature block
# MIIL+QYJKoZIhvcNAQcCoIIL6jCCC+YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCEF/+7037b3G0J
# Ihkrf8FWPY92q53UnGbQrL5UAFHE76CCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDuJtNaW76Et5kgDtEW8elccDiYQ+oR
# PDlmZLxFcT5AETANBgkqhkiG9w0BAQEFAASCAQAtjpkCxnvN5wGDTze3LibaVZBa
# 804ZG1Q2A1rc024rwd4wjdmuTZkUx/ZQxHIdLQqX3dpP9RHXHFnvjlxx8gLq/EQq
# 5m5Cgy4izWRu7mchc2lMT64nCLItyYwhGpiKacrUgmk+H0lw3JW8lkCx4/0UcE9D
# QxXnxGO32tBP5R/nN4ovqMWNIGYRJHnEyCYBWOyC5N1hE0NiI3ljk31CxHnFQMGU
# iQovHIvjyPQvWUAWEZoPTnbw/eRkorLFno+qu8Do6dmsuxJ6ZLbx4dO7nl94Fk44
# b/qp726Vy4i58yYSi6jjYDCjwn7B0dw8D7Q1xK90DQJSyXnfkiNg6mwTP6Xd
# SIG # End signature block
