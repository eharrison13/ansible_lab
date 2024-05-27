##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Rancher Government Solutions RKE2
# Version:  V1R5
# Class:    UNCLASSIFIED
# Updated:  5/13/2024
# Author:   Naval Air Systems Command (NAVAIR)
##########################################################################
$ErrorActionPreference = "Stop"

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

Function Get-V254553 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254553
        STIG ID    : CNTR-R2-000010
        Rule ID    : SV-254553r954686_rule
        CCI ID     : CCI-000068, CCI-000185, CCI-000382, CCI-000803, CCI-001184, CCI-001453, CCI-002420, CCI-002422, CCI-002450
        Rule Name  : SRG-APP-000014-CTR-000035
        Rule Title : Rancher RKE2 must protect authenticity of communications sessions with the use of FIPS-validated 140-2 or 140-3 security requirements for cryptographic modules.
        DiscussMD5 : 120FD4742249839918BF1FA416E697C9
        CheckMD5   : C766616AD775B8BA176F0953B5D3EFE0
        FixMD5     : 66FE0847618E5F44728C5C08195BB772
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $found = 0
    $finding = (Get-Process | Where-Object { $_.name -eq "kube-apiserver"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String
        #If the setting "tls-min-version" is not configured or it is set to "VersionTLS10" or "VersionTLS11", this is a finding.
        If ((($finding.split(" ") | Select-String "tls-min-version") -split ("="))[1] -ge "VersionTLS12") {
            $found++
            $FindingMessage = "kube-apiserver --tls-min-version is set to VersionTLS12 or greater."
        }
        Else {
            $FindingMessage = "kube-apiserver --tls-min-version is not set to VersionTLS12 or greater."
        }
        $FindingDetails += $FindingMessage | Out-String
        #If "tls-cipher-suites" is not set for all servers, or does not contain the following, this is a finding:
        If ((($finding.split(" ") | Select-String "tls-cipher-suites") -split ("="))[1] -eq "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384") {
            $found++
            $FindingMessage = "kube-apiserver --tls-cipher-suites is set to required string."
        }
        Else {
            $FindingMessage = "kube-apiserver --tls-cipher-suites is not set to required string."
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    else {
        $FindingMessage += $(FormatFinding "kube-apiserver process was not found found on system") | Out-String
    }

    $finding = (Get-Process | Where-Object { $_.name -eq "kube-controller-manager"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String
        If ((($finding.split(" ") | Select-String "tls-min-version") -split ("="))[1] -ge "VersionTLS12") {
            $found++
            $FindingMessage = "kube-controller-manager --tls-min-version is set to VersionTLS12 or greater."
        }
        Else {
            $FindingMessage = "kube-controller-manager --tls-min-version is not set to VersionTLS12 or greater."
        }
        $FindingDetails += $FindingMessage | Out-String
        If ((($finding.split(" ") | Select-String "tls-cipher-suites") -split ("="))[1] -eq "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384") {
            $found++
            $FindingMessage = "kube-controller-manager --tls-cipher-suites is set to required string."
        }
        Else {
            $FindingMessage = "kube-controller-manager --tls-cipher-suites is not set to required string."
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    else {
        $FindingMessage += "kube-controller-manager process was not found found on system"
    }

    $finding = (Get-Process | Where-Object { $_.name -eq "kube-scheduler"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String
        If ((($finding.split(" ") | Select-String "tls-min-version") -split ("="))[1] -ge "VersionTLS12") {
            $found++
            $FindingMessage = "kube-scheduler --tls-min-version is set to VersionTLS12 or greater."
        }
        Else {
            $FindingMessage = "kube-scheduler --tls-min-version is not set to VersionTLS12 or greater."
        }
        $FindingDetails += $FindingMessage | Out-String
        If ((($finding.split(" ") | Select-String "tls-cipher-suites") -split ("="))[1] -eq "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384") {
            $found++
            $FindingMessage = "kube-scheduler --tls-cipher-suites is set to required string."
        }
        Else {
            $FindingMessage = "kube-scheduler --tls-cipher-suites is not set to required string."
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    else {
        $FindingMessage += "kube-scheduler process was not found on system"
    }
    if(Get-Process | Where-Object { $_.name -in "kube-controller-manager","kube-apiserver","kube-scheduler"}){
        If ($found -eq 6) {
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

Function Get-V254554 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254554
        STIG ID    : CNTR-R2-000030
        Rule ID    : SV-254554r954692_rule
        CCI ID     : CCI-000015
        Rule Name  : SRG-APP-000023-CTR-000055
        Rule Title : RKE2 must use a centralized user management solution to support account management functions.
        DiscussMD5 : CAC05079CC5E2A7C0F995C25ED99DDF7
        CheckMD5   : A979612B91F4E05F4ADBA145C1798802
        FixMD5     : 4662BDB61010D4DC951E7AF3D21B625E
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = (Get-Process | Where-Object { $_.name -eq "kube-controller-manager"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String

        #If --use-service-account-credentials argument is not set to "true" or is not configured, this is a finding.
        If ((($finding.split(" ") | Select-String "use-service-account-credentials") -split ("="))[1] -eq $true) {
            $FindingMessage = "kube-scheduler --use-service-account-credentials is set to true."
            $Status = "NotAFinding"
        }
        Else {
            $FindingMessage = "kube-scheduler --use-service-account-credentials is not set to true or is not configured."
            $Status = "Open"
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    Else{
        $FindingDetails = "kube-controller-manager not found on system"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V254555 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254555
        STIG ID    : CNTR-R2-000060
        Rule ID    : SV-254555r954698_rule
        CCI ID     : CCI-000018, CCI-000130, CCI-000131, CCI-000132, CCI-000133, CCI-000134, CCI-000135, CCI-000172, CCI-000366, CCI-001403, CCI-001404, CCI-001464, CCI-001487, CCI-001814, CCI-001851, CCI-001889, CCI-001890, CCI-002130, CCI-002234, CCI-002884
        Rule Name  : SRG-APP-000026-CTR-000070
        Rule Title : Rancher RKE2 components must be configured in accordance with the security configuration settings based on DOD security configuration or implementation guidance, including SRGs, STIGs, NSA configuration guides, CTOs, and DTMs.
        DiscussMD5 : 293EBF76299A9A31A93C228856AD3517
        CheckMD5   : 36E55BE53B47558414432BD37F610E61
        FixMD5     : 56F959D361B7FF4E56003559C9B37990
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $found = 0
    $finding = (Get-Process | Where-Object { $_.name -eq "kube-apiserver"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String

        If ((($finding.split(" ") | Select-String "audit-policy-file") -split ("="))[1] -match "\S") {
            $FindingMessage = "kube-apiserver --audit-policy-file is set."
            $found++
        }
        Else {
            $FindingMessage = "kube-apiserver --audit-policy-file is not configured."
        }
        $FindingDetails += $FindingMessage | Out-String

        If ((($finding.split(" ") | Select-String "audit-log-mode") -split ("="))[1] -eq "blocking-strict") {
            $FindingMessage = "kube-apiserver --audit-log-mode is set to blocking-strict."
            $found++
        }
        Else {
            $FindingMessage = "kube-apiserver --audit-log-mode is not set to blocking-strict or is not configured."
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    Else {
        $FindingDetails += "kube-apiserver not found on system"
    }
    if(Test-Path "/etc/rancher/rke2/config.yaml"){
        $finding = (Get-Content /etc/rancher/rke2/config.yaml | Select-String "profile")
        If ($finding) {
            $finding = $finding.ToString()
            $FindingDetails += $(FormatFinding $finding) | Out-String
            if(test-path '/etc/rancher/rke2/rke2.yaml'){
                $finding3 = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml version | Select-String Server
                $FindingDetails += $finding3 | Out-String
                If (($finding3 -split ("[+:]"))[1].trim(" v") -le 1.24) {
                    If (($finding -split (" "))[1].trim('"') -eq "cis-1.6") {
                        $found++
                        $FindingMessage = "CIS Profile set to 1.6"
                    }
                    Else {
                        $FindingMessage = "CIS Profile not set to 1.6 or is not configured"
                    }
                }
                else {
                    If (($finding -split (" "))[1].trim('"') -eq "cis-1.23") {
                        $found++
                        $FindingMessage = "CIS Profile set to 1.23"
                    }
                    Else {
                        $FindingMessage = "CIS Profile not set to 1.23 or is not configured"
                    }
                }
                $FindingDetails += $FindingMessage | Out-String
            }
            else {
                $FindingDetails += "system does not have a /etc/rancher/rke2/rke2.yaml"
            }
        }
        Else {
            $FindingDetails += "No profile string found in config.yaml"
        }
    }
    else {
        $FindingDetails += "system does not have a /etc/rancher/rke2/config.yaml"
    }
    $finding = (Get-Process | Where-Object { $_.name -eq "kube-apiserver"}).CommandLine
    If ($finding) {
        $finding = Get-Content (($finding.split(" ") | Select-String "audit-policy-file") -split ("="))[1]
        $FindingDetails += $(FormatFinding $finding) | Out-String
        if (($finding -join ('')).Replace(' ', '') -eq 'apiVersion:audit.k8s.io/v1kind:Policymetadata:name:rke2-audit-policyrules:-level:Metadataresources:-group:""resources:["secrets"]-level:RequestResponseresources:-group:""resources:["*"]') {
            $found++
            $FindingMessage = "Audit Policy File matches requirements"
        }
        Else {
            $FindingMessage = "Audit Policy File does not match requirements"
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    Else {
        $FindingDetails += "kube-apiserver not found on system"
    }

    If((Get-Process | Where-Object { $_.name -eq "kube-apiserver"}) -or (Get-Content /etc/rancher/rke2/config.yaml | Select-String "profile")){
        If ($found -eq 4) {
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

Function Get-V254556 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254556
        STIG ID    : CNTR-R2-000100
        Rule ID    : SV-254556r954708_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-CTR-000090
        Rule Title : The Kubernetes Controller Manager must have secure binding.
        DiscussMD5 : 66AB62873A113C9719D906C305D58D73
        CheckMD5   : ACBD27CAFB661AD57FE5F4BA54DAD4F2
        FixMD5     : 8A0D8898E3DD20D53E3E63961C9F91B0
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = (Get-Process | Where-Object { $_.name -eq "kube-controller-manager"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String

        If ((($finding.split(" ") | Select-String "bind-address") -split ("="))[1] -eq "127.0.0.1") {
            $FindingMessage = "kube-controller-manager --bind-address is set to 127.0.0.1."
            $Status = "NotAFinding"
        }
        Else {
            $FindingMessage = "kube-controller-manager --bind-address is not set to 127.0.0.1 or is not configured."
            $Status = "Open"
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    else {
        $FindingDetails += "kube-controller-manager process not found on system"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V254557 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254557
        STIG ID    : CNTR-R2-000110
        Rule ID    : SV-254557r954708_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-CTR-000090
        Rule Title : The Kubernetes Kubelet must have anonymous authentication disabled.
        DiscussMD5 : 64B90A4ABBB693546D11D19C134E807A
        CheckMD5   : 3B6CF9ACDDD90A5A02ECDC17D38D00B7
        FixMD5     : A17DEF77B23FCCA3640986FB7D5FBB01
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = (Get-Process | Where-Object { $_.name -eq "kubelet"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String

        If ((($finding.split(" ") | Select-String "anonymous-auth") -split ("="))[1] -eq $false) {
            $FindingMessage = "kubelet --anonymous-auth is set to false."
            $Status = "NotAFinding"
        }
        Else {
            $FindingMessage = "kubelet --anonymous-auth is not set to false or is not configured."
            $Status = "Open"
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    else {
        $FindingDetails += "kubelet process not found on system"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V254558 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254558
        STIG ID    : CNTR-R2-000120
        Rule ID    : SV-254558r954708_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-CTR-000095
        Rule Title : The Kubernetes API server must have the insecure port flag disabled.
        DiscussMD5 : 5FEEC9515F9EFC80DD46D2204520FE20
        CheckMD5   : 278E7460747CF64144D7996DE2F25565
        FixMD5     : 1ED0EA5836ECD0F34637CC6056208861
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if(test-path '/etc/rancher/rke2/rke2.yaml'){
        $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml version | Select-String Server
        $FindingDetails += $(FormatFinding $finding) | Out-String
        If (($finding -split ("[+:]"))[1].trim(" v") -le 1.23 -and ($finding -split ("[+:]"))[1].trim(" v") -ge 1.20) {
            $finding = (Get-Process | Where-Object { $_.name -eq "kube-apiserver"}).CommandLine
            If ($finding) {
                $FindingDetails += $(FormatFinding $finding) | Out-String
                $finding = $finding.split("=") | Select-String "insecure-port"
                If (($NULL -eq $finding) -or (($finding)[1] -eq "0")) {
                    $FindingMessage = "kube-apiserver --insecure-port is set to 0 or is not configured."
                    $Status = "NotAFinding"
                }
                Else {
                    $FindingMessage = "kube-apiserver --insecure-port is not set to 0."
                    $Status = "Open"
                }
                $FindingDetails += $FindingMessage | Out-String
            }
            else {
                $FindingDetails += "kube-apiserver process not found on system"
            }
        }
        Elseif (($finding -split ("[+:]"))[1].trim(" v") -eq 1.24) {
            $Status = "Not_Applicable"
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    else {
        $FindingDetails += "system does not have a /etc/rancher/rke2/rke2.yaml"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V254559 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254559
        STIG ID    : CNTR-R2-000130
        Rule ID    : SV-254559r954708_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-CTR-000095
        Rule Title : The Kubernetes Kubelet must have the read-only port flag disabled.
        DiscussMD5 : B7182AAF88661892F5C911BCE3BFC260
        CheckMD5   : 6AB372C13B3AB1CDE9407E3AFD8D2D2B
        FixMD5     : 50DED6F6A5CB1F26175B39D18232513C
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = (Get-Process | Where-Object { $_.name -eq "kubelet"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String

        If ((($finding.split(" ") | Select-String "read-only-port") -split ("="))[1] -eq 0) {
            $FindingMessage = "kubelet --read-only-port is set to 0."
            $Status = "NotAFinding"
        }
        Else {
            $FindingMessage = "kubelet --read-only-port is not set to 0 or is not configured."
            $Status = "Open"
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    else {
        $FindingDetails += "kubelet process not found on system"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V254560 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254560
        STIG ID    : CNTR-R2-000140
        Rule ID    : SV-254560r954708_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-CTR-000095
        Rule Title : The Kubernetes API server must have the insecure bind address not set.
        DiscussMD5 : 1C681A5890D454AC06FD27CBF3098F5B
        CheckMD5   : A22E80C6B0B02222DD5FEDFE5693C6EA
        FixMD5     : 3BECB9B14878A911D2DB304020F843B6
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if(test-path '/etc/rancher/rke2/rke2.yaml'){
        $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml version | Select-String Server
        $FindingDetails += $(FormatFinding $finding) | Out-String
        If (($finding -split ("[+:]"))[1].trim(" v") -gt 1.20) {
            $Status = "Not_Applicable"
        }
        Else {
            $finding = "Upgrade to a supported version of RKE2 Kubernetes."
            $FindingDetails += $(FormatFinding $finding) | Out-String
            $Status = "Open"
        }
    }
    else {
        $FindingDetails += "system does not have a /etc/rancher/rke2/rke2.yaml"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V254561 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254561
        STIG ID    : CNTR-R2-000150
        Rule ID    : SV-254561r954708_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-CTR-000095
        Rule Title : The Kubernetes kubelet must enable explicit authorization.
        DiscussMD5 : 3C23D558EAF12604B16D4C20508C2CAC
        CheckMD5   : AA1181E49F412C83C76083D8E839CB83
        FixMD5     : 981B25E6D7DD1EFB1218FEA7695C30B8
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = (Get-Process | Where-Object { $_.name -eq "kubelet"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String

        If ((($finding.split(" ") | Select-String "authorization-mod") -split ("="))[1] -eq "Webhook") {
            $FindingMessage = "kubelet --authorization-mod is set to Webhook."
            $Status = "NotAFinding"
        }
        Else {
            $FindingMessage = "kubelet --authorization-mod is not set to Webhook or is not configured."
            $Status = "Open"
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    else {
        $FindingDetails += "kublet process not found on system"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V254562 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254562
        STIG ID    : CNTR-R2-000160
        Rule ID    : SV-254562r954708_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-CTR-000100
        Rule Title : The Kubernetes API server must have anonymous authentication disabled.
        DiscussMD5 : EC45C0668655A032A4DB52A74024EF06
        CheckMD5   : 1BE5E19F81CA5635E1FA19E687D12B0A
        FixMD5     : 5EB90ABE8A8CB6C17543475AD49A9BCE
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = (Get-Process | Where-Object { $_.name -eq "kube-apiserver"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String

        If ((($finding.split(" ") | Select-String "anonymous-auth") -split ("="))[1] -eq $false) {
            $FindingMessage = "kube-apiserver --anonymous-auth is set to false."
            $Status = "NotAFinding"
        }
        Else {
            $FindingMessage = "kube-apiserver --anonymous-auth is not set to false or is not configured."
            $Status = "Open"
        }
    }
    else {
        $FindingDetails += "kube-apiserver process not found on system"
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

Function Get-V254563 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254563
        STIG ID    : CNTR-R2-000320
        Rule ID    : SV-254563r954784_rule
        CCI ID     : CCI-001487
        Rule Name  : SRG-APP-000100-CTR-000200
        Rule Title : All audit records must identify any containers associated with the event within Rancher RKE2.
        DiscussMD5 : 4EBD2150B8AC7353654D718FCA8F43C2
        CheckMD5   : AFC537501D329740DE3D57BEC50EBDFF
        FixMD5     : 42E7D26402FE16AC2634962334923229
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = (Get-Process | Where-Object { $_.name -eq "kube-apiserver"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String

        #If --protect-kernel-defaults argument is not set to "true" or is not configured, this is a finding.
        If ((($finding.split(" ") | Select-String "audit-log-maxage") -split ("="))[1] -ge 30) {
            $FindingMessage = "kube-apiserver --audit-log-maxage is set to 30 or more days."
            $Status = "NotAFinding"
        }
        Else {
            $FindingMessage = "kube-apiserver --audit-log-maxage is not set to 30 or more days, or is not configured."
            $Status = "Open"
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    else {
        $FindingDetails += "kube-apiserver process not found on system"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V254564 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254564
        STIG ID    : CNTR-R2-000520
        Rule ID    : SV-254564r954820_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-CTR-000300
        Rule Title : Configuration and authentication files for Rancher RKE2 must be protected.
        DiscussMD5 : 6CD36A99E7B1D0BE4DCCF1A66B93D1DE
        CheckMD5   : 14B2DFC2619096F972ACFAA93B1F5E95
        FixMD5     : 3610650F606DC482EF37CDBD1884C9F7
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $found = 0
    $finding = (stat -c "%a %U %G %n" /etc/rancher/rke2/*)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "600 root root" -c) -gt 0) {
        $found++
        $FindingMessage = "Permissions are not correct on files in /etc/rancher/rke2/"
    }
    Else {
        $FindingMessage = "Permissions are correct on files in /etc/rancher/rke2/"
    }
    $FindingDetails += $FindingMessage | Out-String

    $finding = (stat -c "%U %G %n" /var/lib/rancher/rke2/*)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "root root" -c) -gt 0) {
        $found++
        $FindingMessage = "Owner / Group are not correct on files in /var/lib/rancher/rke2/"
    }
    Else {
        $FindingMessage = "Owner / Group are correct on files in /var/lib/rancher/rke2/"
    }
    $FindingDetails += $FindingMessage | Out-String

    $finding = (stat -c "%U %G %n" /var/lib/rancher/rke2/agent/*)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "root root" -c) -gt 0) {
        $found++
        $FindingMessage = "Owner / Group are not correct on files in /var/lib/rancher/rke2/agent/"
    }
    Else {
        $FindingMessage = "Owner / Group are correct on files in /var/lib/rancher/rke2/agent/"
    }
    $FindingDetails += $FindingMessage | Out-String

    $finding = (stat -c "%a %n" /var/lib/rancher/rke2/agent/*.kubeconfig)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "640" -c) -gt 0) {
        $found++
        $FindingMessage = "Permissions are not correct on kubeconfig files in /var/lib/rancher/rke2/agent/"
    }
    Else {
        $FindingMessage = "Permissions are correct on kubeconfig files in /var/lib/rancher/rke2/agent/"
    }
    $FindingDetails += $FindingMessage | Out-String

    $finding = (stat -c "%a %n" /var/lib/rancher/rke2/agent/*.crt)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "600" -c) -gt 0) {
        $found++
        $FindingMessage = "Permissions are not correct on crt files in /var/lib/rancher/rke2/agent/"
    }
    Else {
        $FindingMessage = "Permissions are correct on crt files in /var/lib/rancher/rke2/agent/"
    }
    $FindingDetails += $FindingMessage | Out-String

    $finding = (stat -c "%a %n" /var/lib/rancher/rke2/agent/*.key)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "600" -c) -gt 0) {
        $found++
        $FindingMessage = "Permissions are not correct on key files in /var/lib/rancher/rke2/agent/"
    }
    Else {
        $FindingMessage = "Permissions are correct on key files in /var/lib/rancher/rke2/agent/"
    }
    $FindingDetails += $FindingMessage | Out-String

    $finding = (stat -c "%a %n" /var/lib/rancher/rke2/agent/pod-manifests/)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "700" -c) -gt 0) {
        $found++
        $FindingMessage = "Permissions are not correct for /var/lib/rancher/rke2/agent/pod-manifests/"
    }
    Else {
        $FindingMessage = "Permissions are correct for /var/lib/rancher/rke2/agent/pod-manifests/"
    }
    $FindingDetails += $FindingMessage | Out-String

    $finding = (stat -c "%a %n" /var/lib/rancher/rke2/agent/etc/)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "700" -c) -gt 0) {
        $found++
        $FindingMessage = "Permissions are not correct for /var/lib/rancher/rke2/agent/etc/"
    }
    Else {
        $FindingMessage = "Permissions are correct for /var/lib/rancher/rke2/agent/etc/"
    }
    $FindingDetails += $FindingMessage | Out-String

    $finding = (stat -c "%a %U %G %n" /var/lib/rancher/rke2/bin/*)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "750 root root" -c) -gt 0) {
        $found++
        $FindingMessage = "Permissions are not correct on files in /var/lib/rancher/rke2/bin"
    }
    Else {
        $FindingMessage = "Permissions are correct on files in /var/lib/rancher/rke2/bin"
    }
    
    $finding = (stat -c "%a %U %G %n" /var/lib/rancher/rke2)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "750 root root" -c) -gt 0) {
        $found++
        $FindingMessage = "Permissions are not correct on files in /var/lib/rancher/rke2"
    }
    Else {
        $FindingMessage = "Permissions are correct on files in /var/lib/rancher/rke2"
    }

    
    $finding = (stat -c "%U %G %n" /var/lib/rancher/rke2/data/*)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "root root" -c) -gt 0) {
        $found++
        $FindingMessage = "Owner / Group are not correct on files in /var/lib/rancher/rke2/data"
    }
    Else {
        $FindingMessage = "Owner / Group are correct on files in /var/lib/rancher/rke2/data"
    }

    $finding = (stat -c "%a %U %G %n" /var/lib/rancher/rke2/data/*)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "640 root root" -c) -gt 0) {
        $found++
        $FindingMessage = "Permissions are not correct on files in /var/lib/rancher/rke2/data"
    }
    Else {
        $FindingMessage = "Permissions are correct on files in /var/lib/rancher/rke2/data"
    }

    $finding = (stat -c "%U %G %n" /var/lib/rancher/rke2/server/*)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "root root" -c) -gt 0) {
        $found++
        $FindingMessage = "Owner / Group are not correct on files in /var/lib/rancher/rke2/server"
    }
    Else {
        $FindingMessage = "Owner / Group are correct on files in /var/lib/rancher/rke2/server"
    }

    $finding = (stat -c "%a %n" /var/lib/rancher/rke2/server/cred /var/lib/rancher/rke2/server/db /var/lib/rancher/rke2/server/tls)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "700" -c) -gt 0) {
        $found++
        $FindingMessage = "Permissions are not correct on cred, db, and tls in /var/lib/rancher/rke2/server"
    }
    Else {
        $FindingMessage = "Permissions are correct on cred, db, and tls in /var/lib/rancher/rke2/server"
    }
    
    $finding = (stat -c "%a %n" /var/lib/rancher/rke2/server/manifests /var/lib/rancher/rke2/server/logs)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "750" -c) -gt 0) {
        $found++
        $FindingMessage = "Permissions are not correct on manifests and logs in /var/lib/rancher/rke2/server"
    }
    Else {
        $FindingMessage = "Permissions are correct on manifests and logs in /var/lib/rancher/rke2/server"
    }
    
    $finding = (stat -c "%a %n" /var/lib/rancher/rke2/server/token)
    $FindingDetails += $(FormatFinding $finding) | Out-String
    If (($finding | grep -v "750" -c) -gt 0) {
        $found++
        $FindingMessage = "Permissions are not correct on token in /var/lib/rancher/rke2/server"
    }
    Else {
        $FindingMessage = "Permissions are correct on token in /var/lib/rancher/rke2/server"
    }

    if(test-path '/etc/rancher/rke2/config.yaml'){
        $finding = Get-Content /etc/rancher/rke2/config.yaml
        $FindingDetails += $(FormatFinding $finding) | Out-String
        if($finding | select-string 'write-kubeconfig-mode: "0600"') {
            $FindingMessage = '/etc/rancher/rke2/config.yaml contains write-kubeconfig-mode: "0600"'
        }
        else{
            $found++
            $FindingMessage = '/etc/rancher/rke2/config.yaml does not contain write-kubeconfig-mode: "0600"'
        }
    }

    if ($found -gt 0) {
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

Function Get-V254565 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254565
        STIG ID    : CNTR-R2-000550
        Rule ID    : SV-254565r954822_rule
        CCI ID     : CCI-000381, CCI-001764
        Rule Name  : SRG-APP-000141-CTR-000315
        Rule Title : Rancher RKE2 must be configured with only essential configurations.
        DiscussMD5 : 111D62C55697089EF7CB91E7C6D8906E
        CheckMD5   : B1B5903D55FA245026E71BF1F3CF188A
        FixMD5     : 15882A526B657F27F6041CE6D2FA15F8
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if(test-path '/etc/rancher/rke2/config.yaml'){
        $finding = Get-Content /etc/rancher/rke2/config.yaml
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }
    else {
        $FindingDetails += "system does not have a /etc/rancher/rke2/config.yaml"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V254566 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254566
        STIG ID    : CNTR-R2-000580
        Rule ID    : SV-254566r954824_rule
        CCI ID     : CCI-000382, CCI-001762
        Rule Name  : SRG-APP-000142-CTR-000325
        Rule Title : Rancher RKE2 runtime must enforce ports, protocols, and services that adhere to the PPSM CAL.
        DiscussMD5 : 757FC70698A3F1629DE153FD2FCA0066
        CheckMD5   : 12BE7A2D991282EA6D847B02C820EF76
        FixMD5     : D0798F63B592807F8B28E1FF5BE7DCDC
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if(test-path '/var/lib/rancher/rke2/agent/pod-manifests/kube-apiserver.yaml'){
        $finding = Select-String "--insecure-port" -Path /var/lib/rancher/rke2/agent/pod-manifests/kube-apiserver.yaml
        $FindingDetails += "grep kube-apiserver.yaml -I -insecure-port" | Out-String
        $FindingDetails += $(FormatFinding $finding) | Out-String

        $finding = Select-String "--secure-port" -Path /var/lib/rancher/rke2/agent/pod-manifests/kube-apiserver.yaml
        $FindingDetails += "grep kube-apiserver.yaml -I -secure-port" | Out-String
        $FindingDetails += $(FormatFinding $finding) | Out-String

        $finding = Select-String "--etcd-servers" -Path /var/lib/rancher/rke2/agent/pod-manifests/kube-apiserver.yaml
        $FindingDetails += "grep kube-apiserver.yaml -I -etcd-servers *" | Out-String
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }
    else {
        $FindingDetails += "system does not have a /var/lib/rancher/rke2/agent/pod-manifests/kube-apiserver.yaml"
    }
    if(test-path '/etc/rancher/rke2/rke2.yaml'){
        $finding = (/var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get po -n kube-system -l component=kube-controller-manager -o=jsonpath="{.items[*].spec.containers[*].args}").split(",") | Select-String "--secure-port", "--etcd-servers", "--insecure-port"
        $FindingDetails += '/var/lib/rancher/rke2/bin/kubectl get po -n kube-system -l component=kube-controller-manager -o=jsonpath="{.items[*].spec.containers[*].args}"' | Out-String
        $FindingDetails += $(FormatFinding $finding) | Out-String

        $finding = (/var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get po -n kube-system -l component=kube-scheduler -o=jsonpath="{.items[*].spec.containers[*].args}").split(",") | Select-String "--secure-port", "--etcd-servers", "--insecure-port"
        $FindingDetails += '/var/lib/rancher/rke2/bin/kubectl get po -n kube-system -l component=kube-scheduler -o=jsonpath="{.items[*].spec.containers[*].args}"' | Out-String
        $FindingDetails += $(FormatFinding $finding) | Out-String

        $finding = (/var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get po -n kube-system -l component=kube-apiserver -o=jsonpath="{.items[*].spec.containers[*].args}").split(",") | Select-String "--secure-port", "--etcd-servers", "--insecure-port"
        $FindingDetails += '/var/lib/rancher/rke2/bin/kubectl get po -n kube-system -l component=kube-apiserver -o=jsonpath="{.items[*].spec.containers[*].args}"' | Out-String
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }
    else {
        $FindingDetails += "system does not have a /etc/rancher/rke2/rke2.yaml"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V254567 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254567
        STIG ID    : CNTR-R2-000800
        Rule ID    : SV-254567r954864_rule
        CCI ID     : CCI-000196
        Rule Name  : SRG-APP-000171-CTR-000435
        Rule Title : Rancher RKE2 must store only cryptographic representations of passwords.
        DiscussMD5 : B4574D9C97E80AF015C00153E09EA136
        CheckMD5   : 17B826DD0EB61DAB069C8107A57BAE5C
        FixMD5     : 71F1BAF58EADDB098AA503E6911F8E43
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if(test-path '/etc/rancher/rke2/rke2.yaml'){
        $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get pods -A
        $FindingDetails += "kubectl get pods -A" | Out-String
        $FindingDetails += $(FormatFinding $finding) | Out-String

        $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get jobs -A
        $FindingDetails += "kubectl get jobs -A" | Out-String
        $FindingDetails += $(FormatFinding $finding) | Out-String

        $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get cronjobs -A
        $FindingDetails += "kubectl get cronjobs -A" | Out-String
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }
    else {
    $FindingDetails += "system does not have a /etc/rancher/rke2/rke2.yaml"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V254568 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254568
        STIG ID    : CNTR-R2-000890
        Rule ID    : SV-254568r954892_rule
        CCI ID     : CCI-001133
        Rule Name  : SRG-APP-000190-CTR-000500
        Rule Title : Rancher RKE2 must terminate all network connections associated with a communications session at the end of the session, or as follows: for in-band management sessions (privileged sessions), the session must be terminated after five minutes of inactivity.
        DiscussMD5 : BA39C5BB6D3444F2FC3598B9D9F0BA34
        CheckMD5   : F21F5F9D711C2485A49FE9AAD3839E0D
        FixMD5     : C8E10374E733F55F69872F3B0E2D5FCE
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = (Get-Process | Where-Object { $_.name -eq "kubelet"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String

        #If --treaming-connection-idle-timeout argument is not set to "true" or is not configured, this is a finding.
        If ((($finding.split(" ") | Select-String "treaming-connection-idle-timeout") -split ("="))[1] -le "5m") {
            $FindingMessage = "kubelet --treaming-connection-idle-timeout is set to 5 minutes or less."
            $Status = "NotAFinding"
        }
        Else {
            $FindingMessage = "kubelet --treaming-connection-idle-timeout is not set to 5 minutes or less, or is not configured."
            $Status = "Open"
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    else {
        $FindingDetails += "kublet process not found on system"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V254569 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254569
        STIG ID    : CNTR-R2-000940
        Rule ID    : SV-254569r954934_rule
        CCI ID     : CCI-001084
        Rule Name  : SRG-APP-000233-CTR-000585
        Rule Title : Rancher RKE2 runtime must isolate security functions from nonsecurity functions.
        DiscussMD5 : AE77B63CBCEBB4084D5CA85E934B5E55
        CheckMD5   : 8BDEEF9A356CEE0D06B7ED5CAE01984C
        FixMD5     : 6A248E3571C2ACBAF6228D253334E121
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = (Get-Process | Where-Object { $_.name -eq "kubelet"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String

        If ((($finding.split(" ") | Select-String "protect-kernel-defaults") -split ("="))[1] -eq $true) {
            $FindingMessage = "kubelet --protect-kernel-defaults is set to true."
            $Status = "NotAFinding"
        }
        Else {
            $FindingMessage = "kubelet --protect-kernel-defaults is not set to true or is not configured."
            $Status = "Open"
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    else {
        $FindingDetails += "kublet process not found on system"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V254570 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254570
        STIG ID    : CNTR-R2-000970
        Rule ID    : SV-254570r954946_rule
        CCI ID     : CCI-001082, CCI-001090, CCI-002530
        Rule Name  : SRG-APP-000243-CTR-000600
        Rule Title : Rancher RKE2 runtime must maintain separate execution domains for each container by assigning each container a separate address space to prevent unauthorized and unintended information transfer via shared system resources.
        DiscussMD5 : 92721D033F360E1A438D12850166F246
        CheckMD5   : 8381E07B46EC516B7D57AE047DA28739
        FixMD5     : FF8AB163E09B64022B017D45CA4EC24F
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if(test-path '/etc/rancher/rke2/rke2.yaml'){
        $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get namespaces
        $FindingDetails += "kubectl get namespaces" | Out-String
        $FindingDetails += $(FormatFinding $finding) | Out-String

        $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get all -n default -o name
        $FindingDetails += "kubectl get all -n default" | Out-String
        $FindingDetails += $(FormatFinding $finding) | Out-String

        $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get all -n kube-public -o name
        $FindingDetails += "kubectl get all -n kube-public" | Out-String
        $FindingDetails += $(FormatFinding $finding) | Out-String

        $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get all -n kube-node-lease -o name
        $FindingDetails += "kubectl get all -n kube-node-lease" | Out-String
        $FindingDetails += $(FormatFinding $finding) | Out-String

        $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get all -n kube-system -o name
        $FindingDetails += "kubectl get all -n kube-system" | Out-String
        $FindingDetails += $(FormatFinding $finding) | Out-String
    }
    else {
        $FindingDetails += "system does not have a /etc/rancher/rke2/rke2.yaml"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V254571 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254571
        STIG ID    : CNTR-R2-001130
        Rule ID    : SV-254571r955082_rule
        CCI ID     : CCI-002233, CCI-002235
        Rule Name  : SRG-APP-000340-CTR-000770
        Rule Title : Rancher RKE2 must prevent nonprivileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.
        DiscussMD5 : 1CE0BBEF15311450459C8F6650673A23
        CheckMD5   : 5F1EFB09BE266BA9EC6BBAC7420741BD
        FixMD5     : A5AAE0EB3695C744DE83CBF5CC0A15C7
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if(test-path '/etc/rancher/rke2/rke2.yaml'){
        $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml version | Select-String Server
        $FindingDetails += $(FormatFinding $finding) | Out-String
        If (($finding -split ("[+:]"))[1].trim(" v") -le 1.24) {
            $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get podsecuritypolicy
            $FindingDetails += $(FormatFinding $finding) | Out-String
            $Status = "Not_Reviewed"
        }
        Else {
            if(test-path '/etc/rancher/rke2/rke2-pss.yaml'){
                $finding = Get-Content /etc/rancher/rke2/rke2-pss.yaml
                $FindingDetails += $(FormatFinding $finding) | Out-String
                If (($finding | grep defaults: -A 6).replace(" ", "") -join '' -eq 'defaults:enforce:"restricted"enforce-version:"latest"audit:"restricted"audit-version:"latest"warn:"restricted"warn-version:"latest"') {
                    $Status = "NotAFinding"
                }
                Else {
                    $Status = "Open"
                }
            }
            else {
                $FindingDetails += "system does not have a /etc/rancher/rke2/rke2-pss.yaml"
            }
        }
    }
    else {
        $FindingDetails += "system does not have a /etc/rancher/rke2/rke2.yaml"
    }

    $finding = (Get-Process | Where-Object { $_.name -eq "kube-apiserver"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String

        #If  --authorization-mode is not set to "RBAC,Node" or is not configured, this is a finding.
        If ((($finding.split(" ") | Select-String "authorization-mode") -split ("="))[1] -eq "Node,RBAC") {
            $FindingMessage = "kube-scheduler --authorization-mode is set to Node,RBAC."
            $Status = "NotAFinding"
        }
        Else {
            $FindingMessage = "kube-scheduler --authorization-mode is not set to Node,RBAC or is not configured."
            $Status = "Open"
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    else {
        $FindingDetails += "kube-apiserver process not found on system"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V254572 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254572
        STIG ID    : CNTR-R2-001270
        Rule ID    : SV-254572r955575_rule
        CCI ID     : CCI-001812
        Rule Name  : SRG-APP-000378-CTR-000880
        Rule Title : Rancher RKE2 must prohibit the installation of patches, updates, and instantiation of container images without explicit privileged status.
        DiscussMD5 : A618710D7C1F4AE0B637343C785C2FE9
        CheckMD5   : 74A680F7DF55629E7D8D212AAB1957A5
        FixMD5     : 007944CAD1A07FB9A81BF40DF23466BD
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $finding = (Get-Process | Where-Object { $_.name -eq "kube-apiserver"}).CommandLine
    If ($finding) {
        $FindingDetails += $(FormatFinding $finding) | Out-String

        #If  --authorization-mode is not set to "RBAC,Node" or is not configured, this is a finding.
        If ((($finding.split(" ") | Select-String "authorization-mode") -split ("="))[1] -eq "Node,RBAC") {
            $FindingMessage = "kube-scheduler --authorization-mode is set to Node,RBAC."
            $Status = "NotAFinding"
        }
        Else {
            $FindingMessage = "kube-scheduler --authorization-mode is not set to Node,RBAC or is not configured."
            $Status = "Open"
        }
        $FindingDetails += $FindingMessage | Out-String
    }
    else {
        $FindingDetails += "kube-apiserver process not found on system"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V254573 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254573
        STIG ID    : CNTR-R2-001500
        Rule ID    : SV-254573r956028_rule
        CCI ID     : CCI-002476
        Rule Name  : SRG-APP-000429-CTR-001060
        Rule Title : Rancher RKE2 keystore must implement encryption to prevent unauthorized disclosure of information at rest within Rancher RKE2.
        DiscussMD5 : 6CAC83AFA7436D654D8ADC95A3F2FDDD
        CheckMD5   : 47B07D86F05E9942D2F83F75367AC24A
        FixMD5     : 96BF21E5F4EA2FA412BDF3F5F22C9C2F
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if(test-path "/var/lib/rancher/rke2/server/cred/encryption-config.json"){
        $finding = Get-Content /var/lib/rancher/rke2/server/cred/encryption-config.json
        $FindingDetails += $(FormatFinding $finding)
    }
    else {
        $FindingDetails += "system does not have a /var/lib/rancher/rke2/server/cred/encryption-config.json"
    }
    #Ensure the RKE2 configuration file on all RKE2 servers, located at /etc/rancher/rke2/config.yaml, does NOT contain: secrets-encryption: false
    if(test-path '/etc/rancher/rke2/config.yaml'){
        $finding = Select-String -Path /etc/rancher/rke2/config.yaml -Pattern "secrets-encryption: false"
        If ($finding) {
            $Status = "Open"
            $FindingDetails += $finding | Out-String
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails += "/etc/rancher/rke2/config.yaml, does NOT contain secrets-encryption: false"
        }
    }
    else {
        $FindingDetails += "system does not have a /etc/rancher/rke2/config.yaml"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V254574 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254574
        STIG ID    : CNTR-R2-001580
        Rule ID    : SV-254574r955723_rule
        CCI ID     : CCI-002617
        Rule Name  : SRG-APP-000454-CTR-001110
        Rule Title : Rancher RKE2 must remove old components after updated versions have been installed.
        DiscussMD5 : 12D3E83936A3FF5AC511113EEABF02EF
        CheckMD5   : C84840A81D68C4B3AF3EE3ECEB89CE7D
        FixMD5     : E31CE520DBA1C86D6FC50049C4F015B2
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if(test-path '/etc/rancher/rke2/rke2.yaml'){
        $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get pods --all-namespaces -o jsonpath="{..image}" | tr -s '[[:space:]]' '\n' | Sort-Object | uniq -c
        $FindingDetails += $finding | Out-String
    }
    else {
        $FindingDetails += "system does not have a /etc/rancher/rke2/rke2.yaml"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V254575 {
    <#
    .DESCRIPTION
        Vuln ID    : V-254575
        STIG ID    : CNTR-R2-001620
        Rule ID    : SV-254575r955727_rule
        CCI ID     : CCI-002605
        Rule Name  : SRG-APP-000456-CTR-001125
        Rule Title : Rancher RKE2 registry must contain the latest images with most recent updates and execute within Rancher RKE2 runtime as authorized by IAVM, CTOs, DTMs, and STIGs.
        DiscussMD5 : 690B2699C1501789FF62C86E2354D88A
        CheckMD5   : C5DBDDF1BDC00C3666798AE3983BFD16
        FixMD5     : F9EE341C102013B756A52F558A77FE80
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    if(test-path "/etc/rancher/rke2/rke2.yaml"){
        $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get nodes
        $FindingDetails += "kubectl get nodes" | Out-String
        $FindingDetails += $finding | Out-String
        $finding = /var/lib/rancher/rke2/bin/kubectl --kubeconfig /etc/rancher/rke2/rke2.yaml get pods --all-namespaces -o jsonpath="{.items[*].spec.containers[*].image}" | tr -s '[[:space:]]' '\n' | Sort-Object | uniq -c
        $FindingDetails += $finding | Out-String
    }
    else {
        $FindingDetails += "system does not have a /etc/rancher/rke2/rke2.yaml"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDuHXc922RH9dff
# 2v6+8xm3bAN5Cv6W4pn5hW5ZpKoJVKCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCALHS4rsaJpoEAWMCG9JZcmmH/6e/r1
# xtv21XC1TcnYzjANBgkqhkiG9w0BAQEFAASCAQBqvwdgVhJPDHxQj8vk93u6OtBh
# Vl5FD2zVSprkX622kvFuO6sONol2lQZCdgdiOAG+hee+JcDB69PW59M/sTohxcdG
# Zb5S2ds90u3WN1qrBoJvNV//CIF++OPBO5ZQb9hIKpu1vpFjiFDBduyue9+6T13p
# qckJIlaJLlOGY9OFoE5nkDIxNDjqxXdFlt95FYKh+UFfrRYUmj+1RKmPtbVzqe1L
# MrxeXy6vGlVdUDphdRjSeNwJtvdMcaKIxvSdqrBVuf8JhAKHYrSZy6jIvmpIg3n9
# CH+MosoSLAii8rD0AhKtP/UTR3/HxxrFv0x4JdlF1BNnrVC0Vkj1M/bIBR0d
# SIG # End signature block
