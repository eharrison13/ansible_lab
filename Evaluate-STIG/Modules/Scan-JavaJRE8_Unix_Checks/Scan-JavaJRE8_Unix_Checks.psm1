##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     Java Runtime Environment (JRE) version 8
# Version:  V1R3
# Class:    UNCLASSIFIED
# Updated:  5/13/2024
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Format-JavaPath {
    # https://en.wikipedia.org/wiki/File_URI_scheme
    # https://docs.oracle.com/javase/8/docs/technotes/guides/deploy/properties.html
    Param (
        [Parameter(Mandatory = $true)]
        [String]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet("deployment.properties", "exception.sites")]
        [String]$JavaFile
    )

    $Result = New-Object System.Collections.Generic.List[System.Object]
    $Pass = $true

    $WorkingPath = $Path -replace "\\{5,}", "///" -replace "\\{4}", "//" -replace "\\{3}", "/" -replace "\\{2}", "/" -replace "\\{1}", ""

    Switch ($JavaFile) {
        "deployment.properties" {
            # Java variables don't appear to work for deployment.properties path
            If ($WorkingPath -like '*$SYSTEM_HOME*' -or $WorkingPath -like '*$USER_HOME*' -or $WorkingPath -like '*$JAVA_HOME*') {
                $Pass = $false
                $Formatted = "Path to deployment.properites cannot include a variable.`r`nRefer to https://docs.oracle.com/javase/8/docs/technotes/guides/deploy/properties.html"
            }
            ElseIf ($WorkingPath -notlike 'file:*') {
                $Pass = $false
                $Formatted = "Path to deployment.properites must start with proper 'file:' format.`r`nRefer to https://docs.oracle.com/javase/8/docs/technotes/guides/deploy/properties.html"
            }
            Else {
                Switch -Regex ($WorkingPath) {
                    # Local path patterns
                    "^file:/{1}[A-Za-z0-9]" {
                        # 'file:/<local path>'
                        $Formatted = $WorkingPath -replace "file:", ""
                    }
                    "^file:/{3}[A-Za-z0-9]" {
                        # 'file:///<local path>'
                        $Formatted = $WorkingPath -replace "file:/{3}", "/"
                    }
                    # UNC path pattern
                    "^file:/{2}[A-Za-z0-9]" {
                        # 'file://<server>'
                        $Formatted = $WorkingPath -replace "file:", ""
                        If ($Formatted -match ":") {
                            $Pass = $false
                        }
                    }
                    # Dynamic pattern
                    "^file:/{4,}[A-Za-z0-9]" {
                        # 'file:////<server or drive letter>' (4 or more slashes)
                        $Formatted = $WorkingPath -replace "file:/{5,}", "////"
                    }
                    Default {
                        $Pass = $false
                        $Formatted = "Path to deployment.properites is invalid format.`r`nRefer to https://docs.oracle.com/javase/8/docs/technotes/guides/deploy/properties.html"
                    }
                }
            }
        }
        "exception.sites" {
            If ($WorkingPath -like '*$SYSTEM_HOME*') {
                $WorkingPath = $WorkingPath.Replace('$SYSTEM_HOME', '/etc/.java/deployment')
            }
            Switch -Regex ($WorkingPath) {
                # Local path patterns
                "^/{1}[A-Za-z0-9]" {
                    # '/<local path>'
                    $Formatted = $WorkingPath
                }
                # Dynamic pattern
                "^/{2,}[A-Za-z0-9]" {
                    # '//<server or drive letter>' (2 or more slashes)
                    $Formatted = $WorkingPath -replace "/{2,}", "//"
                }
                Default {
                    $Pass = $false
                    $Formatted = "Path to exception.sites is an invalid format."
                }
            }
        }
    }

    $NewObj = [PSCustomObject]@{
        Pass       = $Pass
        Configured = $Path
        Working    = $WorkingPath
        Formatted  = $Formatted
    }
    $Result.Add($NewObj)

    Return $Result
}

Function Get-V66721 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66721
        STIG ID    : JRE8-UX-000010
        Rule ID    : SV-81211r1_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : Oracle JRE 8 must have a deployment.config file present.
        DiscussMD5 : 91D4281474ED54A1748E785FA85518E9
        CheckMD5   : C4E54062304601F2AEF1E046046CEE72
        FixMD5     : E9F14D23BA1A89A8AD861D2D8E931DAB
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigFile = "/etc/.java/deployment/deployment.config"

    If (Test-Path $ConfigFile) {
        $Status = "NotAFinding"
        $FindingDetails += "The following config file was found:" | Out-String
        $FindingDetails += "" | Out-String
        $FindingDetails += $ConfigFile | Out-String
    }
    Else {
        $Status = "Open"
        $FindingDetails += "No deployment.config file found" | Out-String
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V66909 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66909
        STIG ID    : JRE8-UX-000020
        Rule ID    : SV-81399r2_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : Oracle JRE 8 deployment.config file must contain proper keys and values.
        DiscussMD5 : 8FB93155C9BB13C1B3634DD0F84DDDE2
        CheckMD5   : A55825EB652B461B5D8E6FF5FB3E0962
        FixMD5     : CC78F18EAAA8CBB5565F9626D08B0610
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigFile = "/etc/.java/deployment/deployment.config"

    $KeysToEval = "deployment.system.config=", `
        "deployment.system.config.mandatory=true"

    $Compliant = $true
    If (-Not(Test-Path $ConfigFile)) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found" | Out-String
    }
    Else {
        $Option1Set = $false
        $Option2Set = $false
        $FindingDetails += "Config File:`t`t$($ConfigFile)" | Out-String
        $FindingDetails += "" | Out-String
        $ConfigFileContent = Get-Content -Path $ConfigFile
        ForEach ($Line in $ConfigFileContent) {
            If (($Line -Replace "\s", "") -like "$($KeysToEval[0])*") {
                $Option1Set = $true
                If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                    $PropsPath = ($Line.Split("=")[1]).Trim()
                }
                If ($PropsPath) {
                    $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                    If ($PropsFile.Pass -ne $true) {
                        $Compliant = $false
                        $FindingDetails += "$Line" | Out-String
                        $FindingDetails += "" | Out-String
                        $FindingDetails += $PropsFile.Formatted | Out-String
                    }
                    ElseIf ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                        $Compliant = $false
                        $FindingDetails += "$Line" | Out-String
                        $FindingDetails += "" | Out-String
                        $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                    }
                    Else {
                        $FindingDetails += "$Line is present" | Out-String
                    }
                }
                Else {
                    $Compliant = $false
                    $FindingDetails += "$Line" | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                }
            }
            ElseIf (($Line -Replace "\s", "") -eq $KeysToEval[1]) {
                $Option2Set = $true
                $FindingDetails += "$Line is present" | Out-String
            }
        }

        If ($Option1Set -eq $false) {
            $Compliant = $false
            $FindingDetails += "Path to 'deployment.properties' is NOT present" | Out-String
        }
        ElseIf ($Option2Set -eq $false) {
            $Compliant = $false
            $FindingDetails += "deployment.system.config.mandatory=true is NOT present" | Out-String
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

Function Get-V66911 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66911
        STIG ID    : JRE8-UX-000030
        Rule ID    : SV-81401r1_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : Oracle JRE 8 must have a deployment.properties file present.
        DiscussMD5 : 588666C94B5F3D39746B984449C6E6D5
        CheckMD5   : EF858FBA3D142B1779B49366FE514C55
        FixMD5     : EDDD2479375CEB9BB512D1D98FE2AB8B
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigFile = "/etc/.java/deployment/deployment.config"

    $Compliant = $true
    If (-Not(Test-Path $ConfigFile)) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found" | Out-String
    }
    Else {
        $FindingDetails += "Config File:`t`t$($ConfigFile)" | Out-String
        # Get path to deployment.properties from .config file
        $ConfigFileContent = Get-Content -Path $ConfigFile
        ForEach ($Line in $ConfigFileContent) {
            If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                $PropsPath = ($Line.Split("=")[1]).Trim()
                Break
            }
        }
        If ($PropsPath) {
            $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
            If ($PropsFile.Pass -ne $true) {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "$Line" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += $PropsFile.Formatted | Out-String
            }
            Else {
                $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                $FindingDetails += "" | Out-String
                If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                    $Compliant = $false
                    $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                }
                Else {
                    If (Test-Path $PropsFile.Formatted) {
                        $FindingDetails += "Properties file exists in the path defined." | Out-String
                    }
                    Else {
                        $Compliant = $false
                        $FindingDetails += "Properties file not found in the path defined." | Out-String
                    }
                }
            }
        }
        Else {
            $Compliant = $false
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V66913 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66913
        STIG ID    : JRE8-UX-000060
        Rule ID    : SV-81403r1_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : Oracle JRE 8 must default to the most secure built-in setting.
        DiscussMD5 : 61476BE2840E85A7AA739C3F90814373
        CheckMD5   : D6334D52C7D46EF33A9AF0500535A654
        FixMD5     : 81DEE608C012C410673FBF4AEA881EBC
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigFile = "/etc/.java/deployment/deployment.config"

    $KeysToEval = "deployment.security.level=VERY_HIGH", `
        "deployment.security.level.locked"

    $Compliant = $true
    If (-Not(Test-Path $ConfigFile)) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found" | Out-String
    }
    Else {
        $FindingDetails += "Config File:`t`t$($ConfigFile)" | Out-String
        # Get path to deployment.properties from .config file
        $ConfigFileContent = Get-Content -Path $ConfigFile
        ForEach ($Line in $ConfigFileContent) {
            If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                $PropsPath = ($Line.Split("=")[1]).Trim()
                Break
            }
        }
        If ($PropsPath) {
            $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
            If ($PropsFile.Pass -ne $true) {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "$Line" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += $PropsFile.Formatted | Out-String
            }
            Else {
                $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                $FindingDetails += "" | Out-String
                If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                    $Compliant = $false
                    $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                }
                Else {
                    If (Test-Path $PropsFile.Formatted) {
                        $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                        ForEach ($Key in $KeysToEval) {
                            If ($Key -in ($DeployFileContent -Replace "\s", "" -replace ".locked\s*=.*$", ".locked")) {
                                $FindingDetails += "$Key is present" | Out-String
                            }
                            Else {
                                $Compliant = $false
                                $FindingDetails += "$Key is NOT present" | Out-String
                            }
                        }
                    }
                    Else {
                        $Compliant = $false
                        $FindingDetails += "Properties file not found in the path defined." | Out-String
                    }
                }
            }
        }
        Else {
            $Compliant = $false
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V66915 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66915
        STIG ID    : JRE8-UX-000070
        Rule ID    : SV-81405r1_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516
        Rule Title : Oracle JRE 8 must be set to allow Java Web Start (JWS) applications.
        DiscussMD5 : 5DEE22E2DE37260B37F6F641CDFAE90C
        CheckMD5   : 681BC1FD9BDA1230E8A61C7C21C88892
        FixMD5     : 11C9D913495619013FAE2442026F7C96
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigFile = "/etc/.java/deployment/deployment.config"

    $KeysToEval = "deployment.webjava.enabled=true", `
        "deployment.webjava.enabled.locked"

    $Compliant = $true
    If (-Not(Test-Path $ConfigFile)) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found" | Out-String
    }
    Else {
        $FindingDetails += "Config File:`t`t$($ConfigFile)" | Out-String
        # Get path to deployment.properties from .config file
        $ConfigFileContent = Get-Content -Path $ConfigFile
        ForEach ($Line in $ConfigFileContent) {
            If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                $PropsPath = ($Line.Split("=")[1]).Trim()
                Break
            }
        }
        If ($PropsPath) {
            $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
            If ($PropsFile.Pass -ne $true) {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "$Line" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += $PropsFile.Formatted | Out-String
            }
            Else {
                $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                $FindingDetails += "" | Out-String
                If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                    $Compliant = $false
                    $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                }
                Else {
                    If (Test-Path $PropsFile.Formatted) {
                        $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                        ForEach ($Key in $KeysToEval) {
                            If ($Key -in ($DeployFileContent -Replace "\s", "" -replace ".locked\s*=.*$", ".locked")) {
                                $FindingDetails += "$Key is present" | Out-String
                            }
                            Else {
                                $Compliant = $false
                                $FindingDetails += "$Key is NOT present" | Out-String
                            }
                        }
                    }
                    Else {
                        $Compliant = $false
                        $FindingDetails += "Properties file not found in the path defined." | Out-String
                    }
                }
            }
        }
        Else {
            $Compliant = $false
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V66917 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66917
        STIG ID    : JRE8-UX-000080
        Rule ID    : SV-81407r1_rule
        CCI ID     : CCI-001695
        Rule Name  : SRG-APP-000112
        Rule Title : Oracle JRE 8 must disable the dialog enabling users to grant permissions to execute signed content from an untrusted authority.
        DiscussMD5 : 884B69274C3B7E49843DC681FC28341A
        CheckMD5   : 0440BF8BB57507D02C51FA7923DECC7D
        FixMD5     : 325309F86E188AF4F54199F77AAF31FF
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigFile = "/etc/.java/deployment/deployment.config"

    If ($ScanType -in "Classified") {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA."
    }
    Else {
        $KeysToEval = "deployment.security.askgrantdialog.notinca=false", `
            "deployment.security.askgrantdialog.notinca.locked"

        $Compliant = $true
        If (-Not(Test-Path $ConfigFile)) {
            $Compliant = $false
            $FindingDetails += "No deployment.config file found" | Out-String
        }
        Else {
            $FindingDetails += "Config File:`t`t$($ConfigFile)" | Out-String
            # Get path to deployment.properties from .config file
            $ConfigFileContent = Get-Content -Path $ConfigFile
            ForEach ($Line in $ConfigFileContent) {
                If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                    $PropsPath = ($Line.Split("=")[1]).Trim()
                    Break
                }
            }
            If ($PropsPath) {
                $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                If ($PropsFile.Pass -ne $true) {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "$Line" | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += $PropsFile.Formatted | Out-String
                }
                Else {
                    $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                    $FindingDetails += "" | Out-String
                    If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                        $Compliant = $false
                        $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                    }
                    Else {
                        If (Test-Path $PropsFile.Formatted) {
                            $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                            ForEach ($Key in $KeysToEval) {
                                If ($Key -in ($DeployFileContent -Replace "\s", "" -replace ".locked\s*=.*$", ".locked")) {
                                    $FindingDetails += "$Key is present" | Out-String
                                }
                                Else {
                                    $Compliant = $false
                                    $FindingDetails += "$Key is NOT present" | Out-String
                                }
                            }
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "Properties file not found in the path defined." | Out-String
                        }
                    }
                }
            }
            Else {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V66919 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66919
        STIG ID    : JRE8-UX-000090
        Rule ID    : SV-81409r1_rule
        CCI ID     : CCI-001695
        Rule Name  : SRG-APP-000112
        Rule Title : Oracle JRE 8 must lock the dialog enabling users to grant permissions to execute signed content from an untrusted authority.
        DiscussMD5 : CF669DA14A24210AF51C2FEB68300BBC
        CheckMD5   : 8C14F6145C7192D65BEB9E8C1D450F7D
        FixMD5     : 7B5BB65067CB648832EC4C0FD3B84BB2
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigFile = "/etc/.java/deployment/deployment.config"

    If ($ScanType -in "Classified") {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA."
    }
    Else {
        $KeysToEval = "deployment.security.askgrantdialog.show=false", `
            "deployment.security.askgrantdialog.show.locked"

        $Compliant = $true
        If (-Not(Test-Path $ConfigFile)) {
            $Compliant = $false
            $FindingDetails += "No deployment.config file found" | Out-String
        }
        Else {
            $FindingDetails += "Config File:`t`t$($ConfigFile)" | Out-String
            # Get path to deployment.properties from .config file
            $ConfigFileContent = Get-Content -Path $ConfigFile
            ForEach ($Line in $ConfigFileContent) {
                If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                    $PropsPath = ($Line.Split("=")[1]).Trim()
                    Break
                }
            }
            If ($PropsPath) {
                $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                If ($PropsFile.Pass -ne $true) {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "$Line" | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += $PropsFile.Formatted | Out-String
                }
                Else {
                    $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                    $FindingDetails += "" | Out-String
                    If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                        $Compliant = $false
                        $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                    }
                    Else {
                        If (Test-Path $PropsFile.Formatted) {
                            $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                            ForEach ($Key in $KeysToEval) {
                                If ($Key -in ($DeployFileContent -Replace "\s", "" -replace ".locked\s*=.*$", ".locked")) {
                                    $FindingDetails += "$Key is present" | Out-String
                                }
                                Else {
                                    $Compliant = $false
                                    $FindingDetails += "$Key is NOT present" | Out-String
                                }
                            }
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "Properties file not found in the path defined." | Out-String
                        }
                    }
                }
            }
            Else {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V66921 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66921
        STIG ID    : JRE8-UX-000100
        Rule ID    : SV-81411r1_rule
        CCI ID     : CCI-000185
        Rule Name  : SRG-APP-000175
        Rule Title : Oracle JRE 8 must set the option to enable online certificate validation.
        DiscussMD5 : A49775A6E44134FD46FF4732407BF5FB
        CheckMD5   : EC84F58A66EA4580C5FC4A38D4A2DCAF
        FixMD5     : 9F8170004F58D4AEEA94FBA1FD9A22F1
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigFile = "/etc/.java/deployment/deployment.config"

    If ($ScanType -in "Classified") {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA."
    }
    Else {
        $KeysToEval = "deployment.security.validation.ocsp=true", `
            "deployment.security.validation.ocsp.locked"

        $Compliant = $true
        If (-Not(Test-Path $ConfigFile)) {
            $Compliant = $false
            $FindingDetails += "No deployment.config file found" | Out-String
        }
        Else {
            $FindingDetails += "Config File:`t`t$($ConfigFile)" | Out-String
            # Get path to deployment.properties from .config file
            $ConfigFileContent = Get-Content -Path $ConfigFile
            ForEach ($Line in $ConfigFileContent) {
                If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                    $PropsPath = ($Line.Split("=")[1]).Trim()
                    Break
                }
            }
            If ($PropsPath) {
                $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                If ($PropsFile.Pass -ne $true) {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "$Line" | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += $PropsFile.Formatted | Out-String
                }
                Else {
                    $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                    $FindingDetails += "" | Out-String
                    If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                        $Compliant = $false
                        $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                    }
                    Else {
                        If (Test-Path $PropsFile.Formatted) {
                            $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                            ForEach ($Key in $KeysToEval) {
                                If ($Key -in ($DeployFileContent -Replace "\s", "" -replace ".locked\s*=.*$", ".locked")) {
                                    $FindingDetails += "$Key is present" | Out-String
                                }
                                Else {
                                    $Compliant = $false
                                    $FindingDetails += "$Key is NOT present" | Out-String
                                }
                            }
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "Properties file not found in the path defined." | Out-String
                        }
                    }
                }
            }
            Else {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V66923 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66923
        STIG ID    : JRE8-UX-000110
        Rule ID    : SV-81413r1_rule
        CCI ID     : CCI-001169
        Rule Name  : SRG-APP-000209
        Rule Title : Oracle JRE 8 must prevent the download of prohibited mobile code.
        DiscussMD5 : CEC79E03E4228BD7547CB3EBAB995CA3
        CheckMD5   : 78C60C93923FABA5BFD79739E2A18CDD
        FixMD5     : 3999EBFF2A891ADAEDED7A9C7190DE07
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigFile = "/etc/.java/deployment/deployment.config"

    $KeysToEval = "deployment.security.blacklist.check=true", `
        "deployment.security.blacklist.check.locked"

    $Compliant = $true
    If (-Not(Test-Path $ConfigFile)) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found" | Out-String
    }
    Else {
        $FindingDetails += "Config File:`t`t$($ConfigFile)" | Out-String
        # Get path to deployment.properties from .config file
        $ConfigFileContent = Get-Content -Path $ConfigFile
        ForEach ($Line in $ConfigFileContent) {
            If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                $PropsPath = ($Line.Split("=")[1]).Trim()
                Break
            }
        }
        If ($PropsPath) {
            $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
            If ($PropsFile.Pass -ne $true) {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "$Line" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += $PropsFile.Formatted | Out-String
            }
            Else {
                $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                $FindingDetails += "" | Out-String
                If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                    $Compliant = $false
                    $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                }
                Else {
                    If (Test-Path $PropsFile.Formatted) {
                        $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                        ForEach ($Key in $KeysToEval) {
                            If ($Key -in ($DeployFileContent -Replace "\s", "" -replace ".locked\s*=.*$", ".locked")) {
                                $FindingDetails += "$Key is present" | Out-String
                            }
                            Else {
                                $Compliant = $false
                                $FindingDetails += "$Key is NOT present" | Out-String
                            }
                        }
                    }
                    Else {
                        $Compliant = $false
                        $FindingDetails += "Properties file not found in the path defined." | Out-String
                    }
                }
            }
        }
        Else {
            $Compliant = $false
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V66925 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66925
        STIG ID    : JRE8-UX-000120
        Rule ID    : SV-81415r2_rule
        CCI ID     : CCI-001774
        Rule Name  : SRG-APP-000386
        Rule Title : Oracle JRE 8 must enable the option to use an accepted sites list.
        DiscussMD5 : F07373721D4DC99C769562427B1C6F3B
        CheckMD5   : 55BC64EBF4CFDAE753B1D0F8FF7500E4
        FixMD5     : ECC649E6493D45B1ABF568289B294A63
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigFile = "/etc/.java/deployment/deployment.config"

    $KeysToEval = "deployment.user.security.exception.sites"

    $Compliant = $true
    If (-Not(Test-Path $ConfigFile)) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found" | Out-String
    }
    Else {
        $FindingDetails += "Config File:`t`t$($ConfigFile)" | Out-String
        # Get path to deployment.properties from .config file
        $ConfigFileContent = Get-Content -Path $ConfigFile
        ForEach ($Line in $ConfigFileContent) {
            If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                $PropsPath = ($Line.Split("=")[1]).Trim()
                Break
            }
        }
        If ($PropsPath) {
            $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
            If ($PropsFile.Pass -ne $true) {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "$Line" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += $PropsFile.Formatted | Out-String
            }
            Else {
                $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                $FindingDetails += "" | Out-String
                If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                    $Compliant = $false
                    $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                }
                Else {
                    If (Test-Path $PropsFile.Formatted) {
                        $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                        ForEach ($Key in $KeysToEval) {
                            If ($DeployFileContent -match $Key) {
                                ForEach ($Line in $DeployFileContent) {
                                    If ($Line -like "$($KeysToEval)*") {
                                        $ExceptionPath = ($Line.Split("=")[1]).Trim()
                                        Break
                                    }
                                }
                                If ($ExceptionPath) {
                                    $ExceptionFile = Format-JavaPath -Path $ExceptionPath -JavaFile exception.sites
                                    If ($ExceptionFile.Pass -ne $true) {
                                        $Compliant = $false
                                        $FindingDetails += "$Line" | Out-String
                                        $FindingDetails += "" | Out-String
                                        $FindingDetails += $ExceptionFile.Formatted | Out-String
                                    }
                                    ElseIf ($ExceptionFile.Formatted.Split("/")[0, -1][1] -ne "exception.sites") {
                                        $Compliant = $false
                                        $FindingDetails += "$Line" | Out-String
                                        $FindingDetails += "" | Out-String
                                        $FindingDetails += "$Key does not point to an 'exception.sites' file." | Out-String
                                    }
                                    Else {
                                        $FindingDetails += "$Line is present" | Out-String
                                    }
                                }
                                Else {
                                    $Compliant = $false
                                    $FindingDetails += "$Line" | Out-String
                                    $FindingDetails += "" | Out-String
                                    $FindingDetails += "Path to 'exception.sites' file is not defined in properties file." | Out-String
                                }
                            }
                            Else {
                                $Compliant = $false
                                $FindingDetails += "$Key is NOT present" | Out-String
                            }
                        }
                    }
                    Else {
                        $Compliant = $false
                        $FindingDetails += "Properties file not found in the path defined." | Out-String
                    }
                }
            }
        }
        Else {
            $Compliant = $false
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V66927 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66927
        STIG ID    : JRE8-UX-000130
        Rule ID    : SV-81417r1_rule
        CCI ID     : CCI-001774
        Rule Name  : SRG-APP-000386
        Rule Title : Oracle JRE 8 must have an exception.sites file present.
        DiscussMD5 : F07373721D4DC99C769562427B1C6F3B
        CheckMD5   : F071BC4DA9172CC248A012337EF8A102
        FixMD5     : D24B0D67013B5A3E18908526549F8D27
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigFile = "/etc/.java/deployment/deployment.config"

    If ($ScanType -in "Classified") {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA."
    }
    Else {
        $KeysToEval = "deployment.user.security.exception.sites"

        $Compliant = $true
        If (-Not(Test-Path $ConfigFile)) {
            $Compliant = $false
            $FindingDetails += "No deployment.config file found" | Out-String
        }
        Else {
            $FindingDetails += "Config File:`t`t$($ConfigFile)" | Out-String
            # Get path to deployment.properties from .config file
            $ConfigFileContent = Get-Content -Path $ConfigFile
            ForEach ($Line in $ConfigFileContent) {
                If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                    $PropsPath = ($Line.Split("=")[1]).Trim()
                    Break
                }
            }
            If ($PropsPath) {
                $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                If ($PropsFile.Pass -ne $true) {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "$Line" | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += $PropsFile.Formatted | Out-String
                }
                Else {
                    $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                    If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                        $Compliant = $false
                        $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                    }
                    Else {
                        If (Test-Path $PropsFile.Formatted) {
                            $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                            ForEach ($Key in $KeysToEval) {
                                If ($DeployFileContent -match $Key) {
                                    ForEach ($Line in $DeployFileContent) {
                                        If ($Line -like "$($KeysToEval)*") {
                                            $ExceptionPath = ($Line.Split("=")[1]).Trim()
                                            Break
                                        }
                                    }
                                    If ($ExceptionPath) {
                                        $ExceptionFile = Format-JavaPath -Path $ExceptionPath -JavaFile exception.sites
                                        If ($ExceptionFile.Pass -ne $true) {
                                            $Compliant = $false
                                            $FindingDetails += "" | Out-String
                                            $FindingDetails += "$Line" | Out-String
                                            $FindingDetails += "" | Out-String
                                            $FindingDetails += $ExceptionFile.Formatted | Out-String
                                        }
                                        Else {
                                            $FindingDetails += "Exception File:`t`t$($ExceptionFile.Configured)" | Out-String
                                            $FindingDetails += "" | Out-String
                                            If ($ExceptionFile.Formatted.Split("/")[0, -1][1] -ne "exception.sites") {
                                                $Compliant = $false
                                                $FindingDetails += "$Key does not point to an 'exception.sites' file." | Out-String
                                            }
                                            Else {
                                                If (Test-Path $ExceptionFile.Formatted) {
                                                    $FindingDetails += "Exception file exists in the path defined." | Out-String
                                                }
                                                Else {
                                                    $Compliant = $false
                                                    $FindingDetails += "Exception file not found in the path defined." | Out-String
                                                }
                                            }
                                        }
                                    }
                                    Else {
                                        $Compliant = $false
                                        $FindingDetails += "" | Out-String
                                        $FindingDetails += "Path to 'exception.sites' file is not defined in properties file." | Out-String
                                    }
                                }
                                Else {
                                    $Compliant = $false
                                    $FindingDetails += "" | Out-String
                                    $FindingDetails += "$Key is NOT present" | Out-String
                                }
                            }
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "" | Out-String
                            $FindingDetails += "Properties file not found in the path defined." | Out-String
                        }
                    }
                }
            }
            Else {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V66929 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66929
        STIG ID    : JRE8-UX-000150
        Rule ID    : SV-81419r1_rule
        CCI ID     : CCI-001991
        Rule Name  : SRG-APP-000401
        Rule Title : Oracle JRE 8 must enable the dialog to enable users to check publisher certificates for revocation.
        DiscussMD5 : C3D8C5511483BF09893323791B8DFE96
        CheckMD5   : 71F37CA63D6799FEC5EDB410DFF45FDB
        FixMD5     : A78D21DCB7FF170922F19D4C1C03609E
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigFile = "/etc/.java/deployment/deployment.config"

    If ($ScanType -in "Classified") {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA."
    }
    Else {
        $KeysToEval = "deployment.security.validation.crl=true", `
            "deployment.security.validation.crl.locked"

        $Compliant = $true
        If (-Not(Test-Path $ConfigFile)) {
            $Compliant = $false
            $FindingDetails += "No deployment.config file found" | Out-String
        }
        Else {
            $FindingDetails += "Config File:`t`t$($ConfigFile)" | Out-String
            # Get path to deployment.properties from .config file
            $ConfigFileContent = Get-Content -Path $ConfigFile
            ForEach ($Line in $ConfigFileContent) {
                If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                    $PropsPath = ($Line.Split("=")[1]).Trim()
                    Break
                }
            }
            If ($PropsPath) {
                $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                If ($PropsFile.Pass -ne $true) {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "$Line" | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += $PropsFile.Formatted | Out-String
                }
                Else {
                    $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                    $FindingDetails += "" | Out-String
                    If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                        $Compliant = $false
                        $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                    }
                    Else {
                        If (Test-Path $PropsFile.Formatted) {
                            $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                            ForEach ($Key in $KeysToEval) {
                                If ($Key -in ($DeployFileContent -Replace "\s", "" -replace ".locked\s*=.*$", ".locked")) {
                                    $FindingDetails += "$Key is present" | Out-String
                                }
                                Else {
                                    $Compliant = $false
                                    $FindingDetails += "$Key is NOT present" | Out-String
                                }
                            }
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "Properties file not found in the path defined." | Out-String
                        }
                    }
                }
            }
            Else {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V66931 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66931
        STIG ID    : JRE8-UX-000160
        Rule ID    : SV-81421r1_rule
        CCI ID     : CCI-001991
        Rule Name  : SRG-APP-000401
        Rule Title : Oracle JRE 8 must lock the option to enable users to check publisher certificates for revocation.
        DiscussMD5 : 641C7784614699CE2C93D8CA2E495B55
        CheckMD5   : 1176EB32C94023E5D1CDFD508D83A2EB
        FixMD5     : 6104CC5D40C2B234D2D0AA6589008344
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigFile = "/etc/.java/deployment/deployment.config"

    If ($ScanType -in "Classified") {
        $Status = "Not_Applicable"
        $FindingDetails += "This is a classified system so this requirement is NA."
    }
    Else {
        $KeysToEval = "deployment.security.revocation.check=ALL_CERTIFICATES", `
            "deployment.security.revocation.check.locked"

        $Compliant = $true
        If (-Not(Test-Path $ConfigFile)) {
            $Compliant = $false
            $FindingDetails += "No deployment.config file found" | Out-String
        }
        Else {
            $FindingDetails += "Config File:`t`t$($ConfigFile)" | Out-String
            # Get path to deployment.properties from .config file
            $ConfigFileContent = Get-Content -Path $ConfigFile
            ForEach ($Line in $ConfigFileContent) {
                If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                    $PropsPath = ($Line.Split("=")[1]).Trim()
                    Break
                }
            }
            If ($PropsPath) {
                $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
                If ($PropsFile.Pass -ne $true) {
                    $Compliant = $false
                    $FindingDetails += "" | Out-String
                    $FindingDetails += "$Line" | Out-String
                    $FindingDetails += "" | Out-String
                    $FindingDetails += $PropsFile.Formatted | Out-String
                }
                Else {
                    $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                    $FindingDetails += "" | Out-String
                    If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                        $Compliant = $false
                        $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                    }
                    Else {
                        If (Test-Path $PropsFile.Formatted) {
                            $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                            ForEach ($Key in $KeysToEval) {
                                If ($Key -in ($DeployFileContent -Replace "\s", "" -replace ".locked\s*=.*$", ".locked")) {
                                    $FindingDetails += "$Key is present" | Out-String
                                }
                                Else {
                                    $Compliant = $false
                                    $FindingDetails += "$Key is NOT present" | Out-String
                                }
                            }
                        }
                        Else {
                            $Compliant = $false
                            $FindingDetails += "Properties file not found in the path defined." | Out-String
                        }
                    }
                }
            }
            Else {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V66933 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66933
        STIG ID    : JRE8-UX-000170
        Rule ID    : SV-81423r1_rule
        CCI ID     : CCI-002460
        Rule Name  : SRG-APP-000488
        Rule Title : Oracle JRE 8 must prompt the user for action prior to executing mobile code.
        DiscussMD5 : EB406C03E21F7D1CBE591AA7FDC219DE
        CheckMD5   : F551C7A3701972DBCFDAA2C0CDBFF1FC
        FixMD5     : 201AB606A1B0DED343C7258E70D23E93
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $ConfigFile = "/etc/.java/deployment/deployment.config"

    $KeysToEval = "deployment.insecure.jres=PROMPT", `
        "deployment.insecure.jres.locked"

    $Compliant = $true
    If (-Not(Test-Path $ConfigFile)) {
        $Compliant = $false
        $FindingDetails += "No deployment.config file found" | Out-String
    }
    Else {
        $FindingDetails += "Config File:`t`t$($ConfigFile)" | Out-String
        # Get path to deployment.properties from .config file
        $ConfigFileContent = Get-Content -Path $ConfigFile
        ForEach ($Line in $ConfigFileContent) {
            If (($Line -Replace "\s", "") -like "deployment.system.config=*") {
                $PropsPath = ($Line.Split("=")[1]).Trim()
                Break
            }
        }
        If ($PropsPath) {
            $PropsFile = Format-JavaPath -Path $PropsPath -JavaFile deployment.properties
            If ($PropsFile.Pass -ne $true) {
                $Compliant = $false
                $FindingDetails += "" | Out-String
                $FindingDetails += "$Line" | Out-String
                $FindingDetails += "" | Out-String
                $FindingDetails += $PropsFile.Formatted | Out-String
            }
            Else {
                $FindingDetails += "Properties File:`t`t$($PropsFile.Configured)" | Out-String
                $FindingDetails += "" | Out-String
                If ($PropsFile.Formatted.Split("/")[0, -1][1] -ne "deployment.properties") {
                    $Compliant = $false
                    $FindingDetails += "deployment.system.config does not point to a 'deployment.properties' file." | Out-String
                }
                Else {
                    If (Test-Path $PropsFile.Formatted) {
                        $DeployFileContent = Get-Content -Path $PropsFile.Formatted
                        ForEach ($Key in $KeysToEval) {
                            If ($Key -in ($DeployFileContent -Replace "\s", "" -replace ".locked\s*=.*$", ".locked")) {
                                $FindingDetails += "$Key is present" | Out-String
                            }
                            Else {
                                $Compliant = $false
                                $FindingDetails += "$Key is NOT present" | Out-String
                            }
                        }
                    }
                    Else {
                        $Compliant = $false
                        $FindingDetails += "Properties file not found in the path defined." | Out-String
                    }
                }
            }
        }
        Else {
            $Compliant = $false
            $FindingDetails += "" | Out-String
            $FindingDetails += "Path to 'deployment.Properties' file is not defined in deployment.config." | Out-String
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

Function Get-V66937 {
    <#
    .DESCRIPTION
        Vuln ID    : V-66937
        STIG ID    : JRE8-UX-000180
        Rule ID    : SV-81427r1_rule
        CCI ID     : CCI-002605
        Rule Name  : SRG-APP-000456
        Rule Title : The version of Oracle JRE 8 running on the system must be the most current available.
        DiscussMD5 : 1A65A3F13B756E1A1094EFEA1913C357
        CheckMD5   : 7072FDA515397EA01DD65078489A9562
        FixMD5     : C276CB234E7261A6644215C1898FC872
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$ScanType,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$Username,

        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $Result = Start-ProcessWithOutput -FileName "java" -Arguments "-version"
    $JavaVer = $Result.StdErr
    $FindingDetails += $JavaVer | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAr+j6jFTkV5YpC
# 7+wIfDAYYDrF4zdStg90fcPJI/E8W6CCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCUd9uP5H3Glh7KV3mJi+TMFiNdFXhQ
# Pxz3A4DaflDm+DANBgkqhkiG9w0BAQEFAASCAQCBsBxFIqfP3RxyWv2gNbfBNSQG
# tcQLO+H/C/ZQMbNPBXh4hFYX62iikt0oJwJfYWtXiC94WIJiORl5npOM1XCLhM1X
# q04MQPblxHq3oyx/cTYRZYtD7L1Beq++BooU653eXXDu1ILwWhpONjh8bEFXTooI
# e20cB65U3nfH409JG7TPfoNzzFw+/lRBGXXAfTW04XnJVKehZmUcrdLXy+9q36nL
# HxwnoUsFodeNIfgZwXlIQv05Mf7fDkR/OtJu9tXtCoWBuX7cwRlmfKKxqIRWFTvO
# 4CpXv0jHYgYcx45tNvSURmt/Gzjx/hj0ZXUIu+MXXc9qxXxDXXMereWDdagd
# SIG # End signature block
