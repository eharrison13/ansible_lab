##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     MS SQL Server 2014 Database
# Version:  V1R6
# Class:    UNCLASSIFIED
# Updated:  5/13/2024
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V67359 {
    <#
    .DESCRIPTION
        Vuln ID    : V-67359
        STIG ID    : SQL4-00-011200
        Rule ID    : SV-81849r2_rule
        CCI ID     : CCI-000169
        Rule Name  : SRG-APP-000089-DB-000064
        Rule Title : SQL Server must generate Trace or Audit records for organization-defined auditable events.
        DiscussMD5 : E69375F89B30492809807EC889B44D6B
        CheckMD5   : 49B2CC13D8D014C519FADAE8F8DDCAC9
        FixMD5     : FB517D79EFC0E0BCBD0F4E176EBBD845
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Instance,
        [Parameter(Mandatory = $true)]
        [String]$Database,
        [Parameter(Mandatory = $false)]
        [String]$Username,
        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $FindingDetails = Confirm-TraceAuditSetting -Instance $Instance -Database $Database
    If ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "All required events are being audited."
    }
    Else {
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

Function Get-V67373 {
    <#
    .DESCRIPTION
        Vuln ID    : V-67373
        STIG ID    : SQL4-00-015620
        Rule ID    : SV-81863r1_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000200
        Rule Title : In a database owned by a login not having administrative privileges at the instance level, the database property TRUSTWORTHY must be OFF unless required and authorized.
        DiscussMD5 : 858D9C1CBA1753CDC01F7E80CFFB6D1A
        CheckMD5   : BD3CAA48647043D3BEF40DAC0DABE6EB
        FixMD5     : 18E188DD591F7FFD013FA1E8AB17A22A
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Instance,
        [Parameter(Mandatory = $true)]
        [String]$Database,
        [Parameter(Mandatory = $false)]
        [String]$Username,
        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT
        DB_NAME() AS [Database],
        SUSER_SNAME(D.owner_sid) AS [Database Owner],
        CASE WHEN D.is_trustworthy_on = 1 THEN 'ON' ELSE 'off' END
        AS [Trustworthy]
        FROM
        sys.databases D
        WHERE
        D.[name] = DB_NAME()
        AND DB_NAME() <> 'msdb'
        AND D.is_trustworthy_on = 1
    "
    if ($res) {
        $Status = 'Not_Reviewed'
        $FindingDetails += "DBA, review the system security plan to determine whether the need for TRUSTWORTHY is documented as approved for these databases:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check query."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V67375 {
    <#
    .DESCRIPTION
        Vuln ID    : V-67375
        STIG ID    : SQL4-00-015610
        Rule ID    : SV-81865r1_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000200
        Rule Title : In a database owned by [sa], or by any other login having administrative privileges at the instance level, the database property TRUSTWORTHY must be OFF.
        DiscussMD5 : 858D9C1CBA1753CDC01F7E80CFFB6D1A
        CheckMD5   : 11B5CD659845EF612A94B8A00B251797
        FixMD5     : 387E745777BC33C701D43C3E90009DB0
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Instance,
        [Parameter(Mandatory = $true)]
        [String]$Database,
        [Parameter(Mandatory = $false)]
        [String]$Username,
        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        WITH FixedServerRoles(RoleName) AS
        (
              SELECT 'sysadmin'
              UNION SELECT 'securityadmin'
              UNION SELECT 'serveradmin'
              UNION SELECT 'setupadmin'
              UNION SELECT 'processadmin'
              UNION SELECT 'diskadmin'
              UNION SELECT 'dbcreator'
              UNION SELECT 'bulkadmin'
        )
        SELECT
              DB_NAME() AS [Database],
              SUSER_SNAME(D.owner_sid) AS [Database Owner],
              F.RoleName AS [Fixed Server Role],
              CASE WHEN D.is_trustworthy_on = 1 THEN 'ON' ELSE 'off' END
                    AS [Trustworthy]
        FROM
              FixedServerRoles F
              INNER JOIN sys.databases D ON D.Name = DB_NAME()
        WHERE
              IS_SRVROLEMEMBER(F.RoleName, SUSER_SNAME(D.owner_sid)) = 1
        AND   DB_NAME() <> 'msdb'
        AND   D.is_trustworthy_on = 1;
    "
    if ($res) {
        $Status = 'Open'
        $FindingDetails += "The following databases owned by SA have TRUSTWORTHY improperly set to ON:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check query."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V67381 {
    <#
    .DESCRIPTION
        Vuln ID    : V-67381
        STIG ID    : SQL4-00-024100
        Rule ID    : SV-81871r1_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231-DB-000154
        Rule Title : The Database Master Key must be encrypted by the Service Master Key, where a Database Master Key is required and another encryption method has not been specified.
        DiscussMD5 : E20E1D2CC9839DC27B64F09DFB76F6DD
        CheckMD5   : 1C5FD01A4D392C8AE5E0AC62F51E5577
        FixMD5     : BC25B295DA82CF8E76CE091ECE2A6DFC
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Instance,
        [Parameter(Mandatory = $true)]
        [String]$Database,
        [Parameter(Mandatory = $false)]
        [String]$Username,
        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
    SELECT name
    FROM [master].sys.databases
    WHERE is_master_key_encrypted_by_server = 1
    AND owner_sid <> 1
    AND state = 0;
    "
    if ($res) {
        $Status = 'Open'
        $FindingDetails += "DBA, ensure the SSP has approved the encryption of these database master keys using the service master keys:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check query."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V67383 {
    <#
    .DESCRIPTION
        Vuln ID    : V-67383
        STIG ID    : SQL4-00-024200
        Rule ID    : SV-81873r1_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231-DB-000154
        Rule Title : Database Master Key passwords must not be stored in credentials within the database.
        DiscussMD5 : EDE5EA77177F1E32F465CDF5484BC80F
        CheckMD5   : 8E21E42521FC9A6C99372943F46DE291
        FixMD5     : 3999F8A6B2D14C45172F747201183A09
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Instance,
        [Parameter(Mandatory = $true)]
        [String]$Database,
        [Parameter(Mandatory = $false)]
        [String]$Username,
        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT COUNT(credential_id)
        FROM [master].sys.master_key_passwords
    "
    if ($res.column1 -gt 0) {
        $Status = 'Open'
        $FindingDetails += "Marked as Open because the check query found $($res.column1) master password(s) being stored within the database."
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "Marked as NF because the check query found no master passwords being stored within the database."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V67385 {
    <#
    .DESCRIPTION
        Vuln ID    : V-67385
        STIG ID    : SQL4-00-024300
        Rule ID    : SV-81875r2_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231-DB-000154
        Rule Title : Symmetric keys (other than the database master key) must use a DoD certificate to encrypt the key.
        DiscussMD5 : 5BCD73D14BD84F2D910166227A858D71
        CheckMD5   : ED6109EFD5B06A41FA5940A7A5783A33
        FixMD5     : 523F15726A0DE67F4261D30AB268CF4D
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Instance,
        [Parameter(Mandatory = $true)]
        [String]$Database,
        [Parameter(Mandatory = $false)]
        [String]$Username,
        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT s.name, k.crypt_type_desc
        FROM sys.symmetric_keys s, sys.key_encryptions k
        WHERE s.symmetric_key_id = k.key_id
        AND s.name <> '##MS_DatabaseMasterKey##'
        AND k.crypt_type IN ('ESKP', 'ESKS')
        ORDER BY s.name, k.crypt_type_desc;
    "
    if ($res) {
        $Status = 'Not_Reviewed'
        $FindingDetails += "DBA, ensure these symmetric keys use DoD PKI certs for encryption and that they are documented in the SSP:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check query."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V67413 {
    <#
    .DESCRIPTION
        Vuln ID    : V-67413
        STIG ID    : SQL4-00-035800
        Rule ID    : SV-81903r2_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000494-DB-000344
        Rule Title : Trace or Audit records must be generated when categorized information (e.g., classification levels/security levels) is accessed.
        DiscussMD5 : 4DC5E8FDDC9A552CD25442C66A72293E
        CheckMD5   : 58B3FC126D8CBAD883866B61C9431764
        FixMD5     : CF3A90E9ECFD32ED8EB2765B09212CEB
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Instance,
        [Parameter(Mandatory = $true)]
        [String]$Database,
        [Parameter(Mandatory = $false)]
        [String]$Username,
        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
    SELECT a.name AS 'AuditName',
    s.name AS 'SpecName',
    d.audit_action_name AS 'ActionName',
    d.audited_result AS 'Result'
    FROM sys.server_audit_specifications s
    JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
    JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
    WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP'
    "
    if ($res) {
        $Status = 'NotAFinding'
        #$FindingDetails += "The audit is being performed."
        # 20201027 JJS Added all Results to output
        $FindingDetails += "The audit is being performed.`n$($res | Format-Table -AutoSize| Out-String)"

    }
    else {
        $Status = "Open"
        $FindingDetails = "DBA, no audits are being done for retrieval of privilege/permissions/role membership info. Does the SSP agree this is OK?"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V67415 {
    <#
    .DESCRIPTION
        Vuln ID    : V-67415
        STIG ID    : SQL4-00-035900
        Rule ID    : SV-81905r2_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000494-DB-000345
        Rule Title : Trace or Audit records must be generated when unsuccessful attempts to access categorized information (e.g., classification levels/security levels) occur.
        DiscussMD5 : 4B8AA5406C666B4122F61EB9553C240F
        CheckMD5   : 43AFFDA6BD9252311902F861E833BE0F
        FixMD5     : CEF65A41D81675563AAA8FFB69D33907
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Instance,
        [Parameter(Mandatory = $true)]
        [String]$Database,
        [Parameter(Mandatory = $false)]
        [String]$Username,
        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
    SELECT a.name AS 'AuditName',
    s.name AS 'SpecName',
    d.audit_action_name AS 'ActionName',
    d.audited_result AS 'Result'
    FROM sys.server_audit_specifications s
    JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
    JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
    WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP'
    "
    if ($res) {
        $Status = 'NotAFinding'
        #$FindingDetails += "The audit is being performed."
        # 20201027 JJS Added all Results to output
        $FindingDetails += "The audit is being performed.`n$($res | Format-Table -AutoSize| Out-String)"
    }
    else {
        $Status = "Open"
        $FindingDetails = "DBA, no audits are being done for retrieval of privilege/permissions/role membership info. Does the SSP agree this is OK?"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V67417 {
    <#
    .DESCRIPTION
        Vuln ID    : V-67417
        STIG ID    : SQL4-00-036200
        Rule ID    : SV-81907r2_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000495-DB-000328
        Rule Title : SQL Server must generate Trace or Audit records when privileges/permissions are modified via locally-defined security objects.
        DiscussMD5 : 8BD6B45B25B07E1F885DC225C3B1A9F6
        CheckMD5   : 06CA9D5475C788785EDC5ED1DB4D10FA
        FixMD5     : 3572B1DFE26BEBBA3F7785CD87229353
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Instance,
        [Parameter(Mandatory = $true)]
        [String]$Database,
        [Parameter(Mandatory = $false)]
        [String]$Username,
        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $svrlist = (Get-ISQL -ServerInstance $Instance -Database $Database "SELECT @@servername as instance").instance
    if ($svrlist) {
        foreach ($svr in $svrlist) {
            $res = Get-ISQL -ServerInstance $svr "
            SELECT name AS 'Audit Name',
            status_desc AS 'Audit Status',
            audit_file_path AS 'Current Audit File'
            FROM sys.dm_server_audit_status
        "
            if ($res) {
                $res2 = Get-ISQL -ServerInstance $svr "
            with q as (
                    select 'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP' as audit_action_name
            union select 'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP'
            union select 'DATABASE_OWNERSHIP_CHANGE_GROUP'
            union select 'DATABASE_PERMISSION_CHANGE_GROUP'
            union select 'DATABASE_ROLE_MEMBER_CHANGE_GROUP'
            union select 'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP'
            union select 'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP'
            union select 'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP'
            union select 'SERVER_OBJECT_PERMISSION_CHANGE_GROUP'
            union select 'SERVER_PERMISSION_CHANGE_GROUP'
            union select 'SERVER_ROLE_MEMBER_CHANGE_GROUP'
            except
                    SELECT d.audit_action_name AS 'ActionName'
                    FROM sys.server_audit_specifications s
                    JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                    JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                    WHERE a.is_state_enabled = 1
                    and s.is_state_enabled = 1
            )
            select @@SERVERNAME as InstanceName, Audit_Action_Name from q order by 1, 2
            "
                if ($res2) {
                    $Status = 'Open'
                    $FindingDetails += "The following actions are not being audited:`n$($res2 | Format-Table -AutoSize| Out-String)"
                } # if ($res2)
            }
            else {
                $Status = 'Open'
                $FindingDetails += "It appears that no audits have been defined yet for instance $svr`n"
            } # if ($res)
        } # foreach ($svr in $svrlist)
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "No SQL instances are running on this server."
    } # if ($svrlist)

    if ($FindingDetails -eq '') {
        $Status = 'NotAFinding'
        $FindingDetails = "Audits appear to be configured correctly."
    } # if ($FindingDetails -eq '')
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V67419 {
    <#
    .DESCRIPTION
        Vuln ID    : V-67419
        STIG ID    : SQL4-00-036300
        Rule ID    : SV-81909r2_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000495-DB-000329
        Rule Title : SQL Server must generate Trace or Audit records when unsuccessful attempts to modify privileges/permissions via locally-defined security objects occur.
        DiscussMD5 : EF04256FD66BF83190C5657CD28B7E5C
        CheckMD5   : 2431A19C546ED1F86D9691CBAE8BBB94
        FixMD5     : 3572B1DFE26BEBBA3F7785CD87229353
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Instance,
        [Parameter(Mandatory = $true)]
        [String]$Database,
        [Parameter(Mandatory = $false)]
        [String]$Username,
        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $svrlist = (Get-ISQL -ServerInstance $Instance -Database $Database "SELECT @@servername as instance").instance
    if ($svrlist) {
        foreach ($svr in $svrlist) {
            $res = Get-ISQL -ServerInstance $svr "
            SELECT name AS 'Audit Name',
            status_desc AS 'Audit Status',
            audit_file_path AS 'Current Audit File'
            FROM sys.dm_server_audit_status
        "
            if ($res) {
                $res2 = Get-ISQL -ServerInstance $svr "
            with q as (
                    select 'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP' as audit_action_name
            union select 'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP'
            union select 'DATABASE_OWNERSHIP_CHANGE_GROUP'
            union select 'DATABASE_PERMISSION_CHANGE_GROUP'
            union select 'DATABASE_ROLE_MEMBER_CHANGE_GROUP'
            union select 'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP'
            union select 'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP'
            union select 'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP'
            union select 'SERVER_OBJECT_PERMISSION_CHANGE_GROUP'
            union select 'SERVER_PERMISSION_CHANGE_GROUP'
            union select 'SERVER_ROLE_MEMBER_CHANGE_GROUP'
            except
                    SELECT d.audit_action_name AS 'ActionName'
                    FROM sys.server_audit_specifications s
                    JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                    JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                    WHERE a.is_state_enabled = 1
                    and s.is_state_enabled = 1
            )
            select @@SERVERNAME as InstanceName, Audit_Action_Name from q order by 1, 2
            "
                if ($res2) {
                    $Status = 'Open'
                    $FindingDetails += "The following actions are not being audited:`n$($res2 | Format-Table -AutoSize| Out-String)"
                } # if ($res2)
            }
            else {
                $Status = 'Open'
                $FindingDetails += "It appears that no audits have been defined yet for instance $svr`n"
            } # if ($res)
        } # foreach ($svr in $svrlist)
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "No SQL instances are running on this server."
    } # if ($svrlist)

    if ($FindingDetails -eq '') {
        $Status = 'NotAFinding'
        $FindingDetails = "Audits appear to be configured correctly."
    } # if ($FindingDetails -eq '')
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V67421 {
    <#
    .DESCRIPTION
        Vuln ID    : V-67421
        STIG ID    : SQL4-00-036400
        Rule ID    : SV-81911r2_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000496-DB-000334
        Rule Title : SQL Server must generate Trace or Audit records when locally-defined security objects are modified.
        DiscussMD5 : B5F2E8EBFA7567485785B421A4ADF035
        CheckMD5   : 22D215E5EEB17A0F820793CB17B6F97C
        FixMD5     : A6AF829790405294C5669C9D3F87FE25
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Instance,
        [Parameter(Mandatory = $true)]
        [String]$Database,
        [Parameter(Mandatory = $false)]
        [String]$Username,
        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
    SELECT a.name AS 'AuditName',
    s.name AS 'SpecName',
    d.audit_action_name AS 'ActionName',
    d.audited_result AS 'Result'
    FROM sys.server_audit_specifications s
    JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
    JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
    WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_CHANGE_GROUP'
    "
    if ($res) {
        $Status = 'NotAFinding'
        #$FindingDetails = "The SCHEMA_OBJECT_CHANGE_GROUP audit is being performed."
        # 20201027 JJS Added all Results to output
        $FindingDetails = "The SCHEMA_OBJECT_CHANGE_GROUP audit is being performed.`n$($res | Format-Table -AutoSize| Out-String)"

    }
    else {
        $Status = "Open"
        $FindingDetails = "The SCHEMA_OBJECT_CHANGE_GROUP audit is not being performed."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V67423 {
    <#
    .DESCRIPTION
        Vuln ID    : V-67423
        STIG ID    : SQL4-00-038200
        Rule ID    : SV-81913r3_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000507-DB-000357
        Rule Title : SQL Server must generate Trace or Audit records when unsuccessful accesses to designated objects occur.
        DiscussMD5 : 15452D59DD99BD0CEB25CC2B351A7151
        CheckMD5   : 70AC920C5DD01FA82AA213B7FFA5D89B
        FixMD5     : 682E48E4CBE0CC53C8B4DEE0082B1BEF
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Instance,
        [Parameter(Mandatory = $true)]
        [String]$Database,
        [Parameter(Mandatory = $false)]
        [String]$Username,
        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
    SELECT a.name AS 'AuditName',
    s.name AS 'SpecName',
    d.audit_action_name AS 'ActionName',
    d.audited_result AS 'Result'
    FROM sys.server_audit_specifications s
    JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
    JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
    WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP'
    "
    if ($res) {
        $Status = 'NotAFinding'
        #$FindingDetails += "The audit is being performed."
        # 20201027 JJS Added all Results to output
        $FindingDetails += "The audit is being performed.`n$($res | Format-Table -AutoSize| Out-String)"
    }
    else {
        $Status = "Open"
        $FindingDetails = "DBA, no audits are being done for retrieval of privilege/permissions/role membership info. Does the SSP agree this is OK?"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V67425 {
    <#
    .DESCRIPTION
        Vuln ID    : V-67425
        STIG ID    : SQL4-00-038100
        Rule ID    : SV-81915r3_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000507-DB-000356
        Rule Title : SQL Server must generate Trace or Audit records when successful accesses to designated objects occur.
        DiscussMD5 : B424B72B54F63B0E81198AD977EE8E61
        CheckMD5   : F5ACF272964336B7459E5EB17B335C8A
        FixMD5     : 3C9EFD565906379F8741B5785C030B8D
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Instance,
        [Parameter(Mandatory = $true)]
        [String]$Database,
        [Parameter(Mandatory = $false)]
        [String]$Username,
        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
    SELECT a.name AS 'AuditName',
    s.name AS 'SpecName',
    d.audit_action_name AS 'ActionName',
    d.audited_result AS 'Result'
    FROM sys.server_audit_specifications s
    JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
    JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
    WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP'
    "
    if ($res) {
        $Status = 'NotAFinding'
        #$FindingDetails += "The audit is being performed."
        # 20201027 JJS Added all Results to output
        $FindingDetails += "The audit is being performed.`n$($res | Format-Table -AutoSize| Out-String)"

    }
    else {
        $Status = "Open"
        $FindingDetails = "DBA, no audits are being done for retrieval of privilege/permissions/role membership info. Does the SSP agree this is OK?"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V67427 {
    <#
    .DESCRIPTION
        Vuln ID    : V-67427
        STIG ID    : SQL4-00-037400
        Rule ID    : SV-81917r2_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000502-DB-000349
        Rule Title : Trace or Audit records must be generated when unsuccessful attempts to delete categorized information (e.g., classification levels/security levels) occur.
        DiscussMD5 : 8E109A26687674426F124DB6FD5F33E3
        CheckMD5   : F8EB43AC909741B2DECC37C2F924DCC4
        FixMD5     : 1F4156BD8FF5A297ED8F0A2E625C0E27
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Instance,
        [Parameter(Mandatory = $true)]
        [String]$Database,
        [Parameter(Mandatory = $false)]
        [String]$Username,
        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
    SELECT a.name AS 'AuditName',
    s.name AS 'SpecName',
    d.audit_action_name AS 'ActionName',
    d.audited_result AS 'Result'
    FROM sys.server_audit_specifications s
    JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
    JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
    WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP'
    "
    if ($res) {
        $Status = 'NotAFinding'
        #$FindingDetails += "The SCHEMA_OBJECT_ACCESS_GROUP audit is being performed."
        # 20201027 JJS Added all Results to output
        $FindingDetails += "The SCHEMA_OBJECT_ACCESS_GROUP audit is being performed.`n$($res | Format-Table -AutoSize| Out-String)"

    }
    else {
        $Status = "Open"
        $FindingDetails = "DBA, no audits are being done when data classifications are unsuccessfully deleted. Does the SSP agree this is OK?"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V67429 {
    <#
    .DESCRIPTION
        Vuln ID    : V-67429
        STIG ID    : SQL4-00-037300
        Rule ID    : SV-81919r2_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000502-DB-000348
        Rule Title : Trace or Audit records must be generated when categorized information (e.g., classification levels/security levels) is deleted.
        DiscussMD5 : 89DD77B4CA52B4403E35DC172B115D9E
        CheckMD5   : 0651B6B24A0BECE549432A227400146F
        FixMD5     : 1F4156BD8FF5A297ED8F0A2E625C0E27
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Instance,
        [Parameter(Mandatory = $true)]
        [String]$Database,
        [Parameter(Mandatory = $false)]
        [String]$Username,
        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
    SELECT a.name AS 'AuditName',
    s.name AS 'SpecName',
    d.audit_action_name AS 'ActionName',
    d.audited_result AS 'Result'
    FROM sys.server_audit_specifications s
    JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
    JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
    WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP'
    "
    if ($res) {
        $Status = 'NotAFinding'
        #$FindingDetails += "The SCHEMA_OBJECT_ACCESS_GROUP audit is being performed."
        # 20201027 JJS Added all Results to output
        $FindingDetails += "The SCHEMA_OBJECT_ACCESS_GROUP audit is being performed.`n$($res | Format-Table -AutoSize| Out-String)"

    }
    else {
        $Status = "Open"
        $FindingDetails = "DBA, no audits are being done when data classifications are deleted. Does the SSP agree this is OK?"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V67431 {
    <#
    .DESCRIPTION
        Vuln ID    : V-67431
        STIG ID    : SQL4-00-037200
        Rule ID    : SV-81921r3_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000501-DB-000337
        Rule Title : SQL Server must generate Trace or Audit records when unsuccessful attempts to drop locally-defined security objects occur.
        DiscussMD5 : BD6EF0BDB7E4A0ECBCA0026FBE63B2B0
        CheckMD5   : F0E83C088A5E59E58CE531ABE27C85BB
        FixMD5     : 6BB04033EEC001884FBBC1AA3118C2A3
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Instance,
        [Parameter(Mandatory = $true)]
        [String]$Database,
        [Parameter(Mandatory = $false)]
        [String]$Username,
        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
    SELECT a.name AS 'AuditName',
    s.name AS 'SpecName',
    d.audit_action_name AS 'ActionName',
    d.audited_result AS 'Result'
    FROM sys.server_audit_specifications s
    JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
    JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
    WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_CHANGE_GROUP'
    "
    if ($res) {
        $Status = 'NotAFinding'
        #$FindingDetails = "The SCHEMA_OBJECT_CHANGE_GROUP audit is being performed."
        # 20201027 JJS Added all Results to output
        $FindingDetails = "The SCHEMA_OBJECT_CHANGE_GROUP audit is being performed.`n$($res | Format-Table -AutoSize| Out-String)"

    }
    else {
        $Status = "Open"
        $FindingDetails = "The SCHEMA_OBJECT_CHANGE_GROUP audit is not being performed."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V67433 {
    <#
    .DESCRIPTION
        Vuln ID    : V-67433
        STIG ID    : SQL4-00-037100
        Rule ID    : SV-81923r3_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000501-DB-000336
        Rule Title : SQL Server must generate Trace or Audit records when locally-defined security objects are dropped.
        DiscussMD5 : 89E7B9112026B8E9C94BE3E3647F0F31
        CheckMD5   : 35372CFC8C231D723755C773A807A174
        FixMD5     : 6BB04033EEC001884FBBC1AA3118C2A3
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Instance,
        [Parameter(Mandatory = $true)]
        [String]$Database,
        [Parameter(Mandatory = $false)]
        [String]$Username,
        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
    SELECT a.name AS 'AuditName',
    s.name AS 'SpecName',
    d.audit_action_name AS 'ActionName',
    d.audited_result AS 'Result'
    FROM sys.server_audit_specifications s
    JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
    JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
    WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_CHANGE_GROUP'
    "
    if ($res) {
        $Status = 'NotAFinding'
        #$FindingDetails = "The SCHEMA_OBJECT_CHANGE_GROUP audit is being performed."
        # 20201027 JJS Added all Results to output
        $FindingDetails = "The SCHEMA_OBJECT_CHANGE_GROUP audit is being performed.`n$($res | Format-Table -AutoSize| Out-String)"

    }
    else {
        $Status = "Open"
        $FindingDetails = "The SCHEMA_OBJECT_CHANGE_GROUP audit is not being performed."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V67435 {
    <#
    .DESCRIPTION
        Vuln ID    : V-67435
        STIG ID    : SQL4-00-036500
        Rule ID    : SV-81925r2_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000496-DB-000335
        Rule Title : SQL Server must generate Trace or Audit records when unsuccessful attempts to modify locally-defined security objects occur.
        DiscussMD5 : 88B0B6D464BBF9AF9A8E7AB21EE439C1
        CheckMD5   : 163BF9A57B8EE4DDD8C8497139EDF1B0
        FixMD5     : A6AF829790405294C5669C9D3F87FE25
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Instance,
        [Parameter(Mandatory = $true)]
        [String]$Database,
        [Parameter(Mandatory = $false)]
        [String]$Username,
        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
    SELECT a.name AS 'AuditName',
    s.name AS 'SpecName',
    d.audit_action_name AS 'ActionName',
    d.audited_result AS 'Result'
    FROM sys.server_audit_specifications s
    JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
    JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
    WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_CHANGE_GROUP'
    "
    if ($res) {
        $Status = 'NotAFinding'
        #$FindingDetails = "The SCHEMA_OBJECT_CHANGE_GROUP audit is being performed."
        # 20201027 JJS Added all Results to output
        $FindingDetails = "The SCHEMA_OBJECT_CHANGE_GROUP audit is being performed.`n$($res | Format-Table -AutoSize| Out-String)"

    }
    else {
        $Status = "Open"
        $FindingDetails = "The SCHEMA_OBJECT_CHANGE_GROUP audit is not being performed."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V67437 {
    <#
    .DESCRIPTION
        Vuln ID    : V-67437
        STIG ID    : SQL4-00-036600
        Rule ID    : SV-81927r2_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000498-DB-000346
        Rule Title : Trace or Audit records must be generated when categorized information (e.g., classification levels/security levels) is created.
        DiscussMD5 : 7FCA8B37D29ADA4F2DD7EC5C9E349080
        CheckMD5   : 363164231C2398D19E08CEEE7EBB397D
        FixMD5     : 8D70BA8BBDE0F7CA45ECDDEDA7EC7162
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Instance,
        [Parameter(Mandatory = $true)]
        [String]$Database,
        [Parameter(Mandatory = $false)]
        [String]$Username,
        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
    SELECT a.name AS 'AuditName',
    s.name AS 'SpecName',
    d.audit_action_name AS 'ActionName',
    d.audited_result AS 'Result'
    FROM sys.server_audit_specifications s
    JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
    JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
    WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP'
    "
    if ($res) {
        $Status = 'NotAFinding'
        #$FindingDetails += "The SCHEMA_OBJECT_ACCESS_GROUP audit is being performed."
        # 20201027 JJS Added all Results to output
        $FindingDetails += "The SCHEMA_OBJECT_ACCESS_GROUP audit is being performed.`n$($res | Format-Table -AutoSize| Out-String)"

    }
    else {
        $Status = "Open"
        $FindingDetails = "DBA, no audits are being done when data classifications are modified. Does the SSP agree this is OK?"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V67439 {
    <#
    .DESCRIPTION
        Vuln ID    : V-67439
        STIG ID    : SQL4-00-036800
        Rule ID    : SV-81929r2_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000498-DB-000347
        Rule Title : Trace or Audit records must be generated when unsuccessful attempts to create categorized information (e.g., classification levels/security levels) occur.
        DiscussMD5 : 5611A02A30656063E7A91C42DBC58207
        CheckMD5   : 269CC2FFE28B0B33B5587CC97CD85FE9
        FixMD5     : 8D70BA8BBDE0F7CA45ECDDEDA7EC7162
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Instance,
        [Parameter(Mandatory = $true)]
        [String]$Database,
        [Parameter(Mandatory = $false)]
        [String]$Username,
        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
    SELECT a.name AS 'AuditName',
    s.name AS 'SpecName',
    d.audit_action_name AS 'ActionName',
    d.audited_result AS 'Result'
    FROM sys.server_audit_specifications s
    JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
    JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
    WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP'
    "
    if ($res) {
        $Status = 'NotAFinding'
        #$FindingDetails += "The SCHEMA_OBJECT_ACCESS_GROUP audit is being performed."
        # 20201027 JJS Added all Results to output
        $FindingDetails += "The SCHEMA_OBJECT_ACCESS_GROUP audit is being performed.`n$($res | Format-Table -AutoSize| Out-String)"

    }
    else {
        $Status = "Open"
        $FindingDetails = "DBA, no audits are being done when data classifications are unsuccessfully modified. Does the SSP agree this is OK?"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V67441 {
    <#
    .DESCRIPTION
        Vuln ID    : V-67441
        STIG ID    : SQL4-00-036650
        Rule ID    : SV-81931r2_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000498-DB-000346
        Rule Title : Trace or Audit records must be generated when categorized information (e.g., classification levels/security levels) is modified.
        DiscussMD5 : 1EE2338DBB2DA66294A4337ACBD0700A
        CheckMD5   : 12FFFB78426D663983A14D613F32D026
        FixMD5     : 346353BAC603495DAC381657FE1551A2
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Instance,
        [Parameter(Mandatory = $true)]
        [String]$Database,
        [Parameter(Mandatory = $false)]
        [String]$Username,
        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
    SELECT a.name AS 'AuditName',
    s.name AS 'SpecName',
    d.audit_action_name AS 'ActionName',
    d.audited_result AS 'Result'
    FROM sys.server_audit_specifications s
    JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
    JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
    WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP'
    "
    if ($res) {
        $Status = 'NotAFinding'
        #$FindingDetails += "The SCHEMA_OBJECT_ACCESS_GROUP audit is being performed."
        # 20201027 JJS Added all Results to output
        $FindingDetails += "The SCHEMA_OBJECT_ACCESS_GROUP audit is being performed.`n$($res | Format-Table -AutoSize| Out-String)"

    }
    else {
        $Status = "Open"
        $FindingDetails = "DBA, no audits are being done when data classifications are modified. Does the SSP agree this is OK?"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V67443 {
    <#
    .DESCRIPTION
        Vuln ID    : V-67443
        STIG ID    : SQL4-00-036850
        Rule ID    : SV-81933r2_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000498-DB-000347
        Rule Title : Trace or Audit records must be generated when unsuccessful attempts to modify categorized information (e.g., classification levels/security levels) occur.
        DiscussMD5 : C683091EC2BA10245DD6FCF0FF71B21E
        CheckMD5   : 056B02CFC419CBE4187480F5E0CE17FC
        FixMD5     : 346353BAC603495DAC381657FE1551A2
    #>

    Param (
        [Parameter(Mandatory = $false)]
        [String]$AnswerFile,
        [Parameter(Mandatory = $true)]
        [String]$ScanType,
        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,
        [Parameter(Mandatory = $true)]
        [String]$Instance,
        [Parameter(Mandatory = $true)]
        [String]$Database,
        [Parameter(Mandatory = $false)]
        [String]$Username,
        [Parameter(Mandatory = $false)]
        [String]$UserSID
    )

    $ModuleName = (Get-Command $MyInvocation.MyCommand).Source
    $VulnID = ($MyInvocation.MyCommand.Name).Replace("Get-V", "V-")
    $Status = "Not_Reviewed"  # Acceptable values are 'Not_Reviewed', 'Open', 'NotAFinding', 'Not_Applicable'
    $FindingDetails = ""
    $Comments = ""
    $AFStatus = ""
    $SeverityOverride = ""  # Acceptable values are 'CAT_I', 'CAT_II', 'CAT_III'.  Only use if STIG calls for a severity change based on specified critera.
    $Justification = ""  # If SeverityOverride is used, a justification is required.
    # $ResultObject = [System.Collections.Generic.List[System.Object]]::new()

    #---=== Begin Custom Code ===---#
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
    SELECT a.name AS 'AuditName',
    s.name AS 'SpecName',
    d.audit_action_name AS 'ActionName',
    d.audited_result AS 'Result'
    FROM sys.server_audit_specifications s
    JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
    JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
    WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP'
    "
    if ($res) {
        $Status = 'NotAFinding'
        #$FindingDetails += "The SCHEMA_OBJECT_ACCESS_GROUP audit is being performed."
        # 20201027 JJS Added all Results to output
        $FindingDetails += "The SCHEMA_OBJECT_ACCESS_GROUP audit is being performed.`n$($res | Format-Table -AutoSize| Out-String)"

    }
    else {
        $Status = "Open"
        $FindingDetails = "DBA, no audits are being done when data classifications are unsuccessfully modified. Does the SSP agree this is OK?"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAGoUnDp/JiT836
# vf2SnL0oKIkc7YAuWnMufNOrOUIWWqCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAgfWSXmmal3BDkIJ6UBJYl5gu7QHmj
# slroVlq1FLOw7TANBgkqhkiG9w0BAQEFAASCAQA2bETg09YfJDvFyR2t9D5UMTwV
# DtuFMr580+SFifVQ2IfPwlhnz4JcCiIKvFTT+x02owjHzAXB6pFk9E8fu8CNKtZg
# CNAwtC2kdogpkNmzjRxs16+yg2CcgfKjXarO4GQYvbVPzo/XgMiTmMZSAy0R9JDJ
# UXar/2ifpeFEMxRK6QxtBM97h0CkTVeIpgUjVeVoBj+XP2NsYqThOdeVWrExD7Id
# hAVhyV3sQyeFC042Mz3pGA2QChnNGCgHYMEcz8tU+jAd/fa0q133frQUn54hJ1IO
# 6Wjrs2AR5Nw/cHnYODdiPayD7xtBCgohQGi/IPYaBp3um6Xb2cpLsTGmJhp9
# SIG # End signature block
