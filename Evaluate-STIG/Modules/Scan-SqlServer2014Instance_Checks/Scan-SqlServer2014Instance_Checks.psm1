##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     MS SQL Server 2014 Instance
# Version:  V2R3
# Class:    UNCLASSIFIED
# Updated:  5/13/2024
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V213807 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213807
        STIG ID    : SQL4-00-000100
        Rule ID    : SV-213807r395442_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-DB-000031
        Rule Title : The number of concurrent SQL Server sessions for each system account must be limited.
        DiscussMD5 : BD6C0A04BBCFB8C9896628FE1A8CCC99
        CheckMD5   : C15BB091E7C0E0A647151516FF2A8AC9
        FixMD5     : 01A1FF7C9FB6854D44702D972A7EEDFF
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
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "SELECT name, is_disabled FROM master.sys.server_triggers"

    if (!$res) {
        $Status = "Open"
        $FindingDetails = "No triggers are defined."
    }
    else {
        # 20201021 JJS Fixed output of $res
        $FindingDetails = "Confirm there are triggers that limit the number of concurrent sessions to an organization-defined number per user for all accounts and/or account types. `n$($res | Format-Table -AutoSize| Out-String)"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213809 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213809
        STIG ID    : SQL4-00-010200
        Rule ID    : SV-213809r395853_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000092
        Rule Title : SQL Server default account [sa] must have its name changed.
        DiscussMD5 : 898D79C643876788A53F3FF350095BA8
        CheckMD5   : 0EBC4A9A40B6BEA5EBD882270611A3DA
        FixMD5     : 39733C6C785C898254835F7499888B09
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
            SELECT name
            FROM sys.sql_logins
            WHERE [name] = 'sa'
                OR [principal_id] = 1"
            if ($res) {
                if ($res.name -eq 'sa') {
                    #$FindingDetails += "The SQL Server default account has not been renamed on $svr."
                    # 20201027 JJS Added all Results to output
                    $FindingDetails += "The SQL Server default account has not been renamed on $svr.`n$($svr | Format-Table -AutoSize| Out-String)"

                }
            } # if ($res)
        } # foreach ($svr in $svrlist)
        if ($FindingDetails -gt '') {
            $Status = 'Open'
        }
        else {
            $Status = 'NotAFinding'
            $FindingDetails = "The SQL Server default account has been renamed."
        } # if ($FindingDetails -gt '')
    }
    else {
        $Status = 'NotAFinding'
        $FindingDetails += "No SQL instances are running on this server."
    } # if ($svrlist)
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213810 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213810
        STIG ID    : SQL4-00-011300
        Rule ID    : SV-213810r395709_rule
        CCI ID     : CCI-000171
        Rule Name  : SRG-APP-000090-DB-000065
        Rule Title : Where SQL Server Trace is in use for auditing purposes, SQL Server must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be traced.
        DiscussMD5 : 005E32DB0BBD59F3A40139118B87C550
        CheckMD5   : 121C9C4FB842104BCF5F067D95BDAC3E
        FixMD5     : F58D3F8423A494A0A63F2438AAD375BE
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
        SELECT @@servername as instance,
    CASE
    WHEN SP.class_desc IS NOT NULL THEN
    CASE
    WHEN SP.class_desc = 'SERVER' AND S.is_linked = 0 THEN 'SERVER'
    WHEN SP.class_desc = 'SERVER' AND S.is_linked = 1 THEN 'SERVER (linked)'
    ELSE SP.class_desc
    END
    WHEN E.name IS NOT NULL THEN 'ENDPOINT'
    WHEN S.name IS NOT NULL AND S.is_linked = 0 THEN 'SERVER'
    WHEN S.name IS NOT NULL AND S.is_linked = 1 THEN 'SERVER (linked)'
    WHEN P.name IS NOT NULL THEN 'SERVER_PRINCIPAL'
    ELSE '???'
    END AS [Securable Class],
    CASE
    WHEN E.name IS NOT NULL THEN E.name
    WHEN S.name IS NOT NULL THEN S.name
    WHEN P.name IS NOT NULL THEN P.name
    ELSE '???'
    END AS [Securable],
    P1.name AS [Grantee],
    P1.type_desc AS [Grantee Type],
    sp.permission_name AS [Permission],
    sp.state_desc AS [State],
    P2.name AS [Grantor],
    P2.type_desc AS [Grantor Type],
    R.name AS [Role Name]
    FROM
    sys.server_permissions SP
    INNER JOIN sys.server_principals P1
    ON P1.principal_id = SP.grantee_principal_id
    INNER JOIN sys.server_principals P2
    ON P2.principal_id = SP.grantor_principal_id

    FULL OUTER JOIN sys.servers S
    ON SP.class_desc = 'SERVER'
    AND S.server_id = SP.major_id

    FULL OUTER JOIN sys.endpoints E
    ON SP.class_desc = 'ENDPOINT'
    AND E.endpoint_id = SP.major_id

    FULL OUTER JOIN sys.server_principals P
    ON SP.class_desc = 'SERVER_PRINCIPAL'
    AND P.principal_id = SP.major_id

    FULL OUTER JOIN sys.server_role_members SRM
    ON P.principal_id = SRM.member_principal_id

    LEFT OUTER JOIN sys.server_principals R
    ON SRM.role_principal_id = R.principal_id
    WHERE sp.permission_name IN ('ALTER ANY SERVER AUDIT','CONTROL SERVER','ALTER ANY DATABASE','CREATE ANY DATABASE')
    OR R.name IN ('sysadmin','dbcreator')
    "
    if ($res) {
        $Status = 'Open'
        $FindingDetails += "DBA, ensure the following have been authorized by the ISSM to create and/or maintain audit definitions:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check queries."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213811 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213811
        STIG ID    : SQL4-00-011310
        Rule ID    : SV-213811r395709_rule
        CCI ID     : CCI-000171
        Rule Name  : SRG-APP-000090-DB-000065
        Rule Title : Where SQL Server Audit is in use, SQL Server must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited at the server level.
        DiscussMD5 : EC43AE66A02E8FB37FFFF34FE702BF3E
        CheckMD5   : 03A0FDCDE849F7DA74224B49EE6B7A3C
        FixMD5     : F5E787175538C27E7EF29FB20542385E
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
        SELECT @@servername as instance,
    CASE
    WHEN SP.class_desc IS NOT NULL THEN
    CASE
    WHEN SP.class_desc = 'SERVER' AND S.is_linked = 0 THEN 'SERVER'
    WHEN SP.class_desc = 'SERVER' AND S.is_linked = 1 THEN 'SERVER (linked)'
    ELSE SP.class_desc
    END
    WHEN E.name IS NOT NULL THEN 'ENDPOINT'
    WHEN S.name IS NOT NULL AND S.is_linked = 0 THEN 'SERVER'
    WHEN S.name IS NOT NULL AND S.is_linked = 1 THEN 'SERVER (linked)'
    WHEN P.name IS NOT NULL THEN 'SERVER_PRINCIPAL'
    ELSE '???'
    END AS [Securable Class],
    CASE
    WHEN E.name IS NOT NULL THEN E.name
    WHEN S.name IS NOT NULL THEN S.name
    WHEN P.name IS NOT NULL THEN P.name
    ELSE '???'
    END AS [Securable],
    P1.name AS [Grantee],
    P1.type_desc AS [Grantee Type],
    sp.permission_name AS [Permission],
    sp.state_desc AS [State],
    P2.name AS [Grantor],
    P2.type_desc AS [Grantor Type],
    R.name AS [Role Name]
    FROM
    sys.server_permissions SP
    INNER JOIN sys.server_principals P1
    ON P1.principal_id = SP.grantee_principal_id
    INNER JOIN sys.server_principals P2
    ON P2.principal_id = SP.grantor_principal_id

    FULL OUTER JOIN sys.servers S
    ON SP.class_desc = 'SERVER'
    AND S.server_id = SP.major_id

    FULL OUTER JOIN sys.endpoints E
    ON SP.class_desc = 'ENDPOINT'
    AND E.endpoint_id = SP.major_id

    FULL OUTER JOIN sys.server_principals P
    ON SP.class_desc = 'SERVER_PRINCIPAL'
    AND P.principal_id = SP.major_id

    FULL OUTER JOIN sys.server_role_members SRM
    ON P.principal_id = SRM.member_principal_id

    LEFT OUTER JOIN sys.server_principals R
    ON SRM.role_principal_id = R.principal_id
    WHERE sp.permission_name IN ('ALTER ANY SERVER AUDIT','CONTROL SERVER','ALTER ANY DATABASE','CREATE ANY DATABASE')
    OR R.name IN ('sysadmin','dbcreator')
    "
    if ($res) {
        $Status = 'Open'
        $FindingDetails += "DBA, ensure the following have been authorized by the ISSM to create and/or maintain audit definitions:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check queries."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213812 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213812
        STIG ID    : SQL4-00-011410
        Rule ID    : SV-213812r395712_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000091-DB-000066
        Rule Title : Where SQL Server Audit is in use, SQL Server must generate audit records when privileges/permissions are retrieved.
        DiscussMD5 : FF6D480324FF4C8B1426EAB7366EF82D
        CheckMD5   : 7BB4B467C1013DF53F9B08D68E41B24E
        FixMD5     : 5CE32D103D386E9FA99F50BCD3D40F33
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

Function Get-V213819 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213819
        STIG ID    : SQL4-00-013000
        Rule ID    : SV-213819r395805_rule
        CCI ID     : CCI-000140
        Rule Name  : SRG-APP-000109-DB-000049
        Rule Title : Unless it has been determined that availability is paramount, SQL Server must shut down upon the failure of an Audit, or a Trace used for auditing purposes, to include the unavailability of space for more audit/trace log records.
        DiscussMD5 : 40DDBCE3283C60B0926683E0278A3FC2
        CheckMD5   : 5A270623E24092EEBA2123576D32FE7C
        FixMD5     : BB21A67F8E3292E8C4D06F38620B4EA3
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
    #$res = Get-ISQL -ServerInstance $Instance -Database $Database "SELECT 1 FROM sys.server_audits where on_failure_desc = 'SHUTDOWN SERVER INSTANCE'"
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "SELECT * FROM sys.server_audits where on_failure_desc = 'SHUTDOWN SERVER INSTANCE'"
    if ($res) {
        $Status = 'NotAFinding'
        #$FindingDetails += "The check query found that SQL Sever will shut down upon audit failure."
        # 20201027 JJS Added all Results to output
        $FindingDetails += "The check query found that SQL Sever will shut down upon audit failure.`n$($res | Format-Table -AutoSize| Out-String)"
    }
    else {
        $Status = "Open"
        $FindingDetails = "Audit failures do not cause SQL Server to shut down."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213820 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213820
        STIG ID    : SQL4-00-013600
        Rule ID    : SV-213820r810820_rule
        CCI ID     : CCI-000162
        Rule Name  : SRG-APP-000118-DB-000059
        Rule Title : The audit information produced by SQL Server must be protected from unauthorized read access.
        DiscussMD5 : C1FA7110BD2ABC32665BB12002BAB21D
        CheckMD5   : 0EAA757A43DB05614D728003881E44BD
        FixMD5     : AEE8FA2A19A5C4ED688E761DB659AB48
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
    $authSQLSVC = @('FullControl')
    $authSSASVC = @('ReadAndExecute', 'Write')

    $hashAuth = @{
        'BUILTIN\Administrators'         = @('Read')
        'NT Service\MSSQL$<INSTANCE>'    = $authSQLSVC
        'NT Service\SQLAgent$<INSTANCE>' = $authSSASVC
    }
    # The MSSQL STIG doesn't say these are acceptable, but they do seem to be bestowed by MSSQL, so should also not be a finding:
    $auditAuth = @{
        #    'BUILTIN\Administrators'         = @('FullControl')
        #    'NT AUTHORITY\SYSTEM'            = @('FullControl')
    }

    $iDirCnt = 0
    $sDirList = ''

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "select @@ServerName as ServerName, @@ServiceName as InstanceName"
    if ($res) {
        $res | ForEach-Object {
            $sServerName = $_.ServerName
            $sInstance = $_.InstanceName

            # But we just want the service accounts used by this particular instance
            $myhash = $hashAuth + @{} # the empty set forces the array to duplicate, not just update its pointer

            # First add accounts for the SQL Service
            $sServName = 'MSSQLSERVER'
            if ($sInstance -ne $sServName) {
                $sServName = "mssql`$$sInstance"
            } # service name will either be mssqlserver or mssql$sqlnn
            $sname = (Get-CimInstance win32_service | Where-Object name -EQ $sServName).startname
            $myhash[$sname] = $authSQLSVC # add authorizations for the account on the service
            $sname = "NT SERVICE\MSSQL`$$sInstance"
            $myhash[$sname] = $authSQLSVC # also add authorizations for the "NT SERVICE" account that MSSQL creates

            # Add accounts for the SQL Agent
            $ssasrv = (Get-CimInstance win32_service | Where-Object name -EQ "SQLAgent`$$sInstance")  # at some point we need code for SQLAgent on a default instance
            if ($ssasrv) {
                $sname = $ssasrv.startname
                $myhash[$sname] = $authSSASVC
                $sname = "NT SERVICE\SQLAgent`$$sInstance"
                $myhash[$sname] = $authSSASVC
            }

            $paths = Get-ISQL -ServerInstance $sServerName "select log_file_path from sys.server_file_audits"
            if ($paths) {
                foreach ($path in $paths.log_file_path) {
                    $iDirCnt += 1
                    $sDir = $path -replace '\\$'
                    $SearchDir = "$sDir\*.sqlaudit"

                    $pathHash = $myhash += @{}
                    foreach ($k in $auditAuth.Keys) {
                        $pathHash[$k] = $auditAuth[$k]
                    }
                    $sDirList += "  $SearchDir`n";
                    Get-Acl $SearchDir -ErrorAction SilentlyContinue | Select-Object access -Unique | ForEach-Object {
                        $FindingDetails += Get-AccessProblem -CurrentAuthorizations $_.access -AllowedAuthorizations $pathHash -FilePath $SearchDir -InstanceName $sInstance
                    }

                } # foreach ($path in $paths.path)
            } # if ($paths)
        } # $res.InstanceName | foreach-object
    } # if ($res)

    # Interpret results...
    if ($FindingDetails -gt '') {
        $Status = "Open"
    }
    else {
        $Status = "NotAFinding"
        if ($iDirCnt -eq 0) {
            $FindingDetails = "No audit directories were found on this host."
        }
        else {
            $FindingDetails = "The audit files in the following directories were checked and found to have proper authorizations:`n`n$sDirList"
        }
    } # if ($FindingDetails -gt '')
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213821 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213821
        STIG ID    : SQL4-00-013700
        Rule ID    : SV-213821r395823_rule
        CCI ID     : CCI-000163
        Rule Name  : SRG-APP-000119-DB-000060
        Rule Title : The audit information produced by SQL Server must be protected from unauthorized modification.
        DiscussMD5 : 56C246FD25088092F5302FD20FA1B440
        CheckMD5   : C873A77E681803902FC6C22969E714D1
        FixMD5     : 63F7D37721EE10D313AFC6C1B1BC5955
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
    $authSQLSVC = @('FullControl')
    $authSSASVC = @('ReadAndExecute', 'Write')

    $hashAuth = @{
        'BUILTIN\Administrators'         = @('Read')
        'NT Service\MSSQL$<INSTANCE>'    = $authSQLSVC
        'NT Service\SQLAgent$<INSTANCE>' = $authSSASVC
    }
    # The following rights get bestowed by MSSQL on file creation, and the STIG says they're not a finding:
    $traceAuth = @{
        'OWNER RIGHTS'                   = @('FullControl')
        'BUILTIN\Administrators'         = @('FullControl')
        'NT Service\SQLAgent$<INSTANCE>' = @('FullControl')
    }
    # The MSSQL STIG doesn't say these are acceptable (as the STIG only considers trace files), but they do seem to be bestowed by MSSQL, so should also not be a finding:
    $auditAuth = @{
        'BUILTIN\Administrators' = @('FullControl')
        'NT AUTHORITY\SYSTEM'    = @('FullControl')
    }

    $iDirCnt = 0
    $sDirList = ''

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "select @@ServerName as ServerName, @@ServiceName as InstanceName"
    if ($res) {
        $res | ForEach-Object {
            $sServerName = $_.ServerName
            $sInstance = $_.InstanceName

            # But we just want the service accounts used by this particular instance
            $myhash = $hashAuth + @{} # the empty set forces the array to duplicate, not just update its pointer

            # First add accounts for the SQL Service
            $sServName = 'MSSQLSERVER'
            if ($sInstance -ne $sServName) {
                $sServName = "mssql`$$sInstance"
            } # service name will either be mssqlserver or mssql$sqlnn
            $sname = (Get-CimInstance win32_service | Where-Object name -EQ $sServName).startname
            $myhash[$sname] = $authSQLSVC # add authorizations for the account on the service
            $sname = "NT SERVICE\MSSQL`$$sInstance"
            $myhash[$sname] = $authSQLSVC # also add authorizations for the "NT SERVICE" account that MSSQL creates

            # Add accounts for the SQL Agent
            $ssasrv = (Get-CimInstance win32_service | Where-Object name -EQ "SQLAgent`$$sInstance")  # at some point we need code for SQLAgent on a default instance
            if ($ssasrv) {
                $sname = $ssasrv.startname
                $myhash[$sname] = $authSSASVC
                $sname = "NT SERVICE\SQLAgent`$$sInstance"
                $myhash[$sname] = $authSSASVC
            }

            $paths = Get-ISQL -ServerInstance $sServerName "select log_file_path from sys.server_file_audits"
            if ($paths) {
                foreach ($path in $paths.log_file_path) {
                    $iDirCnt += 1
                    $sDir = $path -replace '\\$'
                    $SearchDir = "$sDir\*.sqlaudit"

                    $pathHash = $myhash += @{}
                    foreach ($k in $auditAuth.Keys) {
                        $pathHash[$k] = $auditAuth[$k]
                    }
                    $sDirList += "  $SearchDir`n";
                    Get-Acl $SearchDir -ErrorAction SilentlyContinue | Select-Object access -Unique | ForEach-Object {
                        $FindingDetails += Get-AccessProblem -CurrentAuthorizations $_.access -AllowedAuthorizations $pathHash -FilePath $SearchDir -InstanceName $sInstance
                    }

                } # foreach ($path in $paths.path)
            } # if ($paths)
        } # $res.InstanceName | foreach-object
    } # if ($res)

    # Interpret results...
    if ($FindingDetails -gt '') {
        $Status = "Open"
    }
    else {
        $Status = "NotAFinding"
        if ($iDirCnt -eq 0) {
            $FindingDetails = "No audit directories were found on this host."
        }
        else {
            $FindingDetails = "The audit files in the following directories were checked and found to have proper authorizations:`n`n$sDirList"
        }
    } # if ($FindingDetails -gt '')
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213822 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213822
        STIG ID    : SQL4-00-013800
        Rule ID    : SV-213822r395826_rule
        CCI ID     : CCI-000164
        Rule Name  : SRG-APP-000120-DB-000061
        Rule Title : The audit information produced by SQL Server must be protected from unauthorized deletion.
        DiscussMD5 : 58681C376C295C1E140371F30094F88C
        CheckMD5   : 04D53C5EE227CBCD0E1509ED6F3F6E37
        FixMD5     : 06D8FDEFA1D239C1C0D763BFBB9C3DF9
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
    $authSQLSVC = @('FullControl')
    $authSSASVC = @('ReadAndExecute', 'Write')

    $hashAuth = @{
        'BUILTIN\Administrators'         = @('Read')
        'NT Service\MSSQL$<INSTANCE>'    = $authSQLSVC
        'NT Service\SQLAgent$<INSTANCE>' = $authSSASVC
    }
    # The following rights get bestowed by MSSQL on file creation, and the STIG says they're not a finding:
    $traceAuth = @{
        'OWNER RIGHTS'                   = @('FullControl')
        'BUILTIN\Administrators'         = @('FullControl')
        'NT Service\SQLAgent$<INSTANCE>' = @('FullControl')
    }
    # The MSSQL STIG doesn't say these are acceptable (as the STIG only considers trace files), but they do seem to be bestowed by MSSQL, so should also not be a finding:
    $auditAuth = @{
        'BUILTIN\Administrators' = @('FullControl')
        'NT AUTHORITY\SYSTEM'    = @('FullControl')
    }

    $iDirCnt = 0
    $sDirList = ''

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "select @@ServerName as ServerName, @@ServiceName as InstanceName"
    if ($res) {
        $res | ForEach-Object {
            $sServerName = $_.ServerName
            $sInstance = $_.InstanceName

            # But we just want the service accounts used by this particular instance
            $myhash = $hashAuth + @{} # the empty set forces the array to duplicate, not just update its pointer

            # First add accounts for the SQL Service
            $sServName = 'MSSQLSERVER'
            if ($sInstance -ne $sServName) {
                $sServName = "mssql`$$sInstance"
            } # service name will either be mssqlserver or mssql$sqlnn
            $sname = (Get-CimInstance win32_service | Where-Object name -EQ $sServName).startname
            $myhash[$sname] = $authSQLSVC # add authorizations for the account on the service
            $sname = "NT SERVICE\MSSQL`$$sInstance"
            $myhash[$sname] = $authSQLSVC # also add authorizations for the "NT SERVICE" account that MSSQL creates

            # Add accounts for the SQL Agent
            $ssasrv = (Get-CimInstance win32_service | Where-Object name -EQ "SQLAgent`$$sInstance")  # at some point we need code for SQLAgent on a default instance
            if ($ssasrv) {
                $sname = $ssasrv.startname
                $myhash[$sname] = $authSSASVC
                $sname = "NT SERVICE\SQLAgent`$$sInstance"
                $myhash[$sname] = $authSSASVC
            }

            $paths = Get-ISQL -ServerInstance $sServerName "select log_file_path from sys.server_file_audits"
            if ($paths) {
                foreach ($path in $paths.log_file_path) {
                    $iDirCnt += 1
                    $sDir = $path -replace '\\$'
                    $SearchDir = "$sDir\*.sqlaudit"

                    $pathHash = $myhash += @{}
                    foreach ($k in $auditAuth.Keys) {
                        $pathHash[$k] = $auditAuth[$k]
                    }
                    $sDirList += "  $SearchDir`n";
                    Get-Acl $SearchDir -ErrorAction SilentlyContinue | Select-Object access -Unique | ForEach-Object {
                        $FindingDetails += Get-AccessProblem -CurrentAuthorizations $_.access -AllowedAuthorizations $pathHash -FilePath $SearchDir -InstanceName $sInstance
                    }

                } # foreach ($path in $paths.path)
            } # if ($paths)
        } # $res.InstanceName | foreach-object
    } # if ($res)

    # Interpret results...
    if ($FindingDetails -gt '') {
        $Status = "Open"
    }
    else {
        $Status = "NotAFinding"
        if ($iDirCnt -eq 0) {
            $FindingDetails = "No audit directories were found on this host."
        }
        else {
            $FindingDetails = "The audit files in the following directories were checked and found to have proper authorizations:`n`n$sDirList"
        }
    } # if ($FindingDetails -gt '')
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213823 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213823
        STIG ID    : SQL4-00-013900
        Rule ID    : SV-213823r395829_rule
        CCI ID     : CCI-001493
        Rule Name  : SRG-APP-000121-DB-000202
        Rule Title : Audit tools used in, or in conjunction with, SQL Server must be protected from unauthorized access.
        DiscussMD5 : F71B9F9E548A98B1AAD9ECCF2C2DF02F
        CheckMD5   : 2D084AB3E21572E4E21BA7246A6734A6
        FixMD5     : FFE3D012BA4247B9305C967BBDEDB31D
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
        SELECT @@servername as instance,
    login.name, perm.permission_name, perm.state_desc
    FROM sys.server_permissions perm
    JOIN sys.server_principals login
    ON perm.grantee_principal_id = login.principal_id
    WHERE permission_name in ('CONTROL SERVER', 'ALTER ANY DATABASE AUDIT', 'ALTER ANY SERVER AUDIT','ALTER TRACE')
    and login.name not like '##MS_%'"
    if ($res) {
        $Status = 'Open'
        $FindingDetails += "DBA, ensure the following are documented in the SSP as authorized to access audits:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check queries."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213824 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213824
        STIG ID    : SQL4-00-014000
        Rule ID    : SV-213824r395832_rule
        CCI ID     : CCI-001494
        Rule Name  : SRG-APP-000122-DB-000203
        Rule Title : SQL Server and/or the operating system must protect its audit configuration from unauthorized modification.
        DiscussMD5 : 0B29BC6AE1DA19EEE4ED10ACD7D59885
        CheckMD5   : BBB34A2053B13DD84545E299063E28E3
        FixMD5     : DFBF6C255676198B774891CDB78783B7
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
        SELECT @@servername as instance,
    login.name, perm.permission_name, perm.state_desc
    FROM sys.server_permissions perm
    JOIN sys.server_principals login
    ON perm.grantee_principal_id = login.principal_id
    WHERE permission_name in ('CONTROL SERVER', 'ALTER ANY DATABASE AUDIT', 'ALTER ANY SERVER AUDIT')
    and login.name not like '##MS_%'"
    if ($res) {
        $Status = 'Open'
        $FindingDetails += "DBA, ensure the following are documented in the SSP as authorized to access audit configurations:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check queries."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213825 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213825
        STIG ID    : SQL4-00-014100
        Rule ID    : SV-213825r395835_rule
        CCI ID     : CCI-001495
        Rule Name  : SRG-APP-000123-DB-000204
        Rule Title : SQL Server and the operating system must protect SQL Server audit features from unauthorized removal.
        DiscussMD5 : 2F451FC2C183A8455BE085B5AE2B811D
        CheckMD5   : 37C6F9C579424E16CA4DE5BA343BEE8A
        FixMD5     : DFBF6C255676198B774891CDB78783B7
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
        SELECT @@servername as instance,
    login.name, perm.permission_name, perm.state_desc
    FROM sys.server_permissions perm
    JOIN sys.server_principals login
    ON perm.grantee_principal_id = login.principal_id
    WHERE permission_name in ('CONTROL SERVER', 'ALTER ANY DATABASE AUDIT', 'ALTER ANY SERVER AUDIT')
    and login.name not like '##MS_%'"
    if ($res) {
        $Status = 'Open'
        $FindingDetails += "DBA, ensure the following are documented in the SSP as authorized to access audits:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check queries."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213828 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213828
        STIG ID    : SQL4-00-015400
        Rule ID    : SV-213828r395850_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000198
        Rule Title : SQL Server software installation account(s) must be restricted to authorized users.
        DiscussMD5 : F5A20E7D777F09C30BDDF9567C3B1562
        CheckMD5   : 36FF96234324C5E0C90ACE7F0FC09E1F
        FixMD5     : CEBCC4812F6E6B5825754E425B6C3431
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
    $Status = 'Open'
    $FindingDetails += "DBA, ensure the following are documented in the SSP as authorized to install/update SQL Server:`n`n$(
        (
        Get-ChildItem "C:\program files\Microsoft SQL Server\*\setup bootstrap\log" -Recurse -Include *.log | Select-String -Pattern 'LogonUser = '
        ) -replace '^.*LogonUser = ' -replace 'SYSTEM','SYSTEM (Windows Update)' | Sort-Object -Unique | Out-String
    )"
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213829 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213829
        STIG ID    : SQL4-00-015500
        Rule ID    : SV-213829r395850_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000199
        Rule Title : Database software directories, including SQL Server configuration files, must be stored in dedicated directories, separate from the host OS and other applications.
        DiscussMD5 : 18AFC31B2C84A1C98CA7EF16E78BDE42
        CheckMD5   : 683F50D25B3F3C76BFB5A4B8F14AB9EF
        FixMD5     : C67C7931EA6FABA14E1301689487A742
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
    $windir = $env:windir -replace '\\$'

    # iterate through the SQL instances, determining their root directories.
    Get-ISQL -ServerInstance $Instance -Database $Database "select @@servername as Instance" | ForEach-Object {
        $sInstance = $_.Instance
        $oServer = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Server -ArgumentList $sInstance
        $rootdir = $oServer.RootDirectory

        if ($rootdir -like "$windir\*") {
            $FindingDetails += "The root directory of $sInstance, $rootdir, appears to be a subdir under $windir`n"
        }
        elseif ($rootdir -inotmatch '^[a-z]:\\(program *files\\)?m(icro)?s(oft)? ?sql ?server') {
            $FindingDetails += "The root directory of $sInstance, $rootdir, does not match the expected pattern. Might it be in a subdir under another application?`n"
        }
        else {
            # 20201027 JJS Added all Results to output
            $FindingDetails += "The root directory of $sInstance, $rootdir looked at.`n"
        }
    } # Get-ISQL -ServerInstance $Instance -Database $Database ... ForEach-Object


    # Interpret results...
    if ($FindingDetails -gt '') {
        $Status = "Open"
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "The database software appears sufficiently isolated from the OS and other applications."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213830 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213830
        STIG ID    : SQL4-00-016200
        Rule ID    : SV-213830r395853_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000090
        Rule Title : SQL Server must have the publicly available Northwind sample database removed.
        DiscussMD5 : D0540EBE11551DAEB46C02E263D09C66
        CheckMD5   : 4E9A778FD54D0C87EC213670671ED295
        FixMD5     : C1BAF6032A1927569BAFA966320F3603
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
        select @@SERVERNAME as InstanceName
            , name AS DatabaseName
            FROM sys.databases
        WHERE name IN (
                'pubs'
                , 'Northwind'
                , 'AdventureWorks'
                , 'WorldwideImporters'
                )
        ORDER BY 1, 2
        "
    if ($res) {
        $Status = "Open"
        $FindingDetails = "The following demonstration/sample databases should not exist on a production server:`n$($res | Format-Table | Out-String)"
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "No demonstration or sample databases were found."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213831 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213831
        STIG ID    : SQL4-00-016300
        Rule ID    : SV-213831r395853_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000090
        Rule Title : SQL Server must have the publicly available pubs sample database removed.
        DiscussMD5 : 40437A989C0CC2A06ECB69A7F649B3BE
        CheckMD5   : F32F6DC6CF9DFC11ABA1BDA8A279AA50
        FixMD5     : A86B774DCDE6ED85A4748EC54925D8D9
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
        select @@SERVERNAME as InstanceName
            , name AS DatabaseName
            FROM sys.databases
        WHERE name IN (
                'pubs'
                , 'Northwind'
                , 'AdventureWorks'
                , 'WorldwideImporters'
                )
        ORDER BY 1, 2
        "
    if ($res) {
        $Status = "Open"
        $FindingDetails = "The following demonstration/sample databases should not exist on a production server:`n$($res | Format-Table | Out-String)"
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "No demonstration or sample databases were found."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213832 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213832
        STIG ID    : SQL4-00-016310
        Rule ID    : SV-213832r395853_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000090
        Rule Title : SQL Server must have the publicly available AdventureWorks sample database removed.
        DiscussMD5 : 351A487CA2C7613C0B1C57A9E35D54AC
        CheckMD5   : C9261BD3974A5E419E06BDE2767DB6B6
        FixMD5     : 2E9D8141A1F04746FF393A42DEB7D0D6
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
        select @@SERVERNAME as InstanceName
            , name AS DatabaseName
            FROM sys.databases
        WHERE name IN (
                'pubs'
                , 'Northwind'
                , 'AdventureWorks'
                , 'WorldwideImporters'
                )
        ORDER BY 1, 2
        "
    if ($res) {
        $Status = "Open"
        $FindingDetails = "The following demonstration/sample databases should not exist on a production server:`n$($res | Format-Table | Out-String)"
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "No demonstration or sample databases were found."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213846 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213846
        STIG ID    : SQL4-00-016855
        Rule ID    : SV-213846r395853_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000091
        Rule Title : SQL Server must have the Filestream feature disabled if it is unused.
        DiscussMD5 : 4F695B0A66CD0F182D83E53EF74C5E8E
        CheckMD5   : DF7126A3042ECC3A04A915A9316F7A7D
        FixMD5     : E46CCC27EEDAE360574AF409E7D9B0E2
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
    $qry = "
        select @@SERVERNAME InstanceName
            , value
            , value_in_use
        from sys.configurations
        where name = 'filestream access level'
        and (value > 0 or value_in_use > 0)
    "
    Get-ISQL -ServerInstance $Instance -Database $Database $qry | ForEach-Object {
        if ($_.value -gt 0) {
            #$FindingDetails += "Instance $($_.InstanceName) is configured with FileStream enabled.`n"
            # 20201027 JJS Added all Results to output
            $FindingDetails += "Instance $($_.InstanceName) Value $($_.Value) value_in_use $($_.value_in_use) is configured with FileStream enabled.`n"
        }
        else {
            #$FindingDetails += "Instance $($_.InstanceName) is running with FileStream enabled.`n"
            # 20201027 JJS Added all Results to output
            $FindingDetails += "Instance $($_.InstanceName) Value $($_.Value) value_in_use $($_.value_in_use) is running with FileStream enabled.`n"
        }
    } # foreach-object

    if ($FindingDetails -gt ' ') {
        $Status = "Open"
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "FileStream is not enabled."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213848 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213848
        STIG ID    : SQL4-00-017100
        Rule ID    : SV-213848r395853_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000092
        Rule Title : The SQL Server default account [sa] must be disabled.
        DiscussMD5 : CE413C3DD4617F4EED252DDB9664ED40
        CheckMD5   : B76A90A3AA947333B4D221577842B6DE
        FixMD5     : CABCA60CD3BD9D50501C3225C46411B9
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
            SELECT name, is_disabled
            FROM sys.sql_logins
            WHERE principal_id = 1"
            if ($res) {
                if ($res.name -eq 'sa') {
                    #$FindingDetails += "The 'sa' account has not been renamed on $svr.`n"
                    # 20201027 JJS Added all Results to output
                    $FindingDetails += "The 'sa' account has not been renamed on $svr.`n$($res | Format-Table -AutoSize| Out-String)"
                }
                if ($res.is_disabled -ne $true) {
                    #$FindingDetails += "The SQL Server
                    # 20201027 JJS Added all Results to outputdefault account [sa] account is not disabled on $svr.`n"
                    $FindingDetails += "The SQL Server default account [sa] account is not disabled on $svr.`n$($res | Format-Table -AutoSize| Out-String)"
                }
            }
            else {
                $FindingDetails = "This is odd -- no sql login was found with principal_id = 1"
            } # if ($res)
        } # foreach ($svr in $svrlist)

        if ($FindingDetails -gt '') {
            $Status = 'Open'
        }
        else {
            $Status = 'NotAFinding'
            $FindingDetails += "The SQL Server default account [sa] has been renamed and disabled."
        } # if ($FindingDetails -gt '')

    }
    else {
        $Status = 'NotAFinding'
        $FindingDetails += "No SQL instances are running on this server."
    } # if ($svrlist)
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213849 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213849
        STIG ID    : SQL4-00-017200
        Rule ID    : SV-213849r395853_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000093
        Rule Title : Access to xp_cmdshell must be disabled, unless specifically required and approved.
        DiscussMD5 : 0DD51441D9D8F15FB28444EF43432A7F
        CheckMD5   : 54C15BAA1871B083DBB46599B4280F58
        FixMD5     : 006833C74ED71A3078667A1C6CEAF462
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
    $qry = "
        select @@SERVERNAME InstanceName
            , value
            , value_in_use
        from sys.configurations
        where name = 'xp_cmdshell'
        and 1 in (value, value_in_use)
    "
    Get-ISQL -ServerInstance $Instance -Database $Database $qry | ForEach-Object {
        if ($_.value -eq 1) {
            #$FindingDetails += "Instance $($_.InstanceName) is configured with xp_cmdshell enabled.`n"
            # 20201027 JJS Added all Results to output
            $FindingDetails += "Instance $($_.InstanceName) is configured with xp_cmdshell enabled.`n$($_ | Format-Table -AutoSize| Out-String)"
        }
        else {
            #$FindingDetails += "Instance $($_.InstanceName) is running with xp_cmdshell enabled.`n"
            # 20201027 JJS Added all Results to output
            $FindingDetails += "Instance $($_.InstanceName) is running with xp_cmdshell enabled.`n$($_ | Format-Table -AutoSize| Out-String)"
        }
    } # foreach-object

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "XP_CmdShell is not enabled."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213850 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213850
        STIG ID    : SQL4-00-017400
        Rule ID    : SV-213850r744320_rule
        CCI ID     : CCI-000382
        Rule Name  : SRG-APP-000142-DB-000094
        Rule Title : SQL Server must be configured to prohibit or restrict the use of unauthorized network protocols.
        DiscussMD5 : 610677C19047BF559C0F48BB4E81E51E
        CheckMD5   : 1993EF606684BC430A1F6B121A0DE526
        FixMD5     : 2C7C0F514A3FFA471837BD20F5D18604
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
        SELECT @@servername as Instance
            , dn.value_data as Protocol
        from sys.dm_server_registry dn
        inner join sys.dm_server_registry de on dn.registry_key = de.registry_key
        where dn.value_name = 'DisplayName'
        and de.value_name = 'Enabled'
        and de.value_data = 1
        and dn.value_data not in ('Shared Memory','TCP/IP')
    "
    if ($res) {
        $Status = 'Open'
        $FindingDetails += "DBA, If the following protocols are not documented as required and authorized, they must be disabled:`n$($res | Format-Table -AutoSize| Out-String)"
    }
    else {
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

Function Get-V213851 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213851
        STIG ID    : SQL4-00-017410
        Rule ID    : SV-213851r810821_rule
        CCI ID     : CCI-000382
        Rule Name  : SRG-APP-000142-DB-000094
        Rule Title : SQL Server must be configured to prohibit or restrict the use of unauthorized network ports.
        DiscussMD5 : 610677C19047BF559C0F48BB4E81E51E
        CheckMD5   : 5F7EA5FA7B5789660BF5CB9BC8DB09CF
        FixMD5     : 09662C5D15622EE46E107727809F49FE
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
    Get-ISQL -ServerInstance $Instance -Database $Database "
        select @@servername as Instance
            , ds.value_data StaticPort
            , dd.value_data DynamicPort
        from sys.dm_server_registry ds
        inner join sys.dm_server_registry dd on ds.registry_key = dd.registry_key
        where ds.registry_key like '%IPAll'
        and dd.registry_key like '%IPAll'
        and ds.value_name = 'TcpPort'
        and dd.value_name = 'TcpDynamicPorts'
    " | ForEach-Object {
        $inst = $_.Instance
        $DynamicPort = Get-LeftNumbers($_.DynamicPort.trim())
        $StaticPort = Get-LeftNumbers($_.StaticPort.trim())
        if ($DynamicPort -gt 0) {
            $FindingDetails += "Instance $inst is configured to use dynamic ports $DynamicPort."
        }
        elseif ($StaticPort -lt 49152) {
            $FindingDetails += "Instance $inst is configured with a lower-value static port StaticPort $StaticPort."
        }
    }

    if ($FindingDetails -gt '') {
        $Status = 'Open'
        $FindingDetails += "`nNote: the STIG asks that port usage comply with PPSM or organizational mandates, but industry best practices advise using high-number static ports."
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "High-number static ports are being used, as per industry best practices."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213858 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213858
        STIG ID    : SQL4-00-030300
        Rule ID    : SV-213858r395475_rule
        CCI ID     : CCI-000015
        Rule Name  : SRG-APP-000023-DB-000001
        Rule Title : SQL Server authentication and identity management must be integrated with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.
        DiscussMD5 : AECB0D086A4A8A7F31A22508A6B8401F
        CheckMD5   : 9E7AEB7220C3694B2B4A9F69D51158CA
        FixMD5     : A1B9EF428A4900BA352B1996016B458B
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
    $in = Get-ISQL -ServerInstance $Instance -Database $Database "select @@servername"
    if ($in) {
        foreach ($h in $in.column1) {
            $res = Get-ISQL -ServerInstance $h "EXEC sp_configure 'contained database authentication'"
            if ($res.run_value -eq 1 -or $res.config_value -eq 1) {
                $FindingDetails += "Instance $h is using contained database authentication.`n"
            }
            $res = Get-ISQL -ServerInstance $h "
            SELECT CASE SERVERPROPERTY('IsIntegratedSecurityOnly')
            WHEN 1 THEN 'Windows Authentication'
            WHEN 0 THEN 'Windows and SQL Server Authentication'
            END as AuthenticationMode
        "
            if ($res.AuthenticationMode -ne 'Windows Authentication') {
                $FindingDetails += "Instance $h's login authention mode is $($res.AuthenticationMode) instead of Windows Authentication.`n"
            }
        } # foreach
        if ($FindingDetails -gt "") {
            $Status = 'Open'
            $FindingDetails += "DBA, ensure the above are documented as authorized in the SSP.`n"
            $res = Get-ISQL -ServerInstance $Instance -Database $Database "
            select @@servername
                , name
            FROM sys.sql_logins
            WHERE type_desc = 'SQL_LOGIN'
            AND is_disabled = 0
        "
            if ($res) {
                $FindingDetails += "DBA, also ensure the following accounts are authorized in the SSP to be managed by SQL Server:`n$($res | Format-Table -AutoSize| Out-String)"
            } # if ($res)
        } # if ($FindingDetails -gt "")
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "No active SQL instances currently exist on this host."
    } # if ($in)

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "Windows Authentication is used."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213859 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213859
        STIG ID    : SQL4-00-030410
        Rule ID    : SV-213859r395712_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000091-DB-000325
        Rule Title : Where SQL Server Audit is in use, SQL Server must generate audit records when unsuccessful attempts to retrieve privileges/permissions occur.
        DiscussMD5 : 08421D6F203E1E3AA2D3327D3627F2E6
        CheckMD5   : 318F9A7F5907B92F0703983112C6BD7C
        FixMD5     : 5CE32D103D386E9FA99F50BCD3D40F33
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

Function Get-V213860 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213860
        STIG ID    : SQL4-00-030600
        Rule ID    : SV-213860r495393_rule
        CCI ID     : CCI-000140
        Rule Name  : SRG-APP-000109-DB-000321
        Rule Title : Where availability is paramount, the SQL Server must continue processing (preferably overwriting existing records, oldest first), in the event of lack of space for more Audit/Trace log records; and must keep processing after any failure of an Audit/Trace.
        DiscussMD5 : A0D8730D9469A489AA1171C941AB32E0
        CheckMD5   : B4C8C00681899646E876386EA75D1A61
        FixMD5     : 4FA8298295D96FF5CFCBCAE2C75D8119
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
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "SELECT a.name 'audit_name',
    a.type_desc 'storage_type',
    f.max_rollover_files
    FROM sys.server_audits a
    LEFT JOIN sys.server_file_audits f ON a.audit_id = f.audit_id
    WHERE a.is_state_enabled = 1"
    if ($res) {
        if ($res.storage_type -eq 'FILE') {
            if ($res.max_rollover_files -gt 0) {
                $Status = 'NotAFinding'
                #$FindingDetails += "The storage type is 'FILE' and the max rollover files are greater than zero."
                # 20201027 JJS Added all Results to output
                $FindingDetails += "The storage type is 'FILE' and the max rollover files are greater than zero.`n$($res | Format-Table -AutoSize| Out-String)"
            }
            else {
                $Status = "Open"
                #$FindingDetails += "The storage type is 'FILE' and the max rollover files are zero."
                # 20201027 JJS Added all Results to output
                $FindingDetails += "The storage type is 'FILE' and the max rollover files are zero.`n$($res | Format-Table -AutoSize| Out-String)"
            } # if ($res.max_rollover_files -gt 0)
        }
        elseif ($res.storage_type -in 'APPLICATION LOG', 'SECURITY LOG') {
            $Status = 'NotAFinding'
            #$FindingDetails += "LOG storage types do not require max rollover files to be configured."
            # 20201027 JJS Added all Results to output
            $FindingDetails += "LOG storage types do not require max rollover files to be configured.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        else {
            $Status = "Open"
            #$FindingDetails = "An unexpected storage type was found on the security audit."
            # 20201027 JJS Added all Results to output
            $FindingDetails = "An unexpected storage type was found on the security audit.`n$($res | Format-Table -AutoSize| Out-String)"
        } # if ($res.storage_type -eq 'FILE')
    }
    else {
        $Status = "Open"
        $FindingDetails = "No audits appear to be configured on this system."
    } # if ($res)
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213861 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213861
        STIG ID    : SQL4-00-030700
        Rule ID    : SV-213861r531244_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000362
        Rule Title : The role(s)/group(s) used to modify database structure (including but not necessarily limited to tables, indexes, storage, etc.) and logic modules (stored procedures, functions, triggers, links to software external to SQL Server, etc.) must be restricted to authorized users.
        DiscussMD5 : 978959640256E1378015BF8DB91A4E1E
        CheckMD5   : 9E71938FF750257A99E9A9EE804A66CC
        FixMD5     : 1150AED4FC0263C32AC610A31912103C
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
    SELECT P.type_desc AS principal_type, P.name AS principal_name, O.type_desc,
    CASE class
    WHEN 0 THEN DB_NAME()
    WHEN 1 THEN OBJECT_SCHEMA_NAME(major_id) + '.' + OBJECT_NAME(major_id)
    WHEN 3 THEN SCHEMA_NAME(major_id)
    ELSE class_desc + '(' + CAST(major_id AS nvarchar) + ')'
    END AS securable_name, DP.state_desc, DP.permission_name
    FROM sys.database_permissions DP
    JOIN sys.database_principals P ON DP.grantee_principal_id = P.principal_id
    LEFT OUTER JOIN sys.all_objects O ON O.object_id = DP.major_id AND O.type IN ('TR','TA','P','X','RF','PC','IF','FN','TF','U')
    WHERE DP.type IN ('AL','ALTG') AND DP.class IN (0, 1, 53)
    "
    if ($res) {
        $Status = 'Open'
        $FindingDetails += "DBA, ensure the following accounts are authorized in the SSP to modify objects:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
    SELECT R.name AS role_name, M.type_desc AS principal_type, M.name AS principal_name
    FROM sys.database_principals R
    JOIN sys.database_role_members DRM ON R.principal_id = DRM.role_principal_id
    JOIN sys.database_principals M ON DRM.member_principal_id = M.principal_id
    WHERE R.name IN ('db_ddladmin','db_owner')
    AND M.name != 'dbo'
    "
    if ($res) {
        if ($FindingDetails -eq "") {
            $Status = 'Open'
            $FindingDetails += "DBA, ensure the following accounts are authorized in the SSP to modify objects:`n"
        }
        $FindingDetails += $($res | Format-Table -AutoSize | Out-String)
    } # if ($res)

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check queries."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213862 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213862
        STIG ID    : SQL4-00-031100
        Rule ID    : SV-213862r863333_rule
        CCI ID     : CCI-000803, CCI-002450
        Rule Name  : SRG-APP-000179-DB-000114
        Rule Title : SQL Server must use NIST FIPS 140-2 or 140-3 validated cryptographic modules for cryptographic operations.
        DiscussMD5 : 5F2ADCE13DCC1DE02CD4DD58E28750C8
        CheckMD5   : E56804C55133870156BA2EBE21DEC061
        FixMD5     : B813D3A7A0D813AC8BAE8222A223B3EB
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
    $TempUserHivePath = ""  # User's loaded hive to perform check
    $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\"  # Registry path identified in STIG
    $RegistryValueName = "Enabled"  # Value name identified in STIG
    $RegistryValue = @("1")  # Value expected in STIG (if REG_DWORD/REG_QWORD use hex and remove leading 0x000...)
    $RegistryType = "REG_DWORD"  # Value type expected in STIG
    $SettingName = "System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing"  # GPO setting name identified in STIG
    $SettingState = "Enabled"  # GPO configured state identified in STIG.
    $SettingNotConfiguredAllowed = $false  # Set to true if STIG allows for setting to be Not Configured.

    If ($TempUserHivePath) {
        $FindingDetails += "User Profile Evaluated: $($Username)" | Out-String
        $FindingDetails += "" | Out-String
        $RegistryResult = Get-RegistryResult -Path $TempUserHivePath -ValueName $RegistryValueName
    }
    Else {
        $RegistryResult = Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName
    }

    If ($RegistryResult.Type -in @("REG_DWORD", "REG_QWORD")) {
        $RegistryResultValue = "0x{0:x8}" -f $RegistryResult.Value + " ($($RegistryResult.Value))" # Convert to hex and fomat to 0x00000000
        #$RegistryResult.Value = "{0:x}" -f $RegistryResult.Value # Convert to hex
    }
    Else {
        $RegistryResultValue = $RegistryResult.Value
    }

    If ($RegistryResult.Type -eq "(NotFound)") {
        #If the registry value does not exist
        If ($SettingNotConfiguredAllowed -eq $true) {
            #And it is allowed to be not configured set to notAFinding
            $Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            #Or, if it must be configured, set this to Open
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
    }
    Else {
        #If the registry value is found...
        If ($RegistryResult.Value -in $RegistryValue -and $RegistryResult.Type -eq $RegistryType) {
            #And the registry result matches the expected registry value AND the registry result type matches the expected value type, set to NotAFinding
            $Status = "NotAFinding"
            $FindingDetails += "'$($SettingName)' is $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
        }
        Else {
            #If either the registry value or registry type is not expected, consider this out of spec and set to Open.
            $Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                #If the registry result matches the expected value
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-String
            }
            Else {
                #If the result value and expected value are different, print what the value is set to and what it should be.
                $FindingDetails += "Value:`t`t$($RegistryResultValue) [Expected $($RegistryValue -join " or ")]" | Out-String
            }
            If ($RegistryResult.Type -eq $RegistryType) {
                #If the result type is the same as expected
                $FindingDetails += "Type:`t`t$($RegistryResult.Type)" | Out-String
            }
            Else {
                #If the result type is different from what is expected, print both.
                $FindingDetails += "Type:`t`t$($RegistryResult.Type) [Expected '$RegistryType']" | Out-String
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

Function Get-V213863 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213863
        STIG ID    : SQL4-00-031400
        Rule ID    : SV-213863r397765_rule
        CCI ID     : CCI-001090
        Rule Name  : SRG-APP-000243-DB-000374
        Rule Title : Access to database files must be limited to relevant processes and to authorized, administrative users.
        DiscussMD5 : 6219D3BDDC7ECCE2CCCEC7B904118CB0
        CheckMD5   : 5293FB043B9E69C62EA83DD33D36FF2D
        FixMD5     : FC93E4BC6D28969DBAFCC36743EA1288
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
    <#
    Allowed privileges per the STIG:

    Database Administrators ALL Full Control
    SQL Server Service SID Data; Log; Backup; Full Control
    SQL Server Agent Service SID Backup Full Control
    SYSTEM ALL Full Control
    CREATOR OWNER ALL Full Control
    #>


    $hashBase = @{
        #$C_ACCT_SQLADMINS                       = @('FullControl') # 20200805 JJS commented out
        'BUILTIN\Administrators'      = @('FullControl')
        #$C_ACCT_SQLSVC                          = @('FullControl') # 20200805 JJS commented out
        'NT SERVICE\MSSQL$<INSTANCE>' = @('FullControl')
        'NT AUTHORITY\SYSTEM'         = @('FullControl')
        'CREATOR OWNER'               = @('FullControl')
    }

    $hashDataLog = $hashBase += @{}
    $hashBackup = $hashBase += @{
        #$C_ACCT_SQLAGENT                        = @('FullControl') # 20200805 JJS commented out
        'NT SERVICE\SQLAgent$<INSTANCE>' = @('FullControl')
    }

    $iDirCnt = 0
    $fFound = $false
    $sDirList = ''

    # Poll MSSQL to get directories of interest...
    Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT distinct @@servername ServerName
            , @@servicename Instance
            , directorytype
            , replace(rtrim(replace(directoryname, '\', ' ')), ' ', '\') directoryname
        FROM
        (
            SELECT
                CAST(SERVERPROPERTY('InstanceDefaultDataPath') AS nvarchar(260)) AS DirectoryName,
                'DataLog' AS DirectoryType
            UNION ALL
            SELECT
                CAST(SERVERPROPERTY('InstanceDefaultLogPath') AS nvarchar(260)),
                'DataLog' AS DirectoryType
            UNION ALL
            SELECT DISTINCT
                LEFT(physical_name, (LEN(physical_name) - CHARINDEX('\', REVERSE(physical_name)))),
                CASE type
                    WHEN 0 THEN 'DataLog'
                    WHEN 1 THEN 'DataLog'
                    ELSE 'Other'
                END
            FROM sys.master_files
            UNION ALL
            SELECT DISTINCT
                LEFT(physical_device_name, (LEN(physical_device_name) - CHARINDEX('\', REVERSE(physical_device_name)))),
                'Backup'
            FROM msdb.dbo.backupmediafamily
            WHERE device_type IN (2, 9, NULL)
        ) A
        ORDER BY
            DirectoryType,
            DirectoryName
    " | ForEach-Object {
        $sInstance = $_.Instance
        $sServer = $_.ServerName
        $sDir = $_.DirectoryName
        $sType = $_.DirectoryType
        $fFound = $true;

        if (Test-Path $sDir) {
            $objACL = Get-Acl $sDir
        }
        else {
            $objACL = $null
            #$FindingDetails += "Instance $sServer appears to be running, but $sDir seems missing.`n"
            # 20201027 JJS Added all Results to output
            $FindingDetails += "Instance $sServer appears to be running, but $sDir seems missing.`n$($_ | Format-Table -AutoSize| Out-String)"
        } # if (test-path $sdir)

        if ($objACL) {
            $sDirList += "  $sDir`n"; $iDirCnt += 1

            if ($sType -eq 'Backup') {
                $hashAuth = $hashBackup
            }
            else {
                $hashAuth = $hashDataLog
            }
            $FindingDetails += Get-AccessProblem -CurrentAuthorizations $objACL.access -AllowedAuthorizations $hashAuth -FilePath $sDir -InstanceName $sInstance
        } # if ($objACL)
    } # Get-ISQL -ServerInstance $Instance -Database $Database ... | foreach-object


    # Interpret results...
    if ($FindingDetails -gt '') {
        $Status = "Open"
    }
    else {
        if ($fFound) {
            $Status = "NotAFinding"
            if ($iDirCnt -eq 0) {
                $FindingDetails = "No SQL data, log, or backup directories were found on this host."
            }
            elseif ($iDirCnt -gt 1) {
                $FindingDetails = "The following directories were checked and found to have proper authorizations:`n`n$sDirList"
            }
            else {
                $FindingDetails = "The following root directory was checked and found to have proper authorizations:`n`n$sDirList"
            }
        }
        else {
            $Status = "Open"
            $FindingDetails = "Unable to determine the SQL data root directory."
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

Function Get-V213866 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213866
        STIG ID    : SQL4-00-032600
        Rule ID    : SV-213866r855537_rule
        CCI ID     : CCI-002233
        Rule Name  : SRG-APP-000342-DB-000302
        Rule Title : Execution of software modules (to include stored procedures, functions, and triggers) with elevated privileges must be restricted to necessary cases only.
        DiscussMD5 : 1CE3CDB718366BE6140FFC60200041CE
        CheckMD5   : C103F7B0DD3DC572FA0C47B7EB9B141E
        FixMD5     : 5FD3DB15BD4F8EB1801AF58654B5BE47
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
        SELECT @@servername as instance
            , C.name AS credential_name
            , C.credential_identity
            , P.enabled as EnabledAsProxy
        FROM sys.credentials C
        LEFT JOIN msdb.dbo.sysproxies P on C.credential_id = P.credential_id
    "
    if ($res) {
        $Status = 'Open'
        $FindingDetails += "DBA, ensure the following have been documented as authorized for use by external processes:`n$($res | Format-Table -AutoSize| Out-String)"
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check queries."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213868 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213868
        STIG ID    : SQL4-00-033000
        Rule ID    : SV-213868r855539_rule
        CCI ID     : CCI-001849
        Rule Name  : SRG-APP-000357-DB-000316
        Rule Title : SQL Server must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.
        DiscussMD5 : CB6D963E3907155B3097E6EAE8702569
        CheckMD5   : 79D4E723FCCEACAA355B8EDBEE2BB4EE
        FixMD5     : 0BC9F847D53E92FFFE1C4D60C00A4F42
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
        SELECT @@servername as instance
            , max_file_size
            , max_rollover_files
            , max_files
            , log_file_path
        FROM sys.server_file_audits
    "
    if ($res) {
        $res | ForEach-Object {
            $maxsize = (0 + $_.max_file_size) * 1024 * 1024
            $maxfiles = 0 + $_.max_rollover_files
            if ($maxfiles -eq 2147483647) {
                $maxfiles = 0 + $_.max_files
            }
            $logdisk = $_.log_file_path -replace ':.*$'
            $psdrive = Get-PSDrive $logdisk
            $capacity = $psdrive.Free + $psdrive.Used
            if ((($maxsize * $maxfiles) -gt $capacity) -or 0 -in $maxsize, $maxfiles ) {
                $Status = 'Open'
                #$FindingDetails += "Audit path $($_.log_file_path) has potential to exceed disk capacity."
                # 20201027 JJS Added all Results to output
                $FindingDetails += "Audit path $($_.log_file_path) has potential to exceed disk capacity.`n$($_ | Format-Table -AutoSize| Out-String)"
            }
        } # $res | foreach-object
        if ($FindingDetails -eq '') {
            $Status = 'NotAFinding'
            $FindingDetails += "All audit storage is within capacity."
        } # if ($FindingDetails -eq '')
    }
    else {
        $Status = "Open"
        $FindingDetails = 'No audits are defined at all, but the STIG doesn''t allow for "Not Applicable."'
    } #   if ($res)
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213871 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213871
        STIG ID    : SQL4-00-033600
        Rule ID    : SV-213871r855543_rule
        CCI ID     : CCI-001890
        Rule Name  : SRG-APP-000374-DB-000322
        Rule Title : SQL Server must produce time stamps that can be mapped to Coordinated Universal Time (UTC, formerly GMT).
        DiscussMD5 : F354B68A32C0CC148C7DE3E3D81C2924
        CheckMD5   : 17624EE654281282099CC42E4CC73187
        FixMD5     : 9BE37620A6ED79C0F703D69ECFB1599D
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
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "select @@servername as instance, isnull(default_domain(),'NULL') as DefaultDomain"
    if ($res) {
        $res | ForEach-Object {
            if ($_.DefaultDomain -eq 'NULL') {
                # The instance is not part of a domain, so we need to see if a time source is set.
                $ts = (w32tm /query /source)
                if ($ts -eq 'Local CMOS Clock') {
                    #$FindingDetails += "Instance $($_.instance) does not appear to sync with a time server."
                    # 20201027 JJS Added all Results to output
                    $FindingDetails += "Instance $($_.instance) does not appear to sync with a time server.`n$($_ | Format-Table -AutoSize| Out-String)"
                }
            }
        } # $res | foreach-object
        if ($FindingDetails -eq '') {
            $Status = 'NotAFinding'
            $FindingDetails += "All servers are either part of a domain or are configured to correctly synchronize with a time server."
        } # if ($FindingDetails -eq '')
    }
    else {
        $Status = "Open"
        $FindingDetails = "Unable to determine default domain."
    } # if ($res)
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213872 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213872
        STIG ID    : SQL4-00-033800
        Rule ID    : SV-213872r855544_rule
        CCI ID     : CCI-001812
        Rule Name  : SRG-APP-000378-DB-000365
        Rule Title : SQL Server must prohibit user installation of logic modules (stored procedures, functions, triggers, views, etc.) without explicit privileged status.
        DiscussMD5 : 36A4117F91759B423744DC5FF7ECF008
        CheckMD5   : EF47B1FA501F3B3F12F5B08F0530B1EB
        FixMD5     : AC7C96967AF1F8369B5EE86CE6CC9849
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
        SELECT @@servername as instance
            , db_name() as databasename
            , P.type_desc AS principal_type
            , P.name AS principal_name
            , O.type_desc
            , CASE class
                WHEN 0 THEN DB_NAME()
                WHEN 1 THEN OBJECT_SCHEMA_NAME(major_id) + '.' + OBJECT_NAME(major_id)
                WHEN 3 THEN SCHEMA_NAME(major_id)
                ELSE class_desc + '(' + CAST(major_id AS nvarchar) + ')'
            END AS securable_name, DP.state_desc
            , DP.permission_name
        FROM sys.database_permissions DP
        JOIN sys.database_principals P ON DP.grantee_principal_id = P.principal_id
        LEFT OUTER JOIN sys.all_objects O ON O.object_id = DP.major_id AND O.type IN ('TR','TA','P','X','RF','PC','IF','FN','TF','U')
        WHERE DP.type IN ('AL','ALTG') AND DP.class IN (0, 1, 53)
    "
    if ($res) {
        $Status = 'Open'
        $FindingDetails += "DBA, ensure the following principals are authorized in the SSP to modify the specified object or type:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT @@servername as instance
            , db_name() as databasename
            , R.name AS role_name
            , M.type_desc AS principal_type
            , M.name AS principal_name
        FROM sys.database_principals R
        JOIN sys.database_role_members DRM ON R.principal_id = DRM.role_principal_id
        JOIN sys.database_principals M ON DRM.member_principal_id = M.principal_id
        WHERE R.name IN ('db ddladmin','db_owner')
        AND M.name != 'dbo'
    "
    if ($res) {
        if ($FindingDetails -eq "") {
            $Status = 'Open'
            $FindingDetails += "DBA, ensure the following user/role memberships are authorized in the SSP:`n"
        }
        $FindingDetails += $($res | Format-Table -AutoSize | Out-String)
    } # if ($res)

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check queries."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213873 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213873
        STIG ID    : SQL4-00-033900
        Rule ID    : SV-213873r855545_rule
        CCI ID     : CCI-001813
        Rule Name  : SRG-APP-000380-DB-000360
        Rule Title : SQL Server and Windows must enforce access restrictions associated with changes to the configuration of the SQL Server instance or database(s).
        DiscussMD5 : 88DA8C452AAFDBB8DA9B3A809D507D46
        CheckMD5   : 007032B5F18663455BF464141E7E9A77
        FixMD5     : 04435115AD4D85ED33E028E17EB3E29F
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
        SELECT @@servername as instance
            , p.name AS Principal,
    p.type_desc AS Type,
    sp.permission_name AS Permission,
    sp.state_desc AS State
    FROM sys.server_principals p
    INNER JOIN sys.server_permissions sp ON p.principal_id = sp.grantee_principal_id
    WHERE (sp.permission_name = 'CONTROL SERVER' OR sp.state = 'W')
    AND p.name not in ('##MS_PolicySigningCertificate##')
    "
    if ($res) {
        $FindingDetails += "DBA, ensure the following have been documented as authorized to control the server:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT @@servername as instance
    , m.name AS Member,
    m.type_desc AS Type,
    r.name AS Role
    FROM sys.server_principals m
    INNER JOIN sys.server_role_members rm ON m.principal_id = rm.member_principal_id
    INNER JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
    WHERE r.name IN ('sysadmin','securityadmin','serveradmin')
    and m.name not in (
        'Sandman'
    , 'NT SERVICE\SQLWriter'
    , 'NT SERVICE\Winmgmt'
    , 'NT SERVICE\MSSQL`$'+@@SERVICENAME
    , 'NT SERVICE\SQLAgent`$'+@@SERVICENAME
    )"
    if ($res) {
        $FindingDetails += "DBA, ensure the following have been documented as authorized to administer the server:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    if ($FindingDetails -eq '') {
        $Status = "NotAFinding"
        $FindingDetails = "The check queries did not find any accounts other than those authorized in the SSP."
    }
    else {
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

Function Get-V213874 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213874
        STIG ID    : SQL4-00-034000
        Rule ID    : SV-213874r855546_rule
        CCI ID     : CCI-001814
        Rule Name  : SRG-APP-000381-DB-000361
        Rule Title : SQL Server must produce Trace or Audit records of its enforcement of access restrictions associated with changes to the configuration of the DBMS or database(s).
        DiscussMD5 : B96BB396C3E74830E792C9277CE0D1C0
        CheckMD5   : 24C0D2788CEFE5AFE3DA017B3458704F
        FixMD5     : E28DD45DCB9CDEE98C20B1AA991F55CA
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
                    select 'APPLICATION_ROLE_CHANGE_PASSWORD_GROUP' as audit_action_name
            union select 'AUDIT_CHANGE_GROUP'
            union select 'BACKUP_RESTORE_GROUP'
            union select 'DATABASE_CHANGE_GROUP'
            union select 'DATABASE_OBJECT_ACCESS_GROUP'
            union select 'DATABASE_OBJECT_CHANGE_GROUP'
            union select 'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP'
            union select 'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP'
            union select 'DATABASE_OPERATION_GROUP'
            union select 'DATABASE_OWNERSHIP_CHANGE_GROUP'
            union select 'DATABASE_PERMISSION_CHANGE_GROUP'
            union select 'DATABASE_PRINCIPAL_CHANGE_GROUP'
            union select 'DATABASE_PRINCIPAL_IMPERSONATION_GROUP'
            union select 'DATABASE_ROLE_MEMBER_CHANGE_GROUP'
            union select 'DBCC_GROUP'
            union select 'LOGIN_CHANGE_PASSWORD_GROUP'
            union select 'SCHEMA_OBJECT_CHANGE_GROUP'
            union select 'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP'
            union select 'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP'
            union select 'SERVER_OBJECT_CHANGE_GROUP'
            union select 'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP'
            union select 'SERVER_OBJECT_PERMISSION_CHANGE_GROUP'
            union select 'SERVER_OPERATION_GROUP'
            union select 'SERVER_PERMISSION_CHANGE_GROUP'
            union select 'SERVER_PRINCIPAL_IMPERSONATION_GROUP'
            union select 'SERVER_ROLE_MEMBER_CHANGE_GROUP'
            union select 'SERVER_STATE_CHANGE_GROUP'
            union select 'TRACE_CHANGE_GROUP'
            except
                    SELECT d.audit_action_name AS 'ActionName'
                    FROM sys.server_audit_specifications s
                    JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
                    JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
                    WHERE a.is_state_enabled = 1
                    and s.is_state_enabled = 1
                    and d.audited_result like '%FAILURE%'
                    and d.audited_result like '%FAILURE%'
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

Function Get-V213875 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213875
        STIG ID    : SQL4-00-034200
        Rule ID    : SV-213875r855547_rule
        CCI ID     : CCI-001762
        Rule Name  : SRG-APP-000383-DB-000364
        Rule Title : SQL Server must disable communication protocols not required for operation.
        DiscussMD5 : FA329FD78B2D93F14C195815A5F5BA7F
        CheckMD5   : D3460C2F0963CA9FB3522227E8C86750
        FixMD5     : 7C21CD00E6F7FCA08D3C19BBFA7192AB
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
    # This check of protocols is copied from v-79185
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT @@servername as Instance
            , dn.value_data as Protocol
        from sys.dm_server_registry dn
        inner join sys.dm_server_registry de on dn.registry_key = de.registry_key
        where dn.value_name = 'DisplayName'
        and de.value_name = 'Enabled'
        and de.value_data = 1
        and dn.value_data not in ('Shared Memory','TCP/IP')
    "
    if ($res) {
        $FindingDetails += "DBA, If the following protocols are not documented as required and authorized, they must be disabled:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    # This check of port numbers is copied from v-79187
    Get-ISQL -ServerInstance $Instance -Database $Database "
        select @@servername as Instance
            , ds.value_data StaticPort
            , dd.value_data DynamicPort
        from sys.dm_server_registry ds
        inner join sys.dm_server_registry dd on ds.registry_key = dd.registry_key
        where ds.registry_key like '%IPAll'
        and dd.registry_key like '%IPAll'
        and ds.value_name = 'TcpPort'
        and dd.value_name = 'TcpDynamicPorts'
    " | ForEach-Object {
        $inst = $_.Instance
        # 20201104 JJS added trim functions
        $DynamicPort = Get-LeftNumbers($_.DynamicPort.trim())
        $StaticPort = Get-LeftNumbers($_.StaticPort.trim())
        if ($DynamicPort -gt 0) {
            # 20201021 JJS added DynamicPort to output
            #$FindingDetails += "Instance $inst is configured to use dynamic ports.`n$($_.DynamicPort | format-table -AutoSize| out-string)"
            # 20201027 JJS Added all Results to output
            #$FindingDetails += "Instance $inst is configured to use dynamic ports.`n$($_ | format-table -AutoSize| out-string)"
            $FindingDetails += "Instance $inst is configured to use dynamic ports $DynamicPort."
        }
        elseif ($StaticPort -lt 49152) {
            #$FindingDetails += "Instance $inst is configured with a lower-value static port.`n"
            # 20201027 JJS Added all Results to output
            #$FindingDetails += "Instance $inst is configured with a lower-value static port.`n$($_ | format-table -AutoSize| out-string)"
            $FindingDetails += "Instance $inst is configured with a lower-value static port StaticPort $StaticPort."
        } # if ($_.DynamicPort -gt 0)
    } # Get-ISQL -ServerInstance $Instance -Database $Database ... | ForEach-Object

    # See if any SQL Telemetry/CEIP services are enabled. (Other SQL services are authorized on this system).
    $res = Get-Service sqltelemetry* | Where-Object StartType -NE 'Disabled'
    if ($res) {
        $FindingDetails += "The following services are not authorized and should be disabled:`n$($res | Format-Table -AutoSize| Out-String)"
    } # if ($res)

    if ($FindingDetails -eq '') {
        $Status = "NotAFinding"
        $FindingDetails = "Protocols, ports and services align with system documentation."
    }
    else {
        $Status = 'Open'
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

Function Get-V213877 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213877
        STIG ID    : SQL4-00-035000
        Rule ID    : SV-213877r855549_rule
        CCI ID     : CCI-002420
        Rule Name  : SRG-APP-000441-DB-000378
        Rule Title : The confidentiality and integrity of information managed by SQL Server must be maintained during preparation for transmission.
        DiscussMD5 : 7C69F2757045E210D5F38044715B0F36
        CheckMD5   : C4C9F7F69B83F4B6C6D28CA9900D5899
        FixMD5     : E3F323CD125F89D9802819E0E8F2C4F8
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
        SELECT @@servername as instance
    , name, type_desc, encryption_algorithm_desc
    FROM sys.database_mirroring_endpoints
    WHERE encryption_algorithm != 2"
    if ($res) {
        $Status = 'Open'
        $FindingDetails += "The following should either be encrypted or documented as authorized for unencrypted transmission:`n$($res | Format-Table -AutoSize| Out-String)"
    }
    else {
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

Function Get-V213878 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213878
        STIG ID    : SQL4-00-035100
        Rule ID    : SV-213878r855550_rule
        CCI ID     : CCI-002422
        Rule Name  : SRG-APP-000442-DB-000379
        Rule Title : The confidentiality and integrity of information managed by SQL Server must be maintained during reception.
        DiscussMD5 : B56BD71A2BA81A6A4CB9794D13A257D8
        CheckMD5   : 426AC2A64681AB720C87ADFCACBC098F
        FixMD5     : 2A40E91805220862B16BF5E7ACD2009D
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
        SELECT @@servername as instance, name, type_desc, encryption_algorithm_desc
    FROM sys.service_broker_endpoints
    WHERE encryption_algorithm != 2"
    if ($res) {
        $Status = 'Open'
        $FindingDetails += "The following should either be encrypted or documented as authorized for unencrypted transmission:`n$($res | Format-Table -AutoSize| Out-String)"
    }
    else {
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

Function Get-V213881 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213881
        STIG ID    : SQL4-00-035600
        Rule ID    : SV-213881r400753_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000492-DB-000332
        Rule Title : SQL Server must produce Trace or Audit records when security objects are accessed.
        DiscussMD5 : E0DB7A72C2CE379EAA47478B824A919E
        CheckMD5   : D81521EF6785F7BBC31C7D9ABA03BE49
        FixMD5     : EEE87DC9F955DE582377D4CBE2B59F0D
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
        $FindingDetails += "The audit is being performed."
    }
    else {
        $Status = "Open"
        #$FindingDetails = "DBA, no audits are being done for retrieval of privilege/permissions/role membership info. Does the SSP agree this is OK?"
        # 20201027 JJS Added all Results to output
        $FindingDetails = "DBA, no audits are being done for retrieval of privilege/permissions/role membership info. Does the SSP agree this is OK?`n$($res | Format-Table -AutoSize| Out-String)"

    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213882 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213882
        STIG ID    : SQL4-00-035700
        Rule ID    : SV-213882r400753_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000492-DB-000333
        Rule Title : SQL Server must produce Trace or Audit records when unsuccessful attempts to access security objects occur.
        DiscussMD5 : C70B81AE172A9002E38E04E92E0C3CEA
        CheckMD5   : 90B26E6E10ACD2CEB22D4BFFF8F4EC75
        FixMD5     : 2FDAF6DB3D7D68B709BD476A405391CA
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
        $FindingDetails += "The audit is being performed."
    }
    else {
        $Status = "Open"
        #$FindingDetails = "DBA, no audits are being done for retrieval of privilege/permissions/role membership info. Does the SSP agree this is OK?"
        # 20201027 JJS Added all Results to output
        $FindingDetails = "DBA, no audits are being done for retrieval of privilege/permissions/role membership info. Does the SSP agree this is OK?`n$($res | Format-Table -AutoSize| Out-String)"

    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213883 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213883
        STIG ID    : SQL4-00-036000
        Rule ID    : SV-213883r400762_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000495-DB-000326
        Rule Title : SQL Server must generate Trace or Audit records when privileges/permissions are added.
        DiscussMD5 : 06488FB05A967BF8B9DD7B65401E4A3E
        CheckMD5   : D887881A9FB84EA8A1F6961ADCD85ABC
        FixMD5     : 1CDFD0621E63D5B6EA4D82DF8D4BE965
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

Function Get-V213884 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213884
        STIG ID    : SQL4-00-036100
        Rule ID    : SV-213884r400762_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000495-DB-000327
        Rule Title : SQL Server must generate Trace or Audit records when unsuccessful attempts to add privileges/permissions occur.
        DiscussMD5 : 545EA3C3B6BCA171BC148B21B48B8C1A
        CheckMD5   : 3362D9F4B784A60E4C3601BCC3C63844
        FixMD5     : 1CDFD0621E63D5B6EA4D82DF8D4BE965
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

Function Get-V213885 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213885
        STIG ID    : SQL4-00-036900
        Rule ID    : SV-213885r400831_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000499-DB-000330
        Rule Title : SQL Server must generate Trace or Audit records when privileges/permissions are deleted.
        DiscussMD5 : DC2270964CB25C50770D8E4AE070F30C
        CheckMD5   : 2FD3BBF98C934028B74A5C333537E007
        FixMD5     : C214E8997638FB46069E3AA1D10752C8
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

Function Get-V213886 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213886
        STIG ID    : SQL4-00-037000
        Rule ID    : SV-213886r400831_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000499-DB-000331
        Rule Title : SQL Server must generate Trace or Audit records when unsuccessful attempts to delete privileges/permissions occur.
        DiscussMD5 : D992DB8B9936B84F054B93BE267FB679
        CheckMD5   : 06A39011A0284AB8D82ECAD6678FF66E
        FixMD5     : 23D9D1D2BFD7BC2B3C31AA4A5F4F96D9
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
                    and d.audited_result like '%FAILURE%'
                    and d.audited_result like '%FAILURE%'
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

Function Get-V213887 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213887
        STIG ID    : SQL4-00-037500
        Rule ID    : SV-213887r754860_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000503-DB-000350
        Rule Title : SQL Server must generate Trace or Audit records when successful logons or connections occur.
        DiscussMD5 : 4258C5233A7D6A70C8D37313F5680714
        CheckMD5   : AFAA1AA7EDEF5189B303E5C14280902D
        FixMD5     : E61661DA69EAC53DEA6F5B7008DC90A3
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
    WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SUCCESSFUL_LOGIN_GROUP'
    "
    if ($res) {
        $Status = 'NotAFinding'
        #$FindingDetails += "The SUCCESSFUL_LOGIN_GROUP audit is being performed."
        # 20201027 JJS Added all Results to output
        $FindingDetails += "The SUCCESSFUL_LOGIN_GROUP audit is being performed.`n$($res | Format-Table -AutoSize| Out-String)"

    }
    else {
        $Status = "Open"
        $FindingDetails = "DBA, the SUCCESSFUL_LOGIN_GROUP audit is not being performed. Is the instance auditing failed and successful logins?"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213888 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213888
        STIG ID    : SQL4-00-037600
        Rule ID    : SV-213888r754858_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000503-DB-000351
        Rule Title : SQL Server must generate Trace or Audit records when unsuccessful logons or connection attempts occur.
        DiscussMD5 : 6A1374D39B7D5F354AC0544ECC2C9D2C
        CheckMD5   : 040C4670BD44804AF1878FD9B05F88F1
        FixMD5     : 2A0E7E5D306F8E7063FE8120641191DA
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
    WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'FAILED_LOGIN_GROUP'
    "
    if ($res) {
        $Status = 'NotAFinding'
        #$FindingDetails = "The FAILED_LOGIN_GROUP audit is being performed."
        # 20201027 JJS Added all Results to output
        $FindingDetails = "The FAILED_LOGIN_GROUP audit is being performed.`n$($res | Format-Table -AutoSize| Out-String)"
    }
    else {
        $Status = "Open"
        $FindingDetails = "The FAILED_LOGIN_GROUP audit is not being performed."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213889 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213889
        STIG ID    : SQL4-00-037700
        Rule ID    : SV-213889r400846_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000504-DB-000354
        Rule Title : SQL Server must generate Trace or Audit records for all privileged activities or other system-level access.
        DiscussMD5 : FC6D8D572655FFA8DA7072C3D8322ED8
        CheckMD5   : CF385FC9317A21B8F5558567BF36B13C
        FixMD5     : BBE1DC2562198C001B967ABB9CE69DBE
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
                    select 'APPLICATION_ROLE_CHANGE_PASSWORD_GROUP' as audit_action_name
            union select 'AUDIT_CHANGE_GROUP'
            union select 'BACKUP_RESTORE_GROUP'
            union select 'DATABASE_CHANGE_GROUP'
            union select 'DATABASE_OBJECT_CHANGE_GROUP'
            union select 'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP'
            union select 'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP'
            union select 'DATABASE_OPERATION_GROUP'
            union select 'DATABASE_OWNERSHIP_CHANGE_GROUP'
            union select 'DATABASE_PERMISSION_CHANGE_GROUP'
            union select 'DATABASE_PRINCIPAL_CHANGE_GROUP'
            union select 'DATABASE_PRINCIPAL_IMPERSONATION_GROUP'
            union select 'DATABASE_ROLE_MEMBER_CHANGE_GROUP'
            union select 'DBCC_GROUP'
            union select 'LOGIN_CHANGE_PASSWORD_GROUP'
            union select 'SCHEMA_OBJECT_CHANGE_GROUP'
            union select 'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP'
            union select 'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP'
            union select 'SERVER_OBJECT_CHANGE_GROUP'
            union select 'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP'
            union select 'SERVER_OBJECT_PERMISSION_CHANGE_GROUP'
            union select 'SERVER_OPERATION_GROUP'
            union select 'SERVER_PERMISSION_CHANGE_GROUP'
            union select 'SERVER_PRINCIPAL_IMPERSONATION_GROUP'
            union select 'SERVER_ROLE_MEMBER_CHANGE_GROUP'
            union select 'SERVER_STATE_CHANGE_GROUP'
            union select 'TRACE_CHANGE_GROUP'
            union select 'USER_CHANGE_PASSWORD_GROUP'
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

Function Get-V213890 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213890
        STIG ID    : SQL4-00-037800
        Rule ID    : SV-213890r400846_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000504-DB-000355
        Rule Title : SQL Server must generate Trace or Audit records when unsuccessful attempts to execute privileged activities or other system-level access occur.
        DiscussMD5 : A9AE5E85350CF82794D045C9C550596B
        CheckMD5   : 99AB93668398D48567C8A1D986A2EE1F
        FixMD5     : BBE1DC2562198C001B967ABB9CE69DBE
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
                    select 'APPLICATION_ROLE_CHANGE_PASSWORD_GROUP' as audit_action_name
            union select 'AUDIT_CHANGE_GROUP'
            union select 'BACKUP_RESTORE_GROUP'
            union select 'DATABASE_CHANGE_GROUP'
            union select 'DATABASE_OBJECT_CHANGE_GROUP'
            union select 'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP'
            union select 'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP'
            union select 'DATABASE_OPERATION_GROUP'
            union select 'DATABASE_OWNERSHIP_CHANGE_GROUP'
            union select 'DATABASE_PERMISSION_CHANGE_GROUP'
            union select 'DATABASE_PRINCIPAL_CHANGE_GROUP'
            union select 'DATABASE_PRINCIPAL_IMPERSONATION_GROUP'
            union select 'DATABASE_ROLE_MEMBER_CHANGE_GROUP'
            union select 'DBCC_GROUP'
            union select 'LOGIN_CHANGE_PASSWORD_GROUP'
            union select 'LOGOUT_GROUP'
            union select 'SCHEMA_OBJECT_CHANGE_GROUP'
            union select 'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP'
            union select 'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP'
            union select 'SERVER_OBJECT_CHANGE_GROUP'
            union select 'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP'
            union select 'SERVER_OBJECT_PERMISSION_CHANGE_GROUP'
            union select 'SERVER_OPERATION_GROUP'
            union select 'SERVER_PERMISSION_CHANGE_GROUP'
            union select 'SERVER_PRINCIPAL_IMPERSONATION_GROUP'
            union select 'SERVER_ROLE_MEMBER_CHANGE_GROUP'
            union select 'SERVER_STATE_CHANGE_GROUP'
            union select 'TRACE_CHANGE_GROUP'
            union select 'USER_CHANGE_PASSWORD_GROUP'
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

Function Get-V213891 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213891
        STIG ID    : SQL4-00-037900
        Rule ID    : SV-213891r400849_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000505-DB-000352
        Rule Title : SQL Server must generate Trace or Audit records when logoffs or disconnections occur.
        DiscussMD5 : 44586DECECBD8E24FA8A22CC0C94F9BC
        CheckMD5   : 7E38D7E91023835A1DE0119665EF32D9
        FixMD5     : 092171863749C871BC0830F3D134DCD2
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
                    select 'APPLICATION_ROLE_CHANGE_PASSWORD_GROUP' as audit_action_name
            union select 'AUDIT_CHANGE_GROUP'
            union select 'BACKUP_RESTORE_GROUP'
            union select 'DATABASE_CHANGE_GROUP'
            union select 'DATABASE_OBJECT_CHANGE_GROUP'
            union select 'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP'
            union select 'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP'
            union select 'DATABASE_OPERATION_GROUP'
            union select 'DATABASE_OWNERSHIP_CHANGE_GROUP'
            union select 'DATABASE_PERMISSION_CHANGE_GROUP'
            union select 'DATABASE_PRINCIPAL_CHANGE_GROUP'
            union select 'DATABASE_PRINCIPAL_IMPERSONATION_GROUP'
            union select 'DATABASE_ROLE_MEMBER_CHANGE_GROUP'
            union select 'DBCC_GROUP'
            union select 'LOGIN_CHANGE_PASSWORD_GROUP'
            union select 'LOGOUT_GROUP'
            union select 'SCHEMA_OBJECT_CHANGE_GROUP'
            union select 'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP'
            union select 'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP'
            union select 'SERVER_OBJECT_CHANGE_GROUP'
            union select 'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP'
            union select 'SERVER_OBJECT_PERMISSION_CHANGE_GROUP'
            union select 'SERVER_OPERATION_GROUP'
            union select 'SERVER_PERMISSION_CHANGE_GROUP'
            union select 'SERVER_PRINCIPAL_IMPERSONATION_GROUP'
            union select 'SERVER_ROLE_MEMBER_CHANGE_GROUP'
            union select 'SERVER_STATE_CHANGE_GROUP'
            union select 'TRACE_CHANGE_GROUP'
            union select 'USER_CHANGE_PASSWORD_GROUP'
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

Function Get-V213892 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213892
        STIG ID    : SQL4-00-038000
        Rule ID    : SV-213892r400852_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000506-DB-000353
        Rule Title : SQL Server must generate Trace or Audit records when concurrent logons/connections by the same user from different workstations occur.
        DiscussMD5 : ED9B6AD0656843C188D0333F2D5EB1C5
        CheckMD5   : 16AAF99B39F220B3D6DE32B9A0BFEAD4
        FixMD5     : CC91273B85593C268475833C39CF700B
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
    WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SUCCESSFUL_LOGIN_GROUP'
    "
    if ($res) {
        $Status = 'NotAFinding'
        #$FindingDetails += "The SUCCESSFUL_LOGIN_GROUP audit is being performed."
        # 20201027 JJS Added all Results to output
        $FindingDetails += "The SUCCESSFUL_LOGIN_GROUP audit is being performed.`n$($res | Format-Table -AutoSize| Out-String)"

    }
    else {
        $Status = "Open"
        $FindingDetails = "DBA, the SUCCESSFUL_LOGIN_GROUP audit is not being performed. Is the instance auditing failed and successful logins?"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213894 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213894
        STIG ID    : SQL4-00-038900
        Rule ID    : SV-213894r397501_rule
        CCI ID     : CCI-000192, CCI-000193, CCI-000194, CCI-000195, CCI-000205, CCI-001619
        Rule Name  : SRG-APP-000164-DB-000401
        Rule Title : If SQL Server authentication, using passwords, is employed, SQL Server must enforce the DoD standards for password complexity.
        DiscussMD5 : 83C828BC7D49296F9579FA1A2059CBE2
        CheckMD5   : 636BFB0EDCE9AD4A73545DD95B2DD6F2
        FixMD5     : 16B235684ABF21D5F4728177D3106F3D
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
    # 20200805 JJS Changed res to ress
    $ress = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT @@servername as instance
            , name
        FROM sys.databases
        WHERE containment = 1"
    if ($ress) {
        # 20200805 JJS Changed res to ress
        #$res | foreach-object { # 20200805 JJS Rewrote
        foreach ($res in $ress) {
            # 20200805 JJS Changed to
            $res2 = Get-ISQL -ServerInstance $res.instance -Database $res.name "select name from sys.database_principals where authentication_type = 2"
            if ($res2) {
                $FindingDetails += "Database $($res.name) of instance $($res.instance) has users using SQL authentication:`n$($res2 | Format-Table -AutoSize | Out-String)"
            } # if ($res2)
        } # $res | foreach-object
        $Status = 'Open'
        if ($FindingDetails -eq '') {
            # 20201028 JJS Fixed spelling error teh to the
            $FindingDetails += "DBA, ensure the following contained databases are documented as authorized:`n$($res | Format-Table -AutoSize | Out-String)"
        } # if ($FindingDetails -eq '')
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "No contained databases were found on this instance."
    } # if ($res)
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213895 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213895
        STIG ID    : SQL4-00-038910
        Rule ID    : SV-213895r397501_rule
        CCI ID     : CCI-000198, CCI-000199, CCI-000200
        Rule Name  : SRG-APP-000164-DB-000401
        Rule Title : If SQL Server authentication, using passwords, is employed, SQL Server must enforce the DoD standards for password lifetime.
        DiscussMD5 : 485BB1CB8C2ACAE78A458CFC06116185
        CheckMD5   : 3B89D487FDF8364FE0E4B5DCC2E291F9
        FixMD5     : C0CE6BD145D7B5D40A046870038D1961
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
    $fSQLAuth = $false
    $in = Get-ISQL -ServerInstance $Instance -Database $Database "select @@servername"
    if ($in) {
        foreach ($h in $in.column1) {
            $res = Get-ISQL -ServerInstance $h "
            SELECT CASE SERVERPROPERTY('IsIntegratedSecurityOnly')
                    WHEN 1 THEN 'Windows Authentication'
                    WHEN 0 THEN 'SQL Server Authentication'
                END as AuthMode"
            if ($res.AuthMode -eq 'SQL Server Authentication') {
                $fSQLAuth = $true
                Get-ISQL -ServerInstance $h "
            select name LoginName, is_expiration_checked, is_policy_checked
                FROM sys.sql_logins
            where name not in ('Sandman','##MS_PolicyTsqlExecutionLogin##','##MS_PolicyEventProcessingLogin##')
                and 0 in (is_expiration_checked, is_policy_checked)
            " | ForEach-Object {
                    if ($_.is_expiration_checked -eq 0) {
                        #$FindingDetails += "Login $($_.LoginName) on instance $h does not have expiration checked.`n"
                        # 20201027 JJS Added all Results to output
                        $FindingDetails += "Login $($_.LoginName) on instance $h does not have expiration checked.`n$($_ | Format-Table -AutoSize| Out-String)"
                    }
                    if ($_.is_policy_checked -eq 0) {
                        #$FindingDetails += "Login $($_.LoginName) on instance $h does not have a password policy check.`n"
                        # 20201027 JJS Added all Results to output
                        $FindingDetails += "Login $($_.LoginName) on instance $h does not have a password policy check.`n$($_ | Format-Table -AutoSize| Out-String)"
                    }
                } # Get-ISQL -ServerInstance $Instance -Database $Database ... foreach-object
            } # if ($res.AuthenticationMod -eq 'SQL Server Authentication')
        } # foreach ($h in $in.column1)
        if ($FindingDetails -gt '') {
            $Status = 'Open'
        }
        else {
            if ($fSQLAuth) {
                $Status = "Open"
                $FindingDetails = "SQL Server Authentication is being used. The accounts are set properly for password complexity and expiration. The STIG asks that local policy be checked that complexity rules are being enforced."
            }
            else {
                $Status = "NotAFinding"
                $FindingDetails = "Windows authentication is being used."
            } # if ($fSQLAuth)
        } # if ($FindingDetails -gt '')
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "No active SQL instances currently exist on this host."
    } # if ($in)
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213897 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213897
        STIG ID    : SQL4-00-039020
        Rule ID    : SV-213897r397603_rule
        CCI ID     : CCI-000206
        Rule Name  : SRG-APP-000178-DB-000083
        Rule Title : When using command-line tools such as SQLCMD in a mixed-mode authentication environment, users must use a logon method that does not expose the password.
        DiscussMD5 : 70CB57DE6C0D76A13EEFC565DE4E82DF
        CheckMD5   : 2AC06085EEB097A4A4AD1822B3E23EE1
        FixMD5     : 910263D603463E59EC44A101FF7A2DA5
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
    $in = Get-ISQL -ServerInstance $Instance -Database $Database "select @@servername"
    if ($in) {
        foreach ($h in $in.column1) {
            $res = Get-ISQL -ServerInstance $h "EXEC master.sys.XP_LOGINCONFIG 'login mode'"
            if ($res.config_value -ne 'Windows NT Authentication') {
                $Status = "Open"
                $FindingDetails += "Instance $h's login authention mode is $($res.config_value) instead of Windows Authentication.`n"
            }
        } # foreach
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "No active SQL instances currently exist on this host."
    }
    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "Windows NT Authentication is being used."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213898 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213898
        STIG ID    : SQL4-00-039100
        Rule ID    : SV-213898r401224_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-DB-000363
        Rule Title : The SQL Server Browser service must be disabled if its use is not necessary..
        DiscussMD5 : 7F2B5C79D86E3859AB596E26B9A3A2C2
        CheckMD5   : 0741FDEA64FC6C947694F069391F8DA7
        FixMD5     : 6AA719BFC7850F665DFA451E06521AAE
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
    $res = Get-Service SQLBrowser
    if ($res) {
        if ($res.StartType -eq 'Disabled') {
            $Status = "NotAFinding"
            # 20201027 JJS Added all Results to output
            $FindingDetails = "The SQL Browser is disabled.`n$($res | Format-Table -AutoSize| Out-String)"
        }
        else {
            $Status = "Open"
            # 20201027 JJS Added all Results to output
            $FindingDetails = "The SQL Browser service is not disabled, but if it has been documented and approved as required, this is not a finding.`n$($res | Format-Table -AutoSize| Out-String)"
        } # if ($res.StartType -eq 'Disabled')
    }
    else {
        $Status = "Open"
        $FindingDetails = "Could not find the SQL Browser service."
    } # if ($res)
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAJOMtqfpmcWz92
# M5Ce4TbpkvpdLs2wDuTXyWHIo20c26CCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCD3EWZDsF/sbyLIeETFNaX+ciLJef7z
# FDHaZE8oSwH0RjANBgkqhkiG9w0BAQEFAASCAQCC9QEDLPp0SQuNa8sxjWhYsMsB
# NHCVrDfbZ2DGBWkFKvVfj8wBgpDPvWLgXdsQZssLl+NpDq5OU+tQtUyPpgaWsnUL
# 1hubWezkMisPkZPGufR0nG0cD3f5Ln2adOYl17ZmQMYLTdbyvE5pgvq+RW4qm6mD
# 127Wxc8alh0XpKnCKA6d3mZGkrPWCpBXIDTrolLNTlH3UlBL1xdXrpRaYN4ayaSr
# 148sl9rL2XJSfkZWnf1ECAcStYoEH9VRuowxBEaE6kFQ3cZ9IgXUfB3q7BCX25kw
# USI8C8xka9wIEU1RP3ajk2l7fSSZ2uBYGsfKgicDTBKZt/dzGUYUsqpWPTZI
# SIG # End signature block
