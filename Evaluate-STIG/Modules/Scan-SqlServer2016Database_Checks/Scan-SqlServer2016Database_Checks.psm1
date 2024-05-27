##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     MS SQL Server 2016 Database
# Version:  V2R9
# Class:    UNCLASSIFIED
# Updated:  5/13/2024
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V213900 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213900
        STIG ID    : SQL6-D0-000100
        Rule ID    : SV-213900r929096_rule
        CCI ID     : CCI-000015
        Rule Name  : SRG-APP-000023-DB-000001
        Rule Title : SQL Server databases must integrate with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.
        DiscussMD5 : 7FC4C2C0F6D9636B40A83E1363B6210C
        CheckMD5   : 66F3EB77F2B4834E2A19004864C31ECD
        FixMD5     : 47D9DE68DEB3FA4318AFDF1C2FBCB7EB
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
    # Check for contained databases:
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "EXEC sp_configure 'contained database authentication'"
    if ($res.run_value -eq 1 -or $res.config_value -eq 1) {
        $FindingDetails += "Instance $h is using contained database authentication.`n"
        $status = 'Open'
    }

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
      SELECT CASE SERVERPROPERTY('IsIntegratedSecurityOnly')
               WHEN 1 THEN 'Windows Authentication'
               WHEN 0 THEN 'Windows and SQL Server Authentication'
            END as AuthenticationMode
    "
    if ($res.AuthenticationMode -ne 'Windows Authentication') {
        $FindingDetails += "The instance allows Mixed Authentication. Confirm this is documented as necessary and approved by the ISSO/ISSM.`n"
    }

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
      select @@servername, name
        from sys.database_principals
       WHERE type_desc = 'SQL_USER'
         AND authentication_type_desc = 'DATABASE'
    "
    if ($res) {
        $FindingDetails += "DBA, ensure the following accounts are documented as authorized to be managed by SQL Server:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "Contained database authentication is not used.`nMixed authentication mod is not used.`nNo database-managed accounts exist."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213901 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213901
        STIG ID    : SQL6-D0-000300
        Rule ID    : SV-213901r879530_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-DB-000084
        Rule Title : SQL Server must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.
        DiscussMD5 : 7DF88A644477D5202A9EEEAB5D2F9640
        CheckMD5   : 08A03698F7CB8B68B9F44B1261D6C613
        FixMD5     : 34E7EF8E07AB1BF83551B1C9B9947C55
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
    If ($Database -eq "tempdb") {
        $Status = "Not_Applicable"
        $FindingDetails += "This is the '$Database' database so this requirement is NA."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213902 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213902
        STIG ID    : SQL6-D0-000400
        Rule ID    : SV-213902r944379_rule
        CCI ID     : CCI-000166
        Rule Name  : SRG-APP-000080-DB-000063
        Rule Title : SQL Server must protect against a user falsely repudiating by ensuring only clearly unique Active Directory user accounts can connect to the database.
        DiscussMD5 : 65D29485673D50AB20BF56A9FE981C15
        CheckMD5   : 489BEA7B6637CBFA62B505A924157D1C
        FixMD5     : 8B9142449F0FC17EB620EFC3E8D4C177
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
    $fComputer = $fUnknown = $false
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT name as UserName
          FROM sys.database_principals
         WHERE type in ('U','G')
           AND name LIKE '%$'
    "
    if ($res) {
        $outarray = @()
        $res | ForEach-Object {
            $sUID = $_.username
            $sShortUID = $sUID -replace '^.*\\', '' -replace '\$$', ''

            try {
                $sType = ([ADSISearcher]"(name=${sShortUID})").findone().Properties['ObjectCategory'].item(0) -replace ',.*$', '' -replace '^CN=', ''
            }
            catch {
                $sType = ''
            }
            if ($sType) {
                $outarray += [pscustomobject]@{Name = $sUID; ADType = $sType}
                if ($stype -eq 'Computer') {
                    $fComputer = $true
                }
            }
            else {
                $outarray += [pscustomobject]@{name = $sUID; ADType = 'Indeterminable, needs analyst review'}
                $fUnknown = $true
            }
        }

        $FindingDetails = "The following accounts were found in SQL and checked against AD:`n$($outarray | Format-Table -HideTableHeaders -AutoSize| Out-String)"
        if ($fUnknown) {
            $FindingDetails += "At least one account NEEDS REVIEWED."
            $Status = "Not_Reviewed"
        }
        elseif ($fComputer) {
            $FindingDetails += "OPEN because at least one computer account was found."
            $Status = "Open"
        }
        else {
            $FindingDetails += "NOT A FINDING: No computer accounts were found."
            $Status = "NotAFinding"
        }
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "NOT A FINDING: The check query returned no results."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213903 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213903
        STIG ID    : SQL6-D0-000500
        Rule ID    : SV-213903r879554_rule
        CCI ID     : CCI-000166
        Rule Name  : SRG-APP-000080-DB-000063
        Rule Title : SQL Server must protect against a user falsely repudiating by use of system-versioned tables (Temporal Tables).
        DiscussMD5 : 7441CAD39A3A04034F8B9DC32ED8C37C
        CheckMD5   : 6D96FD5E6353E1162A4926F88C14802A
        FixMD5     : 04D7D8FBD50CAEE7D6E9EBBD24D5A3B4
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
        SELECT SCHEMA_NAME(T.schema_id) AS schema_name, T.name AS table_name, T.temporal_type_desc, SCHEMA_NAME(H.schema_id) + '.' + H.name AS history_table
        FROM sys.tables T
        JOIN sys.tables H ON T.history_table_id = H.object_id
        WHERE T.temporal_type != 0
        ORDER BY schema_name, table_name
    "
    $FindingDetails += "DBA, Using the system documentation, determine which tables in this database are required to be temporal tables.`n`n"
    if ($res) {
        $FindingDetails += "If any tables listed in the documentation are not in this list, this is a finding.:`n$($res | Format-Table -AutoSize| Out-String)"
    } else {
        $FindingDetails += "If the documentation lists any tables at all, mark this vulnerability as a finding because no such tables exist."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213904 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213904
        STIG ID    : SQL6-D0-000600
        Rule ID    : SV-213904r944381_rule
        CCI ID     : CCI-000166
        Rule Name  : SRG-APP-000080-DB-000063
        Rule Title : SQL Server must protect against a user falsely repudiating by ensuring databases are not in a trust relationship.
        DiscussMD5 : EF61961F0A45A02D8F40A7DC7D4463F8
        CheckMD5   : 22CC6947EBA9D7403460DD0A7E56BB6B
        FixMD5     : D3E964A7163F4E4CB7761773B7790EC3
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
        SELECT @@SERVERNAME               as InstanceName
            , DB_NAME()                  AS [Database]
            , SUSER_SNAME(d.owner_sid)   AS DatabaseOwner
            , CASE
                WHEN role.name IN ('sysadmin','securityadmin')
                OR permission.permission_name = 'CONTROL SERVER'
                THEN 'YES'
                ELSE 'No'
            END AS 'IsOwnerPrivileged'
        FROM sys.databases d
        LEFT JOIN sys.server_principals login ON d.owner_sid = login.sid
        LEFT JOIN sys.server_role_members rm ON login.principal_id = rm.member_principal_id
        LEFT JOIN sys.server_principals role ON rm.role_principal_id = role.principal_id
        LEFT JOIN sys.server_permissions permission ON login.principal_id = permission.grantee_principal_id
        WHERE d.name = DB_NAME()
        AND DB_NAME() <> 'msdb'
        AND D.is_trustworthy_on = 1
    "
    if (!$res) {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check query."
    }
    else {
        $FindingDetails = "DBA, Confirm that an approved server documentation documents the need for TRUSTWORTHY in the following:$($res | Format-Table | Out-String)"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213905 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213905
        STIG ID    : SQL6-D0-000700
        Rule ID    : SV-213905r879560_rule
        CCI ID     : CCI-000171
        Rule Name  : SRG-APP-000090-DB-000065
        Rule Title : SQL Server must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.
        DiscussMD5 : 399867828DF606C19B45A8014399DEE3
        CheckMD5   : ED8D4962CDD3D8045AD1D17B2B283C3E
        FixMD5     : 6CEAE3AF9B65200A1B70608302D3FC2C
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
    # Check for accounts with the db_owner role...
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT
        R.name AS role_name,
        RM.name AS role_member_name,
        RM.type_desc
        FROM sys.database_principals R
        JOIN sys.database_role_members DRM ON
        R.principal_id = DRM.role_principal_id
        JOIN sys.database_principals RM ON
        DRM.member_principal_id = RM.principal_id
        WHERE R.type = 'R'
        AND R.name = 'db_owner'
        ORDER BY role_member_name
    " | Sort-Object -Unique role_member_name
    if ($res) {
        if ($res.role_name.count -eq 1 -and $res.role_member_name -eq 'dbo') {
            $FindingDetails = "The only account authorized to act as a db owner is 'dbo', but DISA still requires it be documented as authorized:`n$($res | Format-Table | Out-String)"
        }
        else {
            $FindingDetails = "DBA, Confirm that the following accounts are documented as authorized to act as database owners:`n$($res | Format-Table | Out-String)"
        }
    } # if ($res)

    # Check for accounts with the CONTROL or ALTER ANY DATABASE AUDIT privileges...
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT
        PERM.permission_name,
        DP.name AS principal_name,
        DP.type_desc AS principal_type,
        DBRM.role_member_name
        FROM sys.database_permissions PERM
        JOIN sys.database_principals DP ON PERM.grantee_principal_id = DP.principal_id
        LEFT OUTER JOIN (
        SELECT
        R.principal_id AS role_principal_id,
        R.name AS role_name,
        RM.name AS role_member_name
        FROM sys.database_principals R
        JOIN sys.database_role_members DRM ON R.principal_id = DRM.role_principal_id
        JOIN sys.database_principals RM ON DRM.member_principal_id = RM.principal_id
        WHERE R.type = 'R'
        ) DBRM ON DP.principal_id = DBRM.role_principal_id
        WHERE PERM.permission_name IN ('CONTROL','ALTER ANY DATABASE AUDIT')
        ORDER BY
        permission_name,
        principal_name,
        role_member_name
    " | Sort-Object -Unique permission_name, principal_name, role_member_name
    if ($res) {
        if ($res.permission_name.count -eq 1) {
            $FindingDetails += "DBA, Confirm that the following account is documented as authorized to administer audits:`n$($res | Format-Table | Out-String)"
        }
        else {
            $FindingDetails += "DBA, Confirm that the following accounts are documented as authorized to administer audits:`n$($res | Format-Table | Out-String)"
        }
    } # if ($res)

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

Function Get-V213906 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213906
        STIG ID    : SQL6-D0-001100
        Rule ID    : SV-213906r879586_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000179
        Rule Title : SQL Server must limit privileges to change software modules, to include stored procedures, functions, and triggers.
        DiscussMD5 : 39B6782765F128EC0472D2F036E28EA9
        CheckMD5   : 2513A93FF04F36CC007391EB3B946EB5
        FixMD5     : F6BACF21AD37E05EDCE860A7854E1131
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
            END AS securable_name, DP.state_desc, DP.permission_name
        FROM sys.database_permissions DP
            JOIN sys.database_principals P ON DP.grantee_principal_id = P.principal_id
            LEFT OUTER JOIN sys.all_objects O ON O.object_id = DP.major_id
                AND O.type IN ('TR','TA','P','X','RF','PC','IF','FN','TF','U')
        WHERE DP.type IN ('AL','ALTG') AND DP.class IN (0, 1, 53)
    "
    if ($res) {
        $FindingDetails += "DBA, ensure the following accounts are authorized in the server documentation to change procedures, functions and triggers:`n$($res | Format-Table -AutoSize| Out-String)"
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
        WHERE R.name IN ('db_ddladmin','db_owner')
            AND M.name != 'dbo'
    "
    if ($res) {
        if ($FindingDetails -eq "") {
            #If the second query is the only query to return results, add the message to the DBA.
            $FindingDetails += "DBA, ensure the following accounts are authorized in the server documentation to change procedures, functions and triggers:`n"
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

Function Get-V213907 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213907
        STIG ID    : SQL6-D0-001200
        Rule ID    : SV-213907r879586_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000179
        Rule Title : SQL Server must limit privileges to change software modules, to include stored procedures, functions, and triggers, and links to software external to SQL Server.
        DiscussMD5 : 39B6782765F128EC0472D2F036E28EA9
        CheckMD5   : 4452EFC1E53D9B375346AE45ED37710A
        FixMD5     : 2B76A81FC685ACBD10A9D4BEDDD3884B
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
        with approvedschemas as (
        select 'db_accessadmin' as schema_name , 'db_accessadmin' as owning_principal
        union all select 'db_backupoperator'   , 'db_backupoperator'
        union all select 'db_datareader'       , 'db_datareader'
        union all select 'db_datawriter'       , 'db_datawriter'
        union all select 'db_ddladmin'         , 'db_ddladmin'
        union all select 'db_denydatareader'   , 'db_denydatareader'
        union all select 'db_denydatawriter'   , 'db_denydatawriter'
        union all select 'db_owner'            , 'db_owner'
        union all select 'db_securityadmin'    , 'db_securityadmin'
        union all select 'guest'               , 'guest'
        union all select 'INFORMATION_SCHEMA'  , 'INFORMATION_SCHEMA'
        union all select 'sys'                 , 'sys'
        union all select 'TargetServersRole'   , 'TargetServersRole'
        union all select 'SQLAgentUserRole'    , 'SQLAgentUserRole'
        union all select 'SQLAgentReaderRole'  , 'SQLAgentReaderRole'
        union all select 'SQLAgentOperatorRole', 'SQLAgentOperatorRole'
        union all select 'DatabaseMailUserRole', 'DatabaseMailUserRole'
        union all select 'db_ssisadmin'        , 'db_ssisadmin'
        union all select 'db_ssisltduser'      , 'db_ssisltduser'
        union all select 'db_ssisoperator'     , 'db_ssisoperator'
        union all select 'replmonitor', 'replmonitor'
        union all select '##MS_SSISServerCleanupJobLogin##', '##MS_SSISServerCleanupJobLogin##'
        )
        select @@servername as instance, db_name() as databasename
            , S.name AS schema_name
            , P.name AS owning_principal
        FROM sys.schemas S
        JOIN sys.database_principals P ON S.principal_id = P.principal_id
        where p.name != 'dbo'
        except
        select @@servername as instance, db_name() as databasename, schema_name, owning_principal
        from approvedschemas
    "
    if ($res) {
    # Per #304 return NR in case server documentation supports the settings
    # $Status = 'Open'
        $FindingDetails += "DBA, ensure the following principals are authorized in the server documentation to own schemas:`n$($res | Format-Table -AutoSize| Out-String)"
    }
    else {

        $Status = "NotAFinding"
        $FindingDetails = "No principals other than the standard MSSQL principals own database schemas."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213908 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213908
        STIG ID    : SQL6-D0-001300
        Rule ID    : SV-213908r879586_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000200
        Rule Title : Database objects (including but not limited to tables, indexes, storage, stored procedures, functions, triggers, links to software external to SQL Server, etc.) must be owned by database/DBMS principals authorized for ownership.
        DiscussMD5 : 8B9C1DDE3BEE6081210CCE4DA6722CF5
        CheckMD5   : D44CBE32042C5E36D44A45F51C0EEA6E
        FixMD5     : 40520C2C65EF62295706838A0B750DFB
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
    # Check for accounts with the db_owner role...
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        ;with objects_cte as
        (SELECT o.name, o.type_desc,
        CASE
        WHEN o.principal_id is null then s.principal_id
        ELSE o.principal_id
        END as principal_id
        FROM sys.objects o
        INNER JOIN sys.schemas s
        ON o.schema_id = s.schema_id
        WHERE o.is_ms_shipped = 0
        )
        SELECT cte.name, cte.type_desc, dp.name as ObjectOwner
        FROM objects_cte cte
        INNER JOIN sys.database_principals dp
        ON cte.principal_id = dp.principal_id
        where dp.name != 'dbo'
        ORDER BY dp.name, cte.name
    " | Where-Object ObjectOwner -NE 'dbo'
    if ($res) {
        $FindingDetails += "DBA, Confirm that an approved server documentation documents the following accounts as authorized to own database objects:`n$($res | Format-Table | Out-String)"
    }

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check query."
    }
    else {
        #$Status = "Open"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213909 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213909
        STIG ID    : SQL6-D0-001400
        Rule ID    : SV-213909r879586_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000362
        Rule Title : The role(s)/group(s) used to modify database structure (including but not necessarily limited to tables, indexes, storage, etc.) and logic modules (stored procedures, functions, triggers, links to software external to SQL Server, etc.) must be restricted to authorized users.
        DiscussMD5 : 978959640256E1378015BF8DB91A4E1E
        CheckMD5   : 2087000BE0DDCC381BA9B432628FC5A2
        FixMD5     : 52E96BE4F6968CFE0C8A49E5EFE7CBE7
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
        # Per #304 return NR in case server documentation supports the settings
        # $Status = 'Open'
        $FindingDetails += "DBA, ensure the following accounts are authorized in the server documentation to modify objects:`n$($res | Format-Table -AutoSize| Out-String)"
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
            # Per #304 return NR in case server documentation supports the settings
            # $Status = 'Open'
            $FindingDetails += "DBA, ensure the following accounts are authorized in the server documentation to modify objects:`n"
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

Function Get-V213910 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213910
        STIG ID    : SQL6-D0-001500
        Rule ID    : SV-213910r879641_rule
        CCI ID     : CCI-001665
        Rule Name  : SRG-APP-000226-DB-000147
        Rule Title : In the event of a system failure, hardware loss or disk failure, SQL Server must be able to restore necessary databases with least disruption to mission processes.
        DiscussMD5 : D3A0EFF900E4D54CB29E4136BC37B021
        CheckMD5   : DAEEB41AD29C9023BCB9A2C9DBFD5C94
        FixMD5     : B8F652DC1E84DBF27B62D6F60ADB3826
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
        USE [master]
        GO
        SELECT name, recovery_model_desc
        FROM sys.databases
        WHERE name = '$($Database)'
        ORDER BY name
    "

    $FindingDetails += "DBA, Using the system documentation, confirm, the following recovery models."
    if ($res) {
        $FindingDetails += "If the recovery model description does not match the documented recovery model, this is a finding.:`n$($res | Format-Table -AutoSize| Out-String)"
    } else {
        $FindingDetails += "No results were returned by the recovery model check query."
    }

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        USE [msdb]
        GO
        SELECT database_name,
        CASE type
        WHEN 'D' THEN 'Full'
        WHEN 'I' THEN 'Differential'
        WHEN 'L' THEN 'Log'
        ELSE type
        END AS backup_type,
        is_copy_only,backup_start_date, backup_finish_date
        FROM dbo.backupset
        WHERE (backup_start_date >= dateadd(day, - 30, getdate())) AND
        (database_name = '$($Database)')
        ORDER BY database_name, backup_start_date DESC
    "

    $FindingDetails += "DBA, Review the jobs set up to implement the backup plan. If they are absent, this is a finding.`n"
    if ($res) {
        $FindingDetails += "Jobs set up to implement the backup plan:`n$($res | Format-Table -AutoSize| Out-String)"
    } else {
#       $Status = 'Open'  <--------------------- remove this line
        $FindingDetails += "No results were returned by the backup plan check query."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213911 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213911
        STIG ID    : SQL6-D0-001600
        Rule ID    : SV-213911r879642_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231-DB-000154
        Rule Title : The Database Master Key encryption password must meet DOD password complexity requirements.
        DiscussMD5 : 6DB1720E47256E1D39E45A10BEB1F948
        CheckMD5   : 8FF290AA00A14E9728234B7B20EF516B
        FixMD5     : 4D5F529F01B53EFEFCFD26046322E8A2
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
            , db_name() as DatabaseName
            , COUNT(name)  keycount
    FROM sys.symmetric_keys s, sys.key_encryptions k
    WHERE s.name = '##MS_DatabaseMasterKey##'
    AND s.symmetric_key_id = k.key_id
    AND k.crypt_type in ('ESKP', 'ESP2', 'ESP3')"
    if ($res) {
        $res2 = $res | Where-Object keycount -GT 0
        if ($res2) {
            $FindingDetails = "Review procedures and evidence of password requirements used to encrypt the following Database Master Keys:`n$($res2 | Format-Table -AutoSize| Out-String)"
#           $Status = 'Open'   <---- This line needs removed from Scan-SqlServer2016Database_Checks.psm1
        }
    }
    if ($FindingDetails -eq "") {
        $Status = "Not_Applicable"
        $FindingDetails = "No database master keys exist."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213912 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213912
        STIG ID    : SQL6-D0-001700
        Rule ID    : SV-213912r879642_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231-DB-000154
        Rule Title : The Database Master Key must be encrypted by the Service Master Key, where a Database Master Key is required and another encryption method has not been specified.
        DiscussMD5 : E20E1D2CC9839DC27B64F09DFB76F6DD
        CheckMD5   : 25A67476861EB638F52679DCFD298620
        FixMD5     : CFDA680ABB86823956A93B86BDD4C75B
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
        $FindingDetails += "DBA, ensure the server documentation has approved the encryption of these database master keys using the service master keys:`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213914 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213914
        STIG ID    : SQL6-D0-001900
        Rule ID    : SV-213914r879643_rule
        CCI ID     : CCI-001084
        Rule Name  : SRG-APP-000233-DB-000124
        Rule Title : SQL Server must isolate security functions from non-security functions.
        DiscussMD5 : 3C4897D983873B453A50F0FC5F362181
        CheckMD5   : 1452CEE7916954A9AC8F77A1EEEC5810
        FixMD5     : 8EB21B5D5DF9FEC31B9EF3B9A0EB3E38
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
    #master, msdb, model, tempdb
    $DefaultDatabases = "master, msdb, model, tempdb"
    If ($DefaultDatabases.IndexOf($Database) -ne -1) {
        $Status = "Not_Applicable"
        $FindingDetails += "This is the '$Database' database so this requirement is NA."
    } else {
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        USE [master]
        GO
        SELECT Name
        FROM sys.databases
        WHERE (database_id > 4) AND
        ( name = '$($Database)')
        ORDER BY 1;
        "
        # ( name = ' - $Database - ')
        # "$($assoc.Id) - $($assoc.Name) - $($assoc.Owner)"
        if ($res) {
            $FindingDetails += "DBA, Review the database structure to determine where security related functionality is stored.`n If security-related database objects or code are not kept separate, this is a finding:`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213918 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213918
        STIG ID    : SQL6-D0-002500
        Rule ID    : SV-213918r879689_rule
        CCI ID     : CCI-002262
        Rule Name  : SRG-APP-000311-DB-000308
        Rule Title : SQL Server must associate organization-defined types of security labels having organization-defined security label values with information in storage.
        DiscussMD5 : 3F0C4A4681CEFCCB6281795EA4C61B36
        CheckMD5   : B193BB17CF9A2B56073ED23828F79ECD
        FixMD5     : C1F5D2371A244B7B709D6D59F4E32F9F
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
    #master, msdb, model, tempdb
    $DefaultDatabases = "master, msdb, model, tempdb"
    If ($DefaultDatabases.IndexOf($Database) -ne -1) {
        $Status = "NotAFinding"
        $FindingDetails += "This is the '$Database' database so per STIG Support modifying the default databases not required nor recommended.  For the default databases this check is an automatic 'Not A Finding'"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213919 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213919
        STIG ID    : SQL6-D0-002600
        Rule ID    : SV-213919r879690_rule
        CCI ID     : CCI-002263
        Rule Name  : SRG-APP-000313-DB-000309
        Rule Title : SQL Server must associate organization-defined types of security labels having organization-defined security label values with information in process.
        DiscussMD5 : 27AE610739A6ECCC98A928FD913C5CE9
        CheckMD5   : F35188C0168F570BA3C5F104647D925A
        FixMD5     : 8F8187CB697CAAAE56DCA803B3B3FB5F
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
    #master, msdb, model, tempdb
    $DefaultDatabases = "master, msdb, model, tempdb"
    If ($DefaultDatabases.IndexOf($Database) -ne -1) {
        $Status = "NotAFinding"
        $FindingDetails += "This is the '$Database' database so per STIG Support modifying the default databases not required nor recommended.  For the default databases this check is an automatic 'Not A Finding'"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213920 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213920
        STIG ID    : SQL6-D0-002700
        Rule ID    : SV-213920r879691_rule
        CCI ID     : CCI-002264
        Rule Name  : SRG-APP-000314-DB-000310
        Rule Title : SQL Server must associate organization-defined types of security labels having organization-defined security label values with information in transmission.
        DiscussMD5 : 849F4CA5E2D05A3277EB6F43B07AC3B0
        CheckMD5   : 546C833914D0138D4FBE0E9E9D24A11D
        FixMD5     : 41D1DDDB6C0BA366F9049F3D0C1B0EC8
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
    #master, msdb, model, tempdb
    $DefaultDatabases = "master, msdb, model, tempdb"
    If ($DefaultDatabases.IndexOf($Database) -ne -1) {
        $Status = "NotAFinding"
        $FindingDetails += "This is the '$Database' database so per STIG Support modifying the default databases not required nor recommended.  For the default databases this check is an automatic 'Not A Finding'"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213921 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213921
        STIG ID    : SQL6-D0-002800
        Rule ID    : SV-213921r879705_rule
        CCI ID     : CCI-002165
        Rule Name  : SRG-APP-000328-DB-000301
        Rule Title : SQL Server must enforce discretionary access control policies, as defined by the data owner, over defined subjects and objects.
        DiscussMD5 : 597921AC57B1918582E4F7C64889A15B
        CheckMD5   : 8940CDE89ACD7C09A1DABA4DE6007B38
        FixMD5     : 4E66F0FEEE6B81F36689123D9B6EE437
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
            , name AS schema_name
            , USER_NAME(principal_id) AS schema_owner
        FROM sys.schemas
        WHERE schema_id != principal_id
        AND principal_id != 1
    "
    if ($res) {
        #$Status = 'Open'
        $FindingDetails += "DBA, ensure the following accounts are authorized in the server documentation to own schemas:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT @@servername as instance
            , db_name() as databasename
            , object_id
            , name AS securable
            , USER_NAME(principal_id) AS object_owner
            , type_desc
        FROM sys.objects
        WHERE is_ms_shipped = 0 AND principal_id IS NOT NULL
        ORDER BY type_desc, securable, object_owner
    "
    if ($res) {
        if ($FindingDetails -eq "") {
            #$Status = 'Open'
            $FindingDetails += "DBA, ensure the following accounts are authorized in the server documentation to own objects:`n"
        }
        $FindingDetails += $($res | Format-Table -AutoSize | Out-String)
    } # if ($res)

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT @@servername as instance
            , db_name() as databasename
            , U.type_desc
            , U.name AS grantee
            , DP.class_desc AS securable_type
            , CASE DP.class
                WHEN 0 THEN DB_NAME()
                WHEN 1 THEN OBJECT_NAME(DP.major_id)
                WHEN 3 THEN SCHEMA_NAME(DP.major_id)
                ELSE CAST(DP.major_id AS nvarchar)
            END AS securable
            , permission_name
            , state_desc
        FROM sys.database_permissions DP
        JOIN sys.database_principals U ON DP.grantee_principal_id = U.principal_id
        WHERE DP.state = 'W'
        ORDER BY grantee, securable_type, securable
    "
    if ($res) {
        if ($FindingDetails -eq "") {
            #$Status = 'Open'
            $FindingDetails += "DBA, ensure the following accounts are authorized in the server documentation to assig additional permissions:`n"
        }
        $FindingDetails += $($res | Format-Table -AutoSize | Out-String)
    } # if ($res)

    if ($FindingDetails -eq "") {
    # jpb
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

Function Get-V213922 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213922
        STIG ID    : SQL6-D0-002900
        Rule ID    : SV-213922r879719_rule
        CCI ID     : CCI-002233
        Rule Name  : SRG-APP-000342-DB-000302
        Rule Title : Execution of stored procedures and functions that utilize execute as must be restricted to necessary cases only.
        DiscussMD5 : 5D7FC57D87D2245548BC6AC3C58C0621
        CheckMD5   : 6EA16EBC32CE7C95CAD5310D98261BFF
        FixMD5     : A2B2D7210B1E1372F49B47F1DF9616F2
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
            , S.name AS schema_name
            , O.name AS module_name
            , USER_NAME(
                CASE M.execute_as_principal_id
                WHEN -2 THEN COALESCE(O.principal_id, S.principal_id)
                ELSE M.execute_as_principal_id
                END
            ) AS execute_as
        FROM sys.sql_modules M
        JOIN sys.objects O ON M.object_id = O.object_id
        JOIN sys.schemas S ON O.schema_id = S.schema_id
        WHERE execute_as_principal_id IS NOT NULL
        and o.name not in (
                'fn_sysdac_get_username',
                'fn_sysutility_ucp_get_instance_is_mi',
                'sp_send_dbmail',
                'sp_SendMailMessage',
                'sp_syscollector_create_collection_set',
                'sp_syscollector_delete_collection_set',
                'sp_syscollector_disable_collector',
                'sp_syscollector_enable_collector',
                'sp_syscollector_get_collection_set_execution_status',
                'sp_syscollector_run_collection_set',
                'sp_syscollector_start_collection_set',
                'sp_syscollector_update_collection_set',
                'sp_syscollector_upload_collection_set',
                'sp_syscollector_verify_collector_state',
                'sp_syspolicy_add_policy',
                'sp_syspolicy_add_policy_category_subscription',
                'sp_syspolicy_delete_policy',
                'sp_syspolicy_delete_policy_category_subscription',
                'sp_syspolicy_update_policy',
                'sp_sysutility_mi_add_ucp_registration',
                'sp_sysutility_mi_disable_collection',
                'sp_sysutility_mi_enroll',
                'sp_sysutility_mi_initialize_collection',
                'sp_sysutility_mi_remove',
                'sp_sysutility_mi_remove_ucp_registration',
                'sp_sysutility_mi_upload',
                'sp_sysutility_mi_validate_enrollment_preconditions',
                'sp_sysutility_ucp_add_mi',
                'sp_sysutility_ucp_add_policy',
                'sp_sysutility_ucp_calculate_aggregated_dac_health',
                'sp_sysutility_ucp_calculate_aggregated_mi_health',
                'sp_sysutility_ucp_calculate_computer_health',
                'sp_sysutility_ucp_calculate_dac_file_space_health',
                'sp_sysutility_ucp_calculate_dac_health',
                'sp_sysutility_ucp_calculate_filegroups_with_policy_violations',
                'sp_sysutility_ucp_calculate_health',
                'sp_sysutility_ucp_calculate_mi_file_space_health',
                'sp_sysutility_ucp_calculate_mi_health',
                'sp_sysutility_ucp_configure_policies',
                'sp_sysutility_ucp_create',
                'sp_sysutility_ucp_delete_policy',
                'sp_sysutility_ucp_delete_policy_history',
                'sp_sysutility_ucp_get_policy_violations',
                'sp_sysutility_ucp_initialize',
                'sp_sysutility_ucp_initialize_mdw',
                'sp_sysutility_ucp_remove_mi',
                'sp_sysutility_ucp_update_policy',
                'sp_sysutility_ucp_update_utility_configuration',
                'sp_sysutility_ucp_validate_prerequisites',
                'sp_validate_user',
                'syscollector_collection_set_is_running_update_trigger',
                'sysmail_help_status_sp'
            )
        ORDER BY schema_name, module_name
    "
    if ($res) {
        #$Status = 'Open'
        $FindingDetails += "DBA, ensure the following SQL modules are authorized in the server documentation to utilize impersonation:`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213923 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213923
        STIG ID    : SQL6-D0-003000
        Rule ID    : SV-213923r879751_rule
        CCI ID     : CCI-001812
        Rule Name  : SRG-APP-000378-DB-000365
        Rule Title : SQL Server must prohibit user installation of logic modules (stored procedures, functions, triggers, views, etc.) without explicit privileged status.
        DiscussMD5 : A10E25C5B0277C15A1E402A97C2A4803
        CheckMD5   : 8A507789DFA3B946823542C1D1F0787C
        FixMD5     : 9F57EDEEC968C2C2D8E9FF4429F35530
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
        #$Status = 'Open'
        $FindingDetails += "DBA, ensure the following principals are authorized in the server documentation to modify the specified object or type:`n$($res | Format-Table -AutoSize| Out-String)"
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
        WHERE R.name IN ('db_ddladmin','db_owner')
        AND M.name != 'dbo'
    "
    if ($res) {
        if ($FindingDetails -eq "") {
            #$Status = 'Open'
            $FindingDetails += "DBA, ensure the following user/role memberships are authorized in the server documentation:`n"
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

Function Get-V213924 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213924
        STIG ID    : SQL6-D0-003100
        Rule ID    : SV-213924r879753_rule
        CCI ID     : CCI-001813
        Rule Name  : SRG-APP-000380-DB-000360
        Rule Title : SQL Server must enforce access restrictions associated with changes to the configuration of the database(s).
        DiscussMD5 : 95FAB93A0921985CD613247A78F88442
        CheckMD5   : 5672CC23A186BCEB0208C20604F06C79
        FixMD5     : A9DD431780198FEB7EE0BD6041434963
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
    SELECT D.name AS database_name, SUSER_SNAME(D.owner_sid) AS owner_name,
    FRM.is_fixed_role_member
   FROM sys.databases D
   OUTER APPLY (
    SELECT MAX(fixed_role_member) AS is_fixed_role_member
    FROM (
    SELECT IS_SRVROLEMEMBER(R.name, SUSER_SNAME(D.owner_sid)) AS fixed_role_member
    FROM sys.server_principals R
    WHERE is_fixed_role = 1
    ) A
   ) FRM
   WHERE (D.database_id > 4)
    AND (FRM.is_fixed_role_member = 1
    OR FRM.is_fixed_role_member IS NULL)
    AND (D.name = '$($Database)')
    ORDER BY database_name
    "
    # AND (D.name = '" + $Database + "')
    # "$($assoc.Id) - $($assoc.Name) - $($assoc.Owner)"
    if ($res) {
        #$Status = 'Open'
        $FindingDetails += "DBA, Remove unauthorized users from roles`n$($res | Format-Table -AutoSize | Out-String)"
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

Function Get-V213926 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213926
        STIG ID    : SQL6-D0-003300
        Rule ID    : SV-213926r879799_rule
        CCI ID     : CCI-002475
        Rule Name  : SRG-APP-000428-DB-000386
        Rule Title : SQL Server must implement cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest (to include, at a minimum, PII and classified information) on organization-defined information system components.
        DiscussMD5 : C968AE1A06911A9B683DE5B2C85E725D
        CheckMD5   : DBF34A0BE998841E36A79116F6AAB229
        FixMD5     : 3AF67BC7DD663FF1055AFE9BC5988782
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
    DB_NAME(database_id) AS [Database Name], CASE encryption_state WHEN 0 THEN 'No database encryption key present, no encryption'
    WHEN 1 THEN 'Unencrypted'
    WHEN 2 THEN 'Encryption in progress'
    WHEN 3 THEN 'Encrypted'
    WHEN 4 THEN 'Key change in progress'
    WHEN 5 THEN 'Decryption in progress'
    WHEN 6 THEN 'Protection change in progress'
    END AS [Encryption State]
    FROM sys.dm_database_encryption_keys
    "
    if ($res) {
        $FindingDetails += "DBA, review server documentation for each user database for which encryption is called for and it is marked Unencrypted, this is a finding`n$($res | Format-Table -AutoSize | Out-String)"
    }

    if ($FindingDetails -eq "") {
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

Function Get-V251040 {
    <#
    .DESCRIPTION
        Vuln ID    : V-251040
        STIG ID    : SQL6-D0-003200
        Rule ID    : SV-251040r879944_rule
        CCI ID     : CCI-002450
        Rule Name  : SRG-APP-000416-DB-000380
        Rule Title : SQL Server must use NSA-approved cryptography to protect classified information in accordance with the data owners requirements.
        DiscussMD5 : 94530902BF995409CD9A678554C66AA2
        CheckMD5   : C52463E1E5CABC2B678AC4EDC1626660
        FixMD5     : 5BC058F8E0F53241DA87EF240C360082
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
            #$Status = "NotAFinding"
            $FindingDetails += "'$SettingName' is Not Configured in Group Policy which is acceptable per the STIG." | Out-String
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName (Not found)" | Out-String
        }
        Else {
            #Or, if it must be configured, set this to Open
            #$Status = "Open"
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
            #$Status = "Open"
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String #Shutdown without Logon is NOT Disabled
            $FindingDetails += "" | Out-String
            $FindingDetails += "Registry Path:`t$RegistryPath" | Out-String
            $FindingDetails += "Value Name:`t$RegistryValueName" | Out-String
            If ($RegistryResult.Value -in $RegistryValue) {
                #If the registry result matches the expected value
                $FindingDetails += "Value:`t`t$($RegistryResultValue)" | Out-Strings
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

# SIG # Begin signature block
# MIIL+QYJKoZIhvcNAQcCoIIL6jCCC+YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB/KUL6uBk3+nPs
# 9qcjCK2vlsVhBDL8rCtIfQkTcTfiNKCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBrpN0146QNshfxQFgYSWDkOUZvfa3R
# NZ/3J7ROuyrr0TANBgkqhkiG9w0BAQEFAASCAQCXZbhnqtYRnB7MQJgut7y5wSf5
# B6vZqAWieuSw5n1F8FsY4ygD78HlTHf5Ef/P20wbOA7hHUON8CFaMTWrb5GwV/f5
# AgxkoI33Tm1Ilv+mLHeOvw2CxSeocg8yUFr+vL7OZNXl9vXN7CUuFCD4kGeHmSDw
# fIBBbXRiXz9ymjH6F4lr4QsyFcGgBEj7/p4j0JZnAs6oUkJQd1LyDt1JoFlc2mAA
# Hu2YTUGISiS33Jfqcv4diKuI1BYAVj0XFnIzWjQdaOcKGtuEXwSG6NVINA/9kdaZ
# iMOx3xmzknoSB9w6liweTzvSdatnMgVoNH6eO/pEGw5yp4pMzPVNgsvosRfH
# SIG # End signature block
