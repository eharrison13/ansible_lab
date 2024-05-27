##########################################################################
# Evaluate-STIG module
# --------------------
# STIG:     MS SQL Server 2016 Instance
# Version:  V2R12
# Class:    UNCLASSIFIED
# Updated:  5/13/2024
# Author:   Naval Sea Systems Command (NAVSEA)
##########################################################################
$ErrorActionPreference = "Stop"

Function Get-V213929 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213929
        STIG ID    : SQL6-D0-003600
        Rule ID    : SV-213929r951659_rule
        CCI ID     : CCI-000054
        Rule Name  : SRG-APP-000001-DB-000031
        Rule Title : SQL Server must limit the number of concurrent sessions to an organization-defined number per user for all accounts and/or account types.
        DiscussMD5 : 788F8727040B8E808FB1AF96C2700E01
        CheckMD5   : 8F6AB8D2895F077EFDD7E15A09EEEA7F
        FixMD5     : 770326EBE525411C038BA1D49A63BE5C
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

Function Get-V213930 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213930
        STIG ID    : SQL6-D0-003700
        Rule ID    : SV-213930r879522_rule
        CCI ID     : CCI-000015
        Rule Name  : SRG-APP-000023-DB-000001
        Rule Title : SQL Server must integrate with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.
        DiscussMD5 : 673688EED6F139BD856AF5C8E843B129
        CheckMD5   : 8FF7792A933582FA7D6850E274E009B3
        FixMD5     : 657288BFBE1CC3FE9634956E3E3E5DA4
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
    SELECT CASE SERVERPROPERTY('IsIntegratedSecurityOnly')
    WHEN 1 THEN 'Windows Authentication'
    WHEN 0 THEN 'Windows and SQL Server Authentication'
    END as [Authentication Mode]
    "
    If ($res.'Authentication Mode' -eq 'Windows Authentication') {
        $Status = "NotAFinding"
        $FindingDetails = "Authention mode is Windows Authentication.`n$($res | Format-Table -AutoSize| Out-String)"
    }
    Else {
        $ress = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT name
        FROM sys.sql_logins
        WHERE type_desc = 'SQL_LOGIN' AND is_disabled = 0;
        "
        $FindingDetails = "Authention mode is Windows Mixed. Verify the existing SQL accounts are documented and approved.`n$($res | Format-Table -AutoSize| Out-String)`n$($ress | Format-Table -AutoSize | Out-String)"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213931 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213931
        STIG ID    : SQL6-D0-003800
        Rule ID    : SV-213931r879522_rule
        CCI ID     : CCI-000015
        Rule Name  : SRG-APP-000023-DB-000001
        Rule Title : SQL Server must be configured to utilize the most-secure authentication method available.
        DiscussMD5 : CDA175A39661CCE63FAC5BF7057B962B
        CheckMD5   : CB6193A5D6310FA6FC1965EEEA9726E7
        FixMD5     : AAF546D84C37795AC97A8C71213566E1
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
    # Get the current domain
    $darr = (Get-CimInstance WIN32_ComputerSystem | Select-Object Domain, partofdomain)
    if ($darr.partofdomain) {
        $sDom = $darr.domain

        # Get the server\instance and the account that SQL is running under:
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        select acct = service_account, Instance = @@servername
          from sys.dm_server_services
         where servicename like 'SQL Server%'
           and servicename not like 'SQL Server Agent%'
      "
        $sAcct = $res.acct
        $sHost = $res.instance -replace '\\.*$'
        $sInst = $res.instance -replace '^.*\\'
        $sFQDN = "$sHost.$sDom"

        $fVirtualAcct = ($sAcct -like 'NT Service\MSSQL$*')
        if ($fVirtualAcct) {
            $sAcct = "$sDom\$sHost`$"
        }

        # Get the port number
        $res = Get-ISQL "
        select StaticPort  = ds.value_data
             , DynamicPort = dd.value_data
          from sys.dm_server_registry ds
         inner join sys.dm_server_registry dd on ds.registry_key = dd.registry_key
         where ds.registry_key like '%IPAll'
           and dd.registry_key like '%IPAll'
           and ds.value_name = 'TcpPort'
           and dd.value_name = 'TcpDynamicPorts'
      " -ServerInstance $instance -Database $Database
        try {
            $iPort = [int]$res.StaticPort
        }
        catch {
            $iPort = [int]$res.DynamicPort
        }

        # Get an array of SPN information...
        try { $arrSPN = @() + $(setspn -L $sAcct) }
        catch {
          $arrSPN = ""
        }

        # For virtual accounts, there'll be a slew of SPNs. We need just the MSSQLSvc ones...
        if ($fVirtualAcct -and $arrSPN.count -gt 1) {
            $arrSPN2 = @()
            $arrSPN2 += $arrSPN[0]
            $arrSPN2 += $arrSPN -match '^[\s]+MSSQLSvc/'
            $arrSPN = $arrSPN2
        } # if ($fVirtualAcct -and $arrSPN.count -gt 1)

        # Analyze the SPNs
        if ($arrSPN.count -gt 1) {
            $fFound = $false
            $sExcess = ""
            foreach ($i in 1..$($arrSPN.count - 1)) {
                $sSPN = $arrSPN[$i] -replace '^[\s]' # trim whitespace from front of SPN entry
                if ($sSPN -eq "MSSQLSvc/${sFQDN}:${sInst}" -or
                    $sSPN -eq "MSSQLSvc/${sFQDN}:$iPort") {
                    $fFound = $true # we found one we expected
                }
                else {
                    $sExcess += "  $sSPN`n" # we found one we did not expect
                }
            } # foreach ($i in 1..$($arrSPN.count - 1))

            if ($sExcess -gt '') {
                #$Status = "Open"
                $FindingDetails = "The following unexpected SPNs were found for account ${sAcct}:`n`n$sExcess`n"
            } # if ($sExcess -gt '')

            if ($fFound -eq $false) {
                #$Status = "Open"
                $FindingDetails += "These needed SPNs were not found:

  MSSQLSvc/${sFQDN}:$iPort`n$(
            if ($sHost -ne $sInst) {
              "  MSSQLSvc/${sFQDN}:${sInst}"
            }
          )"
            } # if ($fFound -eq $false)

            if ($FindingDetails -eq "") {
                $status = "NotAFinding"
                $FindingDetails = "The following valid SPNs were found for account ${sAcct}:`n`n$(
            $arrspn[1..($arrspn.count - 1)] -join "`n"
          )"
            } # if ($FindingDetails -eq "")

        }
        else {
            #$Status = "Open"
            $FindingDetails += "No SPNs appear to be defined for account $sAcct.

The STIG calls for SPNs for the following:

  MSSQLSvc/${sFQDN}:$iPort`n$(
          if ($sHost -ne $sInst) {
            "  MSSQLSvc/${sFQDN}:${sInst}"
          }
        )"
        } # if ($arrSPN.count -gt 1)

    }
    else {
        $Status = "Not_Applicable"
        $FindingDetails = "Not part of a domain."
    } # if ($da.partofdomain)
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213932 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213932
        STIG ID    : SQL6-D0-003900
        Rule ID    : SV-213932r879530_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-DB-000084
        Rule Title : SQL Server must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.
        DiscussMD5 : D947A5304EF2C79ED7B9CE59890EEF52
        CheckMD5   : 83BD20E14BC2E7DDCB1E20CDD8EB39B9
        FixMD5     : CA98D20747E08C238630FD7FB31FF67C
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
/* Get all permission assignments to logins and roles */
SELECT DISTINCT
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
    END                    AS [Securable Class],
    CASE
        WHEN E.name IS NOT NULL THEN E.name
        WHEN S.name IS NOT NULL THEN S.name
        WHEN P.name IS NOT NULL THEN P.name
        ELSE '???'
    END                    AS [Securable],
    P1.name                AS [Grantee],
    P1.type_desc           AS [Grantee Type],
    sp.permission_name     AS [Permission],
    sp.state_desc          AS [State],
    P2.name                AS [Grantor],
    P2.type_desc           AS [Grantor Type]
FROM
    sys.server_permissions SP
    INNER JOIN sys.server_principals P1
        ON P1.principal_id = SP.grantee_principal_id
    INNER JOIN sys.server_principals P2
        ON P2.principal_id = SP.grantor_principal_id

    FULL OUTER JOIN sys.servers S
        ON  SP.class_desc = 'SERVER'
        AND S.server_id = SP.major_id

    FULL OUTER JOIN sys.endpoints E
        ON  SP.class_desc = 'ENDPOINT'
        AND E.endpoint_id = SP.major_id

    FULL OUTER JOIN sys.server_principals P
        ON  SP.class_desc = 'SERVER_PRINCIPAL'
        AND P.principal_id = SP.major_id
/* End Get all permission assignments to logins and roles */
"
    $res2 = Get-ISQL -ServerInstance $Instance -Database $Database "
/* Get all server role memberships */
SELECT
    R.name    AS [Role],
    M.name    AS [Member]
FROM
    sys.server_role_members X
    INNER JOIN sys.server_principals R ON R.principal_id = X.role_principal_id
    INNER JOIN sys.server_principals M ON M.principal_id = X.member_principal_id
/* EndGet all server role memberships */
"
    $Status = "Not_Reviewed"
    $FindingDetails += "DBA, ensure the following server permissions match the documented requirements:
$($res | Format-Table -AutoSize| Out-String)
$($res2 | Format-Table -AutoSize| Out-String)"
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213933 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213933
        STIG ID    : SQL6-D0-004000
        Rule ID    : SV-213933r879554_rule
        CCI ID     : CCI-000166
        Rule Name  : SRG-APP-000080-DB-000063
        Rule Title : SQL Server must protect against a user falsely repudiating by ensuring all accounts are individual, unique, and not shared.
        DiscussMD5 : FB4C4607254AC5061CC30DFEADAFE76F
        CheckMD5   : DF87A5C633A42E0ECE46764D69CAECA8
        FixMD5     : 6948F205FE4DDAF1D380D71C2FDBB6F0
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
    SELECT name AS Login_Name, type_desc AS Account_Type, is_disabled AS Account_Disabled
    FROM sys.server_principals
    WHERE TYPE IN ('U', 'S', 'G')
    and name not like '%##%'
    ORDER BY name, type_desc
    " | Format-Table -AutoSize | Out-String

    $FindingDetails = "Verify all listed accounts and members of security groups are not shared accounts.`n$($res)"
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213934 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213934
        STIG ID    : SQL6-D0-004100
        Rule ID    : SV-213934r944382_rule
        CCI ID     : CCI-000166
        Rule Name  : SRG-APP-000080-DB-000063
        Rule Title : SQL Server must protect against a user falsely repudiating by ensuring the NT AUTHORITY SYSTEM account is not used for administration.
        DiscussMD5 : 15A79D3A8CE3E6659F3415264A5C495B
        CheckMD5   : AA9E6F2E691427AFEB9980090B830B8E
        FixMD5     : 28D18F849AC0344FCC4023FA31E78896
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
    $stat = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT SERVERPROPERTY('IsClustered') as IsClustered,
            SERVERPROPERTY('IsHadrEnabled') as IsHadrEnabled"
    If ($stat.IsHadrEnabled) {
        $permlist = "'CONNECT SQL', 'CREATE AVAILABILITY GROUP', 'ALTER ANY AVAILABILITY GROUP', 'VIEW SERVER STATE', 'VIEW ANY DATABASE'"
    }
    ElseIf ($stat.IsClustered) {
        $permlist = "'CONNECT SQL', 'VIEW SERVER STATE', 'VIEW ANY DATABASE'"
    }
    Else {
        $permlist = "'CONNECT SQL','VIEW ANY DATABASE'"
    }

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        EXECUTE AS LOGIN = 'NT AUTHORITY\SYSTEM'
        SELECT @@servername as Instance, *
          FROM fn_my_permissions(NULL,NULL)
         where permission_name not in ($permlist)
        REVERT
      "
    If ($res) {
        $Status = "Open"
        $FindingDetails = "The following privileges need revoked from NT AUTHORITY\SYSTEM:`n$($res | Format-Table -AutoSize| Out-String)"
    }
    Else {
        $SYSPERMS = Get-ISQL -ServerInstance $Instance -Database $Database "
        EXECUTE AS LOGIN = 'NT AUTHORITY\SYSTEM'
        SELECT * FROM fn_my_permissions(NULL, 'server')
        REVERT
        GO
        "
        $Status = "NotAFinding"
        $FindingDetails = "The correct permissions are assigned to NT AUTHORITY\SYSTEM.`n$($Stat | Format-Table -AutoSize| Out-String)`n$($SYSPERMS | Format-Table -AutoSize| Out-String)"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213935 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213935
        STIG ID    : SQL6-D0-004200
        Rule ID    : SV-213935r879554_rule
        CCI ID     : CCI-000166
        Rule Name  : SRG-APP-000080-DB-000063
        Rule Title : SQL Server must protect against a user falsely repudiating by ensuring only clearly unique Active Directory user accounts can connect to the instance.
        DiscussMD5 : BADE1E0213C79055C34BA80E08143B87
        CheckMD5   : 2482180692745096A9E74ACFCB57A051
        FixMD5     : 19F44CE94AC59E8F40B4D37BBCDF702C
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
            , name
        FROM sys.server_principals
        WHERE type in ('U','G')
        AND name LIKE '%$'
    "
    if ($res) {
        $Status = 'Open'
        $FindingDetails += "DBA, there are additional checks in the STIG that need to be done for the following:`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213936 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213936
        STIG ID    : SQL6-D0-004300
        Rule ID    : SV-213936r879559_rule
        CCI ID     : CCI-000169
        Rule Name  : SRG-APP-000089-DB-000064
        Rule Title : SQL Server must be configured to generate audit records for DoD-defined auditable events within all DBMS/database components.
        DiscussMD5 : 3AA21F642C2F8D04BFA87BB391307B94
        CheckMD5   : 4FB39F536006F33EBDFE38C6812C58C8
        FixMD5     : 567C19AFFD9258A079661CD021ABC726
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
    $InstalledAudits = Get-ISQL -ServerInstance $Instance -Database $Database "
    SELECT name AS 'Audit Name',
    status_desc AS 'Audit Status',
    audit_file_path AS 'Current Audit File'
    FROM sys.dm_server_audit_status
    "

    $AuditActions = Get-ISQL -ServerInstance $Instance -Database $Database "
    SELECT a.name AS 'AuditName',
    s.name AS 'SpecName',
    d.audit_action_name AS 'ActionName',
    d.audited_result AS 'Result'
    FROM sys.server_audit_specifications s
    JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
    JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
    WHERE a.is_state_enabled = 1
    "

    $FindingDetails = Confirm-TraceAuditSetting -Instance $Instance -Database $Database
    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "All required events are being audited.`n$($InstalledAudits | Format-Table -AutoSize| Out-String)`n$($AuditActions | Format-Table -AutoSize| Out-String)"
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

Function Get-V213937 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213937
        STIG ID    : SQL6-D0-004400
        Rule ID    : SV-213937r879560_rule
        CCI ID     : CCI-000171
        Rule Name  : SRG-APP-000090-DB-000065
        Rule Title : SQL Server must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.
        DiscussMD5 : 1D021E0F8656CA44E867BB6AB28DC3C5
        CheckMD5   : 3E08A3A4234131454F76B25005369A71
        FixMD5     : 349D0846328E1CEDAA23CF341FF2D687
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
        #$Status = 'Open'
        $FindingDetails += "DBA, ensure the following have been authorized by the ISSM to create and/or maintain audit definitions:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    if ($FindingDetails -eq "") {
        #$Status = "NotAFinding"
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

Function Get-V213939 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213939
        STIG ID    : SQL6-D0-004600
        Rule ID    : SV-213939r902984_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000091-DB-000325
        Rule Title : SQL Server must generate audit records when successful/unsuccessful attempts to retrieve privileges/permissions occur.
        DiscussMD5 : 4A37EDD18EBE55E0B8249075BEFDFD57
        CheckMD5   : D06E5AD076EF344A77C1CE5FE7967EF6
        FixMD5     : 0C161107A882AA9691A4A7A8C759D20F
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
    SELECT name AS 'Audit Name',
    status_desc AS 'Audit Status',
    audit_file_path AS 'Current Audit File'
    FROM sys.dm_server_audit_status
    "
    if ($res) {

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
    } else {
        $Status = "Open"
        $FindingDetails = "DBA, no audits are configured. Does the SSP agree this is OK?"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213940 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213940
        STIG ID    : SQL6-D0-004700
        Rule ID    : SV-213940r879562_rule
        CCI ID     : CCI-001464
        Rule Name  : SRG-APP-000092-DB-000208
        Rule Title : SQL Server must initiate session auditing upon startup.
        DiscussMD5 : AB6AE51085416F9DD189F16853A04E3F
        CheckMD5   : 57950466E438256A4744EE0BF7432519
        FixMD5     : 0A248B57FA07744479EE521CCFACE377
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
    SELECT name AS 'Audit Name',
    status_desc AS 'Audit Status',
    audit_file_path AS 'Current Audit File'
    FROM sys.dm_server_audit_status
    WHERE status_desc = 'STARTED'
    "
    if ($res) {
        $Status = 'NotAFinding'
        #$FindingDetails += "The check query found that audits start automatically."
        # 20201027 JJS Added all Results to output
        $FindingDetails += "The check query found that audits start automatically.`n$($res | Format-Table -AutoSize| Out-String)"
    }
    else {
        $Status = "Open"
        $FindingDetails = "The audits do not start up automatically."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213941 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213941
        STIG ID    : SQL6-D0-005500
        Rule ID    : SV-213941r879569_rule
        CCI ID     : CCI-000135
        Rule Name  : SRG-APP-000101-DB-000044
        Rule Title : SQL Server must include additional, more detailed, organization-defined information in the audit records for audit events identified by type, location, or subject.
        DiscussMD5 : 3A673E1024A10A53871599E28F631BDB
        CheckMD5   : 7FE0F6B15125A01A134F6897EC0758FC
        FixMD5     : 5CB6830A88BB052391209242D3BBBC38
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
    $InstalledAudits = Get-ISQL -ServerInstance $Instance -Database $Database "
    SELECT name AS 'Audit Name',
    status_desc AS 'Audit Status',
    audit_file_path AS 'Current Audit File'
    FROM sys.dm_server_audit_status
    "
    $AuditActions = Get-ISQL -ServerInstance $Instance -Database $Database "
    SELECT a.name AS 'AuditName',
    s.name AS 'SpecName',
    d.audit_action_name AS 'ActionName',
    d.audited_result AS 'Result'
    FROM sys.server_audit_specifications s
    JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
    JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
    WHERE a.is_state_enabled = 1
    "
    $CheckAudits = Confirm-TraceAuditSetting $Instance $Database

    If (!$CheckAudits) {
        $Status = "NotAFinding"
        $FindingDetails = "All STIG audits are in use.`n$($InstalledAudits | Format-Table -AutoSize| Out-String)`n$($AuditActions | Format-Table -AutoSize| Out-String)"
    }
    Else {
        $FindingDetails = "Verify audits are in use and match your system documentation.`n$($InstalledAudits | Format-Table -AutoSize| Out-String)`n$($AuditActions | Format-Table -AutoSize| Out-String)"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213942 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213942
        STIG ID    : SQL6-D0-005600
        Rule ID    : SV-213942r879571_rule
        CCI ID     : CCI-000140
        Rule Name  : SRG-APP-000109-DB-000049
        Rule Title : SQL Server must by default shut down upon audit failure, to include the unavailability of space for more audit log records; or must be configurable to shut down upon audit failure.
        DiscussMD5 : C9E2158C1DED475A4D2C0B5103B849D0
        CheckMD5   : 7E3525DE6E25C3CC45C4770E65536192
        FixMD5     : 80AC1ABA8269F07696EEE86288935414
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
        #$Status = "Open"
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

Function Get-V213943 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213943
        STIG ID    : SQL6-D0-005700
        Rule ID    : SV-213943r879571_rule
        CCI ID     : CCI-000140
        Rule Name  : SRG-APP-000109-DB-000321
        Rule Title : SQL Server must be configurable to overwrite audit log records, oldest first (First-In-First-Out - FIFO), in the event of unavailability of space for more audit log records.
        DiscussMD5 : 9B43D7E9010F71ABE89DC8DB7F5B41C7
        CheckMD5   : C7A1AD0CBBC6BE8C223796000F862858
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

Function Get-V213944 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213944
        STIG ID    : SQL6-D0-005900
        Rule ID    : SV-213944r879576_rule
        CCI ID     : CCI-000162, CCI-000163, CCI-000164
        Rule Name  : SRG-APP-000118-DB-000059
        Rule Title : The audit information produced by SQL Server must be protected from unauthorized access, modification, and deletion.
        DiscussMD5 : 47FC5B7FFEE87DEC4BB5549B52ED7614
        CheckMD5   : ABF1DE02F445285D21524EB38CE13835
        FixMD5     : 698CDC5BD96AD730F11E00938CEE650B
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
            $sAgtName = 'SQLSERVERAGENT'

            if ($sInstance -ne $sServName) {

                $sAgtName = "SQLAgent`$$sInstance"

            } # service name will either be SQLSERVERAGENT or SQLAgent$sqlnn

            $ssasrv = (Get-CimInstance win32_service | Where-Object name -EQ $sAgtName)  # at some point we need code for SQLAgent on a default instance

            if ($ssasrv) {

                $sname = $ssasrv.startname

                $myhash[$sname] = $authSSASVC

                $sname = "NT SERVICE\SQLAgent`$$sInstance"

                $myhash[$sname] = $authSSASVC

            }

            #$ssasrv = (Get-CimInstance win32_service | Where-Object name -EQ "SQLAgent`$$sInstance")  # at some point we need code for SQLAgent on a default instance
            #if ($ssasrv) {
                #$sname = $ssasrv.startname
                #$myhash[$sname] = $authSSASVC
                #$sname = "NT SERVICE\SQLAgent`$$sInstance"
                #$myhash[$sname] = $authSSASVC
            #}

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
    If ($FindingDetails -gt '') {
        $Status = "Open"
    }
    Else {
        If ($iDirCnt -eq 0) {
            $res = $(Get-ISQL -ServerInstance $Instance -Database $Database "
              select CountALSL = (SELECT COUNT(audit_id) FROM sys.server_audits WHERE type='SL' OR type='AL'),
                     CountFL   = (SELECT COUNT(audit_id) FROM sys.server_audits WHERE type='FL')
            ")
            If ($res.CountALSL -gt 0 -and $res.CountFL -eq 0) {
                $Status = "Not_Applicable"
                $FindingDetails += "All audits use either the APPLICATION or SECURITY event log, therefore this is N/A." | Out-String
            }
            Else {
                $Status = "NotAFinding"
                $FindingDetails = "No audit directories were found on this host."
            }
        }
        Else {
            $Status = "NotAFinding"
            $FindingDetails = "The audit files in the following directories were checked and found to have proper authorizations:`n`n$sDirList"
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

Function Get-V213948 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213948
        STIG ID    : SQL6-D0-006300
        Rule ID    : SV-213948r902986_rule
        CCI ID     : CCI-001494
        Rule Name  : SRG-APP-000122-DB-000203
        Rule Title : SQL Server must protect its audit configuration from authorized and unauthorized access and modification.
        DiscussMD5 : 08BBD9D594E4A2D65EA5989228CFA844
        CheckMD5   : 63ED8242CD87A58B7FC555C3DC298E47
        FixMD5     : E0C736D990C5FFC667AB40BD8DCA2353
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
        SELECT login.name, perm.permission_name, perm.state_desc
        FROM sys.server_permissions perm
        JOIN sys.server_principals login
        ON perm.grantee_principal_id = login.principal_id
        WHERE permission_name in ('ALTER ANY DATABASE AUDIT', 'ALTER ANY SERVER AUDIT', 'CONTROL SERVER')
        and login.name not like '##MS_%';"
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

Function Get-V213950 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213950
        STIG ID    : SQL6-D0-006500
        Rule ID    : SV-213950r879586_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000179
        Rule Title : SQL Server must limit privileges to change software modules and links to software external to SQL Server.
        DiscussMD5 : 1B4B4243CDF9FDA4AA183E37FA0FC5E0
        CheckMD5   : 8D7178259DEC13162870B020127803BC
        FixMD5     : AB3C0D470295F005A78620796D092218
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
    $arrDirs = @()

    # The STIG explicitly asks that the Binn subdirectory under the RootDirectory folder be checked, so let's include it first...
    $oServer = New-Object -TypeName Microsoft.SqlServer.Management.Smo.Server -ArgumentList $Instance
    $sDir = $oServer.RootDirectory + '\Binn'
    $arrDirs += $sDir

    # The STIG says to "additionally check the owner and... rights for shared software library paths on disk.", so let's
    # find and analyze directories designated in the registry as being bin root directories (Note: this is probably the same directory we added above)...
    Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL*.*\setup' -ErrorAction SilentlyContinue -Name sqlbinroot | ForEach-Object {
      $sDir = $_.sqlbinroot
      if ($sDir -notin $arrDirs) {
        $arrDirs += $sDir
      }
    }

    # Let's also find and analyze the shared code directory designated in the registry...
    Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\*' -ErrorAction SilentlyContinue -Name SharedCode | ForEach-Object {
      $sDir = $_.SharedCode
      if ($sDir -notin $arrDirs) {
        $arrDirs += $sDir
      }
    }

    # The STIG does not specify who is permitted to modify and/or own the directories, but only that the server documentation must be checked.
    # All we can do now is list out the directories, their modifiers and owners.
    $FindingDetails = "DBA, confirm the following accounts are documented as authorized to own/modify the SQL instance's binary files:"
    foreach ($sDir in $arrDirs) {
      $FindingDetails += "`n`nDirectory $sDir"
      try { $objACL = Get-Acl $sdir } catch { $objACL = "" }
      if ($objACL) {
        $sOwner = $objACL.Owner
        $FindingDetails += "`nOwner: $sOwner"

        $arrModifiers = @()
        foreach ($acc in $objACL.Access) {
          if (($acc.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Modify) -eq [System.Security.AccessControl.FileSystemRights]::Modify) {
            $tmpAcct = $acc.IdentityReference
            $tmpRights = $acc.FileSystemRights.toString()
            $entry = "`nModifier: $tmpAcct ($tmpRights)"
            if ($entry -notin $arrModifiers) {
              $arrModifiers += $entry
            }
          }
        }

        foreach ($i in $arrModifiers) {
          $FindingDetails += $i
        }

      }
      else {
        $FindingDetails += "`n<<Error: Insufficient permissions to read ACL; manual check required>>"
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

Function Get-V213952 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213952
        STIG ID    : SQL6-D0-006700
        Rule ID    : SV-213952r879586_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000198
        Rule Title : SQL Server software installation account must be restricted to authorized users.
        DiscussMD5 : 4BCE466FE93F9B3ADA0405D76E39605E
        CheckMD5   : 6D8D16FFC6460CD78492F5D1BAB13F60
        FixMD5     : 019ACD9B2728F5AD19D3D5DAE0B1A646
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
    #$Status = 'Open'
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

Function Get-V213953 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213953
        STIG ID    : SQL6-D0-006800
        Rule ID    : SV-213953r879586_rule
        CCI ID     : CCI-001499
        Rule Name  : SRG-APP-000133-DB-000199
        Rule Title : Database software, including DBMS configuration files, must be stored in dedicated directories, separate from the host OS and other applications.
        DiscussMD5 : A78C64095716905AF69EF175E2B31D14
        CheckMD5   : C2CD834BEE54455E0E1FDAD10A9D4812
        FixMD5     : F15A173F20DFB69A400D74B6C677A51A
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

    $rootdir = $(Get-ISQL -ServerInstance $Instance -Database $Database "
      SELECT value_data
        FROM master.sys.dm_server_registry
       where value_name = 'ImagePath'" | ? value_data -like '*sqlservr*'
    ).value_data -replace '\\Binn\\sqlservr.exe.*$','' -replace '^"',''

    $FindingDetails += "Windows Directory: $windir`n"
    $FindingDetails += "SQL Root Directory: $rootdir`n`n"

    if ($rootdir -like "$windir\*") {
      $Status = "Open"
      $FindingDetails += "SQL appears to be installed within the Windows directory."
    }
    elseif ($rootdir -match '^[a-z]:\\(program *files\\)?m(icro)?s(oft)? ?sql ?server') {
      $Status = "NotAFinding"
      $FindingDetails += "SQL appears to be installed in a directory of its own."
    }
    else {
      $FindingDetails += "DBA, verify that SQL is installed in a directory its own and is not installed in the Operating System directory or another application's directory."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213954 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213954
        STIG ID    : SQL6-D0-006900
        Rule ID    : SV-213954r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000090
        Rule Title : Default demonstration and sample databases, database objects, and applications must be removed.
        DiscussMD5 : 044BE4BDCAA8D536246A6A0E3832F84D
        CheckMD5   : 2F54F68AB6EB0D4556DF7BF72550FE49
        FixMD5     : B0DB6296BA2BA5BBDB35B6F9D3207AEB
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

Function Get-V213955 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213955
        STIG ID    : SQL6-D0-007000
        Rule ID    : SV-213955r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000091
        Rule Title : Unused database components, DBMS software, and database objects must be removed.
        DiscussMD5 : EDEFFAA0C76DBFC3C0637AC6BE1C70E0
        CheckMD5   : A07ECBC9451EE11D9865417CCDD51F5D
        FixMD5     : F8BA2173C775505DCD0AF949A1DCBA2D
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
    $res = Get-SqlProductFeatures $Instance

    If (!$res) {
        $Status = "Open"
        $FindingDetails = "No results were returned from Sql Install Summary File $($SqlInstallSummaryFile)"
    }
    Else {
        $Status = "Not_Reviewed"
        $FindingDetails += "Microsoft SQL Product Features Installed:" | Out-String
        $FindingDetails += $res | Format-Table -AutoSize | Out-String

    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213956 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213956
        STIG ID    : SQL6-D0-007100
        Rule ID    : SV-213956r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000092
        Rule Title : Unused database components that are integrated in SQL Server and cannot be uninstalled must be disabled.
        DiscussMD5 : ABBD58BDD4A90EE0F3F7E24C2D93D5A6
        CheckMD5   : 36429437C18C64FC3622C430CD69CC90
        FixMD5     : 7B332FFDD1399198E91789A1BD0AD98B
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
    #$res = $ProductFeatures
    $res = Get-SqlProductFeatures $Instance

    if (!$res) {
        $Status = "Open"
        $FindingDetails = "No results were returned from Sql Install Summary File $($SqlInstallSummaryFile)"
    }
    else {
        $Status = "Not_Reviewed"
        #$FindingDetails = "Microsoft SQL Product Features Installed:`n$($res | format-table -AutoSize| out-string)"
        $FindingDetails = "$($res | Format-Table -AutoSize| Out-String)"

    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213957 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213957
        STIG ID    : SQL6-D0-007200
        Rule ID    : SV-213957r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000093
        Rule Title : Access to xp_cmdshell must be disabled, unless specifically required and approved.
        DiscussMD5 : BE12ED22C95AA8C733E51B0B0236EC97
        CheckMD5   : D364FF0ACBD255F953E3C5170FDEA919
        FixMD5     : E9FC9C61882EF18FC51782ED9ABD2DB8
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
           $sState = 'configured'
        }
        else {
           $sState = 'running'
        }
        $FindingDetails += "Instance $($_.InstanceName) is $sState with xp_cmdshell enabled.`n$($_ | Format-Table -AutoSize| Out-String)"
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

Function Get-V213958 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213958
        STIG ID    : SQL6-D0-007300
        Rule ID    : SV-213958r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000093
        Rule Title : Access to CLR code must be disabled or restricted, unless specifically required and approved.
        DiscussMD5 : 17B1FBB94140290DCC140C1B53EC3976
        CheckMD5   : 32485AF9FD234A402E678324E870E944
        FixMD5     : C42EF5E275628A77982973C5AD6C52BF
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
    $qry =  "
        select @@SERVERNAME InstanceName
            , value
            , value_in_use
        from sys.configurations
        where name = 'clr enabled'
        and 1 in (value, value_in_use)
    "
    Get-ISQL -ServerInstance $Instance -Database $Database $qry | ForEach-Object {
        if ($_.value -eq 1) {
           $sState = 'configured'
        }
        else {
           $sState = 'running'
        }
        $FindingDetails += "Instance $($_.InstanceName) is $sState with clr enabled.`n$($_ | Format-Table -AutoSize| Out-String)"
    } # foreach-object

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "clr is not enabled."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213959 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213959
        STIG ID    : SQL6-D0-007400
        Rule ID    : SV-213959r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000093
        Rule Title : Access to Non-Standard extended stored procedures must be disabled or restricted, unless specifically required and approved.
        DiscussMD5 : 0195BA82FF386E1502D0D2B7F5BD1659
        CheckMD5   : 41CF01D5ACB8750A24BA5B43FDEDE013
        FixMD5     : 8193C4BAC318F44A3084AE42D657E17B
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
    DECLARE @xplist AS TABLE
    (
    xp_name sysname,
    source_dll nvarchar(255)
    )
    INSERT INTO @xplist
    EXEC sp_helpextendedproc

    SELECT @@servername as instance,
    X.xp_name, X.source_dll, O.is_ms_shipped FROM @xplist X JOIN sys.all_objects O ON X.xp_name = O.name WHERE O.is_ms_shipped = 0 ORDER BY X.xp_name
    "
    if ($res) {
        $Status = 'Open'
        $FindingDetails += "DBA, ensure the SSP documents the following Non-Standard extended stored procedures as required:`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213960 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213960
        STIG ID    : SQL6-D0-007500
        Rule ID    : SV-213960r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000093
        Rule Title : Access to linked servers must be disabled or restricted, unless specifically required and approved.
        DiscussMD5 : 79EE0776974774536210F6F29492C2E8
        CheckMD5   : 16CB99255D155FEFBAB0998A40F3F7B7
        FixMD5     : 4A7EFDD0EF06DD13D4BB1F66B584D025
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
    # Get the instance name as SQL knows it...
    $inst = $(Get-ISQL -ServerInstance $Instance -Database $Database "select instancename = @@servername").instancename

    $links = $(Get-ISQL -ServerInstance $inst 'exec sp_linkedservers' | Where-Object { $_.srv_name -ne $inst }) # Find all but self-referencing links
    if ($links) {
        $FindingDetails = "Check the system documentation to see if the following linked servers are required and approved:`n$($links | Format-Table -AutoSize | Out-String)"
    }

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
      SELECT s.name, p.principal_id, l.remote_name
        FROM sys.servers s
        JOIN sys.linked_logins l ON s.server_id = l.server_id
        LEFT JOIN sys.server_principals p ON l.local_principal_id = p.principal_id
       WHERE s.is_linked = 1
         and s.name != @@servername
         and l.remote_name > ' '
    "
    if ($res) {
        $FindingDetails += "A linked server is defined with a remote name, which potentially allows sysadmin impersonation:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    if ($FindingDetails -eq '') {
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

Function Get-V213961 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213961
        STIG ID    : SQL6-D0-007600
        Rule ID    : SV-213961r879588_rule
        CCI ID     : CCI-000382
        Rule Name  : SRG-APP-000142-DB-000094
        Rule Title : SQL Server must be configured to prohibit or restrict the use of organization-defined protocols as defined in the PPSM CAL and vulnerability assessments.
        DiscussMD5 : C1B77EA47F163A620D90AC893D04C64F
        CheckMD5   : 1D031BBD7F48616EFD654CBEBDDAB29E
        FixMD5     : F8847667D38FA4A239AD472D82FC1ACA
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
    # Change History:
    # 8/30/23   Ken Row   Issue 1223
    #   Changed to return Needs Reviewed unless no protocols whatsoever are enabled.
    #   Also pivoted the results table and shortened the logic for determining the instance name.

    # 6-14-22: Issue 571 - Changed SELECT from SELECT SERVERPROPERTY ('InstanceName'),

    # 3-25-22 Removed parameter (" -Database $Database"),
    # can be null and is not needed to get instance name old: $ThisInst = Get-ISQL -ServerInstance $Instance -Database $Database "

    $ThisInst = $(Get-ISQL -ServerInstance $Instance "
    SELECT CASE
             WHEN SERVERPROPERTY ('InstanceName') IS NULL THEN 'MSSQLSERVER'
             ELSE SERVERPROPERTY ('InstanceName')
           END
    ").Column1

    #Set Remote Registry connection
    $RegSQLVal = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL" -Name $ThisInst

    # Get SQL connection settings
    $regprotocolNamed_Pipes = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$RegSQLVal\MSSQLServer\SuperSocketNetLib\Np" -Name "Enabled"
    $regprotocolShared_Memory = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$RegSQLVal\MSSQLServer\SuperSocketNetLib\Sm" -Name "Enabled"
    $regprotocolTCP = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$RegSQLVal\MSSQLServer\SuperSocketNetLib\Tcp" -Name "Enabled"
    $regprotocolVIA = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$RegSQLVal\MSSQLServer\SuperSocketNetLib\Via" -Name "Enabled"

    if (1 -in $regprotocolNamed_Pipes, $regprotocolShared_Memory, $regprotocolTCP, $regprotocolVIA) {
        $FindingDetails = "DBA/Auditor, verify that the enabled protocols listed here have been documented as authorized:`n"
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "Marked as not a finding because no protocols whatsoever are enabled:`n"
    }
    $FindingDetails += $((Get-Variable regprotocol* | Format-Table -AutoSize | Out-String) -replace 'regprotocol', '' -replace 'Name *Value', 'Protocol      Enabled' -replace '--*  *--*', ' ')
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213962 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213962
        STIG ID    : SQL6-D0-007700
        Rule ID    : SV-213962r879588_rule
        CCI ID     : CCI-000382
        Rule Name  : SRG-APP-000142-DB-000094
        Rule Title : SQL Server must be configured to prohibit or restrict the use of organization-defined ports, as defined in the PPSM CAL and vulnerability assessments.
        DiscussMD5 : A9943FBFBCA0DAC307692D0AF8D583B6
        CheckMD5   : 0B9C93F83DF5CA88006BCEF10C0F4821
        FixMD5     : 6DD081AACB36CF0A625E00531D5F4F30
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

    if ($FindingDetails -gt '') {
        #$Status = 'Open'
        $FindingDetails += "`nNote: the STIG asks that port usage comply with PPSM or organizational mandates, but industry best practices advise using high-number static ports."
    }
    else {
        #$Status = "NotAFinding"
        $FindingDetails = "High-number static ports are being used, as per industry best practices."
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

Function Get-V213963 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213963
        STIG ID    : SQL6-D0-007800
        Rule ID    : SV-213963r879589_rule
        CCI ID     : CCI-000764
        Rule Name  : SRG-APP-000148-DB-000103
        Rule Title : SQL Server must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).
        DiscussMD5 : D7F94F9A112FE6AF20247AC36436B2F8
        CheckMD5   : 45D898768E061146D12E5DCEBE3A48C4
        FixMD5     : A3340B7D0808E3C6B9AF2CC9E8499FD5
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
    USE master
    GO
    SELECT name AS Login_Name, type_desc AS Account_Type, is_disabled AS Account_Disabled
    FROM sys.server_principals
    WHERE TYPE IN ('U', 'S', 'G')
    and name not like '%##%'
    ORDER BY name, type_desc" #| -Autosize | Out-String

    $FindingDetails = "Verify all listed accounts and members of security groups are not shared accounts.`n$($res | Format-Table -AutoSize| Out-String)"
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213964 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213964
        STIG ID    : SQL6-D0-007900
        Rule ID    : SV-213964r951662_rule
        CCI ID     : CCI-000192
        Rule Name  : SRG-APP-000164-DB-000401
        Rule Title : If DBMS authentication using passwords is employed, SQL Server must enforce the DOD standards for password complexity and lifetime.
        DiscussMD5 : A6E88A7923674037BAF522C8F8A48D99
        CheckMD5   : 8F891B33CF001F52AF9266B8CB63B790
        FixMD5     : E6E25411141CB0CC60BE4119B8C3AC95
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
        V-213964 Check Logic:

        If using Windows Authentication, then Not A Finding.

        If not,
            Do the SQL accounts use password complexity and expiration?
            If not, this is Open.

            Does the system use password complexity?
            If not, this is open.
    #>

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
      SELECT CASE SERVERPROPERTY('IsIntegratedSecurityOnly') WHEN 1 THEN 'Windows Authentication' WHEN 0 THEN 'SQL Server Authentication' END as [Authentication Mode]
    "
    $FindingDetails += $($res | Format-Table -AutoSize | Out-String)

    If ($res.'Authentication Mode' -eq 'Windows Authentication') {
        $Status = "NotAFinding"
        $FindingDetails += "Windows authentication is being used."
    } else {
        $FindingDetails += "Windows authentication is NOT being used; must check SQL accounts and password complexity...`n"
        $DefaultSA = $(Get-ISQL -ServerInstance $Instance -Database master "
            SELECT name
            FROM sys.sql_logins
            WHERE [name] = 'sa' OR [principal_id] = 1;
        ").Name

        $ress = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT [name], is_expiration_checked, is_policy_checked
              FROM sys.sql_logins
             where name not in ('$DefaultSA', '##MS_PolicyTsqlExecutionLogin##', '##MS_PolicyEventProcessingLogin##')
        "
        $FindingDetails += $($ress | Format-Table -AutoSize | Out-String)
        $badaccts = $ress | where-object {$_.is_expiration_checked -eq $false -or $_.is_policy_checked -eq $false}
        If ($badaccts) {
            $Status = "Open"
            $FindingDetails += "The following custom SQL accounts are not configured per STIG guidance:`n`n$($badaccts.Name -replace '^','  ' | out-string)"
        }

        # Checking password complexity...
        secedit /export /cfg "$($env:windir)\Temp\Evaluate-STIG\Evaluate-STIG_SecPol.ini"
        $secpol = (Get-Content "$($env:windir)\Temp\Evaluate-STIG\Evaluate-STIG_SecPol.ini")
        $value = $secpol | Where-Object{ $_ -like "PasswordComplexity*" }
        if($Value -ne "PasswordComplexity = 1") {
            $Status = "Open"
            $FindingDetails += "System Password complexity is not compliant."
        } else {
            $FindingDetails += $value
        }

        if ($status -eq 'Not_Reviewed') {
            $Status = "NotAFinding"
            $FindingDetails += "`n`nSQL accounts and password complexity adhere to STIG requirements."
        }
    } # If ($res.'Authentication Mode' -eq 'Windows Authentication')
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213965 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213965
        STIG ID    : SQL6-D0-008000
        Rule ID    : SV-213965r879601_rule
        CCI ID     : CCI-000192
        Rule Name  : SRG-APP-000164-DB-000401
        Rule Title : Contained databases must use Windows principals.
        DiscussMD5 : 0DEBC1B24FF5B8133322502AFC9F9C2C
        CheckMD5   : 47F2CDD51C64244816C5F8AEE9593C98
        FixMD5     : 5E381018749004126817390950FD008F
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
    $ress = Get-ISQL -ServerInstance $Instance -Database $Database "SELECT name FROM sys.databases WHERE containment = 1"
    If ($ress) {
        ForEach ($res in $ress) {
            $res2 = Get-ISQL -ServerInstance $res.instance -Database $res.name "select name from sys.database_principals where authentication_type = 2"
            If ($res2) {
                $Status = 'Open'
                $FindingDetails += "Database $($res.name) of instance $($res.instance) has users using SQL authentication:`n$($res2 | Format-Table -AutoSize | Out-String)"
            }
        }
        If ($FindingDetails -eq '') {
            $FindingDetails += "DBA, ensure the following contained databases are documented as authorized:`n$($res | Format-Table -AutoSize | Out-String)"
        }
    }
    Else {
        $Status = "NotAFinding"
        $FindingDetails = "No contained databases were found on this instance."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213966 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213966
        STIG ID    : SQL6-D0-008200
        Rule ID    : SV-213966r879609_rule
        CCI ID     : CCI-000197
        Rule Name  : SRG-APP-000172-DB-000075
        Rule Title : If passwords are used for authentication, SQL Server must transmit only encrypted representations of passwords.
        DiscussMD5 : A636C3EEF54C828C1893A614F82BBE95
        CheckMD5   : 7AFEF83856E766F7056366788175393F
        FixMD5     : BCD153C4EFC6C49B6117B7D0089040C7
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
    $Status = 'NotAFinding' # if we make it through all the tests unscathed, then NaF

    # Get the FQDN of the Instance's Server name for later use...
    $sqlSvr = $(Get-ISQL -ServerInstance $Instance -Database $Database "select machine = serverproperty('MachineName')").machine
    $sqlFQDN = [system.net.dns]::GetHostByName($sqlSvr).Hostname

    #The check says to look at SQL config mgr, but we cannot automate that, so let's look at the registry...
    $sqlHost = $env:COMPUTERNAME
    $FindingDetails = "Checking encryption settings on host $sqlhost...`n"
    $SQLReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $sqlHost)

    #Get the registry key/path for the instance...
    $sRegKey = $(Get-ISQL -ServerInstance $Instance -Database $Database "
       select registry_key from sys.dm_server_registry where value_name = 'CurrentVersion'
    ").registry_key -replace '\\CurrentVersion$', '' -replace '^HKLM\\Software', 'SOFTWARE'

    #Get cert/encryption info...
    $SQLSNL = $SQLReg.OpenSubKey("$sRegKey\SuperSocketNetLib")
    $Thumbprint = $SQLSNL.GetValue("Certificate")
    $fForceEnc = $SQLSNL.GetValue("ForceEncryption")

    #Examine what we found...
    If ([string]::IsNullOrEmpty($Thumbprint)) {
        $Status = "Open"
        $FindingDetails += "No certificate is assigned for encryption.`n"

    }
    ElseIf ($fForceEnc -eq 0) {
        $Status = "Open"
        $FindingDetails += "Force Encryption value is 0 -- no encryption.`n"

    }
    Else {
        $FindingDetails += "Force Encryption value is 1.`n"
        $sqlcert = Get-ChildItem -Path Cert:\LocalMachine\my | Where-Object Thumbprint -ieq $Thumbprint
        if ($sqlcert) {
            $FindingDetails += "Encryption uses this cert:`n$(
                $sqlcert | Format-List Subject, Issuer, Thumbprint, FriendlyName, NotBefore, NotAfter, HasPrivateKey | Out-String
            )"
            $resTest = Test-Certificate $sqlcert -ErrorAction SilentlyContinue 3>&1 # send warning info to stdout
            if (!($?)) {
                # Test-Cert must have failed.
                $status = "Open"
                $FindingDetails += "But the certificate is not valid because of the following error:`n$(
                    $resTest.message
                    $Error[0].exception
                )`n"

            }
            elseif ($sqlcert.Issuer -eq $sqlcert.Subject) {
                $status = "Open"
                $FindingDetails += "But the certificate appears to be self-signed.`n"

            }
            elseif ($sqlcert.HasPrivateKey -eq $false) {
                $status = "Open"
                $FindingDetails += "But the certificate does not appear to have a private key.`n"

            }
            elseif ($sqlcert.Subject -notlike "CN=$sqlFQDN*") {
                $sSAN = ($sqlcert.Extensions | Where-Object {$_.oid.friendlyname -eq 'Subject Alternative Name'}).format($true)
                $arrSAN = ($sSAN -split "`r?`n").Trim() -notmatch "^$"
                if (!($arrSAN -like "DNS Name=$sqlFQDN")) {
                    $status = "Open"
                    $FindingDetails += "But neither the certificate's subject nor its alternate includes $sqlFQDN.`n"
                }
            }
        }
        else {
            $Status = "Open"
            $FindingDetails += "Thumbprint $Thumbprint not found on an installed cert.`n"
        } # if ($sqlcert)

        if (Get-Service clussvc -ErrorAction SilentlyContinue) {
            # We are running on a cluster, and the current node looks OK. See if the other nodes have the same config...
            $sqlnodelist = $(get-clusternode | Where-Object name -NE $sqlHost).Name
            foreach ($sqlnode in $sqlnodelist) {
                $FindingDetails += "`nChecking SQL configuration on node $sqlnode...`n"
                $SQLReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $sqlnode)

                #Get cert/encryption info...
                $SQLSNL = $SQLReg.OpenSubKey("$sRegKey\SuperSocketNetLib")
                $NodeThumb = $SQLSNL.GetValue("Certificate")
                $fForceEnc = $SQLSNL.GetValue("ForceEncryption")

                #Examine what we found...
                If ([string]::IsNullOrEmpty($NodeThumb)) {
                    $Status = "Open"
                    $FindingDetails += "No certificate is assigned for encryption on node $sqlnode.`n"

                }
                ElseIf ($fForceEnc -eq 0) {
                    $Status = "Open"
                    $FindingDetails += "Force Encryption value is 0 (no encryption) on node $sqlnode.`n"

                }
                else {
                    $FindingDetails += "Force Encryption value is 1.`n"
                    if ($Thumbprint -eq $NodeThumb) {
                        $FindingDetails += "The encryption cert matches the one on $sqlHost.`n"
                    }
                    else {
                        $Status = "Open"
                        $FindingDetails += "The encryption cert on $sqlnode does not match the one on $sqlHost.`n"
                    }
                }
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

Function Get-V213967 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213967
        STIG ID    : SQL6-D0-008300
        Rule ID    : SV-213967r879609_rule
        CCI ID     : CCI-000197
        Rule Name  : SRG-APP-000172-DB-000075
        Rule Title : Confidentiality of information during transmission is controlled through the use of an approved TLS version.
        DiscussMD5 : 5E401BBAC058A556F67269DE379DD5FB
        CheckMD5   : B25A8863CB73C4B3EAF546795F12829F
        FixMD5     : 5434FFEF231A993C4AA0175C125D98B7
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
    $BasePath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\'

    $arrProtocols = @(
        @{Protocol = 'TLS 1.2'; Disabled = 0; Enabled = 1}
        @{Protocol = 'TLS 1.1'; Disabled = 1; Enabled = 0}
        @{Protocol = 'TLS 1.0'; Disabled = 1; Enabled = 0}
        @{Protocol = 'SSL 2.0'; Disabled = 1; Enabled = 0}
        @{Protocol = 'SSL 3.0'; Disabled = 1; Enabled = 0}
    )

    foreach ($prot in $arrProtocols) {
        foreach ($CS in 'Client', 'Server') {
            $path = ($BasePath, $prot.Protocol, $CS -join '\')
            $iDisabled = $iEnabled = ''
            if (Test-Path $path) {
                $o = Get-ItemProperty $path -Name DisabledByDefault -ErrorAction SilentlyContinue
                if (($o) -and [bool]($o.PSobject.Properties.name -match "DisabledByDefault")) {
                    $iDisabled = $o.DisabledByDefault
                }

                $o = Get-ItemProperty $path -Name Enabled -ErrorAction SilentlyContinue
                if (($o) -and [bool]($o.PSobject.Properties.name -match "Enabled")) {
                    $iEnabled = $o.Enabled
                }
            } # if (test-path $path)

            if ($iDisabled -ne $prot.Disabled) {
                $FindingDetails += "$path,DisabledByDefault should be [$($prot.Disabled)] instead of [$iDisabled].`n"
            }
            if ($iEnabled -ne $prot.Enabled) {
                $FindingDetails += "$path,Enabled should be [$($prot.Enabled)] instead of [$iEnabled].`n"
            }
        } # foreach ($CS in 'Client','Server')
    } # foreach ($prot in $arrProtocols)

    if ($FindingDetails -eq '') {
        $Status = 'NotAFinding'
        $FindingDetails = 'The TLS and SSL settings are in compliance.'
    }
    else {
        $Status = 'Open'
        # 20201027 JJS Added all Results to output
        $FindingDetails = "The TLS and SSL settings are Not in compliance.`n$($FindingDetails | Format-Table -AutoSize| Out-String)" # JJS Added
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213968 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213968
        STIG ID    : SQL6-D0-008400
        Rule ID    : SV-213968r879613_rule
        CCI ID     : CCI-000186
        Rule Name  : SRG-APP-000176-DB-000068
        Rule Title : SQL Server must enforce authorized access to all PKI private keys stored/utilized by SQL Server.
        DiscussMD5 : C8DB916557003ABAAE6DA0AE6A0FE977
        CheckMD5   : 07EE4067DF325ABAD105D1E4F556ECEA
        FixMD5     : F484C5A5AA933DC4F03480026E4BAAA1
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
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String #Shutdown without Logon is NOT Disabled
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

Function Get-V213969 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213969
        STIG ID    : SQL6-D0-008700
        Rule ID    : SV-213969r879616_rule
        CCI ID     : CCI-000803
        Rule Name  : SRG-APP-000179-DB-000114
        Rule Title : SQL Server must use NIST FIPS 140-2 or 140-3 validated cryptographic modules for cryptographic operations.
        DiscussMD5 : 3638A4CF22A4C64BC04DE179FF8762BB
        CheckMD5   : 5360DB73E7A0B773FF945EF8A469AE20
        FixMD5     : 8A696BA87A08E09D7882A042F1273B52
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
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String #Shutdown without Logon is NOT Disabled
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

Function Get-V213970 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213970
        STIG ID    : SQL6-D0-008800
        Rule ID    : SV-213970r879617_rule
        CCI ID     : CCI-000804
        Rule Name  : SRG-APP-000180-DB-000115
        Rule Title : SQL Server must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).
        DiscussMD5 : 34AA47BA173BB91D440FC73F875E6E3E
        CheckMD5   : 7691310A71BC5D3654E4C7D97827CD5F
        FixMD5     : 4324588A18B372A4319DFCC99EAC3A55
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
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "SELECT name, type_desc FROM sys.server_principals WHERE type in ('S','U')"

    if (!$res) {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check query."
    }
    else {
        $Status = "Not_Reviewed"
        # 20201021 JJS Fixed output
        $FindingDetails = "Verify server documentation to ensure accounts are documented and unique:`n$($res | Format-Table -AutoSize| Out-String)"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213971 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213971
        STIG ID    : SQL6-D0-009200
        Rule ID    : SV-213971r879639_rule
        CCI ID     : CCI-001188
        Rule Name  : SRG-APP-000224-DB-000384
        Rule Title : SQL Server must maintain the authenticity of communications sessions by guarding against man-in-the-middle attacks that guess at Session ID values.
        DiscussMD5 : DB8F7BD4ADCEAE9D0A153EFF98B105F6
        CheckMD5   : 6C9C8BF730984EEC00683A501EB0B198
        FixMD5     : 55340A06BB91640085504340B962D795
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
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String #Shutdown without Logon is NOT Disabled
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

Function Get-V213972 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213972
        STIG ID    : SQL6-D0-009500
        Rule ID    : SV-213972r879642_rule
        CCI ID     : CCI-001199
        Rule Name  : SRG-APP-000231-DB-000154
        Rule Title : SQL Server must protect the confidentiality and integrity of all information at rest.
        DiscussMD5 : 79B942D3646C93D76A7707AB0A3A081A
        CheckMD5   : 1374BE73B139882C0053E786C13162C3
        FixMD5     : D9F3FC2D4A088D8B89F95C9DE96AE838
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
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "SELECT
d.name AS [Database Name],
CASE e.encryption_state
WHEN 0 THEN 'No database encryption key present, no encryption'
WHEN 1 THEN 'Unencrypted'
WHEN 2 THEN 'Encryption in progress'
WHEN 3 THEN 'Encrypted'
WHEN 4 THEN 'Key change in progress'
WHEN 5 THEN 'Decryption in progress'
WHEN 6 THEN 'Protection change in progress'
END AS [Encryption State]
FROM sys.dm_database_encryption_keys e
RIGHT JOIN sys.databases d ON DB_NAME(e.database_id) = d.name
WHERE d.name NOT IN ('master','model','msdb')
ORDER BY [Database Name]"

    if (!$res) {
        $Status = "NotAFinding"
        $FindingDetails = "No results were returned by the check query."
    }
    else {
        $Status = "Not_Reviewed"
        $FindingDetails = "For each user database where encryption is required, verify that encryption is in effect:`n$($res | Format-Table -AutoSize| Out-String)"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213975 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213975
        STIG ID    : SQL6-D0-009800
        Rule ID    : SV-213975r879649_rule
        CCI ID     : CCI-001090
        Rule Name  : SRG-APP-000243-DB-000373
        Rule Title : SQL Server must prevent unauthorized and unintended information transfer via shared system resources.
        DiscussMD5 : 66C544DC3927A0593C202B3876F4E863
        CheckMD5   : 567A16906A1A70EA33611831E556C9F2
        FixMD5     : 63696CB248FBB2B4D5CB3133D90EA761
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
    $SQLEdition = Get-ISQL -ServerInstance $Instance -Database $Database "
    select SERVERPROPERTY('Edition') as [edition]
    "

    [regex]$EditionReg = '(Standard)+|(Express)+|(Web)+'
    if ($SQLEdition.edition -match $EditionReg) {
        $Status = "Open"
        $FindingDetails = "Common Criteria Compliance is only available in Enterprise and Data Center Editions of SQL Server. Per DISA STIG Support, any SQL Edition that does not support CCC is a permanent 'Open'.`n$($SQLEdition | Format-Table -AutoSize| Out-String)"
    }
    else {
        $res = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT @@servername as instance
             , value_in_use
          FROM sys.configurations
          WHERE name = 'common criteria compliance enabled'
          "
        if ($res.value_in_use -ne 1) {
            $Status = 'Open'
            $FindingDetails = "Instance does not have Common Criteria Compliance enabled. If disabling CCC has been documented and approved due to performance reasons, then this may be downgraded to a CAT III finding.`n$($SQLEdition | Format-Table -AutoSize| Out-String). `n$($res | Format-Table -AutoSize| Out-String)"
        }
        Else {
            $Status = 'NotAFinding'
            $FindingDetails = "Instance has Common Criteria Compliance enabled.`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V213976 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213976
        STIG ID    : SQL6-D0-009900
        Rule ID    : SV-213976r951670_rule
        CCI ID     : CCI-001090
        Rule Name  : SRG-APP-000243-DB-000373
        Rule Title : SQL Server must prevent unauthorized and unintended information transfer via Instant File Initialization (IFI).
        DiscussMD5 : 74BDB0AD35D313D4DC4DC786CC5A93DB
        CheckMD5   : 47093745C02ABCAD943823F30AFE45A5
        FixMD5     : EE83AD24E6EF0B3051F0F7B3E74C99B1
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
            , service_account
         from sys.dm_server_services
        where instant_file_initialization_enabled = 'Y'
    "
    if ($res) {
        $FindingDetails += "DBA, confirm that IFI is documented as required for these instances:`n$($res | Format-Table -AutoSize| Out-String)"
    }

    if ($FindingDetails -eq "") {
        $Status = "NotAFinding"
        $FindingDetails = "No instances appear to be using IFI."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213977 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213977
        STIG ID    : SQL6-D0-010000
        Rule ID    : SV-213977r879649_rule
        CCI ID     : CCI-001090
        Rule Name  : SRG-APP-000243-DB-000374
        Rule Title : Access to database files must be limited to relevant processes and to authorized, administrative users.
        DiscussMD5 : C03AD3CE46BDF8BFA6C4A2ECFB36B6E5
        CheckMD5   : 31EC4DBA96F706D5732D99B95DC24F04
        FixMD5     : 043293298F1EACCB39732D24B4AC3387
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

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "select @@ServerName as ServerName, @@ServiceName as InstanceName"

    if ($res) {

        $res | ForEach-Object {

            $sServerName = $_.ServerName

            $sInstance = $_.InstanceName

            # First add accounts for the SQL Service

            $sServName = 'MSSQLSERVER'

            if ($sInstance -ne $sServName) {

                $sServName = "mssql`$$sInstance"

            } # service name will either be mssqlserver or mssql$sqlnn

            $sname = (Get-CimInstance win32_service | Where-Object name -EQ $sServName).startname

            $hashBase[$sname] = @('FullControl') # add authorizations for the account on the service

            $hashDataLog[$sname] = @('FullControl') # add authorizations for the account on the service

            $hashBackup[$sname] = @('FullControl') # add authorizations for the account on the service

            # Add accounts for the SQL Agent

            $sAgtName = 'SQLSERVERAGENT'

            if ($sInstance -ne $sServName) {

                $sAgtName = "SQLAgent`$$sInstance"

            } # service name will either be SQLSERVERAGENT or SQLAgent$sqlnn

            $ssasrv = (Get-CimInstance win32_service | Where-Object name -EQ $sAgtName)  # at some point we need code for SQLAgent on a default instance

            if ($ssasrv) {

                $sname = $ssasrv.startname

                $hashBackup[$sname] = @('FullControl')

            }

        } # $res.InstanceName | foreach-object

    } # if ($res)


    # Poll MSSQL to get directories of interest...
    Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT distinct @@servername ServerName
            , @@servicename Instance
            , directorytype
            , case when directoryname like '%\' then left(directoryname, len(directoryname)-1) else directoryname end directoryname
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

Function Get-V213978 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213978
        STIG ID    : SQL6-D0-010100
        Rule ID    : SV-213978r879656_rule
        CCI ID     : CCI-001314
        Rule Name  : SRG-APP-000267-DB-000163
        Rule Title : SQL Server must reveal detailed error messages only to the ISSO, ISSM, SA, and DBA.
        DiscussMD5 : D6B89D01BCF6E3C96D08DB2790A0578B
        CheckMD5   : 96F254FB8F0D287DCFCA91E11A32CF28
        FixMD5     : BF05037ECBAE3B8320963B04F0955B54
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
        USE master
        GO
        SELECT Name
        FROM syslogins
        WHERE (sysadmin = 1 or securityadmin = 1)
        and hasaccess = 1"

    if ($res) {
        $FindingDetails = "Review user list to make sure SQL Server reveals detailed error messages only to the ISSO, ISSM, SA, and DBA:`n$($res | Format-Table -AutoSize| Out-String)"
    }
    else {
        $Status = "Open"
        $FindingDetails = "No results were returned by the check query."
    }


    $ErrorLogLocations = @()
    $SqlArgs = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\*\mssqlserver\Parameters" -Name SQLArg*
    $NumberOfArguments = ($SQLArgs | Get-Member | Where-Object {$_.Name -like "SQLArg*"} | Measure-Object).Count
    For ($i = 1; $i -le $NumberOfArguments; $i++) {
        if ($SqlArgs."SQLArg$i" -match '^-e') {
            $ErrorLogLocations += $SqlArgs."SQLArg$i" -replace '^-e'
        }
    }

    $FindingDetails += "`nAlso review these ACLs for the error log to ensure only authorized users have access:`n"
    ForEach ($ErrorLog in $ErrorLogLocations) {
        # Checking for path existence because on a cluster, the instance could be listed in the registry but currently running on a different node
        if (Test-Path $ErrorLog) {
            $ErrorLogPath = [System.IO.Path]::GetDirectoryName($ErrorLog)

            #Get ACL for the actual Error Log file
            $ReturnedACLs = (Get-Acl $ErrorLog).Access | Sort-Object IdentityReference
            If (($ReturnedACLs | Measure-Object).Count -gt 0) {
                $FindingDetails += "ACLs for $($ErrorLog):" | Out-String
                ForEach ($ACL in $ReturnedACLs) {
                    $FindingDetails += "`tFile System Rights:`t$($ACL.FileSystemRights)" | Out-String
                    $FindingDetails += "`tIdentity Reference:`t$($ACL.IdentityReference)" | Out-String
                    $FindingDetails += "`tIs Inherited:`t`t$($ACL.IsInherited)" | Out-String
                    $FindingDetails += "`tInheritance Flags:`t$($ACL.InheritanceFlags)" | Out-String
                    $FindingDetails += "`tPropagation Flags:`t$($ACL.PropagationFlags)" | Out-String
                    $FindingDetails += "" | Out-String
                }
                $FindingDetails += "" | Out-String
            }
            #Get the ACLs for the folder containing the Error Log
            $ReturnedACLs = ""
            $ReturnedACLs = (Get-Acl $ErrorLogPath).Access | Sort-Object IdentityReference
            If (($ReturnedACLs | Measure-Object).Count -gt 0) {
                $FindingDetails += "ACLs for $($ErrorLogPath):" | Out-String
                ForEach ($ACL in $ReturnedACLs) {
                    $FindingDetails += "`tFile System Rights:`t$($ACL.FileSystemRights)" | Out-String
                    $FindingDetails += "`tIdentity Reference:`t$($ACL.IdentityReference)" | Out-String
                    $FindingDetails += "`tIs Inherited:`t`t$($ACL.IsInherited)" | Out-String
                    $FindingDetails += "`tInheritance Flags:`t$($ACL.InheritanceFlags)" | Out-String
                    $FindingDetails += "`tPropagation Flags:`t$($ACL.PropagationFlags)" | Out-String
                    $FindingDetails += "" | Out-String
                }
            }
        } # if (test-path $ErrorLog)
    } # ForEach ($ErrorLog in $ErrorLogLocations)
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213979 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213979
        STIG ID    : SQL6-D0-010400
        Rule ID    : SV-213979r879717_rule
        CCI ID     : CCI-002235
        Rule Name  : SRG-APP-000340-DB-000304
        Rule Title : SQL Server must prevent non-privileged users from executing privileged functions, to include disabling, circumventing, or altering implemented security safeguards/countermeasures.
        DiscussMD5 : E0B93D12BEAEE9E7A73A237441C31C84
        CheckMD5   : 49D3F2967B46F1F3603DC3C143E0BD8B
        FixMD5     : 05C4DF681A5DA99D64F505E50041AAC7
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
    SELECT DISTINCT
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
        P2.type_desc AS [Grantor Type]
    FROM sys.server_permissions SP
        INNER JOIN sys.server_principals P1 ON P1.principal_id = SP.grantee_principal_id
        INNER JOIN sys.server_principals P2 ON P2.principal_id = SP.grantor_principal_id
        FULL OUTER JOIN sys.servers S ON SP.class_desc = 'SERVER'
            AND S.server_id = SP.major_id
        FULL OUTER JOIN sys.endpoints E ON SP.class_desc = 'ENDPOINT'
            AND E.endpoint_id = SP.major_id
        FULL OUTER JOIN sys.server_principals P ON SP.class_desc = 'SERVER_PRINCIPAL'
            AND P.principal_id = SP.major_id
    "

    $res2 = Get-ISQL -ServerInstance $Instance -Database $Database "
        SELECT R.name AS [Role],
            M.Name AS [Member]
        FROM sys.server_role_members X
            INNER JOIN sys.server_principals R ON R.principal_id = X.role_principal_id
            INNER JOIN sys.server_principals M ON M.principal_id = X.member_principal_id
    "

    $FindingDetails += "DBA, ensure that:" | Out-String
    $FindingDetails += "`t1. Actual permissions match documented requirements in the system security plan." | Out-String
    $FindingDetails += "`t2. Only documented and approved logins have priviledged functions." | Out-String
    $FindingDetails += "`t3. The current configuration matches the documented baseline." | Out-String
    $FindingDetails += "" | Out-String
    $FindingDetails += $res | Format-Table -AutoSize | Out-String
    $FindingDetails += $res2 | Format-Table -AutoSize | Out-String
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213980 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213980
        STIG ID    : SQL6-D0-010500
        Rule ID    : SV-213980r879719_rule
        CCI ID     : CCI-002233
        Rule Name  : SRG-APP-000342-DB-000302
        Rule Title : Use of credentials and proxies must be restricted to necessary cases only.
        DiscussMD5 : 7677070C83BA39F838FBF28A617A3C67
        CheckMD5   : F9C2CD2288D20358AE72670048E44AB6
        FixMD5     : 647BF7E5F623C02D916B61E2BC500AE5
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
        #$Status = 'Open'
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

Function Get-V213983 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213983
        STIG ID    : SQL6-D0-010900
        Rule ID    : SV-213983r879730_rule
        CCI ID     : CCI-001849
        Rule Name  : SRG-APP-000357-DB-000316
        Rule Title : SQL Server must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.
        DiscussMD5 : 0291FB1C43D07B85E75591418B9C49B8
        CheckMD5   : 680A767716BB17F87E37ACE14932ABE7
        FixMD5     : 9D6DDDCAF5BF58C307C0782FED7487B2
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
        BEGIN
        DECLARE @Status BIT
        IF (SELECT COUNT(audit_id) FROM sys.server_audits WHERE type='SL' OR type='AL') > 0
            AND (SELECT COUNT(audit_id) FROM sys.server_audits WHERE type='FL') = 0
            BEGIN
                SET @Status = 1
            END
        ELSE
            BEGIN
                SET @Status = 0
            END
        SELECT @Status AS 'Status'
        END
    "
    If ($res.Status -eq $true) {
        $Status = "Not_Applicable"
        $FindingDetails += "All audits use either the APPLICATION or SECURITY event log, therefore this is N/A." | Out-String
    }
    Else {
        $res2 = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT @@servername as instance
                , max_file_size
                , max_rollover_files
                , max_files
                , log_file_path
            FROM sys.server_file_audits
        "
        if ($res2) {
            $res2 | ForEach-Object {
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
            } # $res2 | foreach-object
            if ($FindingDetails -eq '') {
                $Status = 'NotAFinding'
                $FindingDetails += "All audit storage is within capacity."
            } # if ($FindingDetails -eq '')
        }
        else {
            $Status = "Open"
            $FindingDetails = 'No audits are defined at all, but the STIG doesn''t allow for "Not Applicable."'
        } #   if ($res2)
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213986 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213986
        STIG ID    : SQL6-D0-011200
        Rule ID    : SV-213986r879747_rule
        CCI ID     : CCI-001890
        Rule Name  : SRG-APP-000374-DB-000322
        Rule Title : SQL Server must record time stamps in audit records and application data that can be mapped to Coordinated Universal Time (UTC, formerly GMT).
        DiscussMD5 : 90F72AE2AEAC7318800CD6BDAC8F0235
        CheckMD5   : 7425A83D4A77790F4CBB2417FF6D335B
        FixMD5     : 176A8A0E288054109299D23BDF375E8D
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

Function Get-V213987 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213987
        STIG ID    : SQL6-D0-011400
        Rule ID    : SV-213987r879753_rule
        CCI ID     : CCI-001813
        Rule Name  : SRG-APP-000380-DB-000360
        Rule Title : SQL Server must enforce access restrictions associated with changes to the configuration of the instance.
        DiscussMD5 : BF4BBC3B2D5E5C232F2FD45CF2043C4E
        CheckMD5   : 570C22023EB9068788A968442E2B72C6
        FixMD5     : 3CA77E43A66C9CE28D7F3322159F9844
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
    # Commented out 5-5-22 #302 per E. Spears return "NR"
    if ($findingdetails -eq '') {
        $status = "NotAFinding"
        $findingdetails = "the check queries did not find any accounts other than those authorized in the ssp."
    }
    else {
        # 5-12-22 This needs to be reviewed, keep default status, commented line below
        # $status = 'open'
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213988 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213988
        STIG ID    : SQL6-D0-011500
        Rule ID    : SV-213988r879753_rule
        CCI ID     : CCI-001813
        Rule Name  : SRG-APP-000380-DB-000360
        Rule Title : Windows must enforce access restrictions associated with changes to the configuration of the SQL Server instance.
        DiscussMD5 : BF4BBC3B2D5E5C232F2FD45CF2043C4E
        CheckMD5   : 740BCA140FB5748343CB6E25EAA89B4E
        FixMD5     : 960280DCB946E5D563E1C4D172FABAA6
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
    $FindingDetails +=

    try { $res = Get-LocalGroupMember -Group (Get-LocalGroup Administrators).Name }
    catch {
      $res = ""
    }

    if ($res) {
        # 5-12-22 This needs to be reviewed, keep default status, commented line below
        # $Status = 'Open'
        $FindingDetails += "DBA, ensure the following have been documented as authorized to be in the server's local Administrators group:`n$($res | Format-Table -AutoSize| Out-String)"
    }
    else {
        $Status = "NotAFinding" # Commented out 5-5-22 per E. Spears, "change to NR"
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

Function Get-V213989 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213989
        STIG ID    : SQL6-D0-011800
        Rule ID    : SV-213989r879754_rule
        CCI ID     : CCI-001814
        Rule Name  : SRG-APP-000381-DB-000361
        Rule Title : SQL Server must produce audit records of its enforcement of access restrictions associated with changes to the configuration of SQL Server or database(s).
        DiscussMD5 : 65D3C447E5D5484160C4CC0329E6F40C
        CheckMD5   : 9B9D50290DB390A2447EB65DB3BCBE26
        FixMD5     : D2B86F6B70C45330EE7D269CAE74F718
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

Function Get-V213990 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213990
        STIG ID    : SQL6-D0-011900
        Rule ID    : SV-213990r879756_rule
        CCI ID     : CCI-001762
        Rule Name  : SRG-APP-000383-DB-000364
        Rule Title : SQL Server must disable network functions, ports, protocols, and services deemed by the organization to be nonsecure, in accord with the Ports, Protocols, and Services Management (PPSM) guidance.
        DiscussMD5 : D8B1B90771AA0326A7960EA7BF7704C2
        CheckMD5   : 56CB4D7C7855D9543E123C78348B8732
        FixMD5     : 0A1154C0A182DE11CEBC149AF9C040EF
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
        # 20201104 added trim functions
        # 20201104 JJS Added ISNULL
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
        #$Status = 'Open'
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

Function Get-V213991 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213991
        STIG ID    : SQL6-D0-012300
        Rule ID    : SV-213991r879802_rule
        CCI ID     : CCI-002530
        Rule Name  : SRG-APP-000431-DB-000388
        Rule Title : SQL Server must maintain a separate execution domain for each executing process.
        DiscussMD5 : CFE6403CDA6AD739AAFF7CBB3CB8E3DF
        CheckMD5   : 30301968204286A0389B1B5E333AD878
        FixMD5     : 68A11DA0CB3C1E5DF3FF1825550DF4C2
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
      select name, value, value_in_use
        from sys.configurations
       where name = 'clr enabled'
    "
    $resval1 = $($res | where-object {$_.value -gt 0 -or $_.value_in_use -gt 0})

    if ($resval1) {
        $FindingDetails = "DBA, check system documentation to see if the use of CLR assemblies is required.`n"
    }
    else {
        $FindingDetails = "Not a finding: CLR is not enabled.`n"
        $Status = "NotAFinding"
    }
    $FindingDetails += $($res | Format-Table -AutoSize| Out-String)
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213992 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213992
        STIG ID    : SQL6-D0-012400
        Rule ID    : SV-213992r879802_rule
        CCI ID     : CCI-002530
        Rule Name  : SRG-APP-000431-DB-000388
        Rule Title : SQL Server services must be configured to run under unique dedicated user accounts.
        DiscussMD5 : 1B30389FC3D5426252862C231461F01B
        CheckMD5   : F977B736364E0D8A6F195B2D22A73BEB
        FixMD5     : F9C33C92B2EE496ACDEEF3996B48E1C8
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
    $res = (Get-CimInstance Win32_Service | Where-Object {$_.DisplayName -Like 'SQL Server*' -or $_.DisplayName -like 'SQL Full*'} | Group-Object StartName | Where-Object Count -gt 1)
    if ($res) {
        $Status = 'Open'
        $FindingDetails += "The following services are configured with the same service account:`n$(
        $res | Select-Object -ExpandProperty group | Format-Table startname, name, displayname -AutoSize| Out-String
        )"
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "All SQL services are running under unique accounts."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213993 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213993
        STIG ID    : SQL6-D0-012700
        Rule ID    : SV-213993r879825_rule
        CCI ID     : CCI-002617
        Rule Name  : SRG-APP-000454-DB-000389
        Rule Title : When updates are applied to SQL Server software, any software components that have been replaced or made unnecessary must be removed.
        DiscussMD5 : BC2BA832AB9AF85CA7BD7C72B52BD0EC
        CheckMD5   : EDCC1BBEAB8E9FF94737D797F65E9365
        FixMD5     : F8BA2173C775505DCD0AF949A1DCBA2D
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
    #$res = $ProductFeatures
    $res = Get-SqlProductFeatures $Instance

    if (!$res) {
        $Status = "Open"
        $FindingDetails = "No results were returned from Sql Install Summary File $($SqlInstallSummaryFile)"
    }
    else {
        $Status = "Not_Reviewed"
        #$FindingDetails = "Microsoft SQL Product Features Installed:`n$($res | format-table -AutoSize| out-string)"
        $FindingDetails = "$($res | Format-Table -AutoSize| Out-String)"

    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213994 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213994
        STIG ID    : SQL6-D0-012800
        Rule ID    : SV-213994r917657_rule
        CCI ID     : CCI-002605
        Rule Name  : SRG-APP-000456-DB-000390
        Rule Title : Security-relevant software updates to SQL Server must be installed within the time period directed by an authoritative source (e.g. IAVM, CTOs, DTMs, and STIGs).
        DiscussMD5 : ECF63F45593617C9CBC6F01A57EF9C0A
        CheckMD5   : 837DDA780CC100B7C57F3479967B3882
        FixMD5     : 2CC3D323887E94842521D35E74AF6D54
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
    $res = Get-ISQL -ServerInstance $Instance -Database $Database "select @@version as Version"

    if (!$res) {
        $Status = "Open"
        $FindingDetails = "No results were returned by the check query."
    }
    else {
        $Status = "Not_Reviewed"
        $FindingDetails = "Verify Security-relevant software updates to SQL Server must be installed within the time period directed by an authoritative source (e.g. IAVM, CTOs, DTMs, and STIGs):`n$($res | Format-Table -AutoSize| Out-String)"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V213995 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213995
        STIG ID    : SQL6-D0-012900
        Rule ID    : SV-213995r879863_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000492-DB-000332
        Rule Title : SQL Server must be able to generate audit records when successful and unsuccessful attempts to access security objects occur.
        DiscussMD5 : 19560B065298B0CD3180B407A41C7A56
        CheckMD5   : 70F63B091EFD14E36C5CDD0A82CE887B
        FixMD5     : 0811B8D01FAACF489274ACE6E2689CC9
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
    $Compliant = $true

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
    SELECT @@servername as instance
        , db_name() as databasename
        , name AS 'Audit Name'
        , status_desc AS 'Audit Status'
        , audit_file_path AS 'Current Audit File'
    FROM sys.dm_server_audit_status
    "
    If ($res) {
        $FindingDetails += "An audit is configured and running:`n$($res | Format-Table -AutoSize | Out-String)"
    }
    Else {
        $FindingDetails += "No audit is configured or running.`n$($res | Format-Table -AutoSize | Out-String)"
        $Compliant = $False
    }

    $res = Get-ISQL -ServerInstance $Instance -Database $Database "
    SELECT @@servername as instance
        , db_name() as databasename
        , a.name AS 'AuditName'
        , s.name AS 'SpecName'
        , d.audit_action_name AS 'ActionName'
        , d.audited_result AS 'Result'
    FROM sys.server_audit_specifications s
        JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
        JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
    WHERE a.is_state_enabled = 1
        AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP'
    "
    if ($res) {
        $FindingDetails += "`nThe SCHEMA_OBJECT_ACCESS_GROUP is included in the server audit specification.`n$($res | Format-Table -AutoSize | Out-String)"
    }
    else {
        $Compliant = $False
        $FindingDetails = "`nThe SCHEMA_OBJECT_ACCESS_GROUP was not returned in an active audit.`n$($res | Format-Table -AutoSize| Out-String)"
    }

    If ($Compliant -eq $false) {
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

Function Get-V213998 {
    <#
    .DESCRIPTION
        Vuln ID    : V-213998
        STIG ID    : SQL6-D0-013200
        Rule ID    : SV-213998r902989_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000494-DB-000345
        Rule Title : SQL Server must generate audit records when successful and unsuccessful attempts to access categorized information (e.g., classification levels/security levels) occur.
        DiscussMD5 : 9701A279BE24C8E72342CD5384C558BC
        CheckMD5   : 835625D9DA8ABCE271AFD8D22C196E11
        FixMD5     : 8DEEE5EAFD3B41EB88BB16EA4E14F998
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
    } else {
        $Status = "Open"
        $FindingDetails = "DBA, no audits are being done. Does the SSP agree this is OK?"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214000 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214000
        STIG ID    : SQL6-D0-013400
        Rule ID    : SV-214000r902991_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000495-DB-000327
        Rule Title : SQL Server must generate audit records when successful and unsuccessful attempts to add privileges/permissions occur.
        DiscussMD5 : 85648AB396EC0F3F046D918415F9788D
        CheckMD5   : FBD231E0FD0F9B503AAD9EE00E1DC255
        FixMD5     : D8473E88E5E11DAFB0CF74A68998D586
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

Function Get-V214002 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214002
        STIG ID    : SQL6-D0-013600
        Rule ID    : SV-214002r902993_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000495-DB-000329
        Rule Title : SQL Server must generate audit records when successful and unsuccessful attempts to modify privileges/permissions occur.
        DiscussMD5 : 244B9981CB28420A160DFAE80ED6F6F0
        CheckMD5   : F3BF31744476BE84B2FD5DC59D1ED2C5
        FixMD5     : D8473E88E5E11DAFB0CF74A68998D586
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

Function Get-V214004 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214004
        STIG ID    : SQL6-D0-013800
        Rule ID    : SV-214004r902994_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000496-DB-000335
        Rule Title : SQL Server must generate audit records when successful and unsuccessful attempts to modify security objects occur.
        DiscussMD5 : 4AB2B1EB15317A0D747AF3890C81F7FF
        CheckMD5   : 5265E372D748872BB001DD3EB7C0E408
        FixMD5     : 5F186267CFA0AAEC9C9FA7F74FDCA72C
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
        SELECT name AS 'Audit Name',
        status_desc AS 'Audit Status',
        audit_file_path AS 'Current Audit File'
        FROM sys.dm_server_audit_status
        "
    if ($res) {
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

    } else {
        $Status = "Open"
        $FindingDetails = "Audits are not configured or being performed."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214006 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214006
        STIG ID    : SQL6-D0-014000
        Rule ID    : SV-214006r902996_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000498-DB-000347
        Rule Title : SQL Server must generate audit records when successful and unsuccessful attempts to modify categorized information (e.g., classification levels/security levels) occur.
        DiscussMD5 : 5E6FD6F88E06C682FAF5F71F28965A39
        CheckMD5   : 526100F3F8167590D92CAE823B4C76D8
        FixMD5     : 2B81AAA94D50462D8485A6F07101831A
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
        SELECT name AS 'Audit Name',
        status_desc AS 'Audit Status',
        audit_file_path AS 'Current Audit File'
        FROM  sys.dm_server_audit_status
        "
    if ($res) {
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
    } else {
        $Status = "Open"
        $FindingDetails = "DBA, no audits are configured or being done. Does the SSP agree this is OK?"

    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214008 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214008
        STIG ID    : SQL6-D0-014200
        Rule ID    : SV-214008r879870_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000499-DB-000331
        Rule Title : SQL Server must generate audit records when successful and unsuccessful attempts to delete privileges/permissions occur.
        DiscussMD5 : 5478DC245BA77342FC1242EC4FA3542D
        CheckMD5   : FD49EEA75210ADF50ED6BB5AAE4E8244
        FixMD5     : A36A4AA9A952971A36DBEE95B4C028A5
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

Function Get-V214010 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214010
        STIG ID    : SQL6-D0-014400
        Rule ID    : SV-214010r902998_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000501-DB-000337
        Rule Title : SQL Server must generate audit records when successful and unsuccessful attempts to delete security objects occur.
        DiscussMD5 : 4A71BFE48C7D1765EE00642352A3E186
        CheckMD5   : 69577605291956AFC9F427CD7C7A0849
        FixMD5     : 247526D9574ED2FBE6F7716BBEA37D1B
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
    } else {
        $Status = "Open"
        $FindingDetails = "Audit is not configured or being performed."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214012 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214012
        STIG ID    : SQL6-D0-014600
        Rule ID    : SV-214012r903000_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000502-DB-000349
        Rule Title : SQL Server must generate audit records when successful and unsuccessful attempts to delete categorized information (e.g., classification levels/security levels) occur.
        DiscussMD5 : B6C5FA0F421AB4C6B12D142C22E3D2CA
        CheckMD5   : 12AFC658BED4AE1B50727255E2219331
        FixMD5     : 2538AC7480ED23E6E32C48D28A3DD90B
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
        SELECT name AS 'Audit Name',
        status_desc AS 'Audit Status',
        audit_file_path AS 'Current Audit File'
        FROM  sys.dm_server_audit_status
        "
    if ($res) {
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
    } else {
        $Status = "Open"
        $FindingDetails = "DBA, no audits are configured or being done.  Does the SSP agree this is OK?"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214014 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214014
        STIG ID    : SQL6-D0-014800
        Rule ID    : SV-214014r903003_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000503-DB-000351
        Rule Title : SQL Server must generate audit records when successful and unsuccessful logons or connection attempts occur.
        DiscussMD5 : 2931829146566BB5117BFCBAE69102C7
        CheckMD5   : BCA40E84B45B8A039D61610EF5C50945
        FixMD5     : 88168411A8EC01912A3945DAE408710A
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
        SELECT name AS 'Audit Name',
        status_desc AS 'Audit Status',
        audit_file_path AS 'Current Audit File'
        FROM sys.dm_server_audit_status
        "
    if ($res) {
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
            $res2 = Get-ISQL -ServerInstance $Instance -Database $Database "
            SELECT a.name AS 'AuditName',
            s.name AS 'SpecName',
            d.audit_action_name AS 'ActionName',
            d.audited_result AS 'Result'
            FROM sys.server_audit_specifications s
            JOIN sys.server_audits a ON s.audit_guid = a.audit_guid
            JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id
            WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SUCCESSFUL_LOGIN_GROUP'
            "
            if ($res2) {
                $Status = 'NotAFinding'
                $FindingDetails = "The FAILED_LOGIN_GROUP and SUCCESSFUL_LOGIN_GROUP audit are being performed.`n$($res | Format-Table -AutoSize| Out-String)"
            } else {
                $Status = "Open"
                $FindingDetails = "The SUCCESSFUL_LOGIN_GROUP audit is not being performed."
            }
        }
        else {
            $Status = "Open"
            $FindingDetails = "The FAILED_LOGIN_GROUP audit is not being performed."
        }
    } else {
        $Status = "Open"
        $FindingDetails = "DBA, no audits are configured or being done.  Does the SSP agree this is OK?"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214015 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214015
        STIG ID    : SQL6-D0-014900
        Rule ID    : SV-214015r879875_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000504-DB-000354
        Rule Title : SQL Server must generate audit records for all privileged activities or other system-level access.
        DiscussMD5 : 39A258A823D253EF190A162C0DB749E6
        CheckMD5   : F5F221C0172CA0B20D0817C64998387A
        FixMD5     : D6A3DF620AF5A55777DFDADE0956D7E1
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

Function Get-V214016 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214016
        STIG ID    : SQL6-D0-015000
        Rule ID    : SV-214016r879875_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000504-DB-000355
        Rule Title : SQL Server must generate audit records when unsuccessful attempts to execute privileged activities or other system-level access occur.
        DiscussMD5 : 9BC6A32DA96779E8DF68C0785C262E4A
        CheckMD5   : 51502D31B19AE54BF03A90A52019C893
        FixMD5     : C03705A1D54533B228256EBE0173ADA7
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

Function Get-V214017 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214017
        STIG ID    : SQL6-D0-015100
        Rule ID    : SV-214017r879876_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000505-DB-000352
        Rule Title : SQL Server must generate audit records showing starting and ending time for user access to the database(s).
        DiscussMD5 : A0BFC402B3F888DAA98FE0DA1D9BF107
        CheckMD5   : 9D3D25DB9BF53D1CFE967FBBCA881EE3
        FixMD5     : C9D5CEC591C5994ED2FDE73C5A2EAC8E
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

Function Get-V214018 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214018
        STIG ID    : SQL6-D0-015200
        Rule ID    : SV-214018r879877_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000506-DB-000353
        Rule Title : SQL Server must generate audit records when concurrent logons/connections by the same user from different workstations occur.
        DiscussMD5 : 87F84590B2A2F0A4FD590A114F3E593A
        CheckMD5   : 26E9CFDC60D270C5DDCE815A83C7ACE5
        FixMD5     : 293E0CF37578F205FB514C816B6FC1D9
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

Function Get-V214020 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214020
        STIG ID    : SQL6-D0-015400
        Rule ID    : SV-214020r903006_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000507-DB-000357
        Rule Title : SQL Server must generate audit records when successful and unsuccessful accesses to objects occur.
        DiscussMD5 : 579E40321744296ADC6B4BE60B1E40C4
        CheckMD5   : 5A440E41795332BAE9637AE6DECD3F63
        FixMD5     : 74A5C7481B191BF2B134F19EB26F83FE
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
    } else {
        $Status = "Open"
        $FindingDetails = "DBA, no audits are configured or being done.  Does the SSP agree this is OK?"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214021 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214021
        STIG ID    : SQL6-D0-015500
        Rule ID    : SV-214021r879879_rule
        CCI ID     : CCI-000172
        Rule Name  : SRG-APP-000508-DB-000358
        Rule Title : SQL Server must generate audit records for all direct access to the database(s).
        DiscussMD5 : E78490DAD7A3C377F0FD4359659C227C
        CheckMD5   : E36B91B9EBD0C46DB70E81738828451B
        FixMD5     : DCE07852AB2EC49EE958B4623EACFB3D
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
    , name AS AuditName, predicate AS AuditFilter
    FROM sys.server_audits
    WHERE predicate IS NOT NULL   "
    if ($res) {
        #$Status = 'Open'
        $FindingDetails += "DBA, inspect the following filters to ensure administrative activities are not being excluded (note that application actions are permitted by the STIG to be excluded):`n$($res | Format-Table -AutoSize -Wrap | Out-String -Width 160)"
    }
    else {
        #$Status = "NotAFinding"
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

Function Get-V214022 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214022
        STIG ID    : SQL6-D0-015600
        Rule ID    : SV-214022r879885_rule
        CCI ID     : CCI-002450
        Rule Name  : SRG-APP-000514-DB-000381
        Rule Title : SQL Server must implement NIST FIPS 140-2 or 140-3 validated cryptographic modules to provision digital signatures.
        DiscussMD5 : 557FD76C2333464C6D04868F4EA0E0AA
        CheckMD5   : 57306A8B565803FF3079C772EF8270C8
        FixMD5     : 40139061FB15444F2AAFC6F91C4B2329
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
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String #Shutdown without Logon is NOT Disabled
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

Function Get-V214023 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214023
        STIG ID    : SQL6-D0-015700
        Rule ID    : SV-214023r879885_rule
        CCI ID     : CCI-002450
        Rule Name  : SRG-APP-000514-DB-000382
        Rule Title : SQL Server must implement NIST FIPS 140-2 or 140-3 validated cryptographic modules to generate and validate cryptographic hashes.
        DiscussMD5 : 557FD76C2333464C6D04868F4EA0E0AA
        CheckMD5   : CE6D633D4445336AB508FFBCF59887C1
        FixMD5     : 55340A06BB91640085504340B962D795
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
            $FindingDetails += "'$($SettingName)' is NOT $($SettingState)" | Out-String #Shutdown without Logon is NOT Disabled
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

Function Get-V214024 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214024
        STIG ID    : SQL6-D0-015800
        Rule ID    : SV-214024r879885_rule
        CCI ID     : CCI-002450
        Rule Name  : SRG-APP-000514-DB-000383
        Rule Title : SQL Server must implement NIST FIPS 140-2 or 140-3 validated cryptographic modules to protect unclassified information requiring confidentiality and cryptographic protection, in accordance with the data owners requirements.
        DiscussMD5 : 4E9C5A4923D3DF681415A1EAB1CD05A9
        CheckMD5   : D856A1860FF49F2FF69EC2245BFE6946
        FixMD5     : 7439A2A4227594EF43E8DC42A410C5E8
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
    #$RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"
    #$RegistryName = "Enabled"
    #$res = Get-ItemPropertyValue $RegistryPath -Name $RegistryName
    #
    #if ($res -eq 0) {
    #    $FindingDetails += "NIST FIPS 140-2 is Not Enabled." | Out-String
    #    $FindingDetails += "`tRegistry Path:`t$($RegistryPath)" | Out-String
    #    $FindingDetails += "`tRegistry Name:`t$($RegistryName)" | Out-String
    #    $FindingDetails += "`tRegistry Value:`t$($Res)" | Out-String
    #}
    #elseif ($res -eq 1) {
    #    $Status = "NotAFinding"
    #    $FindingDetails += "NIST FIPS 140-2 is Enabled." | Out-String
    #    $FindingDetails += "`tRegistry Path:`t$($RegistryPath)" | Out-String
    #    $FindingDetails += "`tRegistry Name:`t$($RegistryName)" | Out-String
    #    $FindingDetails += "`tRegistry Value:`t$($Res)" | Out-String
    #}
    #else {
    #    $FindingDetails += "NIST FIPS 140-2 setting was not found" | Out-String
    #    $FindingDetails += "`tRegistry Path:`t$($RegistryPath)" | Out-String
    #    $FindingDetails += "`tRegistry Name:`t$($RegistryName)" | Out-String
    #    If ($Null -eq $Res -or $Res -eq "") {
    #        $FindingDetails += "`tRegistry Value:`t(Not Found)" | Out-String
    #    }
    #    Else {
    #        $FindingDetails += "`tRegistry Value:`t$($Res)" | Out-String
    #    }
    #}
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

Function Get-V214026 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214026
        STIG ID    : SQL6-D0-016000
        Rule ID    : SV-214026r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-DB-000363
        Rule Title : SQL Server must configure Customer Feedback and Error Reporting.
        DiscussMD5 : 0E43DFE8442D6AED136B5E5C56613959
        CheckMD5   : 9F91074298BF88612055A4BD48237C9F
        FixMD5     : 0F6E90C90D8836C227D151EA6514724A
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
    $res = (
        Get-ItemProperty -Path 'hklm:\SOFTWARE\Microsoft\Microsoft SQL Server\[0-9][0-9]*', 'hklm:\SOFTWARE\Microsoft\Microsoft SQL Server\*\cpe' |
        Where-Object {1 -in $_.CustomerFeedback, $_.EnableErrorReporting} |
        Select-Object @{Name = 'RegistryPath'; Expression = {$_.PSPath -replace 'Microsoft.*MACHINE', 'HKLM'}}, CustomerFeedback, EnableErrorReporting
    )
    if ($res) {
        $Status = 'Open'
        $FindingDetails += "Has CEIP participation been documented as authorized on this system?  The following registry settings were found:`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V214027 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214027
        STIG ID    : SQL6-D0-016100
        Rule ID    : SV-214027r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-DB-000363
        Rule Title : SQL Server must configure SQL Server Usage and Error Reporting Auditing.
        DiscussMD5 : E9DD233B5EF947689C709ECA97A312DE
        CheckMD5   : E349AF95104388A646347A0FDD182D8E
        FixMD5     : 2D8C2513C27AAA2B6B1313FEE92663B8
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
    # See if any SQL Telemetry/CEIP services are enabled.
    $res = Get-Service sqltelemetry* | Where-Object StartType -NE 'Disabled'
    if ($res) {
        #$FindingDetails += "Telemetry is enabled on this system, and probably should not be. If it is authorized, further STIG checks are needed of telemetry auditing."
        # 20201027 JJS Added all Results to output
        $FindingDetails += "Telemetry is enabled on this system, and probably should not be. If it is authorized, further STIG checks are needed of telemetry auditing.`n$($res | Format-Table -AutoSize| Out-String)"

    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "Telemetry is not enabled, so telemetry auditing need not be configured."

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

Function Get-V214028 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214028
        STIG ID    : SQL6-D0-016200
        Rule ID    : SV-214028r879530_rule
        CCI ID     : CCI-000213
        Rule Name  : SRG-APP-000033-DB-000084
        Rule Title : The SQL Server default account [sa] must be disabled.
        DiscussMD5 : 0EE649FF6871BBEAA49182834EF751C3
        CheckMD5   : 6C015E4A530D5003D7A4BDD9F28A748E
        FixMD5     : D369562613C2DA41510D4CA726FA3149
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

Function Get-V214029 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214029
        STIG ID    : SQL6-D0-016300
        Rule ID    : SV-214029r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000092
        Rule Title : SQL Server default account [sa] must have its name changed.
        DiscussMD5 : 7E056C7283BF18C1E7D20F1A5F40A73E
        CheckMD5   : CEEB359166DDAF6AF6A31F8B58E26C5E
        FixMD5     : 5DDF2C962DA20AB0ABBA8C1FE11B6F8F
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

Function Get-V214030 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214030
        STIG ID    : SQL6-D0-016400
        Rule ID    : SV-214030r879719_rule
        CCI ID     : CCI-002233
        Rule Name  : SRG-APP-000342-DB-000302
        Rule Title : Execution of startup stored procedures must be restricted to necessary cases only.
        DiscussMD5 : 7053D2ECB6E19D8A6CF386B06F754EA2
        CheckMD5   : BF584B82D022E1AB5D7387CA4A5AE378
        FixMD5     : 5C2CAF8EC19D6F2FA7C305BBC023F09E
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
    [name] as StoredProc
    From sys.procedures
    Where OBJECTPROPERTY(OBJECT_ID, 'ExecIsStartup') = 1"
    if ($res) {
        $FindingDetails += "Ensure the following stored procedures have been documented as authorized to run at startup:`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V214031 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214031
        STIG ID    : SQL6-D0-016500
        Rule ID    : SV-214031r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-DB-000363
        Rule Title : SQL Server Mirroring endpoint must utilize AES encryption.
        DiscussMD5 : 2CAD6AAD5991B7F8546AA45B8D671622
        CheckMD5   : 1758AA6E692DD8E565D019BB0DD5074D
        FixMD5     : 10D0524D55B255FCE2724DE4818C6133
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

Function Get-V214032 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214032
        STIG ID    : SQL6-D0-016600
        Rule ID    : SV-214032r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-DB-000363
        Rule Title : SQL Server Service Broker endpoint must utilize AES encryption.
        DiscussMD5 : DBCBCD64B40DB648659E58AA8035DA4A
        CheckMD5   : DC88D0E36264393F90876B90A4F1AED0
        FixMD5     : 407C904E3A39AE6661DC980275B510FD
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

Function Get-V214033 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214033
        STIG ID    : SQL6-D0-016700
        Rule ID    : SV-214033r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000093
        Rule Title : SQL Server execute permissions to access the registry must be revoked, unless specifically required and approved.
        DiscussMD5 : DC96F22CCCE3754E07565A4D3A7EAF6B
        CheckMD5   : 8ECEDC166AF04604CD48BCCF9D1B6286
        FixMD5     : A0219EED6D4F610D3AE18539C6B4B946
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
            OBJECT_NAME(major_id) AS [Stored Procedure]
    ,dpr.NAME AS [Principal]
    FROM sys.database_permissions AS dp
    INNER JOIN sys.database_principals AS dpr ON dp.grantee_principal_id = dpr.principal_id
    WHERE major_id IN (
    OBJECT_ID('xp_regaddmultistring')
    ,OBJECT_ID('xp_regdeletekey')
    ,OBJECT_ID('xp_regdeletevalue')
    ,OBJECT_ID('xp_regenumvalues')
    ,OBJECT_ID('xp_regenumkeys')
    ,OBJECT_ID('xp_regremovemultistring')
    ,OBJECT_ID('xp_regwrite')
    ,OBJECT_ID('xp_instance_regaddmultistring')
    ,OBJECT_ID('xp_instance_regdeletekey')
    ,OBJECT_ID('xp_instance_regdeletevalue')
    ,OBJECT_ID('xp_instance_regenumkeys')
    ,OBJECT_ID('xp_instance_regenumvalues')
    ,OBJECT_ID('xp_instance_regremovemultistring')
    ,OBJECT_ID('xp_instance_regwrite')
    )
    AND dp.[type] = 'EX'
    ORDER BY dpr.NAME;"
    if ($res) {
        $Status = 'Open'
        $FindingDetails += "Has the accessing of the registry via extended stored procedures been documented as requried and authorized?:`n$($res | Format-Table -AutoSize| Out-String)"
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

Function Get-V214034 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214034
        STIG ID    : SQL6-D0-016800
        Rule ID    : SV-214034r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000093
        Rule Title : Filestream must be disabled, unless specifically required and approved.
        DiscussMD5 : 47571C621522FC1C804AF212606D55E1
        CheckMD5   : C5A3B4FFCAC159EC50A5B2BDD6C9755B
        FixMD5     : 9BDA5C3F02D8E44BF9C80D8989BCACC1
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

Function Get-V214035 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214035
        STIG ID    : SQL6-D0-017000
        Rule ID    : SV-214035r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000093
        Rule Title : Ole Automation Procedures feature must be disabled, unless specifically required and approved.
        DiscussMD5 : D0B6E92AF2E16718CEAE9ED2399E5F28
        CheckMD5   : A3F0A8824C5F385DBBC238EAEA4F369B
        FixMD5     : F99D455B730873585C72B2B3F26FAB9E
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
        where name = 'Ole Automation Procedures'
        and (value > 0 or value_in_use > 0)
    "
    Get-ISQL -ServerInstance $Instance -Database $Database $qry | ForEach-Object {
        if ($_.value -gt 0) {

            #$FindingDetails += "Instance $($_.InstanceName) is configured with OLE Automation Procedures enabled.`n"
            # 20201027 JJS Added all Results to output
            $FindingDetails += "Instance $($_.InstanceName) Value $($_.Value) value_in_use $($_.value_in_use) is configured with OLE Automation Procedures enabled.`n"
        }
        else {
            #$FindingDetails += "Instance $($_.InstanceName) is running with OLE Automation Procedures enabled.`n"
            # 20201027 JJS Added all Results to output
            $FindingDetails += "Instance $($_.InstanceName) Value $($_.Value) value_in_use $($_.value_in_use) is running with OLE Automation Procedures enabled.`n"`

        }
    } # foreach-object

    if ($FindingDetails -gt ' ') {
        $Status = "Open"
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "OLE Automation Procedures are not enabled."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214036 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214036
        STIG ID    : SQL6-D0-017100
        Rule ID    : SV-214036r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000092
        Rule Title : SQL Server User Options feature must be disabled, unless specifically required and approved.
        DiscussMD5 : D89F0534189F128C99D986BF2683867B
        CheckMD5   : ED15FB1819DDD312E2D6F5EA696D8381
        FixMD5     : EB21D1D8D9063354BF432368F8D2DC0A
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
        where name = 'user options'
        and (value > 0 or value_in_use > 0)
    "
    Get-ISQL -ServerInstance $Instance -Database $Database $qry | ForEach-Object {
        if ($_.value -gt 0) {
            #$FindingDetails += "Instance $($_.InstanceName) is configured with User Options enabled.`n"
            # 20201027 JJS Added all Results to output
            $FindingDetails += "Instance $($_.InstanceName) Value $($_.Value) value_in_use $($_.value_in_use) is configured with User Options enabled.`n"

        }
        else {
            #$FindingDetails += "Instance $($_.InstanceName) is running with User Options enabled.`n"
            # 20201027 JJS Added all Results to output
            $FindingDetails += "Instance $($_.InstanceName) Value $($_.Value) value_in_use $($_.value_in_use) is running with User Options enabled.`n"
        }
    } # foreach-object

    if ($FindingDetails -gt ' ') {
        $Status = "Open"
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "User Options are not enabled."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214037 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214037
        STIG ID    : SQL6-D0-017200
        Rule ID    : SV-214037r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000093
        Rule Title : Remote Access feature must be disabled, unless specifically required and approved.
        DiscussMD5 : 4DEC0AD02FEA9F459AA2178DEC273FC9
        CheckMD5   : F61C23765E826D59AA8D3C070E2DEF65
        FixMD5     : F549FBAD4B6ADA5BEEE7BD4C226F8A3E
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
        where name = 'remote access'
        and value > 0
    "
    Get-ISQL -ServerInstance $Instance -Database $Database $qry | ForEach-Object {
        # 20201027 JJS Added all Results to output
        $FindingDetails += "Remote Access is enabled.  Review the system documentation to determine whether the use of Remote Access is required (linked servers) and authorized. If it is not authorized, this is a finding.`n`n"
        $FindingDetails += "Instance $($_.InstanceName) Value $($_.Value) value_in_use $($_.value_in_use) is configured with Remote Access enabled.`n"
    } # foreach-object

    if ($FindingDetails -gt ' ') {
        # 5-5-22 per E. Spears #302, change to NR.
        #$Status = "Open"
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "Remote Access is not enabled."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214038 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214038
        STIG ID    : SQL6-D0-017400
        Rule ID    : SV-214038r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000093
        Rule Title : Hadoop Connectivity feature must be disabled, unless specifically required and approved.
        DiscussMD5 : 03FF90FB57E3E87235EA70C3B4BC7529
        CheckMD5   : 081BDF97F81F3034CF137BF41313B1CD
        FixMD5     : 7500C627B6BE72A266D752A94FD3B600
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
        where name = 'hadoop connectivity'
        and value > 0
    "
    Get-ISQL -ServerInstance $Instance -Database $Database $qry | ForEach-Object {
        #$FindingDetails += "Instance $($_.InstanceName) is configured with Hadoop Connectivity enabled.`n"
        $FindingDetails += "Instance $($_.InstanceName) Value $($_.Value) value_in_use $($_.value_in_use) is configured with Hadoop Connectivity enabled.`n"
    } # foreach-object

    if ($FindingDetails -gt ' ') {
       # 5-12-22 This needs to be reviewed, keep default status, commented line below
       # $Status = "Open"
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "Hadoop Connectivity is not enabled."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214039 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214039
        STIG ID    : SQL6-D0-017500
        Rule ID    : SV-214039r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000093
        Rule Title : Allow Polybase Export feature must be disabled, unless specifically required and approved.
        DiscussMD5 : CD00381D0DB6EE51DEB8B440251A2860
        CheckMD5   : F9194A76F45CD1EF2D43AF898EAC8814
        FixMD5     : 4D1B096A613D1BDF20D6EDCBFE37839A
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
        where name = 'allow polybase export'
        and value > 0
    "
    Get-ISQL -ServerInstance $Instance -Database $Database $qry | ForEach-Object {
        #$FindingDetails += "Instance $($_.InstanceName) is configured with Allow Polybase Export enabled.`n"
        # 20201027 JJS Added all Results to output
        $FindingDetails += "Instance $($_.InstanceName) Value $($_.Value) value_in_use $($_.value_in_use) is configured with Allow Polybase Export enabled.`n"
    } # foreach-object

    if ($FindingDetails -gt ' ') {
        # 5-12-22 This needs to be reviewed, keep default status, commented line below
        # $Status = "Open"
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "Allow Polybase Export is not enabled."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214040 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214040
        STIG ID    : SQL6-D0-017600
        Rule ID    : SV-214040r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000093
        Rule Title : Remote Data Archive feature must be disabled, unless specifically required and approved.
        DiscussMD5 : 80B3040EC98EAFFC2A5B46201572DAB8
        CheckMD5   : 4F107B3502835259C6234CB3424FAFE1
        FixMD5     : 50F6C2EC66B541B1F1E03B14B79527D4
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
        where name = 'remote data archive'
        and value > 0
    "
    Get-ISQL -ServerInstance $Instance -Database $Database $qry | ForEach-Object {
        #$FindingDetails += "Instance $($_.InstanceName) is configured with Remote Data Archive enabled.`n"
        # 20201027 JJS Added all Results to output
        $FindingDetails += "Instance $($_.InstanceName) Value $($_.Value) value_in_use $($_.value_in_use) is configured with Remote Data Archive enabled.`n"
    } # foreach-object

    if ($FindingDetails -gt ' ') {
        # 5-12-22 This needs to be reviewed, keep default status, commented line below
        # $Status = "Open"
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "Remote Data Archive is not enabled."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214041 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214041
        STIG ID    : SQL6-D0-017700
        Rule ID    : SV-214041r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000092
        Rule Title : SQL Server External Scripts Enabled feature must be disabled, unless specifically required and approved.
        DiscussMD5 : 8C1C5B5E2F5E6E6DDF586A832C6DBD4F
        CheckMD5   : 0E789A04C4461DB3D13583ECCA543944
        FixMD5     : F4D91A1914B8E5DA077C5100A7FB31C0
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
        where name = 'external scripts enabled'
        and value > 0
    "
    Get-ISQL -ServerInstance $Instance -Database $Database $qry | ForEach-Object {
        #$FindingDetails += "Instance $($_.InstanceName) is configured with External Scripts Enabled enabled.`n"
        $FindingDetails += "Instance $($_.InstanceName) Value $($_.Value) value_in_use $($_.value_in_use) is configured with External Scripts Enabled enabled.`n"
    } # foreach-object

    if ($FindingDetails -gt ' ') {
        # 5-12-22 This needs to be reviewed, keep default status, commented line below
        # $Status = "Open"
        # 20201027 JJS Added all Results to output
        $FindingDetails = "External Scripts Enabled is enabled.`n$($FindingDetails | Format-Table -AutoSize| Out-String)"
    }
    else {
        $Status = "NotAFinding"
        # 20201027 JJS Added all Results to output
        $FindingDetails = "External Scripts Enabled is not enabled.`n$($FindingDetails | Format-Table -AutoSize| Out-String)"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214042 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214042
        STIG ID    : SQL6-D0-017800
        Rule ID    : SV-214042r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-DB-000363
        Rule Title : The SQL Server Browser service must be disabled unless specifically required and approved.
        DiscussMD5 : 45C5B428D19F521838C47C682854983F
        CheckMD5   : 7F5B90BC60F35F357A80EF9DAFD8D6D1
        FixMD5     : D9030476FDB41E63D003009D8362820C
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
            # 5-12-22 This needs to be reviewed, keep default status, commented line below
            # $Status = "Open"
            # 20201027 JJS Added all Results to output
            $FindingDetails = "The SQL Browser service is not disabled, but if it has been documented and approved as required, this is not a finding.`n$($res | Format-Table -AutoSize| Out-String)"
        } # if ($res.StartType -eq 'Disabled')
    }
    else {
        # 5-12-22 This needs to be reviewed, keep default status, commented line below
        # $Status = "Open"
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

Function Get-V214043 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214043
        STIG ID    : SQL6-D0-017900
        Rule ID    : SV-214043r879587_rule
        CCI ID     : CCI-000381
        Rule Name  : SRG-APP-000141-DB-000092
        Rule Title : SQL Server Replication Xps feature must be disabled, unless specifically required and approved.
        DiscussMD5 : 9946702543175AAC4C98B544806B665A
        CheckMD5   : 9F4AC749D2711E70D620903BE322F5FB
        FixMD5     : BF8BB81BFC1A6FF22E472C9CA5B249CE
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
        where name = 'replication xps'
        and value > 0
    "
    Get-ISQL -ServerInstance $Instance -Database $Database $qry | ForEach-Object {
        $FindingDetails += "Instance $($_.InstanceName) is configured with Replication Xps enabled.`n"
    } # foreach-object

    if ($FindingDetails -gt ' ') {
        # 5-12-22 This needs to be reviewed, keep default status, commented line below
        # $Status = "Open"
        # 20201027 JJS Added all Results to output
        $FindingDetails = "Replication Xps is enabled.`n$($FindingDetails | Format-Table -AutoSize| Out-String)"
    }
    else {
        $Status = "NotAFinding"
        $FindingDetails = "Replication Xps is not enabled."
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214044 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214044
        STIG ID    : SQL6-D0-018000
        Rule ID    : SV-214044r879887_rule
        CCI ID     : CCI-000366
        Rule Name  : SRG-APP-000516-DB-000363
        Rule Title : If the SQL Server Browser Service is specifically required and approved, SQL instances must be hidden.
        DiscussMD5 : 5764D6CCDA4219B97C96CD834C6D671F
        CheckMD5   : 3FDB39E9893D3EB22C9764AB55517B28
        FixMD5     : C744F68F615B5D4E433E9B09B619C3F3
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
    DECLARE @HiddenInstance INT
    EXEC master.dbo.Xp_instance_regread
    N'HKEY_LOCAL_MACHINE',
    N'Software\Microsoft\MSSQLServer\MSSQLServer\SuperSocketNetLib',
    N'HideInstance',
    @HiddenInstance output

    SELECT @@servername instance, CASE
            WHEN @HiddenInstance = 0
                AND Serverproperty('IsClustered') = 0 THEN 'No'
            ELSE 'Yes'
        END AS [Hidden]
    " | ForEach-Object {
        if ($_.Hidden -eq 'No') {
            if ((Get-Service SQLBrowser).StartType -ne 'Disabled') {
                $FindingDetails += "Instance $($_.instance) does not have hidden instances, and its host's SQL Browser is not disabled.`n"
            } # if ((get-service SQLBrowser).StartType -ne 'Disabled')
        } # if ($_.Hidden -eq 'No')
    } # foreach-object
    if ($FindingDetails -eq '') {
        $Status = "NotAFinding"
        $FindingDetails = "The system's instances and sql browser are hidden and/or configured properly."
    }
    else {
        #$Status = 'Open'
        # 20201027 JJS Added all Results to output
        $FindingDetails = "The system's instances and sql browser are not hidden and/or configured properly.`n$($FindingDetails | Format-Table -AutoSize| Out-String)"
    }
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
        $AnswerData = (Get-CorporateComment @GetCorpParams)
        If ($Status -eq $AnswerData.ExpectedStatus) {
            $AFKey = $AnswerData.AFKey
            $AFStatus = $AnswerData.AFStatus
            $Comments = $AnswerData.AFComment | Out-String
        }
    }

    Return Send-CheckResult -Module $([String]$ModuleName) -Status $([String]$Status) -FindingDetails $([String]$FindingDetails) -AFKey $([String]$AFKey) -AFStatus $([String]$AFStatus) -Comments $([String]$Comments) -SeverityOverride $([String]$SeverityOverride) -Justification $([String]$Justification)
}

Function Get-V214045 {
    <#
    .DESCRIPTION
        Vuln ID    : V-214045
        STIG ID    : SQL6-D0-018100
        Rule ID    : SV-214045r879615_rule
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
                #$Status = "Open"
                $FindingDetails += "Instance $h's login authentication mode is $($res.config_value) instead of Windows Authentication.`n"
            }
        } # foreach
    }
    else {
        #$Status = "NotAFinding"
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

Function Get-V259739 {
    <#
    .DESCRIPTION
        Vuln ID    : V-259739
        STIG ID    : SQL6-D0-018300
        Rule ID    : SV-259739r972858_rule
        CCI ID     : CCI-003376
        Rule Name  : SRG-APP-000456-DB-000400
        Rule Title : Microsoft SQL Server products must be a version supported by the vendor.
        DiscussMD5 : A62B17501780D92ECF5A0F54F0183A13
        CheckMD5   : 4BC9485BD1A44632BB35E17365C4CCD4
        FixMD5     : AF105E92BBA8DE7AF1D79E237BEDF4BA
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
    $productlist = Get-CimInstance win32_product -Filter "name like '%SQL%' and vendor like 'Microsoft Corp%'" | Select-Object Name, Version -Unique | Sort-Object Name, Version
    $sqlver = ((Get-ISQL -ServerInstance $Instance -Database $Database 'select @@version').Column1 -split "`n" | Select-String "SQL Server" | Out-String).Trim()

    $FindingDetails = "The following SQL-related products are installed: $($productlist | Format-Table | Out-String)The current version of SQL itself is: $sqlver"
    #---=== End Custom Code ===---#

    If ($PSBoundParameters.AnswerFile) {
        $GetCorpParams = @{
            AnswerFile   = $PSBoundParameters.AnswerFile
            VulnID       = $VulnID
            AnswerKey    = $PSBoundParameters.AnswerKey
            LogPath      = $LogPath
            LogComponent = $LogComponent
            OSPlatform   = $OSPlatform
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        if ($PSBoundParameters.SiteName){
            $GetCorpParams.Sitename = $PSBoundParameters.SiteName
        }
        if ($PSBoundParameters.Instance){
            $GetCorpParams.Instance = $PSBoundParameters.Instance
            $GetCorpParams.Database = $PSBoundParameters.Database
        }
        #>
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBy4bjNiobO7ITU
# 5Uc+wNjMAqadC3nJ23pAwcc1wf/w8aCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCoeVpQq5Oak8baPMfW6eZBBKQnGV7V
# f3eMy0O5ruNM5jANBgkqhkiG9w0BAQEFAASCAQCNNDZU8j3kkdKs6+P4IRp99Woh
# Al2w2vrwpgVUFqnJS2FG7G7ZSbuZJ/woFT+0AxYuhhMgvWUjY411pp1zFf7qJxZp
# dCXrUJ6hMln+/4ZvDCakN0g4nPc+ZvmyMJc/CMIHNv/x0txbZxoQ3GYRVYyP6uxA
# Xbr/T0eLHbIVEWTw6H2K739M28O6hgZRmPdn75dEKqMNk9x4MiY9l0otI67mkQtR
# 0tK68qGcXynx/8C9JZRf7oKWfdpuNlL1lt6A23I3/Zf4OdIgE0aHDIgC5lCS8tn/
# IbmH6WVsH4W8k5W/zzTBOfuQGlExf3Etfj/E0etstBa/O6l4qIOVuWkLDTw8
# SIG # End signature block
