# SQL Initialization
if ([enum]::getvalues([System.Management.Automation.ActionPreference]) -contains 'ignore') {
    $ea_ignore = [System.Management.Automation.ActionPreference]::Ignore
}
else {
    $ea_ignore = [System.Management.Automation.ActionPreference]::SilentlyContinue
}

Function New-ValidationObject {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$Results,

        [Parameter(Mandatory = $true)]
        [ValidateSet($True, $False)]
        [Boolean]$Valid
    )

    $ValidationResults = [PSCustomObject]@{
        Results = $Results
        Valid   = $Valid
    }

    Return $ValidationResults
}

Function Start-ProcessWithOutput ($FileName, $Arguments) {
    # Start a process and get the output.  Start-Process cannot do this without redirecting stdout/stderr to a file.
    $Output = [System.Collections.Generic.List[System.Object]]::new()

    $ProcInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcInfo.FileName = $FileName
    $ProcInfo.Arguments = $Arguments
    $ProcInfo.RedirectStandardError = $true
    $ProcInfo.RedirectStandardOutput = $true
    $ProcInfo.UseShellExecute = $false
    $Process = New-Object System.Diagnostics.Process
    $Process.StartInfo = $ProcInfo
    $Process.Start() | Out-Null

    $NewObj = [PSCustomObject]@{
        StdOut   = $Process.StandardOutput.ReadToEnd()
        StdErr   = $Process.StandardError.ReadToEnd()
        ExitCode = $Process.ExitCode
    }
    $Output.Add($NewObj)

    Return $Output
}

Function Get-SupportedProducts {
    Param (
        [Parameter(Mandatory = $true)]
        [String] $ES_Path
    )

    [XML]$STIGList = Get-Content (Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "STIGList.xml")
    $OutList = New-Object System.Collections.Generic.List[System.Object]
    ForEach ($Node in $STIGList.List.STIG) {
        If (-Not(Test-Path (Join-Path -Path $ES_Path -ChildPath "StigContent" | Join-Path -ChildPath $Node.StigContent))) {
            $STIGVersion = "XCCDF missing"
        }
        Else {
            [xml]$Content = Get-Content (Join-Path -Path $ES_Path -ChildPath "StigContent" | Join-Path -ChildPath $Node.StigContent)
            $STIGVer = $Content.Benchmark.Version
            $STIGRel = ((($Content.Benchmark.'plain-text' | Where-Object { $_.id -eq "release-info" }).'#text' -split 'Benchmark')[0].Trim() -split ' ')[1].Trim()
            $STIGVersion = "V$($STIGVer)R$($STIGRel)"
            $STIGDate = (($Content.Benchmark.'plain-text' | Where-Object { $_.id -eq "release-info" }).'#text' -split 'Date:')[1].Trim()
        }

        $NewObj = [PSCustomObject]@{
            Name       = $Node.Name
            Shortname  = $Node.ShortName
            Version    = $STIGVersion
            Date       = $STIGDate
            Deprecated = $Node.Deprecated
        }
        $OutList.Add($NewObj)
    }
    Return $OutList
}

Function Get-ApplicableProducts {
    Param (
        [Parameter(Mandatory = $true)]
        [String] $ES_Path
    )

    [XML]$STIGList = Get-Content (Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "STIGList.xml")
    $OutList = New-Object System.Collections.Generic.List[System.Object]

    $ProgressId = 1
    $ProgressActivity = "Checking STIG applicability"
    $TotalSteps = ($STIGList.List.STIG).Count
    $CurrentStep = 1
    ForEach ($Node in $STIGList.List.STIG) {
        Write-Progress -Id 1 -Activity $ProgressActivity -Status $Node.Name -PercentComplete ($CurrentStep / $TotalSteps * 100)
        $CurrentStep++
        If ($Node.DetectionCode -and (Invoke-Expression $Node.DetectionCode) -eq $true) {
            If (-Not(Test-Path (Join-Path -Path $ES_Path -ChildPath "StigContent" | Join-Path -ChildPath $Node.StigContent))) {
                $STIGVersion = "XCCDF missing"
            }
            Else {
                [xml]$Content = Get-Content (Join-Path -Path $ES_Path -ChildPath "StigContent" | Join-Path -ChildPath $Node.StigContent)
                $STIGVer = $Content.Benchmark.Version
                $STIGRel = ((($Content.Benchmark.'plain-text' | Where-Object { $_.id -eq "release-info" }).'#text' -split 'Benchmark')[0].Trim() -split ' ')[1].Trim()
                $STIGVersion = "V$($STIGVer)R$($STIGRel)"
                $STIGDate = (($Content.Benchmark.'plain-text' | Where-Object { $_.id -eq "release-info" }).'#text' -split 'Date:')[1].Trim()
            }

            $NewObj = [PSCustomObject]@{
                Name       = $Node.Name
                Shortname  = $Node.ShortName
                Version    = $STIGVersion
                Date       = $STIGDate
                Deprecated = $Node.Deprecated
            }
            $OutList.Add($NewObj)
        }
    }
    Write-Progress -Id $ProgressId -Activity $ProgressActivity -Completed
    Return $OutList
}

Function Invoke-RemoteScan {
    Param (
        # Evaluate-STIG parameters
        [Parameter(Mandatory = $true)]
        [String[]]$ComputerName,

        [Parameter(Mandatory = $false)]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [String]$Marking,

        [Parameter(Mandatory = $false)]
        [Int]$VulnTimeout = 15,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]$AFPath,

        [Parameter(Mandatory = $false)]
        [String]$AnswerKey = "DEFAULT",

        [Parameter(Mandatory = $false)]
        [String[]]$Output = "",

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]$OutputPath,

        [Parameter(Mandatory = $false)]
        [Int]$PreviousToKeep = 0,

        [Parameter(Mandatory = $false)]
        [SecureString]$SMPassphrase,

        [Parameter(Mandatory = $false)]
        [String]$SMCollection,

        [Parameter(Mandatory = $false)]
        [Switch]$ApplyTattoo,

        [Parameter(Mandatory = $false)]
        [Switch]$AllowDeprecated,

        [Parameter(Mandatory = $false)]
        [Array]$SelectSTIG,

        [Parameter(Mandatory = $false)]
        [Array]$SelectVuln,

        [Parameter(Mandatory = $false)]
        [Array]$ExcludeVuln,

        [Parameter(Mandatory = $false)]
        [Array]$ExcludeSTIG,

        [Parameter(Mandatory = $false)]
        [Array]$ForceSTIG,

        [Parameter(Mandatory = $false)]
        [Switch]$AltCredential,

        [Parameter(Mandatory = $false)]
        [Int]$ThrottleLimit = 10,

        # Remote scan parameters
        [Parameter(Mandatory = $true)]
        [String]$ESVersion,

        [Parameter(Mandatory = $true)]
        [String]$LogComponent,

        [Parameter(Mandatory = $true)]
        [String]$OSPlatform,

        [Parameter(Mandatory = $true)]
        [String] $ES_Path,

        [Parameter(Mandatory = $true)]
        [String] $RemoteScanDir,

        [Parameter(Mandatory = $true)]
        [String] $RemoteWorkingDir,

        [Parameter(Mandatory = $true)]
        [String] $PowerShellVersion
    )

    Try {
        $StartTime = Get-Date

        # Reconstruct command line for logging purposes
        $ParamsNotForLog = @("ESVersion", "LogComponent", "OSPlatform", "ES_Path", "PowerShellVersion") # Parameters not be be written to log
        $BoundParams = $PSBoundParameters # Collect called parameters
        ForEach ($Item in $ParamsNotForLog) {
            # Remove parameter from collection so that it will not be logged
            $BoundParams.Remove($Item) | Out-Null
        }
        $CommandLine = "Evaluate-STIG.ps1"
        ForEach ($Item in $BoundParams.Keys) {
            Switch ($BoundParams.$Item.GetType().Name) {
                { ($_ -in @("String[]", "Object[]")) } {
                    $CommandLine += " -$($Item) $($BoundParams[$Item] -join ',')"
                }
                "SwitchParameter" {
                    $CommandLine += " -$($Item)"
                }
                DEFAULT {
                    $CommandLine += " -$($Item) $($BoundParams[$Item])"
                }
            }
        }

        $STIGLog_Remote = Join-Path -Path $RemoteScanDir -ChildPath "Evaluate-STIG_Remote.log"
        If (Test-Path $STIGLog_Remote) {
            Remove-Item $STIGLog_Remote -Force
        }
        $STIGLog_STIGManager = Join-Path -Path $RemoteScanDir -ChildPath "Evaluate-STIG_STIGManager.log"
        If (Test-Path $STIGLog_STIGManager) {
            Remove-Item $STIGLog_STIGManager -Force
        }

        # Begin logging
        Write-Log -Path $STIGLog_Remote -Message "Executing: $($CommandLine)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Remote -Message "-" -TemplateMessage LineBreak-Dash -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        If (-NOT([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Log -Path $STIGLog_Remote -Message "WARNING: Executing Evaluate-STIG without local administrative rights." -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
        }
        Write-Log -Path $STIGLog_Remote -Message "Evaluate-STIG Version: $($ESVersion)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

        # Verify required Evaluate-STIG files exist and their integrity
        $Verified = $true
        Write-Log -Path $STIGLog_Remote -Message "Verifying Evaluate-STIG file integrity" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        If (Test-Path (Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "FileList.xml")) {
            [XML]$FileListXML = Get-Content -Path (Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "FileList.xml")
            If ((Test-XmlSignature -checkxml $FileListXML -Force) -ne $true) {
                Write-Log -Path $STIGLog_Remote -Message "ERROR: 'FileList.xml' failed authenticity check. Unable to verify content integrity." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
            }
            Else {
                ForEach ($File in $FileListXML.FileList.File) {
                    $Path = (Join-Path -Path $ES_Path -ChildPath $File.Path | Join-Path -ChildPath $File.Name)
                    If (Test-Path $Path) {
                        If ((Get-FileHash -Path $Path -Algorithm SHA256).Hash -ne $File.SHA256Hash) {
                            $Verified = $false
                            Write-Log -Path $STIGLog_Remote -Message "WARNING: '$($Path)' failed integrity check." -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                        }
                    }
                    Else {
                        If ($File.ScanReq -eq "Required") {
                            $Verified = $false
                            Write-Log -Path $STIGLog_Remote -Message "ERROR: '$($File.Name)' is a required file but not found. Scan results may be incomplete." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                        }
                    }
                }
                If ($Verified -eq $true) {
                    Write-Log -Path $STIGLog_Remote -Message "Evaluate-STIG file integrity check passed." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                }
                Else {
                    Write-Log -Path $STIGLog_Remote -Message "WARNING: One or more Evaluate-STIG files failed integrity check." -WriteOutToStream -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                }
            }
        }
        Else {
            Write-Log -Path $STIGLog_Remote -Message "ERROR: 'FileList.xml' not found. Cannot continue." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
            Exit 2
        }

        # For remote scans, archive Evaluate-STIG files and, if necessary, answer files for faster transport to remote machines
        # Clean up orphaned archives
        If (Test-Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp")) {
            Write-Log -Path $STIGLog_Remote -Message "Removing orphaned folder: $(Join-Path -Path $RemoteWorkingDir -ChildPath 'Evaluate-STIG_tmp')" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            Remove-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp") -Recurse -Force
        }
        If (Test-Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "ESCONTENT.ZIP")) {
            Write-Log -Path $STIGLog_Remote -Message "Removing orphaned file: $(Join-Path -Path $RemoteWorkingDir -ChildPath 'ESCONTENT.ZIP')" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            Remove-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "ESCONTENT.ZIP") -Force
        }
        If (Test-Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "AFILES.ZIP")) {
            Write-Log -Path $STIGLog_Remote -Message "Removing orphaned file: $(Join-Path -Path $RemoteWorkingDir -ChildPath 'AFILES.ZIP')" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            Remove-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "AFILES.ZIP") -Force
        }

        # Copy files needed for scan to Evaluate-STIG_tmp
        # FileList.xml
        If (-Not(Test-Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath "xml"))) {
            $null = New-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath "xml") -ItemType Directory -ErrorAction Stop
        }
        Copy-Item -Path $(Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "FileList.xml") -Destination $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath "xml") -Force -ErrorAction Stop
        # Files marked "Required" and "Optional"
        ForEach ($File in ($FileListXML.FileList.File | Where-Object ScanReq -In @("Required", "Optional"))) {
            If (Test-Path $(Join-Path -Path $ES_Path -ChildPath $File.Path | Join-Path -ChildPath $File.Name)) {
                If (-Not(Test-Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath $File.Path))) {
                    $null = New-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath $File.Path) -ItemType Directory -ErrorAction Stop
                }
                $tmpSource = (Join-Path -Path $ES_Path -ChildPath $File.Path | Join-Path -ChildPath $File.Name)
                $tmpDest = (Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath $File.Path | Join-Path -ChildPath $File.Name)
                Copy-Item -Path  $tmpSource -Destination $tmpDest -Force -ErrorAction Stop
            }
        }

        # Copy default answer file location
        $null = New-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath "AnswerFiles") -ItemType Directory -ErrorAction Stop
        If (Test-Path $(Join-Path -Path $ES_Path -ChildPath "AnswerFiles")) {
            Get-ChildItem -Path $(Join-Path -Path $ES_Path -ChildPath "AnswerFiles") | Where-Object Extension -EQ ".xml" | Copy-Item -Destination $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath "AnswerFiles") -Force -ErrorAction Stop
        }

        # Create archive of Evaluate-STIG core files
        If (-Not(Test-Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "ESCONTENT.ZIP"))) {
            Write-Log -Path $STIGLog_Remote -Message "Prepping files for remote scan" -WriteOutToStream -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            Write-Log -Path $STIGLog_Remote -Message "Compressing Evaluate-STIG files" -WriteOutToStream -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            $Result = Initialize-Archiving -Action Compress -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp" | Join-Path -ChildPath "*") -Destination $(Join-Path -Path $RemoteWorkingDir -ChildPath "ESCONTENT.ZIP") -CompressionLevel Optimal
            If ($Result -ne "Success") {
                Throw $Result
            }
            Remove-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "Evaluate-STIG_tmp") -Recurse -Force
        }

        # Create archive of Answer Files if not in default path (Evaluate-STIG\AnswerFiles)
        If (($AFPath.TrimEnd('\')).TrimEnd('/') -ne (Join-Path -Path $ES_Path -ChildPath "AnswerFiles")) {
            If (-Not(Test-Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "AFILES.ZIP"))) {
                Write-Log -Path $STIGLog_Remote -Message "Compressing answer files from $AFPath" -WriteOutToStream -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                $Result = Get-ChildItem -Path $AFPath | Where-Object Extension -EQ ".xml" | ForEach-Object { Initialize-Archiving -Action Compress -Path $($_.FullName) -DestinationPath $(Join-Path -Path $RemoteWorkingDir -ChildPath "AFILES.ZIP") -Update -CompressionLevel Optimal }
                If ($Result -ne "Success") {
                    Throw $Result
                }
            }
        }

        # Build the list of computers, if necessary.
        $LocalHost = New-Object System.Collections.Generic.List[System.Object]
        $ComputerTempList = New-Object System.Collections.Generic.List[System.Object]
        $ComputerList = New-Object System.Collections.Generic.List[System.Object]
        $WindowsList = New-Object System.Collections.Generic.List[System.Object]
        $LinuxList = New-Object System.Collections.Generic.List[System.Object]
        $OfflineList = New-Object System.Collections.Generic.List[System.Object]
        $RemoteUnresolveCount = 0

        # Get local host data
        $NewObj = [PSCustomObject]@{
            HostName    = ([Environment]::MachineName).ToUpper()
            IPv4Address = (Get-NetIPAddress).IPv4Address
        }
        $LocalHost.Add($NewObj)

        # Put all ComputerName items into a temp list for resolving

        ForEach ($Item in ($ComputerName -split ',(?=(?:[^"]|"[^"]*")*$)')) { #convert string to array, comma delimiter.  if path has comma, it must be enclosed in double quotes
            If (Test-Path $Item -PathType Leaf) {
                Get-Content $Item | ForEach-Object {
                    If ($_ -ne $null) {
                        $ComputerTempList.Add($_)
                    }
                }
                Continue
            }
            If ($Item -is [array]) {
                $Item | ForEach-Object {
                    $ComputerTempList.Add($_)
                }
            }
            Else {
                $ComputerTempList.Add($Item)
            }
        }

        # Get NETBIOS and FQDN of each computer
        Foreach ($Computer in ($ComputerTempList)) {
            If (($Computer -eq "127.0.0.1") -or ($Computer -eq "::1") -or ($Computer -eq "localhost") -or ($Computer.Split('.')[0] -eq $LocalHost.HostName) -or ($Computer -in $LocalHost.IPv4Address)) {
                $NewObj = [PSCustomObject]@{
                    NETBIOS = $LocalHost.HostName
                    FQDN    = "LOCALHOST"
                }
                $ComputerList.Add($NewObj)
            }
            Else {
                # Resolve Computer
                Try {
                    $FQDN = ([Net.DNS]::GetHostEntry($Computer).Hostname).ToUpper()
                    $NewObj = [PSCustomObject]@{
                        NETBIOS = $FQDN.Split('.')[0]
                        FQDN    = $FQDN
                    }
                    $ComputerList.Add($NewObj)
                }
                Catch {
                    Write-Log -Path $STIGLog_Remote -Message "ERROR: Unable to resolve $Computer" -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    $OfflineList.Add($Computer)
                    $RemoteUnresolveCount++
                }
            }
        }
        Remove-Variable ComputerTempList
        [System.GC]::Collect()
        $ComputerList = $ComputerList | Sort-Object NETBIOS -Unique

        $ConnectionScriptBlock = {
            Param (
                [String]$NETBIOS,
                [String]$FQDN
            )
            $tcp = New-Object Net.Sockets.TcpClient
            Try {
                $tcp.Connect($FQDN, 5986)
            }
            catch {
            }

            if ($tcp.Connected) {
                $Connection = "5986"
            }
            else {
                Try {
                    $tcp.Connect($FQDN, 5985)
                }
                catch {
                }

                if ($tcp.Connected) {
                    $Connection = "5985"
                }
                else {
                    Try {
                        $tcp.Connect($FQDN, 22)
                    }
                    catch {
                    }

                    if ($tcp.Connected) {
                        $Connection = "22"
                    }
                }
            }

            $tcp.close()

            [PSCustomObject]@{
                NETBIOS   = $NETBIOS
                FQDN      = $FQDN
                Connected = $Connection
            }
        }

        $ConnectionRunspacePool = [RunspaceFactory]::CreateRunspacePool(1, 10)
        $ConnectionRunspacePool.Open()

        $ProgressSpinner = @("|", "/", "-", "\")
        $ProgressSpinnerPos = 0
        $ConnectionJobs = New-Object System.Collections.ArrayList

        $ComputerList | ForEach-Object {
            $ParamList = @{
                NETBIOS = $_.NETBIOS
                FQDN    = $_.FQDN
            }
            $ConnectionJob = [powershell]::Create().AddScript($ConnectionScriptBlock).AddParameters($ParamList)
            $ConnectionJob.RunspacePool = $ConnectionRunspacePool

            $null = $ConnectionJobs.Add([PSCustomObject]@{
                    Pipe   = $ConnectionJob
                    Result = $ConnectionJob.BeginInvoke()
                })
        }
        Write-Host ""

        Write-Log -Path $STIGLog_Remote -Message "Generating list of scannable hosts" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Do {
            Write-Host "`rGenerating list of scannable hosts.  Attempting connection to $(($ConnectionJobs.Result.IsCompleted | Measure-Object).Count) hosts. $($ProgressSpinner[$ProgressSpinnerPos])" -NoNewline
            $ProgressSpinnerPos++
            Start-Sleep -Seconds .1
            if ($ProgressSpinnerPos -ge $ProgressSpinner.Length) {
                $ProgressSpinnerPos = 0
            }
        } While ( $ConnectionJobs.Result.IsCompleted -contains $false)

        $ConnectionResults = $(ForEach ($ConnectionJob in $ConnectionJobs) {
                $ConnectionJob.Pipe.EndInvoke($ConnectionJob.Result)
            })

        $ConnectionRunspacePool.Close()
        $ConnectionRunspacePool.Dispose()

        $ConnectionResults | ForEach-Object {
            if ($_.Connected -eq "5986") {
                $WindowsList.Add($_)
            }
            elseif ($_.Connected -eq "5985") {
                $WindowsList.Add($_)
            }
            elseif ($_.Connected -eq "22") {
                $LinuxList.Add($_)
            }
            else {
                $OfflineList.Add($_.NETBIOS)
            }
        }
        if ((($WindowsList | Measure-Object).count + ($LinuxList | Measure-Object).count) -eq 0) {
            Write-Log -Path $STIGLog_Remote "ERROR: No valid remote hosts found." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
        }
        else {
            Write-Log -Path $STIGLog_Remote -Message "Connected to $(($WindowsList | Measure-Object).count + ($LinuxList | Measure-Object).count) hosts. $(($WindowsList | Measure-Object).count) Windows and $(($LinuxList | Measure-Object).count) Linux" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            Write-Host "`rGenerating list of scannable machines.  Connected to $(($WindowsList | Measure-Object).count + ($LinuxList | Measure-Object).count) hosts. $(($WindowsList | Measure-Object).count) Windows and $(($LinuxList | Measure-Object).count) Linux" -NoNewline
            Write-Host ""
        }

        # Prompt for AltCredential
        If ($AltCredential -and (($WindowsList | Measure-Object).count -gt 0)) {
            $Credentialcreds = Get-Creds
        }

        $RemoteScriptBlock = {
            Param(
                $ConnectionResult,
                $STIGLog_Remote,
                $LogComponent,
                $OSPlatform,
                $RemoteWorkingDir,
                $ScanType,
                $Marking,
                $VulnTimeout,
                $AnswerKey,
                $Output,
                $OutputPath,
                $PreviousToKeep,
                $SMPassphrase,
                $SMCollection,
                $AltCredential,
                $Credentialcreds,
                $AllowDeprecated,
                $SelectSTIG,
                $SelectVuln,
                $ExcludeVuln,
                $ExcludeSTIG,
                $ForceSTIG,
                $ApplyTattoo,
                $AFPath,
                $ScriptRoot
            )
            $RemoteStartTime = Get-Date

            $Remote_Log = Join-Path -Path $RemoteWorkingDir -ChildPath "Remote_Evaluate-STIG_$($ConnectionResult.NETBIOS).log"

            Write-Log -Path $Remote_Log -Message "Begin Remote Logging" -TemplateMessage LineBreak-Text -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

            Switch ($ConnectionResult.Connected) {
                "5986" {
                    Write-Log -Path $Remote_Log -Message "Connection successful on port 5986. Determined Windows OS." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                }
                "5985" {
                    Write-Log -Path $Remote_Log -Message "Connection successful on port 5985. Determined Windows OS." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                }
                default {
                    Write-Log -Path $Remote_Log -Message "ERROR: Connection unsuccessful on standard ports (Windows ports 5986/5985)." -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                }
            }

            Write-Log -Path $Remote_Log -Message "Scanning : $($ConnectionResult.FQDN)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

            Try {
                Write-Log -Path $Remote_Log -Message "Creating Windows PS Session via HTTPS" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                if ($AltCredential) {
                    $SSLOptions = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
                    $Session = New-PSSession -ComputerName $($ConnectionResult.FQDN) -Credential $Credentialcreds -UseSSL -SessionOption $SSLOptions -ErrorVariable remoteerror -ErrorAction SilentlyContinue
                    if ($remoteerror) {
                        Write-Log -Path $Remote_Log -Message "WARNING: HTTPS connection failed. Attempting HTTP connection." -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                        Write-Log -Path $Remote_Log -Message "Creating Windows PS Session via HTTP" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                        $Session = New-PSSession -ComputerName $($ConnectionResult.FQDN) -Credential $Credentialcreds -ErrorVariable remoteerror -ErrorAction SilentlyContinue
                        if ($remoteerror) {
                            Write-Log -Path $Remote_Log -Message "WARNING: Alternate Credentials failed to create a session. Falling back to $([Environment]::Username)." -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                            $Session = New-PSSession -ComputerName $($ConnectionResult.FQDN) -ErrorVariable remoteerror -ErrorAction SilentlyContinue
                        }
                    }
                }
                else {
                    $SSLOptions = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
                    $Session = New-PSSession -ComputerName $($ConnectionResult.FQDN) -UseSSL -SessionOption $SSLOptions -ErrorVariable remoteerror -ErrorAction SilentlyContinue
                    if ($remoteerror) {
                        Write-Log -Path $Remote_Log -Message "WARNING: HTTPS connection failed. Attempting HTTP connection." -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                        Write-Log -Path $Remote_Log -Message "Creating Windows PS Session via HTTP" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        $Session = New-PSSession -ComputerName $($ConnectionResult.FQDN) -ErrorVariable remoteerror -ErrorAction SilentlyContinue
                    }
                }

                switch -WildCard ($remoteerror) {
                    "*Access is denied*" {
                        Write-Log -Path $Remote_Log -Message "ERROR: -ComputerName requires admin rights on $($ConnectionResult.FQDN)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    }
                    "*WinRM*" {
                        Write-Log -Path $Remote_Log -Message "ERROR: -ComputerName requires WinRM on $($ConnectionResult.FQDN)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    }
                    "*The user name or password is incorrect.*" {
                        Write-Log -Path $Remote_Log -Message "ERROR: -ComputerName requires a valid username and password to connect to $($ConnectionResult.FQDN)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    }
                    default {
                        Write-Log -Path $Remote_Log -Message "ERROR: -ComputerName got an error" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    }
                }

                If (!($Session)) {
                    $Message = $RemoteError
                    Write-Log -Path $Remote_Log -Message $Message -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    Write-Log -Path $Remote_Log -Message "End Remote Logging" -TemplateMessage LineBreak-Text -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                    Add-Content -Path $STIGLog_Remote -Value $(Get-Content $Remote_Log)
                    Remove-Item $Remote_Log
                    $RemoteFailCount["RemoteFail"]++
                    Return "ERROR: $($Message)"
                }

                Write-Log -Path $Remote_Log -Message "Credential: '$(Invoke-Command -ScriptBlock { return whoami } -Session $Session)' used for remote session(s)." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                If ((Invoke-Command -ScriptBlock { (($PsVersionTable.PSVersion).ToString()) -lt 5.1 } -Session $Session)) {
                    $Message = "$($ConnectionResult.FQDN) does not meet minimum PowerShell version (5.1)"
                    Write-Log -Path $Remote_Log -Message $Message -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    Write-Log -Path $Remote_Log -Message "End Remote Logging" -TemplateMessage LineBreak-Text -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                    Add-Content -Path $STIGLog_Remote -Value $(Get-Content $Remote_Log)
                    Remove-Item $Remote_Log
                    $RemoteFailCount["RemoteFail"]++
                    Return "ERROR: $($Message)"
                }

                If (Invoke-Command -ScriptBlock { Test-Path $env:WINDIR\Temp\Evaluate-STIG_RemoteComputer } -Session $Session) {
                    Write-Log -Path $Remote_Log -Message "Removing previous content found in $env:WINDIR\Temp\Evaluate-STIG_RemoteComputer" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    Invoke-Command -ScriptBlock { Remove-Item $env:WINDIR\Temp\Evaluate-STIG_RemoteComputer -Recurse -Force } -Session $Session
                }
                Invoke-Command -ScriptBlock { $null = New-Item -ItemType Directory -Path $env:WINDIR\Temp\Evaluate-STIG_RemoteComputer } -Session $Session
                Invoke-Command -ScriptBlock { $null = New-Item -ItemType Directory -Path $env:WINDIR\Temp\Evaluate-STIG_RemoteComputer\STIG_Compliance } -Session $Session

                If ($SelectSTIG) {
                    If ($ForceSTIG) {
                        $ESArgs = "-SelectSTIG $($SelectSTIG -join ',') -ForceSTIG $($ForceSTIG -join ',') -ScanType $ScanType -AnswerKey $AnswerKey -VulnTimeout $VulnTimeout"
                    }
                    Else {
                        $ESArgs = "-SelectSTIG $($SelectSTIG -join ',') -ScanType $ScanType -AnswerKey $AnswerKey -VulnTimeout $VulnTimeout"
                    }
                }
                ElseIf ($ExcludeSTIG) {
                    If ($ForceSTIG) {
                        $ESArgs = "-ExcludeSTIG $($ExcludeSTIG -join ',') -ForceSTIG $($ForceSTIG -join ',') -ScanType $ScanType -AnswerKey $AnswerKey -VulnTimeout $VulnTimeout"
                    }
                    Else {
                        $ESArgs = "-ExcludeSTIG $($ExcludeSTIG -join ',') -ScanType $ScanType -AnswerKey $AnswerKey -VulnTimeout $VulnTimeout"
                    }
                }
                ElseIf ($ForceSTIG) {
                    $ESArgs = "-ForceSTIG $($ForceSTIG -join ',') -ScanType $ScanType -AnswerKey $AnswerKey -VulnTimeout $VulnTimeout"
                }
                Else {
                    $ESArgs = "-ScanType $ScanType -AnswerKey $AnswerKey -VulnTimeout $VulnTimeout"
                }

                $OutputList = $(($Output -split ",").Trim() | Where-Object {$_ -notin @("Console", "STIGManager")})

                If ($OutputList) {
                    $ESArgs = $ESArgs + " -Output $($Output -join ',') -PreviousToKeep $PreviousToKeep"
                }

                If ($SelectVuln) {
                    $ESArgs = $ESArgs + " -SelectVuln $($SelectVuln -join ',')"
                }

                If ($ExcludeVuln) {
                    $ESArgs = $ESArgs + " -ExcludeVuln $($ExcludeVuln -join ',')"
                }

                If ($Marking) {
                    $ESArgs = $ESArgs + " -Marking $Marking"
                }

                If ($ApplyTattoo) {
                    $ESArgs = $ESArgs + " -ApplyTattoo"
                }

                If ($AllowDeprecated) {
                    $ESArgs = $ESArgs + " -AllowDeprecated"
                }

                $ProgressPreference = "SilentlyContinue"

                Initialize-FileXferToRemote -NETBIOS $($ConnectionResult.NETBIOS) -RemoteTemp "$env:WINDIR\Temp\Evaluate-STIG_RemoteComputer" -OutputPath $OutputPath -AFPath $AFPath -Remote_Log $Remote_Log -LogComponent $LogComponent -OSPlatform $OSPlatform -RemoteWorkingDir $RemoteWorkingDir -ScriptRoot $ScriptRoot -Session $Session

                Write-Log -Path $Remote_Log -Message "Invoking Evaluate-STIG on $($ConnectionResult.FQDN)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                Write-Log -Path $Remote_Log -Message "Scan Arguments: $ESArgs" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                Write-Log -Path $Remote_Log -Message "Local logging of scan is stored at $env:WINDIR\Temp\Evaluate-STIG on $($ConnectionResult.FQDN)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                $RemoteES = Invoke-Command -Session $Session {
                    Param(
                        [string]
                        $ESArgs,

                        [string]
                        $OutputPath
                    )
                    Try {
                        $LogOutput = [System.Collections.Generic.List[System.Object]]::new()
                        $RemoteOutput = [System.Collections.Generic.List[System.Object]]::new()
                        If (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                            $Thumbprint = "d95f944e33528dc23bee8672d6d38da35e6f0017" # Evaluate-STIG code signing certificate
                            ForEach ($Store in @("CurrentUser", "LocalMachine")) {
                                If (Get-ChildItem -Path "Cert:\$Store\TrustedPublisher" | Where-Object Thumbprint -EQ $Thumbprint) {
                                    $CodeSign = $true
                                }
                                Else {
                                    $CodeSign = $False
                                }
                            }
                            If ($CodeSign -eq $true) {
                                $NewObj = [PSCustomObject]@{
                                    Message = "Code signing certificate is trusted on $env:COMPUTERNAME"
                                    Type    = "Info"
                                }
                                $LogOutput.Add($NewObj)
                            }
                            Else {
                                $CodeSign = $False
                                $NewObj = [PSCustomObject]@{
                                    Message = "Code signing certificate is not trusted on $env:COMPUTERNAME"
                                    Type    = "Warning"
                                }
                                $LogOutput.Add($NewObj)
                            }

                            $ESPath = "$env:WINDIR\Temp\Evaluate-STIG_RemoteComputer\Evaluate-STIG.ps1"

                            # Command to run and redirect Write-Host
                            # https://powershell.one/code/9.html
                            $ES_CmdLine = $($ESPath) + ' ' + $($ESArgs) + ' 6>$null'
                            If ($ESArgs -match "-Output ") {
                                # If -Output is creating files, set -OutputPath
                                If ((($ESArgs -split "-Output ")[1] -split " ")[0] -split "," -match @("(^CKL$|^CKLB$|^CombinedCKL$|^CombinedCKLB$|^Summary$|^OQE$)")) {
                                    $ES_CmdLine = $ES_CmdLine + " -OutputPath $env:WINDIR\Temp\Evaluate-STIG_RemoteComputer\STIG_Compliance"
                                }
                            }

                            Switch (Get-ExecutionPolicy) {
                                {($_ -in @("Restricted"))} {
                                    $NewObj = [PSCustomObject]@{
                                        Message = "Execution policy of '$_' found on $env:COMPUTERNAME which is not supported"
                                        Type    = "Error"
                                    }
                                    $LogOutput.Add($NewObj)
                                }
                                {($_ -in @("AllSigned", "RemoteSigned"))} {
                                    If ($CodeSign) {
                                        $NewObj = [PSCustomObject]@{
                                            Message = "Execution policy of '$_' found on $env:COMPUTERNAME"
                                            Type    = "Info"
                                        }
                                        $LogOutput.Add($NewObj)
                                        $Output = Invoke-Expression -Command $ES_CmdLine
                                    }
                                    Else {
                                        $NewObj = [PSCustomObject]@{
                                            Message = "Execution policy of '$_' found on $env:COMPUTERNAME but code signing certificate is not trusted"
                                            Type    = "Error"
                                        }
                                        $LogOutput.Add($NewObj)
                                        $Output = Invoke-Expression -Command $ES_CmdLine
                                    }
                                }
                                Default {
                                    $NewObj = [PSCustomObject]@{
                                        Message = "Execution policy of '$_' found on $env:COMPUTERNAME"
                                        Type    = "Info"
                                    }
                                    $LogOutput.Add($NewObj)
                                    $Output = Invoke-Expression -Command $ES_CmdLine
                                }
                            }

                            $NewObj = [PSCustomObject]@{
                                Message = "Scan completed"
                                Type    = "Info"
                            }
                            $LogOutput.Add($NewObj)

                            $NewObj = [PSCustomObject]@{
                                LogOutput  = $LogOutput
                                ScanResult = $Output
                            }
                            $RemoteOutput.Add($NewObj)

                            Return $RemoteOutput
                        }
                        else {
                            $NewObj = [PSCustomObject]@{
                                Message = "ERROR: You must run this using an account with administrator rights on the remote computer."
                                Type    = "Error"
                            }
                            $LogOutput.Add($NewObj)

                            $NewObj = [PSCustomObject]@{
                                Message = "==========[End Remote Logging]=========="
                                Type    = "Info"
                            }
                            $LogOutput.Add($NewObj)

                            $NewObj = [PSCustomObject]@{
                                LogOutput  = $LogOutput
                                ScanResult = "ERROR: You must run this using an account with administrator rights on the remote computer."
                            }
                            $RemoteOutput.Add($NewObj)
                            Return $RemoteOutput
                        }
                    }
                    Catch {
                        $NewObj = [PSCustomObject]@{
                            Message = "ERROR: Scan Failed. Suggest running locally to determine cause."
                            Type    = "Error"
                        }
                        $LogOutput.Add($NewObj)

                        $NewObj = [PSCustomObject]@{
                            Message = "ERROR: $($_.Exception.Message)"
                            Type    = "Error"
                        }
                        $LogOutput.Add($NewObj)

                        $NewObj = [PSCustomObject]@{
                            Message = "==========[End Remote Logging]=========="
                            Type    = "Info"
                        }
                        $LogOutput.Add($NewObj)

                        $NewObj = [PSCustomObject]@{
                            LogOutput  = $LogOutput
                            ScanResult = "ERROR: Scan Failed. Suggest running locally to determine cause."
                        }
                        $RemoteOutput.Add($NewObj)
                        Return $RemoteOutput
                    }
                } -ArgumentList ($ESArgs, $OutputPath) -ErrorAction SilentlyContinue -InformationAction Ignore

                $RemoteES.LogOutput | ForEach-Object { Write-Log -Path $Remote_Log -Message $_.Message -Component $LogComponent -Type $_.Type -OSPlatform $OSPlatform }

                If ($SelectVuln) {
                    $NetBIOS = "_Partial_$($ConnectionResult.NETBIOS)"
                }
                Else {
                    $NetBIOS = $($ConnectionResult.NETBIOS)
                }

                If ($Output) {
                    If (($Output -split ",").Trim() -match "^STIGManager$") {
                        Try {
                            Import-Module (Join-Path -Path $ScriptRoot -ChildPath "Modules" | Join-Path -ChildPath "STIGManager_Functions") -SkipEditionCheck -ErrorAction Stop

                            $SMObject = [System.Collections.Generic.List[System.Object]]::new()
                            $($RemoteES.ScanResult).$($($RemoteES.ScanResult).Keys).Values | Foreach-Object {$SMObject.Add($_)}

                            if ($SMPassphrase){
                                $SMImport_Params = Get-SMParameters -SMCollection $SMCollection -SMPassphrase $SMPassphrase -ScanObject $SMObject -ScriptRoot $ScriptRoot -WorkingDir $RemoteWorkingDir -OSPlatform $OSPlatform -LogComponent $LogComponent -LogPath $Remote_Log
                            }
                            else{
                                $SMImport_Params = Get-SMParameters -SMCollection $SMCollection -ScanObject $SMObject -ScriptRoot $ScriptRoot -WorkingDir $RemoteWorkingDir -OSPlatform $OSPlatform -LogComponent $LogComponent -LogPath $Remote_Log
                            }

                            Import-Asset @SMImport_Params

                        }
                        Catch {
                            Write-Log -Path $Remote_Log -Message "ERROR: $($_.Exception.Message)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                        }

                    }

                    If (($Output -split ",").Trim() -match @("(^CKL$|^CKLB$|^CombinedCKL$|^CombinedCKLB$|^Summary$|^OQE$)")) {
                        If (Invoke-Command -ScriptBlock { Return Test-Path "$($env:WINDIR)\Temp\Evaluate-STIG_RemoteComputer\STIG_Compliance\$($NetBIOS)" } -Session $Session) {
                            If ($SelectSTIG) {
                                $PreviousArgs = @{SelectedShortName = $SelectSTIG}
                                If (($Output -split ",").Trim() -match @("(^CombinedCKL$)")) {
                                    $PreviousArgs.Add("SelectedCombinedCKL",$true)
                                }
                                If (($Output -split ",").Trim() -match @("(^CombinedCKLB$)")) {
                                    $PreviousArgs.Add("SelectedCombinedCKLB", $true)
                                }
                                If (($Output -split ",").Trim() -match @("(^Summary$)")) {
                                    $PreviousArgs.Add("SelectedSummary", $true)
                                }
                                If (($Output -split ",").Trim() -match @("(^OQE$)")) {
                                    $PreviousArgs.Add("SelectedOQE", $true)
                                }
                                Initialize-PreviousProcessing -ResultsPath (Join-Path $OutputPath -ChildPath $NetBIOS) -PreviousToKeep $PreviousToKeep @PreviousArgs -LogPath $Remote_Log -LogComponent $LogComponent -OSPlatform $OSPlatform
                            }
                            Else {
                                Initialize-PreviousProcessing -ResultsPath (Join-Path $OutputPath -ChildPath $NetBIOS) -PreviousToKeep $PreviousToKeep -LogPath $Remote_Log -LogComponent $LogComponent -OSPlatform $OSPlatform
                            }

                            Initialize-FileXferFromRemote -NETBIOS $NetBIOS -RemoteTemp "$env:WINDIR\Temp\Evaluate-STIG_RemoteComputer" -OutputPath $OutputPath -Remote_Log $Remote_Log -LogComponent $LogComponent -OSPlatform $OSPlatform -RemoteWorkingDir $RemoteWorkingDir -ScriptRoot $ScriptRoot -Session $Session
                        }
                        Else {
                            Write-Log -Path $Remote_Log -Message "No Evaluate-STIG results were found on $($ConnectionResult.FQDN)." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                            $OfflineList.Add($ConnectionResult.FQDN)
                        }
                    }
                }

                # Clean up temp on remote
                If (Invoke-Command -ScriptBlock { Test-Path $env:WINDIR\Temp\Evaluate-STIG_RemoteComputer } -Session $Session) {
                    Invoke-Command -ScriptBlock { Remove-Item $env:WINDIR\Temp\Evaluate-STIG_RemoteComputer -Recurse -Force } -Session $Session
                }

                $TimeToComplete = New-TimeSpan -Start $RemoteStartTime -End (Get-Date)
                $FormatedTime = "{0:c}" -f $TimeToComplete
                Write-Log -Path $Remote_Log -Message "Total Time - $($FormatedTime)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                Write-Log -Path $Remote_Log -Message "End Remote Logging" -TemplateMessage LineBreak-Text -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                Add-Content -Path $STIGLog_Remote -Value $(Get-Content $Remote_Log)
                Remove-Item $Remote_Log

                $Session | Remove-PSSession
                $ProgressPreference = "Continue"
                Return $RemoteES.ScanResult
            }
            Catch {
                Write-Log -Path $Remote_Log -Message "ERROR: $($_.Exception.Message)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                Write-Log -Path $Remote_Log -Message "End Remote Logging" -TemplateMessage LineBreak-Text -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                Add-Content -Path $STIGLog_Remote -Value $(Get-Content $Remote_Log)
                Remove-Item $Remote_Log

                If ($Session) {
                    $Session | Remove-PSSession
                }
                $ProgressPreference = "Continue"
            }
        }

        $RemoteFailCount = [hashtable]::Synchronized(@{})

        $Params = @{
            STIGLog_Remote   = $STIGLog_Remote
            LogComponent     = $LogComponent
            OSPlatform       = $OSPlatform
            RemoteWorkingDir = $RemoteWorkingDir
            ScanType         = $ScanType
            VulnTimeout      = $VulnTimeout
            AnswerKey        = $AnswerKey
            OutputPath       = $OutputPath
            ScriptRoot       = $ES_Path
        }

        If ($AltCredential) {
            $Params.AltCredential = $True
            $Params.CredentialCreds = $Credentialcreds
        }
        Else {
            $Params.AltCredential = $False
        }

        If ($Output) {
            $Params.Output = $Output

            If (($Output -split ",").Trim() -match @("(^CKL$|^CKLB$|^CombinedCKL$|^CombinedCKLB$|^Summary$|^OQE$)")) {
                $Params.PreviousToKeep = $PreviousToKeep
            }

            If (($Output -split ",").Trim() -match "^STIGManager$") {
                if ($SMPassphrase){
                    $Params.SMPassphrase = $SMPassphrase
                }
                if ($SMCollection){
                    $Params.SMCollection = $SMCollection
                }
            }
        }
        Else {
            $Params.Output = $False
        }

        If ($SelectSTIG) {
            $Params.SelectSTIG = $SelectSTIG
        }
        Else {
            $Params.SelectSTIG = $False
        }

        If ($SelectVuln) {
            $Params.SelectVuln = $SelectVuln
        }
        Else {
            $Params.SelectVuln = $False
        }

        If ($ExcludeVuln) {
            $Params.ExcludeVuln = $ExcludeVuln
        }
        Else {
            $Params.ExcludeVuln = $False
        }

        If ($ExcludeSTIG) {
            $Params.ExcludeSTIG = $ExcludeSTIG
        }
        Else {
            $Params.ExcludeSTIG = $False
        }

        If ($ForceSTIG) {
            $Params.ForceSTIG = $ForceSTIG
        }
        Else {
            $Params.ForceSTIG = $False
        }

        If ($Marking) {
            $Params.Marking = $Marking
        }
        Else {
            $Params.Marking = $False
        }

        If ($ApplyTattoo) {
            $Params.ApplyTattoo = $ApplyTattoo
        }
        Else {
            $Params.ApplyTattoo = $False
        }

        If ($AllowDeprecated) {
            $Params.AllowDeprecated = $AllowDeprecated
        }
        Else {
            $Params.AllowDeprecated = $False
        }

        If ($AFPath) {
            $Params.AFPath = $AFPath
        }
        Else {
            $Params.AFPath = $False
        }

        If ($ThrottleLimit) {
            $MaxThreads = $ThrottleLimit
        }
        Else {
            $MaxThreads = 10
        }

        Write-Host "Executing scans"
        # https://learn-powershell.net/2013/04/19/sharing-variables-and-live-objects-between-powershell-runspaces/
        $runspaces = New-Object System.Collections.ArrayList
        $sessionstate = [system.management.automation.runspaces.initialsessionstate]::CreateDefault()
        $sessionstate.variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList 'RemoteFailCount', $RemoteFailCount, ''))

        Get-ChildItem function:/ | ForEach-Object {
            $definition = Get-Content "Function:\$($_.Name)"
            $SessionStateFunction = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $_.Name, $definition
            $sessionstate.Commands.Add($SessionStateFunction)
        }

        $runspacepool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $sessionstate, $Host)
        $runspacepool.ApartmentState = "STA"
        $runspacepool.Open()
        $RunspaceResults = @{}

        # Create pipeline input and output (results) object
        $RSObject = New-Object 'System.Management.Automation.PSDataCollection[PSObject]'

        Foreach ($ConnectionResult in $($ConnectionResults | Where-Object { ($_.Connected -ne "22") -and ($_.FQDN -notin $OfflineList) })) {
            $Job = [powershell]::Create().AddScript($RemoteScriptBlock).AddArgument($ConnectionResult).AddParameters($Params)
            $Job.Streams.ClearStreams()
            $Job.RunspacePool = $RunspacePool

            # Create a temporary collection for each runspace
            $temp = "" | Select-Object Job, Runspace, Hostname, FQDN
            $Temp.HostName = $ConnectionResult.NETBIOS
            $Temp.FQDN = $ConnectionResult.FQDN
            $temp.Job = $Job
            $temp.Runspace = [PSCustomObject]@{
                Instance = $Job
                State    = $Job.BeginInvoke($RSObject, $RSObject)
            }
            $null = $runspaces.Add($temp)
        }

        if (($runspaces | Measure-Object).count -gt 0) {
            Get-RunspaceData -Runspaces $Runspaces -Wait -Usage Remote
        }

        If (($Output -split ",").Trim() -match "^Console$") {
            # Add to results to be returned to console
            If ($RSObject) {
                ForEach ($Object in $RSObject.Keys) {
                    $RunspaceResults.Add($Object,$RSObject.$Object)
                }
            }
        }

        $RunspacePool.Close()
        $RunspacePool.Dispose()

        $RemoteLinuxFail = 0

        if (($LinuxList | Measure-Object).count -gt 0) {
            $SSHUsername = Read-Host "Enter username to SSH to $(($LinuxList | Measure-Object).count) Linux host(s)"

            Foreach ($LinuxHost in $LinuxList) {
                $Remote_Log = Join-Path -Path $RemoteWorkingDir -ChildPath "Remote_Evaluate-STIG_$($LinuxHost.NETBIOS).log"
                Write-Host ""

                If ($PowerShellVersion -ge [Version]"7.1") {
                    Try {
                        $RemoteStartTime = Get-Date

                        Write-Log -Path $Remote_Log -Message "Connection successful on port 22. Determined Linux OS." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        Write-Log -Path $Remote_Log -Message "Scanning : $($LinuxHost.FQDN)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                        Try {
                            $Session = New-PSSession -HostName $LinuxHost.FQDN -UserName $SSHUsername -SSHTransport -ErrorAction Stop
                            $SessionUserName = $SSHUsername
                        }
                        Catch {
                            Write-Log -Path $Remote_Log -Message "WARNING: SSH Session failed for $($LinuxHost.FQDN). Requesting different SSH username" -WriteOutToStream -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                            $AltSSHUsername = Read-Host "Enter username to SSH to $($LinuxHost.FQDN)"
                            $SessionUserName = $AltSSHUsername
                            Try {
                                $Session = New-PSSession -HostName $LinuxHost.FQDN -UserName $AltSSHUsername -SSHTransport -ErrorAction Stop
                            }
                            Catch {
                                Write-Log -Path $Remote_Log -Message "ERROR: SSH Session failed for $($LinuxHost.FQDN)." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                            }
                        }

                        If (Invoke-Command -ScriptBlock { Test-Path /tmp/Evaluate-STIG_RemoteComputer } -Session $Session) {
                            Write-Log -Path $Remote_Log -Message "Removing previous content found in /tmp/Evaluate-STIG_RemoteComputer" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                            Invoke-Command -ScriptBlock { Remove-Item /tmp/Evaluate-STIG_RemoteComputer -Recurse -Force } -Session $Session
                        }
                        Invoke-Command -ScriptBlock { $null = New-Item -ItemType Directory -Path /tmp/Evaluate-STIG_RemoteComputer } -Session $Session
                        Invoke-Command -ScriptBlock { $null = New-Item -ItemType Directory -Path /tmp/Evaluate-STIG_RemoteComputer/STIG_Compliance } -Session $Session

                        $DefaultOutputPath = "/tmp/Evaluate-STIG_RemoteComputer/STIG_Compliance"

                        If ($SelectSTIG) {
                            If ($ForceSTIG) {
                                $ESArgs = "-SelectSTIG $($SelectSTIG -join ',') -ForceSTIG $($ForceSTIG -join ',') -ScanType $ScanType -AnswerKey $AnswerKey -VulnTimeout $VulnTimeout"
                            }
                            Else {
                                $ESArgs = "-SelectSTIG $($SelectSTIG -join ',') -ScanType $ScanType -AnswerKey $AnswerKey -VulnTimeout $VulnTimeout"
                            }
                        }
                        ElseIf ($ExcludeSTIG) {
                            If ($ForceSTIG) {
                                $ESArgs = "-ExcludeSTIG $($ExcludeSTIG -join ',') -ForceSTIG $($ForceSTIG -join ',') -ScanType $ScanType -AnswerKey $AnswerKey -VulnTimeout $VulnTimeout"
                            }
                            Else {
                                $ESArgs = "-ExcludeSTIG $($ExcludeSTIG -join ',') -ScanType $ScanType -AnswerKey $AnswerKey -VulnTimeout $VulnTimeout"
                            }
                        }
                        ElseIf ($ForceSTIG) {
                            $ESArgs = "-ForceSTIG $($ForceSTIG -join ',') -ScanType $ScanType -AnswerKey $AnswerKey -VulnTimeout $VulnTimeout"
                        }
                        Else {
                            $ESArgs = "-ScanType $ScanType -AnswerKey $AnswerKey -VulnTimeout $VulnTimeout"
                        }

                        $OutputList = $($Output | Where-Object {$_ -ne "STIGManager"})

                        If ($OutputList) {
                            $ESArgs = $ESArgs + " -Output $($Output -join ',') -OutputPath $DefaultOutputPath -PreviousToKeep $PreviousToKeep"
                        }

                        If ($SelectVuln) {
                            $ESArgs = $ESArgs + " -SelectVuln $($SelectVuln -join ',')"
                        }

                        If ($ExcludeVuln) {
                            $ESArgs = $ESArgs + " -ExcludeVuln $($ExcludeVuln -join ',')"
                        }

                        If ($Marking) {
                            $ESArgs = $ESArgs + " -Marking $Marking"
                        }

                        If ($ApplyTattoo) {
                            $ESArgs = $ESArgs + " -ApplyTattoo"
                        }

                        If ($AllowDeprecated) {
                            $ESArgs = $ESArgs + " -AllowDeprecated"
                        }

                        $ProgressPreference = "SilentlyContinue"

                        Initialize-FileXferToRemote -NETBIOS $($LinuxHost.NETBIOS) -RemoteTemp "/tmp/Evaluate-STIG_RemoteComputer" -OutputPath $OutputPath -AFPath $AFPath -Remote_Log $Remote_Log -LogComponent $LogComponent -OSPlatform $OSPlatform -RemoteWorkingDir $RemoteWorkingDir -ScriptRoot $ES_Path -Session $Session

                        Write-Log -Path $Remote_Log -Message "Invoking Evaluate-STIG on $($LinuxHost.FQDN)." -WriteOutToStream -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        Write-Log -Path $Remote_Log -Message "Local logging of scan is stored at /tmp/Evaluate-STIG on $($LinuxHost.FQDN)" -WriteOutToStream -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                        #Test for NOPASSWD
                        $NoPasswdTest = Invoke-Command -ScriptBlock { if ((sudo whoami) -ne "root") {
                                Return 2
                            } } -Session $Session -ErrorAction SilentlyContinue -InformationAction Ignore

                        $SudoFailCount = 1
                        if ($NoPasswdTest -eq 2) {
                            do {
                                $sudoPass = Read-Host "[sudo] password for $SessionUserName" -AsSecureString
                                $creds = New-Object System.Management.Automation.PSCredential($SessionUserName, $sudoPass)
                                $sudoPass = $creds.GetNetworkCredential().Password

                                $SudoCheck = Invoke-Command -ScriptBlock {
                                    param(
                                        [String]
                                        $SudoPass
                                    )
                                    if (($sudoPass | sudo -S whoami) -ne "root") {
                                        Write-Host "ERROR: sudo: incorrect password attempt" -ForegroundColor Red
                                        Return 2
                                    }
                                    else { return 0 }
                                } -Session $Session -ArgumentList $sudoPass -ErrorAction SilentlyContinue -InformationAction Ignore

                                $SudoFailCount++
                            }while ($SudoCheck -ne 0 -and $SudoFailCount -le 3)
                        }
                        else {
                            $null = $sudoPass
                        }

                        $RemoteES = Invoke-Command -Session $session {
                            param(
                                [String]
                                $SudoPass,

                                [String]
                                $ESArgs,

                                [string]
                                $DefaultOutputPath,

                                [string]
                                $SSHUsername,

                                [string]
                                $OutputPath
                            )

                            $LogOutput = [System.Collections.Generic.List[System.Object]]::new()
                            $RemoteOutput = [System.Collections.Generic.List[System.Object]]::new()

                            if ($null -ne $SudoPass) {
                                if (($sudoPass | sudo -S whoami) -ne "root") {
                                    $NewObj = [PSCustomObject]@{
                                        Message = "ERROR: sudo: incorrect password attempt"
                                        Type    = "Error"
                                    }
                                    $LogOutput.Add($NewObj)

                                    $NewObj = [PSCustomObject]@{
                                        Message = "==========[End Remote Logging]=========="
                                        Type    = "Info"
                                    }
                                    $LogOutput.Add($NewObj)

                                    $NewObj = [PSCustomObject]@{
                                        LogOutput  = $LogOutput
                                        ScanResult = "ERROR: sudo: incorrect password attempt"
                                    }
                                    $RemoteOutput.Add($NewObj)
                                    Return $RemoteOutput
                                }

                                if (!(Test-Path $DefaultOutputPath)) {
                                    $SudoPass | sudo -S mkdir $DefaultOutputPath
                                }
                            }
                            else {
                                if (!(Test-Path $DefaultOutputPath)) {
                                    sudo mkdir $DefaultOutputPath
                                }
                            }

                            # Now you have cached your sudo password you should be able to call it normally (up to whatever timeout you have configured)

                            $ESPath = "/tmp/Evaluate-STIG_RemoteComputer/Evaluate-STIG.ps1"

                            # Set PowerShell exe
                            $PS_Exe = "pwsh"

                            $ES_CmdLine = "$($ESPath) $($ESArgs)"

                            $ClixmlOut = "/tmp/Evaluate-STIG/ScanResult.xml"
                            $Scriptblock = [scriptblock]::Create('
                                $Output = ' + $ES_CmdLine + '
                                $Output | Export-Clixml -Depth 20 -Path ' + $ClixmlOut + ' -Force
                            ')
                            $Command = "Start-Process $PS_Exe -ArgumentList '-Command $Scriptblock' -Wait;chown -R $SSHUsername`: /tmp/Evaluate-STIG_RemoteComputer /tmp/Evaluate-STIG"
                            Try {
                                $SudoPass | sudo -S pwsh -command $Command

                                $NewObj = [PSCustomObject]@{
                                    Message = "Scan completed"
                                    Type    = "Info"
                                }
                                $LogOutput.Add($NewObj)

                                $NewObj = [PSCustomObject]@{
                                    LogOutput  = $LogOutput
                                    ScanResult = (Import-Clixml -Path $ClixmlOut)
                                }
                                $RemoteOutput.Add($NewObj)

                                Remove-Item -Path $ClixmlOut -Force

                                Return $RemoteOutput
                            }
                            Catch {
                                $NewObj = [PSCustomObject]@{
                                    Message = "ERROR: $($_.Exception.Message)"
                                    Type    = "Error"
                                }
                                $LogOutput.Add($NewObj)

                                $NewObj = [PSCustomObject]@{
                                    Message = "==========[End Remote Logging]=========="
                                    Type    = "Info"
                                }
                                $LogOutput.Add($NewObj)

                                $NewObj = [PSCustomObject]@{
                                    LogOutput  = $LogOutput
                                    ScanResult = "ERROR: $($_.Exception.Message)"
                                }
                                $RemoteOutput.Add($NewObj)

                                Return $RemoteOutput
                            }

                        } -ArgumentList ($sudoPass, $ESArgs, $DefaultOutputPath, $SessionUserName, $OutputPath) -ErrorAction SilentlyContinue -InformationAction Ignore

                        $RemoteES.LogOutput | ForEach-Object { Write-Log -Path $Remote_Log -Message $_.Message -Component $LogComponent -Type $_.Type -OSPlatform $OSPlatform }

                        if ($SelectVuln) {
                            $NetBIOS = "_Partial_$($LinuxHost.NETBIOS)"
                        }
                        else {
                            $NetBIOS = $($LinuxHost.NETBIOS)
                        }

                        if ($RemoteES.ScanResult -match "ERROR:") {
                            $RemoteLinuxFail++
                        }

                        If ($Output) {
                            If (($Output -split ",").Trim() -match "^STIGManager$") {
                                Try {
                                    Import-Module (Join-Path -Path $ScriptRoot -ChildPath "Modules" | Join-Path -ChildPath "STIGManager_Functions") -SkipEditionCheck -ErrorAction Stop

                                    $SMObject = [System.Collections.Generic.List[System.Object]]::new()
                                    $($RemoteES.ScanResult).$($($RemoteES.ScanResult).Keys).Values | Foreach-Object {$SMObject.Add($_)}

                                    if ($SMPassphrase){
                                        $SMImport_Params = Get-SMParameters -SMCollection $SMCollection -SMPassphrase $SMPassphrase -ScanObject $SMObject -ScriptRoot $ScriptRoot -WorkingDir $RemoteWorkingDir -OSPlatform $OSPlatform -LogComponent $LogComponent -LogPath $Remote_Log
                                    }
                                    else{
                                        $SMImport_Params = Get-SMParameters -SMCollection $SMCollection -ScanObject $SMObject -ScriptRoot $ScriptRoot -WorkingDir $RemoteWorkingDir -OSPlatform $OSPlatform -LogComponent $LogComponent -LogPath $Remote_Log
                                    }

                                    Import-Asset @SMImport_Params

                                }
                                Catch {
                                    Write-Log -Path $Remote_Log -Message "ERROR: $($_.Exception.Message)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                                }

                            }

                            If (($Output -split ",").Trim() -match @("(^CKL$|^CKLB$|^CombinedCKL$|^CombinedCKLB$|^Summary$|^OQE$)")) {
                                If (Invoke-Command -ScriptBlock { param ($DefaultOutputPath, $NetBIOS)
                                                                $Path = "$DefaultOutputPath/$NetBIOS"
                                                                Return (pwsh -command "Test-Path $Path" )
                                                                } -Session $Session -ArgumentList ($DefaultOutputPath, $NetBIOS)) {
                                    If ($SelectSTIG) {
                                        $PreviousArgs = @{SelectedShortName = $SelectSTIG}
                                        If (($Output -split ",").Trim() -match @("(^CombinedCKL$)")) {
                                            $PreviousArgs.Add("SelectedCombinedCKL",$true)
                                        }
                                        If (($Output -split ",").Trim() -match @("(^CombinedCKLB$)")) {
                                            $PreviousArgs.Add("SelectedCombinedCKLB", $true)
                                        }
                                        If (($Output -split ",").Trim() -match @("(^Summary$)")) {
                                            $PreviousArgs.Add("SelectedSummary", $true)
                                        }
                                        If (($Output -split ",").Trim() -match @("(^OQE$)")) {
                                            $PreviousArgs.Add("SelectedOQE", $true)
                                        }
                                        Initialize-PreviousProcessing -ResultsPath (Join-Path $OutputPath -ChildPath $NetBIOS) -PreviousToKeep $PreviousToKeep @PreviousArgs -LogPath $Remote_Log -LogComponent $LogComponent -OSPlatform $OSPlatform
                                    }
                                    Else {
                                        Initialize-PreviousProcessing -ResultsPath (Join-Path $OutputPath -ChildPath $NetBIOS) -PreviousToKeep $PreviousToKeep -LogPath $Remote_Log -LogComponent $LogComponent -OSPlatform $OSPlatform
                                    }

                                    Initialize-FileXferFromRemote -NETBIOS $NetBIOS -RemoteTemp "/tmp/Evaluate-STIG_RemoteComputer" -OutputPath $OutputPath -Remote_Log $Remote_Log -LogComponent $LogComponent -OSPlatform $OSPlatform -RemoteWorkingDir $RemoteWorkingDir -ScriptRoot $ScriptRoot -Session $Session
                                }
                                Else {
                                    Write-Log -Path $Remote_Log -Message "No Evaluate-STIG results were found on $($LinuxHost.FQDN)." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                    $OfflineList.Add($LinuxHost.NETBIOS)
                                    $RemoteLinuxFail++
                                }

                                If (Invoke-Command -ScriptBlock { Test-Path /tmp/Evaluate-STIG_RemoteComputer } -Session $Session) {
                                    Invoke-Command -ScriptBlock { Remove-Item /tmp/Evaluate-STIG_RemoteComputer -Recurse -Force } -Session $Session
                                }
                            }

                            If (($Output -split ",").Trim() -match "^Console$") {
                                # Add to results to be returned to console
                                $FormattedResult = @{}
                                ForEach ($Key in $RemoteES.ScanResult.Values.Keys) {
                                    $FormattedResult.Add($Key, $RemoteES.ScanResult.Values.$Key)
                                }
                                $RunspaceResults.Add($NetBIOS, $FormattedResult)
                            }
                        }
                        Else{
                            # Add to results to be returned to console
                            $FormattedResult = @{}
                            ForEach ($Key in $RemoteES.ScanResult.Values.Keys) {
                                $FormattedResult.Add($Key,$RemoteES.ScanResult.Values.$Key)
                            }
                            $RunspaceResults.Add($NetBIOS,$FormattedResult)
                        }

                        $Session | Remove-PSSession

                        $TimeToComplete = New-TimeSpan -Start $RemoteStartTime -End (Get-Date)
                        $FormatedTime = "{0:c}" -f $TimeToComplete
                        Write-Log -Path $Remote_Log -Message "Total Time : $($FormatedTime)" -WriteOutToStream -FGColor Green -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        Write-Log -Path $Remote_Log -Message "End Remote Logging" -TemplateMessage LineBreak-Text -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                        Add-Content -Path $STIGLog_Remote -Value $(Get-Content $Remote_Log)
                        Remove-Item $Remote_Log

                        $ProgressPreference = "Continue"
                    }
                    Catch {
                        Write-Log -Path $Remote_Log -Message "ERROR: $($_.Exception.Message)" -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                        Write-Log -Path $Remote_Log -Message "End Remote Logging" -TemplateMessage LineBreak-Text -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                        Add-Content -Path $STIGLog_Remote -Value $(Get-Content $Remote_Log)
                        Remove-Item $Remote_Log

                        If ($Session) {
                            $Session | Remove-PSSession
                        }
                        $ProgressPreference = "Continue"
                    }
                }
                Else {
                    $RemoteLinuxFail++
                    Write-Log -Path $Remote_Log -Message "ERROR: $($LinuxHost.FQDN) is running a Linux Operating System. PowerShell $($PowerShellVersion -join '.') detected. Evaluate-STIG requires PowerShell 7.1." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    Write-Log -Path $Remote_Log -Message "End Remote Logging" -TemplateMessage LineBreak-Text -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                    Add-Content -Path $STIGLog_Remote -Value $(Get-Content $Remote_Log)
                    Remove-Item $Remote_Log
                }
            }
        }

        $RemoteTimeToComplete = New-TimeSpan -Start $StartTime -End (Get-Date)
        $FormatedTime = "{0:c}" -f $RemoteTimeToComplete
        Write-Host ""
        Write-Log -Path $STIGLog_Remote -Message "Done!" -WriteOutToStream -FGColor Green -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Remote -Message "Total Time - $($FormatedTime)" -WriteOutToStream -FGColor Green -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Remote -Message "Total Hosts - $(($ComputerList | Measure-Object).count)" -WriteOutToStream -FGColor Green -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        if ($($RemoteLinuxFail + $(if ($RemoteFailCount.Values -ge 1) {
                        $($RemoteFailCount.Values)
                    }
                    else {
                        "0"
                    })) -gt 0) {
            Write-Log -Path $STIGLog_Remote -Message "Total Hosts with Error - $($RemoteLinuxFail + $(if ($RemoteFailCount.Values -ge 1){$($RemoteFailCount.Values)}else{"0"}))" -WriteOutToStream -FGColor Red -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        }
        Write-Log -Path $STIGLog_Remote -Message "Total Hosts Not Resolved - $RemoteUnresolveCount" -WriteOutToStream -FGColor Yellow -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Remote -Message "Total Hosts Offline - $(($OfflineList | Measure-Object).Count)" -WriteOutToStream -FGColor Yellow -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Host ""
        If (($Output -split ",").Trim() -match @("(^CKL$|^CKLB$|^CombinedCKL$|^CombinedCKLB$|^Summary$|^OQE$)")) {
            Write-Host "Results saved to " -ForegroundColor Green -NoNewline; Write-Host "$($OutputPath)" -ForegroundColor Cyan
        }
        Write-Host "Local logging of remote scan(s) stored at " -ForegroundColor Green -NoNewline; Write-Host "$($RemoteScanDir)" -ForegroundColor Cyan
        Write-Host "Offline Results saved to " -ForegroundColor Green -NoNewline; Write-Host "$RemoteScanDir\Offline_Hosts.txt" -ForegroundColor Cyan

        if (($OfflineList | Measure-Object).Count -gt 0) {
            if (Test-Path "$RemoteScanDir\Offline_Hosts.txt") {
                Clear-Content "$RemoteScanDir\Offline_Hosts.txt"
            }
            $OfflineList | Sort-Object -Unique | ForEach-Object {
                Add-Content -Path "$RemoteScanDir\Offline_Hosts.txt" -Value $_
            }
        }

        If (Test-Path $RemoteWorkingDir\ESCONTENT.ZIP) {
            Remove-Item -Path $RemoteWorkingDir\ESCONTENT.ZIP -Force
        }
        If (Test-Path $RemoteWorkingDir\AFILES.ZIP) {
            Remove-Item -Path $RemoteWorkingDir\AFILES.ZIP -Force
        }

        Return $RunspaceResults
    }
    Catch {
        Write-Log -Path $STIGLog_Remote "ERROR: $($_.Exception.Message)" -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
    }
}

Function Get-FileUpdatesFromRepo {
    Param (
        [Parameter(Mandatory = $true)]
        [String] $PS_Path,

        [Parameter(Mandatory = $false)]
        [String] $Proxy,

        [Parameter(Mandatory = $false)]
        [Switch] $SecondPass,

        [Parameter(Mandatory = $false)]
        [String] $LocalSource
    )

    Try {
        $UpdateRequired = $false

        if (!($SecondPass)){
            Write-Host "Checking for updates to Evaluate-STIG" -ForegroundColor Gray
        }
        If ($Proxy) {
            Write-Host "Using proxy '$Proxy'" -ForegroundColor Gray
        }
        $URLs = @(
            "https://spork.navsea.navy.mil/nswc-crane-division/evaluate-stig/-/archive/master/evaluate-stig-master.zip?path=Src/Evaluate-STIG"
        )

        $LocalContent = Get-ChildItem $PS_Path -Recurse | Where-Object { ($_.Name -ne "powershell.tar.gz") -and ($_.Name -ne "AnswerFiles") -and ($_.DirectoryName -notlike $(Join-Path -Path $PS_Path -ChildPath "AnswerFiles*") -and ($_.Name -ne "_Update.tmp") -and ($_.DirectoryName -notlike $(Join-Path -Path $PS_Path -ChildPath "_Update.tmp*"))) }
        $LocalVersion = (Select-String -Path $(Join-Path -Path $PS_Path -ChildPath "Evaluate-STIG.ps1") -Pattern '\$EvaluateStigVersion = ' | ForEach-Object { $_.Line.Split(":") }).replace('$EvaluateStigVersion = ', '').Replace('"', '').Trim()
        $LocalPreferences = (Select-Xml -Path $(Join-Path $PS_Path -ChildPath Preferences.xml) -XPath /).Node

        # Create temp folder
        $Update_tmp = (Join-Path -Path $PS_Path -ChildPath "_Update.tmp")
        If (Test-Path $Update_tmp) {
            Remove-Item $Update_tmp -Recurse -Force
        }
        $null = New-Item -Path $PS_Path -Name "_Update.tmp" -ItemType Directory

        if ($LocalSource){
            Write-Host "Using Local Source: '$LocalSource'" -ForegroundColor Gray
            Copy-Item -Path "$LocalSource\*" -Destination $Update_tmp -Recurse
        }
        else{
            # load ZIP methods
            Add-Type -AssemblyName System.IO.Compression.FileSystem

            # Download upstream content
            $ZipFile = $(Join-Path -Path $PS_Path -ChildPath "evaluate-stig-master.zip")
            If ($Islinux) {
                $pkg_mgr = (Get-Content /etc/os-release | grep "ID_LIKE=").replace("ID_LIKE=", "").replace('"', "")
                Switch ($pkg_mgr) {
                    "debian" {
                        If (apt -qq list curl 2>/dev/null | grep installed) {
                            $curl_installed = $true
                        }
                    }
                    "fedora" {
                        If (rpm -qa | grep curl) {
                            $curl_installed = $true
                        }
                    }
                }
                If ($curl_installed) {
                    ForEach ($URL in $URLs) {
                        If ($Proxy) {
                            curl -k $URL --proxy $Proxy --output evaluate-stig-master.zip
                        }
                        Else {
                            curl -k $URL --output evaluate-stig-master.zip
                        }
                        If ((Get-Item $ZipFile).Length -gt 0) {
                            Break
                        }
                    }
                }
                Else {
                    Throw "Curl is required to be installed to download updates."
                }
            }
            Else {
                $WebClient = New-Object System.Net.WebClient
                If ($Proxy) {
                    $WebProxy = New-Object System.Net.WebProxy($Proxy, $true)
                    $WebClient.Proxy = $WebProxy
                }
                ForEach ($URL in $URLs) {
                    $WebClient.DownloadFile($URL, $ZipFile)
                    If ((Get-Item $ZipFile).Length -gt 0) {
                        Break
                    }
                }
            }

            # change extension filter to a file extension that exists
            # inside your ZIP file
            $Filter = '/Evaluate-STIG/'

            # open ZIP archive for reading
            $Zip = [IO.Compression.ZipFile]::OpenRead($ZipFile)

            # Exclude /AnswerFiles/ so we don't overwrite user customizations
            $Exclude = "/AnswerFiles/"

            # find all files in ZIP that match the filter (i.e. file extension)
            $Zip.Entries |
            Where-Object { ($_.FullName -match $Filter) -and ($_.FullName -notmatch $Exclude)} | ForEach-Object {
                # extract the selected items from the ZIP archive
                # and copy them to the out folder
                $FileName = $_.Name
                If ($Filename) {
                    $Path_strip = ($_.FullName).replace("evaluate-stig-master-Src-Evaluate-STIG/Src/Evaluate-STIG", "").Replace($FileName, "")
                    $FilePath = "$(Join-Path -Path $Update_tmp -ChildPath $Path_strip)"
                    [IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$FilePath$FileName", $true)
                }
                Else {
                    $Path_strip = ($_.FullName).replace("evaluate-stig-master-Src-Evaluate-STIG/Src/Evaluate-STIG", "")
                    $null = New-Item -Path $(Join-Path -Path $Update_tmp -ChildPath $Path_strip) -ItemType Directory -Force
                }
            }
            # close ZIP file
            $Zip.Dispose()
            Remove-Item -Path $ZipFile -Force
        }

        $UpstreamVersion = (Select-String -Path $(Join-Path -Path $Update_tmp -ChildPath "Evaluate-STIG.ps1") -Pattern '\$EvaluateStigVersion = ' | ForEach-Object { $_.Line.Split(":") }).replace('$EvaluateStigVersion = ', '').Replace('"', '').Trim()
        $UpstreamPreferences = (Select-Xml -Path $(Join-Path $Update_tmp -ChildPath Preferences.xml) -XPath /).Node

        # Build list objects
        $LocalContentList = New-Object System.Collections.Generic.List[System.Object]
        [XML]$FileList = Get-Content ($LocalContent | Where-Object { $_.Name -eq "FileList.XML" }).FullName
        ForEach ($Item in $LocalContent) {
            If ($Item.PSIsContainer -eq $true) {
                $Hash = ""
            }
            Else {
                $FileListAttributes = (Select-Xml -Xml $FileList -XPath "//File[@Name=""$($Item.Name)""]").Node
                If ($FileListAttributes.Path -match "Modules") {
                    $IsModule = $True
                }
                else {
                    $IsModule = $False
                }
                $ScanReq = $FileListAttributes.ScanReq
                $Hash = (Get-FileHash $Item.FullName -Algorithm SHA256).Hash

            }
            $NewObj = [PSCustomObject]@{
                PSIsContainer = $Item.PSIsContainer
                Name          = $Item.Name
                FullName      = $Item.FullName
                IsModule      = $IsModule
                ScanRequired  = $ScanReq
                Hash          = $Hash
            }
            $LocalContentList.Add($NewObj)
        }

        $UpstreamContent = Get-ChildItem $Update_tmp -Recurse
        $UpstreamContentList = New-Object System.Collections.Generic.List[System.Object]
        [XML]$FileList = Get-Content ($UpstreamContent | Where-Object { $_.Name -eq "FileList.XML" }).FullName
        ForEach ($Item in $UpstreamContent) {
            If ($Item.PSIsContainer -eq $true) {
                $Hash = ""
            }
            Else {
                $FileListAttributes = (Select-Xml -Xml $FileList -XPath "//File[@Name=""$($Item.Name)""]").Node
                If ($FileListAttributes.Path -match "Modules") {
                    $IsModule = $True
                }
                else {
                    $IsModule = $False
                }
                $ScanReq = $FileListAttributes.ScanReq
                $Hash = (Get-FileHash $Item.FullName -Algorithm SHA256).Hash
            }
            $NewObj = [PSCustomObject]@{
                PSIsContainer = $Item.PSIsContainer
                Name          = $Item.Name
                FullName      = $Item.FullName
                IsModule      = $IsModule
                ScanRequired  = $ScanReq
                Hash          = $Hash
            }
            $UpstreamContentList.Add($NewObj)
        }

        # Compare local file hashes to upstream hashes
        ForEach ($Item in ($UpstreamContentList | Where-Object PSIsContainer -NE $true)) {
            $LocalFile = $Item.FullName.Replace($Update_tmp, $PS_Path)
            If (-Not((Test-Path $LocalFile) -and (($LocalContentList | Where-Object FullName -EQ $LocalFile).Hash -eq $Item.Hash))) {
                $UpdateRequired = $true
                Break
            }
        }

        # Look for items that are not part of upstream content (excludes Answer Files)
        ForEach ($Item in $LocalContentList) {
            If ((Test-Path $Item.FullName) -and ($Item.FullName -notin $UpstreamContentList.FullName.Replace($Update_tmp, $PS_Path))) {
                $UpdateRequired = $true
                Break
            }
        }

        # If an update is required, wipe all local content and sync with upstream (excludes Answer Files)
        If ($UpdateRequired -eq $true -or $SecondPass) {
            $OptionalList = New-Object System.Collections.Generic.List[System.Object]
            ForEach ($Item in $LocalContentList) {
                If ($Item.ScanRequired -eq "Optional") {
                    $OptionalModule = $True
                    $OptionalList.Add($Item.Name)
                }
                If (Test-Path $Item.FullName) {
                    Remove-Item $Item.FullName -Recurse -Force
                }
            }
            #ReWrite Local Preferences to Updated Preferences File
            Foreach ($RootNode in $LocalPreferences.SelectNodes("//*")){
                $RootNode.SelectNodes("./*[not(*)]") | Foreach-Object{
                    if ($null -ne $_.'#text'){
                        If ($($UpstreamPreferences.SelectSingleNode(".//$($_.Name)"))){
                            ($UpstreamPreferences.SelectSingleNode(".//$($_.Name)")).InnerText = $_."#text"
                        }
                    }
                }
            }
            $UpstreamPreferences.Save($(Join-Path $Update_tmp -ChildPath Preferences.xml))

            Copy-Item $(Join-Path -Path $Update_tmp -ChildPath "*") -Destination $PS_Path -Recurse -Force -ErrorAction SilentlyContinue
        }

        # If Answer Files folder doesn't exist for some reason, create it since it's the default for -AFPath
        If (-Not(Test-Path $(Join-Path -Path $PS_Path -ChildPath "AnswerFiles"))) {
            New-Item -Path $PS_Path -Name "AnswerFiles" -ItemType Directory | Out-Null
        }
        $Verified = $true
        If (Test-Path (Join-Path -Path $PS_Path -ChildPath "xml" | Join-Path -ChildPath "FileList.xml")) {
            [XML]$FileListXML = Get-Content -Path (Join-Path -Path $PS_Path -ChildPath "xml" | Join-Path -ChildPath "FileList.xml")
            If ((Test-XmlSignature -checkxml $FileListXML -Force) -ne $true) {
                Write-Host "ERROR: 'FileList.xml' in $PS_Path failed authenticity check after update.  Unable to verify content integrity." -ForegroundColor Red
                Throw
            }
            Else {
                ForEach ($File in $FileListXML.FileList.File) {
                    $Path = (Join-Path -Path $PS_Path -ChildPath $File.Path | Join-Path -ChildPath $File.Name)
                    If (Test-Path $Path) {
                        If ((Get-FileHash -Path $Path -Algorithm SHA256).Hash -ne $File.SHA256Hash) {
                            $Verified = $false
                        }
                    }
                    else{
                        If ($File.ScanReq -ne "Optional") {
                            $Verified = $false
                        }
                    }
                }
                If ($Verified -eq $true) {
                    Write-Host "$PS_Path file integrity check passed after update." -ForegroundColor Green
                }
                Else {
                    Write-Host "$PS_Path file integrity check failed after update." -ForegroundColor Red
                    Throw
                }
            }
        }
        Else {
            Write-Host "ERROR: 'FileList.xml' in $PS_Path not found after update.  Unable to verify content integrity." -ForegroundColor Red
            Throw
        }

        # Clean up temp files
        If (Test-Path $Update_tmp) {
            Try {
                Remove-Item -Path $Update_tmp -Recurse -Force -ErrorAction Stop
            }
            Catch{
                Throw
            }
        }
        if ($null -eq $LocalSource){
            If (Test-Path $ZipFile) {
                Remove-Item $ZipFile -Force
            }
        }

        If ($UpdateRequired -eq $true){
            If ($SecondPass) {
                If ($OptionalModule) {
                    Write-Host "The following Optional files require redownloading:" -ForegroundColor Yellow
                    $OptionalList | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
                    Return "Successfully updated to Evaluate-STIG $($UpstreamVersion)."
                }
                Else {
                    Return "Successfully updated to Evaluate-STIG $($UpstreamVersion)."
                }
            }
            else{
                Return "Successfully updated to Evaluate-STIG $($UpstreamVersion)."
            }
        }
        Else {
            if ($SecondPass){
                Return "Successfully updated to Evaluate-STIG $($UpstreamVersion)."
            }
            else{
                "Evaluate-STIG $($LocalVersion) requires no updating."
            }
        }
    }
    Catch {
        # Clean up temp files
        if ($null -eq $LocalSource){
            If (Test-Path $ZipFile) {
                Remove-Item $ZipFile -Force
            }
        }
        If (Test-Path $Update_tmp) {
            $MaxWaitTime = 10
            $RetryCount = 1
            Get-ChildItem $Update_tmp -File -Recurse | Foreach-Object {
                $FileObject = $_.FullName
                Do {
                    try {
                        $filecheck = [System.IO.File]::Open($FileObject, 'Open', 'Read') # Open file
                        $filecheck.Close()
                        $filecheck.Dispose() # Disposing object
                        $unlocked = $true
                    }
                    catch [System.Management.Automation.MethodException] {
                        Start-Sleep 1
                        $RetryCount++
                        $unlocked = $false
                    }
                } Until ($unlocked -or $RetryCount -gt $MaxWaitTime)
                If (!$unlocked){
                    Write-host "$FileObject is locked. Delete retry exceeded $MaxWaitTime seconds."
                }
                else{
                    Remove-Item -Path $_.FullName -Force
                }
            }
            If ((Get-ChildItem $Update_tmp -File -Recurse | Measure-Object).count -eq 0){
                Remove-Item -Path $Update_tmp -Recurse -Force
                if ($Verified){
                    Return "Successfully updated to Evaluate-STIG $($UpstreamVersion)."
                }
                Else{
                    Return "Update failed.  $PS_Path file integrity check failed after update."
                }
            }
            else{
                if ($Verified){
                    Return "Successfully updated to Evaluate-STIG $($UpstreamVersion).`r`nRemediate locked files and manually delete $Update_tmp."
                }
                else{
                    Return "Update failed.  $PS_Path file integrity check failed after update."
                }
            }
        }

        Return $_.Exception.Message

    }
}

Function Get-Creds {
    <#
.NOTES
Author: Joshua Chase
Last Modified: 09 September 2019
Version: 1.1.0
C# signatures obtained from PInvoke.
#>
    [cmdletbinding()]
    Param()
    $Code = @"
using System;
using System.Text;
using System.Security;
using System.Management.Automation;
using System.Runtime.InteropServices;
public class Credentials
{
    private const int CREDUIWIN_GENERIC = 1;
    private const int CREDUIWIN_CHECKBOX = 2;
    private const int CREDUIWIN_AUTHPACKAGE_ONLY = 16;
    private const int CREDUIWIN_IN_CRED_ONLY = 32;
    private const int CREDUIWIN_ENUMERATE_ADMINS = 256;
    private const int CREDUIWIN_ENUMERATE_CURRENT_USER = 512;
    private const int CREDUIWIN_SECURE_PROMPT = 4096;
    private const int CREDUIWIN_PACK_32_WOW = 268435456;
    [DllImport("credui.dll", CharSet = CharSet.Unicode)]
    private static extern uint CredUIPromptForWindowsCredentials(ref CREDUI_INFO notUsedHere,
        int authError,
        ref uint authPackage,
        IntPtr InAuthBuffer,
        uint InAuthBufferSize,
        out IntPtr refOutAuthBuffer,
        out uint refOutAuthBufferSize,
        ref bool fSave,
        int flags);
    [DllImport("credui.dll", CharSet = CharSet.Unicode)]
    private static extern bool CredUnPackAuthenticationBuffer(int dwFlags,
        IntPtr pAuthBuffer,
        uint cbAuthBuffer,
        StringBuilder pszUserName,
        ref int pcchMaxUserName,
        StringBuilder pszDomainName,
        ref int pcchMaxDomainame,
        StringBuilder pszKey,
        ref int pcchMaxKey);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDUI_INFO
    {
        public int cbSize;
        public IntPtr hwndParent;
        public string pszMessageText;
        public string pszCaptionText;
        public IntPtr hbmBanner;
    }
    public static PSCredential getPSCred()
    {
        bool save = false;
        int authError = 0;
        uint result;
        uint authPackage = 0;
        IntPtr outCredBuffer;
        uint outCredSize;
        PSCredential psCreds = null;
        var credui = new CREDUI_INFO
                                {
                                    pszCaptionText = "Enter your credentials",
                                    pszMessageText = "These credentials will be used for Evaluate-STIG remote scans"
                                };
        credui.cbSize = Marshal.SizeOf(credui);
        while (true) //Show the dialog again and again, until Cancel is clicked or the entered credentials are correct.
        {
            //Show the dialog
            result = CredUIPromptForWindowsCredentials(ref credui,
            authError,
            ref authPackage,
            IntPtr.Zero,
            0,
            out outCredBuffer,
            out outCredSize,
            ref save,
            CREDUIWIN_ENUMERATE_CURRENT_USER);
            if (result != 0) break;
            var usernameBuf = new StringBuilder(100);
            var keyBuf = new StringBuilder(100);
            var domainBuf = new StringBuilder(100);
            var maxUserName = 100;
            var maxDomain = 100;
            var maxKey = 100;
            if (CredUnPackAuthenticationBuffer(1, outCredBuffer, outCredSize, usernameBuf, ref maxUserName, domainBuf, ref maxDomain, keyBuf, ref maxKey))
            {
                Marshal.ZeroFreeCoTaskMemUnicode(outCredBuffer);
                var key = new SecureString();
                foreach (char c in keyBuf.ToString())
                {
                    key.AppendChar(c);
                }
                keyBuf.Clear();
                key.MakeReadOnly();
                psCreds = new PSCredential(usernameBuf.ToString(), key);
                GC.Collect();
                break;
            }

            else authError = 1326; //1326 = 'Logon failure: unknown user name or bad password.'
        }
        return psCreds;
    }
}
"@

    Add-Type -TypeDefinition $Code -Language CSharp

    Write-Output ([Credentials]::getPSCred())
}

Function Get-RunspaceData {
    [cmdletbinding()]
    param(
        [System.Collections.ArrayList]$Runspaces,

        [switch]$Wait,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Cisco", "Remote", "VCenter")]
        [String]$Usage
    )
    $RunspacesCount = ($Runspaces | Measure-Object).Count
    $RunspacesCompleteCount = 0

    Do {
        $more = $false
        Foreach ($runspace in $runspaces) {
            If ($runspace.Runspace.State.isCompleted) {
                $runspace.Job.dispose()
                $runspace.Runspace = $null
                $runspace.Job = $null
            }
            ElseIf ($null = $runspace.Runspace) {
                $more = $true
            }
        }
        If ($more -AND $PSBoundParameters['Wait']) {
            Start-Sleep -Milliseconds 100
        }
        #Clean out unused runspace jobs
        $temphash = $runspaces.clone()
        $temphash | Where-Object {
            $Null -eq $_.runspace
        } | ForEach-Object {
            $RunspacesCompleteCount++
            $Runspaces.remove($_)
        }

        Switch ($Usage) {
            'VCenter' {
                $ProgSplat = @{
                    Activity         = "Running VCenter Scans: $ProgressActivity"
                    Status           = ("Completed Evaluate-STIG Jobs: {0} of $RunspacesCount" -f $($RunspacesCount - ($Runspaces | Measure-Object).Count))
                    PercentComplete  = ($RunspacesCompleteCount / $RunspacesCount * 100)
                    CurrentOperation = "Remaining: $($Runspaces.VMName -join ", ")"
                }
                Write-Progress @ProgSplat
            }
            "Cisco" {
                Write-Progress -Activity "Running Cisco Config Scans: $ProgressActivity" -Status ("Completed Evaluate-STIG Jobs: {0} of $RunspacesCount" -f $($RunspacesCount - ($Runspaces | Measure-Object).Count)) -PercentComplete ($RunspacesCompleteCount / $RunspacesCount * 100) -CurrentOperation "Remaining: $($Runspaces.Hostname -join ", ")"
            }
            "Remote" {
                $RunningRunspaces = @((Get-Runspace | Where-Object RunspaceStateInfo -notlike "*Closed*").ConnectionInfo.ComputerName | Sort-Object -Unique | ForEach-Object { ($_).Split('.')[0] })
                Write-Progress -Activity "Running Remote Scans: $ProgressActivity" -Status ("Completed Evaluate-STIG Jobs: {0} of $RunspacesCount" -f $($RunspacesCount - ($Runspaces | Measure-Object).Count)) -PercentComplete ($RunspacesCompleteCount / $RunspacesCount * 100) -CurrentOperation "Scanning: $RunningRunspaces"
            }
        }
    } while ($more -AND $PSBoundParameters['Wait'])

    Switch ($Usage) {
        'VCenter' {
            Write-Progress -Activity "Running VCenter Scans: $ProgressActivity" -Completed
        }
        "Cisco" {
            Write-Progress -Activity "Running Cisco Config Scans: $ProgressActivity" -Completed
        }
        "Remote" {
            Remove-Variable RunningRunspaces
            Write-Progress -Activity "Running Remote Scans: $ProgressActivity" -Completed
        }
    }
}

Function Get-FileEncoding {
    <# http://franckrichard.blogspot.com/2010/08/powershell-get-encoding-file-type.html
    https://community.idera.com/database-tools/powershell/powertips/b/tips/posts/get-text-file-encoding
    http://unicode.org/faq/utf_bom.html
    http://en.wikipedia.org/wiki/Byte_order_mark

    Modified by Dan Ireland March 2021
    #>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        [string]$Path
    )

    $Encoding = "ASCII (no BOM)"

    $BOM = New-Object -TypeName System.Byte[](4)
    $File = New-Object System.IO.FileStream($Path, 'Open', 'Read')
    $null = $File.Read($BOM, 0, 4)
    $File.Close()
    $File.Dispose()

    # EF BB BF (UTF8 with BOM)
    If ($BOM[0] -eq 0xef -and $BOM[1] -eq 0xbb -and $BOM[2] -eq 0xbf -and $BOM[3] -eq 0x23) {
        $Encoding = "UTF-8 with BOM"
    }

    # FE FF  (UTF-16 Big-Endian)
    ElseIf ($BOM[0] -eq 0xfe -and $BOM[1] -eq 0xff) {
        $Encoding = "UTF-16 BE"
    }

    # FF FE  (UTF-16 Little-Endian)
    ElseIf ($BOM[0] -eq 0xff -and $BOM[1] -eq 0xfe) {
        $Encoding = "UTF-16 LE"
    }

    # 00 00 FE FF (UTF32 Big-Endian)
    ElseIf ($BOM[0] -eq 0 -and $BOM[1] -eq 0 -and $BOM[2] -eq 0xfe -and $BOM[3] -eq 0xff) {
        $Encoding = "UTF32 Big-Endian"
    }

    # FE FF 00 00 (UTF32 Little-Endian)
    ElseIf ($BOM[0] -eq 0xfe -and $BOM[1] -eq 0xff -and $BOM[2] -eq 0 -and $BOM[3] -eq 0) {
        $Encoding = "UTF32 Little-Endian"
    }

    # 2B 2F 76 (38 | 38 | 2B | 2F)
    ElseIf ($BOM[0] -eq 0x2b -and $BOM[1] -eq 0x2f -and $BOM[2] -eq 0x76 -and ($BOM[3] -eq 0x38 -or $BOM[3] -eq 0x39 -or $BOM[3] -eq 0x2b -or $BOM[3] -eq 0x2f)) {
        $Encoding = "UTF7"
    }

    # F7 64 4C (UTF-1)
    ElseIf ($BOM[0] -eq 0xf7 -and $BOM[1] -eq 0x64 -and $BOM[2] -eq 0x4c ) {
        $Encoding = "UTF-1"
    }

    # DD 73 66 73 (UTF-EBCDIC)
    ElseIf ($BOM[0] -eq 0xdd -and $BOM[1] -eq 0x73 -and $BOM[2] -eq 0x66 -and $BOM[3] -eq 0x73) {
        $Encoding = "UTF-EBCDIC"
    }

    # 0E FE FF (SCSU)
    ElseIf ( $BOM[0] -eq 0x0e -and $BOM[1] -eq 0xfe -and $BOM[2] -eq 0xff ) {
        $Encoding = "SCSU"
    }

    # FB EE 28  (BOCU-1)
    ElseIf ( $BOM[0] -eq 0xfb -and $BOM[1] -eq 0xee -and $BOM[2] -eq 0x28 ) {
        $Encoding = "BOCU-1"
    }

    # 84 31 95 33 (GB-18030)
    ElseIf ($BOM[0] -eq 0x84 -and $BOM[1] -eq 0x31 -and $BOM[2] -eq 0x95 -and $BOM[3] -eq 0x33) {
        $Encoding = "GB-18030"
    }

    Return $Encoding
}

Function Initialize-Archiving {
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Compress", "Expand")]
        [String]$Action,

        [Parameter(Mandatory = $true)]
        [String]$Path,

        [Parameter(Mandatory = $true)]
        [String]$DestinationPath,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Fastest", "NoCompression", "Optimal")]
        [String]$CompressionLevel = "Optimal",

        [Parameter(Mandatory = $false)]
        [Switch]$Force,

        [Parameter(Mandatory = $false)]
        [Switch]$Update
    )

    # Create runspace pool to include required modules.
    $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $SessionState.ImportPSModule('Microsoft.PowerShell.Archive')
    $RunspacePool = [runspacefactory]::CreateRunspacePool(1, 1, $SessionState, $Host)
    $RunspacePool.Open()

    Switch ($Action) {
        "Compress" {
            $Command = "Compress-Archive -Path '$Path' -DestinationPath '$DestinationPath' -CompressionLevel $CompressionLevel"
            If ($Force) {
                $Command = $Command + " -Force"
            }
            If ($Update) {
                $Command = $Command + " -Update"
            }
        }
        "Expand" {
            $Command = "Expand-Archive -Path '$Path' -DestinationPath '$DestinationPath'"
            If ($Force) {
                $Command = $Command + " -Force"
            }
        }
    }

    Try {
        $RSCodeText = 'Try {' + $Command + '} Catch {$Result=@{CodeFail=$true;Message=$($_.Exception.Message)}; Return $Result}' | Out-String
        $RSCodeSB = [scriptblock]::Create($RSCodeText)
        $Result = Invoke-CodeWithTimeout -Code $RSCodeSB -Timeout 5 -RunspacePool $RunspacePool
        $Result = $Result | Where-Object {$null -ne $_.Status}
        If ($Result.CodeFail) {
            Throw "CodeFail"
        }
        $RunspacePool.Close()
        $RunspacePool.Dispose()
        Return "Success"
    }
    Catch {
        $RunspacePool.Close()
        $RunspacePool.Dispose()
        Return $Result.Message
    }
}

Function Initialize-FileXferToRemote {
    Param (
        [Parameter(Mandatory = $true)]
        [String] $NETBIOS,

        [Parameter(Mandatory = $true)]
        [String] $RemoteTemp,

        [Parameter(Mandatory = $false)]
        [String] $OutputPath,

        [Parameter(Mandatory = $false)]
        [String] $AFPath,

        [Parameter(Mandatory = $false)]
        [String] $Remote_Log,

        [Parameter(Mandatory = $false)]
        [String] $LogComponent,

        [Parameter(Mandatory = $false)]
        [String] $OSPlatform,

        [Parameter(Mandatory = $false)]
        [String] $RemoteWorkingDir,

        [Parameter(Mandatory = $false)]
        [String] $ScriptRoot,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.Runspaces.PSSession] $Session
    )

    Write-Log -Path $Remote_Log -Message "Copying Evaluate-STIG archive" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
    Copy-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath ESCONTENT.ZIP) -Destination $(Join-Path -Path $RemoteTemp -ChildPath \) -Force -ToSession $Session

    Write-Log -Path $Remote_Log -Message "Expanding Evaluate-STIG archive" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
    Invoke-Command -ScriptBlock { param($RemoteTemp) Import-Module Microsoft.PowerShell.Archive; $Global:ProgressPreference = 'SilentlyContinue'; Expand-Archive -Path $(Join-Path -Path $RemoteTemp -ChildPath ESCONTENT.ZIP) -DestinationPath $RemoteTemp -Force } -Session $Session -ArgumentList $RemoteTemp

    If (($AFPath.TrimEnd('\')).TrimEnd('/') -ne (Join-Path -Path $ScriptRoot -ChildPath "AnswerFiles")) {
        Write-Log -Path $Remote_Log -Message "Copying answer file archive" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Invoke-Command -ScriptBlock { param($RemoteTemp) Remove-Item -Path $(Join-Path -Path $RemoteTemp -ChildPath AnswerFiles | Join-Path -ChildPath *.xml) -Force } -Session $Session -ArgumentList $RemoteTemp
        Copy-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath AFILES.ZIP) -Destination $(Join-Path -Path $RemoteTemp -ChildPath \) -Force -ToSession $Session

        Write-Log -Path $Remote_Log -Message "Expanding answer file archive" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Invoke-Command -ScriptBlock { param($RemoteTemp) $Global:ProgressPreference = 'SilentlyContinue'; Expand-Archive -Path $(Join-Path -Path $RemoteTemp -ChildPath AFILES.ZIP) -DestinationPath $(Join-Path -Path $RemoteTemp -ChildPath AnswerFiles) -Force } -Session $Session -ArgumentList $RemoteTemp
    }
}

Function Initialize-FileXferFromRemote {
    Param (
        [Parameter(Mandatory = $true)]
        [String] $NETBIOS,

        [Parameter(Mandatory = $true)]
        [String] $RemoteTemp,

        [Parameter(Mandatory = $false)]
        [String] $OutputPath,

        [Parameter(Mandatory = $false)]
        [String] $Remote_Log,

        [Parameter(Mandatory = $false)]
        [String] $LogComponent,

        [Parameter(Mandatory = $false)]
        [String] $OSPlatform,

        [Parameter(Mandatory = $false)]
        [String] $RemoteWorkingDir,

        [Parameter(Mandatory = $false)]
        [String] $ScriptRoot,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.Runspaces.PSSession] $session
    )

    Write-Log -Path $Remote_Log -Message "Compressing Evaluate-STIG results" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
    Invoke-Command -ScriptBlock { param($RemoteTemp, $NETBIOS) Compress-Archive -Path $(Join-Path -Path $RemoteTemp -ChildPath STIG_Compliance | Join-Path -ChildPath $NETBIOS) -DestinationPath $(Join-Path -Path $RemoteTemp -ChildPath STIG_Compliance | Join-Path -ChildPath "$($NETBIOS).ZIP") -CompressionLevel Optimal -Force } -Session $Session -ArgumentList $RemoteTemp, $NETBIOS

    Write-Log -Path $Remote_Log -Message "Copying Evaluate-STIG results archive" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
    Copy-Item -Path $(Join-Path -Path $RemoteTemp -ChildPath STIG_Compliance | Join-Path -ChildPath "$($NETBIOS).ZIP") -Destination $RemoteWorkingDir -Force -FromSession $Session

    Write-Log -Path $Remote_Log -Message "Expanding Evaluate-STIG results archive to $OutputPath" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

    $Result = Initialize-Archiving -Action Expand -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "$($NETBIOS).ZIP") -DestinationPath $OutputPath -Force
    If ($Result -ne "Success") {
        Throw $Result
    }

    Remove-Item -Path $(Join-Path -Path $RemoteWorkingDir -ChildPath "$($NETBIOS).ZIP") -Force
}

Function Test-STIGDependencyFiles {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$RootPath,

        [Parameter(Mandatory = $true)]
        [psobject]$STIGData,

        [Parameter(Mandatory = $true)]
        [psobject]$LogPath,

        [Parameter(Mandatory = $true)]
        [String]$OSPlatform
    )

    $Pass = $true
    $FailedFiles = @{}
    $DependentFiles = @(
        $(Join-Path -Path $RootPath -ChildPath "StigContent" | Join-Path -ChildPath $STIGData.StigContent),
        $(Join-Path -Path $RootPath -ChildPath "Modules" | Join-Path -ChildPath $STIGData.PsModule | Join-Path -ChildPath "$($STIGData.PsModule).psd1"),
        $(Join-Path -Path $RootPath -ChildPath "Modules" | Join-Path -ChildPath $STIGData.PsModule | Join-Path -ChildPath "$($STIGData.PsModule).psm1")
    )
    ForEach ($File in $DependentFiles) {
        If (-Not(Test-Path $File)) {
            $Pass = $false
            $FailedFiles.Add($File,"NotFound")
        }
    }

    If ($Pass -ne $true) {
        Switch ($STIGData.Classification) {
            {$_ -in @("UNCLASSIFIED")} {
                Write-Log -Path $LogPath -Message "ERROR: $($STIGData.Shortname) failed dependency file check.  STIG will not be scanned." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                ForEach ($Key in $FailedFiles.Keys) {
                    Write-Log -Path $LogPath -Message "ERROR: $($Key) - $($FailedFiles.$Key)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                }
                Write-Log -Path $LogPath -Message "Please run '.\Evaluate-STIG.ps1 -Update' to restore this module or download the 'Evaluate-STIG_$($EvaluateStigVersion).zip from one of these locations:" -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                Write-Log -Path $LogPath -Message "- (NIPR) https://spork.navsea.navy.mil/nswc-crane-division/evaluate-stig/-/releases" -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                Write-Log -Path $LogPath -Message "- (NIPR) https://intelshare.intelink.gov/sites/NAVSEA-RMF" -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                Write-Log -Path $LogPath -Message "- (SIPR) https://intelshare.intelink.sgov.gov/sites/NAVSEA-RMF" -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
            }
            DEFAULT {
                Write-Log -Path $LogPath -Message "WARNING: $($STIGData.Shortname) failed dependency file check.  STIG will not be scanned." -WriteOutToStream -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                ForEach ($Key in $FailedFiles.Keys) {
                    Write-Log -Path $LogPath -Message "WARNING: $($Key) - $($FailedFiles.$Key)" -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                }
                Write-Log -Path $LogPath -Message "Please download this CUI add-on module from:" -WriteOutToStream -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                Write-Log -Path $LogPath -Message "- (NIPR) https://intelshare.intelink.gov/sites/NAVSEA-RMF" -WriteOutToStream -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                Write-Log -Path $LogPath -Message "- (SIPR) https://intelshare.intelink.sgov.gov/sites/NAVSEA-RMF" -WriteOutToStream -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
            }
        }
    }

    Return $Pass
}

Function Test-XmlSignature {
    # Based on code sample from https://stackoverflow.com/questions/56986378/validate-signature-on-signed-xml

    Param (
        [xml]$checkxml,
        [switch]$Force
    )

    # Grab signing certificate from document
    $rawCertBase64 = $checkxml.DocumentElement.Signature.KeyInfo.X509Data.X509Certificate

    If (-not $rawCertBase64) {
        $Valid = 'Unable to locate signing certificate in signed document'
    }
    Else {
        $rawCert = [convert]::FromBase64String($rawCertBase64)
        $signingCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(, $rawCert)

        Add-Type -AssemblyName system.security
        [System.Security.Cryptography.Xml.SignedXml]$signedXml = New-Object System.Security.Cryptography.Xml.SignedXml -ArgumentList $checkxml
        $XmlNodeList = $checkxml.GetElementsByTagName("Signature")
        If ($XmlNodeList[0]) {
            $signedXml.LoadXml([System.Xml.XmlElement] ($XmlNodeList[0]))
            $Valid = $signedXml.CheckSignature($signingCertificate, $Force)
        }
        Else {
            $Valid = 'Unable to locate signature in signed document'
        }
    }
    Return $Valid
}

Function Test-XmlValidation {
    # Based on code samples from https://stackoverflow.com/questions/822907/how-do-i-use-powershell-to-validate-xml-files-against-an-xsd

    Param (
        [Parameter(Mandatory = $true)]
        [String] $XmlFile,

        [Parameter(Mandatory = $true)]
        [String] $SchemaFile
    )

    Try {
        Get-ChildItem $XmlFile -ErrorAction Stop | Out-Null
        Get-ChildItem $SchemaFile -ErrorAction Stop | Out-Null

        $XmlErrors = New-Object System.Collections.Generic.List[System.Object]
        [Scriptblock] $ValidationEventHandler = {
            If ($_.Exception.LineNumber) {
                $Message = "$($_.Exception.Message) Line $($_.Exception.LineNumber), position $($_.Exception.LinePosition)."
            }
            Else {
                $Message = ($_.Exception.Message)
            }

            $NewObj = [PSCustomObject]@{
                Message = $Message
            }
            $XmlErrors.Add($NewObj)
        }

        $ReaderSettings = New-Object -TypeName System.Xml.XmlReaderSettings
        $ReaderSettings.ValidationType = [System.Xml.ValidationType]::Schema
        $ReaderSettings.ValidationFlags = [System.Xml.Schema.XmlSchemaValidationFlags]::ProcessIdentityConstraints -bor [System.Xml.Schema.XmlSchemaValidationFlags]::ProcessSchemaLocation -bor [System.Xml.Schema.XmlSchemaValidationFlags]::ReportValidationWarnings
        $ReaderSettings.Schemas.Add($null, $SchemaFile) | Out-Null
        $readerSettings.add_ValidationEventHandler($ValidationEventHandler)

        Try {
            $Reader = [System.Xml.XmlReader]::Create($XmlFile, $ReaderSettings)
            While ($Reader.Read()) {
            }
        }
        Catch {
            $NewObj = [PSCustomObject]@{
                Message = ($_.Exception.Message)
            }
            $XmlErrors.Add($NewObj)
        }
        Finally {
            $Reader.Close()
        }

        If ($XmlErrors) {
            Return $XmlErrors
        }
        Else {
            Return $true
        }
    }
    Catch {
        Return $_.Exception.Message
        Exit 3
    }
}

Function Test-JsonValidation {
    Param (
        [Parameter(Mandatory = $true)]
        [String] $JsonFile,

        [Parameter(Mandatory = $true)]
        [String] $SchemaFile
    )

    Try {
        Get-ChildItem $JsonFile -ErrorAction Stop | Out-Null
        Get-ChildItem $SchemaFile -ErrorAction Stop | Out-Null

        $Json = Get-Content -Path $JsonFile -Raw
        $Schema = Get-Content -Path $SchemaFile -Raw
        If ([Version]$PSVersionTable.PSVersion -ge [Version]"7.0") {
            Return (Test-Json -Json $Json -Schema $Schema -ErrorAction Stop)
        }
        Else {
            Return "PowerShell $($PSVersionTable.PSVersion -join ".") not supported for Json validation"
        }
    }
    Catch {
        Return $_.Exception.Message
    }
}

Function Invoke-ScanCleanup {
    # Run scan cleanup processes
    Param (
        [Parameter(Mandatory = $true)]
        [String]$WorkingDir,

        [Parameter(Mandatory = $false)]
        [String]$Message,

        [Parameter(Mandatory = $false)]
        [Int]$ExitCode = 0,

        [Parameter(Mandatory = $false)]
        [PSObject]$ErrorData,

        [Parameter(Mandatory)]
        [string]$LogPath,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Windows", "Linux")]
        [String]$OSPlatform,

        [Parameter(Mandatory = $true)]
        [String]$LogComponent
    )

    $ES_Hive_Tasks = @("Eval-STIG_SaveHive", "Eval-STIG_LoadHive", "Eval-STIG_UnloadHive") # Potential scheduled tasks for user hive actions

    # If a bad exit code, we can't continue.
    If ($ExitCode -ne 0) {
        Write-Log -Path $LogPath -Message "ERROR: $($Message)" -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
        Write-Log -Path $LogPath -Message "Unable to continue." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
        Write-Log -Path $LogPath -Message "    $($ErrorData.InvocationInfo.ScriptName)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
        Write-Log -Path $LogPath -Message "    Line: $($ErrorData.InvocationInfo.ScriptLineNumber)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
        Write-Log -Path $LogPath -Message "    $(($ErrorData.InvocationInfo.Line).Trim())" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
    }

    # Platform specific tasks
    Switch ($OSPlatform) {
        "Windows" {
            # Unload temporary user hive
            If (Test-Path Registry::HKU\Evaluate-STIG_UserHive) {
                [System.GC]::Collect()
                Try {
                    Start-Sleep -Seconds 5
                    Write-Log -Path $LogPath -Message "Unloading hive HKU:\Evaluate-STIG_UserHive" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    $Result = Start-Process -FilePath REG -ArgumentList "UNLOAD HKU\Evaluate-STIG_UserHive" -Wait -PassThru -WindowStyle Hidden
                    If ($Result.ExitCode -ne 0) {
                        Throw
                    }
                }
                Catch {
                    # REG command failed so attempt to do as SYSTEM
                    Write-Log -Path $LogPath -Message "WARNING: Failed to unload hive. Trying as SYSTEM." -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                    Try {
                        $Result = Invoke-TaskAsSYSTEM -TaskName $ES_Hive_Tasks[2] -FilePath REG -ArgumentList "UNLOAD HKU\Evaluate-STIG_UserHive" -MaxRunInMinutes 1
                        If ($Result.LastTaskResult -ne 0) {
                            Throw "Failed to unload user hive."
                        }
                    }
                    Catch {
                        Write-Log -Path $LogPath -Message "ERROR: $($_.Exception.Message)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    }
                }
            }
        }
        "Linux"{
            # Place holder for Linux cleanup tasks
        }
    }

    # Remove temporary files
    Try {
        $TempFiles = Get-Item -Path $WorkingDir\* -Exclude Evaluate-STIG.log,Bad_CKL -Force
        If ($TempFiles) {
            Write-Log -Path $LogPath -Message "Removing temporary files" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            ForEach ($Item in $TempFiles) {
                $null = Remove-Item -Path $Item.FullName -Recurse -Force -ErrorAction Stop
            }
        }
    }
    Catch {
        Write-Log -Path $LogPath -Message "ERROR: $($_.Exception.Message)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
    }
}

Function Write-SummaryReport {
    Param (
        [Parameter(Mandatory = $true)]
        [PsObject] $ScanResult,

        [Parameter(Mandatory = $true)]
        [String] $OutputPath,

        [Parameter(Mandatory = $false)]
        [String] $ProcessedUser,

        [Parameter(Mandatory = $false)]
        [Switch] $Detail,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Windows", "Linux")]
        [String]$OSPlatform,

        [Parameter(Mandatory = $true)]
        [String] $ScanStartDate,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Unclassified", "Classified")]
        [String]$ScanType,

        [Parameter(Mandatory = $false)]
        [psobject] $DeviceInfo,

        [Parameter(Mandatory = $false)]
        [String]$Marking
    )

    $ResultsFile = Join-Path -Path $OutputPath -ChildPath "SummaryReport.xml"
    [Xml]$SummaryResults = New-Object System.Xml.XmlDocument

    # Create declaration
    $Dec = $SummaryResults.CreateXmlDeclaration("1.0", "UTF-8", $null)
    $SummaryResults.AppendChild($dec) | Out-Null

    # Create Root element
    $Root = $SummaryResults.CreateNode("element", "Summary", $null)

    if ($Marking) {
        $MarkingHeader = $SummaryResults.CreateComment("                                                                                          $Marking                                                                                          ")
        $null = $SummaryResults.InsertBefore($MarkingHeader, $SummaryResults.Summary)
    }

    # Pull hardware data
    If ($DeviceInfo) {
        $ComputerData = [ordered]@{
            Name               = $($DeviceInfo.Hostname)
            Manufacturer       = "Cisco"
            Model              = $($DeviceInfo.Model)
            SerialNumber       = $($DeviceInfo.SerialNumber)
            BIOSVersion        = ""
            OSName             = $($DeviceInfo.CiscoOS)
            OSVersion          = $($DeviceInfo.CiscoOSVer)
            OSArchitecture     = ""
            CPUArchitecture    = ""
            NetworkAdapters    = ""
            DiskDrives         = ""
            DistinguishedName  = ""
            ScannedUserProfile = $ProcessedUser
        }
    }
    Else {
        Switch ($OSPlatform) {
            "Windows" {
                $W32ComputerSystem = Get-CimInstance Win32_ComputerSystem | Select-Object *
                $W32OperatingSystem = Get-CimInstance Win32_OperatingSystem | Select-Object *
                $W32SystemEnclosure = Get-CimInstance Win32_SystemEnclosure | Select-Object *
                $W32BIOS = Get-CimInstance Win32_BIOS | Select-Object *
                $W32Processor = Get-CimInstance Win32_Processor | Select-Object *
                $W32DiskDrive = Get-CimInstance Win32_DiskDrive | Select-Object *
                $W32NetAdapterConfig = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object IPEnabled -EQ $true | Select-Object *
                $DistinguishedName = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine")."Distinguished-Name"
                If (-Not($DistinguishedName)) {
                    $DistinguishedName = "Not a domain member"
                }

                Switch ($W32Processor.Architecture) {
                    "0" {
                        $CPUArchitecture = "x86"
                    }
                    "1" {
                        $CPUArchitecture = "MIPS"
                    }
                    "2" {
                        $CPUArchitecture = "Alpha"
                    }
                    "3" {
                        $CPUArchitecture = "PowerPC"
                    }
                    "5" {
                        $CPUArchitecture = "ARM"
                    }
                    "6" {
                        $CPUArchitecture = "ia64"
                    }
                    "9" {
                        $CPUArchitecture = "x64"
                    }
                }

                $ComputerData = [ordered]@{
                    Name               = $([Environment]::MachineName)
                    Manufacturer       = ($W32ComputerSystem.Manufacturer | Out-String).Trim()
                    Model              = ($W32ComputerSystem.Model | Out-String).Trim()
                    SerialNumber       = ($W32SystemEnclosure.SerialNumber | Out-String).Trim()
                    BIOSVersion        = ($W32BIOS.SMBIOSBIOSVersion | Out-String).Trim()
                    OSName             = ($W32OperatingSystem.Caption | Out-String).Trim()
                    OSVersion          = ($W32OperatingSystem.Version | Out-String).Trim()
                    OSArchitecture     = ($W32OperatingSystem.OSArchitecture | Out-String).Trim()
                    CPUArchitecture    = ($CPUArchitecture | Out-String).Trim()
                    NetworkAdapters    = ($W32NetAdapterConfig | Sort-Object Index | ForEach-Object { @{'Adapter' = [ordered]@{
                                    InterfaceIndex = ($_.InterfaceIndex | Out-String).Trim()
                                    Caption        = ($_.Caption | Out-String).Trim()
                                    MACAddress     = ($_.MACAddress | Out-String).Trim()
                                    IPv4           = ((($_.IPAddress | Where-Object { ($_ -Like "*.*.*.*") }) -join ",") | Out-String).Trim()
                                    IPv6           = ((($_.IPAddress | Where-Object { ($_ -Like "*::*") }) -join ",") | Out-String).Trim()
                                }
                            } }
                    )
                    DiskDrives         = ($W32DiskDrive | Sort-Object Index | ForEach-Object { @{'Disk' = [ordered]@{
                                    Index         = ($_.Index | Out-String).Trim()
                                    DeviceID      = ($_.DeviceID | Out-String).Trim()
                                    Size          = ("$([Math]::Round($_.Size / 1Gb, 2)) GB" | Out-String).Trim()
                                    Caption       = ($_.Caption | Out-String).Trim()
                                    SerialNumber  = ($_.SerialNumber | Out-String).Trim()
                                    MediaType     = ($_.MediaType | Out-String).Trim()
                                    InterfaceType = ($_.InterfaceType | Out-String).Trim()
                                }
                            } }
                    )
                    DistinguishedName  = $DistinguishedName
                    ScannedUserProfile = $ProcessedUser
                }
            }
            "Linux" {
                $W32HostName = [Environment]::MachineName
                $W32ComputerSystem_Manufacturer = (dmidecode | grep -A5 '^System Information' | grep Manufacturer).Trim().replace("Manufacturer: ", "")
                $W32ComputerSystem_Model = (dmidecode | grep -A5 '^System Information' | grep Product).Trim().replace("Product Name: ", "")
                $W32Computersystem_Serial = (dmidecode | grep -A5 '^System Information' | grep Serial).Trim().replace("Serial Number: ", "")
                $W32OperatingSystem_OSName = (Get-Content /etc/os-release | grep "^PRETTY").replace("PRETTY_NAME=", "").replace('"', "")
                $W32OperatingSystem_OSVersion = (Get-Content /etc/os-release | grep "^VERSION_ID").replace("VERSION_ID=", "").replace('"', "")
                $W32OperatingSystem_OSArchitecture = arch
                $W32BIOS_SMBIOSBIOSVersion = (dmidecode | grep -A3 "^BIOS" | grep Version).Trim().replace("Version: ", "")
                $CPUArchitecture = (lscpu | grep "^Architecture").replace("Architecture:", "").Trim()
                $W32NetAdapterConfig = (lshw -C network -short | awk '!(NR<=2) {print $2}')
                $DistinguishedName = "Not a domain member"
                Try {
                    $LVM_Data = @((lvscan).Split('[\r\n]+'))
                    $W32DiskDrive = $LVM_Data
                }
                Catch {
                    $Disk_Data = @((lsblk -nlo "NAME,SIZE,MOUNTPOINT").Split('[\r\n]+'))
                    $W32DiskDrive = $Disk_Data | ForEach-Object { @{
                            Index    = "'//$($_ | awk '{print $1}')/'"
                            DeviceID = "'//$($_ | awk '{print $3}')'"
                            Size     = "[$($_ | awk '{print $2}')]"
                        }
                    }
                }

                $ComputerData = [ordered]@{
                    Name               = $W32HostName
                    Manufacturer       = ($W32ComputerSystem_Manufacturer | Out-String).Trim()
                    Model              = ($W32ComputerSystem_Model | Out-String).Trim()
                    SerialNumber       = ($W32Computersystem_Serial | Out-String).Trim()
                    BIOSVersion        = ($W32BIOS_SMBIOSBIOSVersion | Out-String).Trim()
                    OSName             = ($W32OperatingSystem_OSName | Out-String).Trim()
                    OSVersion          = ($W32OperatingSystem_OSVersion | Out-String).Trim()
                    OSArchitecture     = ($W32OperatingSystem_OSArchitecture | Out-String).Trim()
                    CPUArchitecture    = ($CPUArchitecture | Out-String).Trim()
                    NetworkAdapters    = ($W32NetAdapterConfig | Sort-Object Index | ForEach-Object { @{'Adapter' = [ordered]@{
                                    InterfaceIndex = (Get-Content /sys/class/net/$_/ifindex)
                                    Caption        = (lshw -C network -short | grep $_ | awk '{print $2}')
                                    MACAddress     = (ip addr show dev $_ | grep "link/ether" | cut -d ' ' -f 6)
                                    IPV4           = (ip -4 addr show dev $_ | grep "inet " | cut -d ' ' -f 6 | cut -f 1 -d '/')
                                    IPV6           = (ip -6 addr show dev $_ | grep "inet " | cut -d ' ' -f 6 | cut -f 1 -d '/')
                                }
                            } }
                    )
                    DiskDrives         = ($W32DiskDrive | Sort-Object Index | ForEach-Object { @{'Disk' = [ordered]@{
                                    Index    = ($_ | cut -d '/' -f 3 | Out-String).Trim()
                                    DeviceID = ($_ | cut -d "'" -f 2 | cut -d '/' -f 4 | Out-String).Trim()
                                    Size     = ($_ | cut -d "]" -f 1 | cut -d "[" -f 2 | Out-String).Trim()
                                }
                            } }
                    )
                    DistinguishedName  = $DistinguishedName
                    ScannedUserProfile = $ProcessedUser
                }
            }
        }
    }

    # Create Computer element
    $Computer = $SummaryResults.CreateNode("element", "Computer", $null)
    $ScanDate = $SummaryResults.CreateNode("element", "ScanDate", $null)
    $EvalSTIGVer = $SummaryResults.CreateNode("element", "EvalSTIGVer", $null)
    $ESScanType = $SummaryResults.CreateNode("element", "ScanType", $null)
    $ScanDate.InnerText = $($ScanStartDate)
    $Computer.AppendChild($ScanDate) | Out-Null
    $EvalSTIGVer.InnerText = $ESVersion
    $Computer.AppendChild($EvalSTIGVer) | Out-Null
    $ESScanType.InnerText = $ScanType
    $Computer.AppendChild($ESScanType) | Out-Null
    if ($Marking) {
        $ESMarking = $SummaryResults.CreateNode("element", "Marking", $null)
        $ESMarking.InnerText = $Marking
        $Computer.AppendChild($ESMarking) | Out-Null
    }
    ForEach ($Key in $ComputerData.GetEnumerator()) {
        $Element = $SummaryResults.CreateNode("element", $($Key.Key), $null)
        If ($Key.Key -eq "NetworkAdapters") {
            ForEach ($Adapter in $ComputerData.NetworkAdapters.Adapter) {
                $NetworkElement = $SummaryResults.CreateNode("element", "Adapter", $null)
                $NetworkElement.SetAttribute("InterfaceIndex", $Adapter.InterfaceIndex)

                $Caption = $SummaryResults.CreateNode("element", "Caption", $null)
                $Caption.InnerText = $Adapter.Caption
                $NetworkElement.AppendChild($Caption) | Out-Null

                $MACAddress = $SummaryResults.CreateNode("element", "MACAddress", $null)
                $MACAddress.InnerText = $Adapter.MACAddress
                $NetworkElement.AppendChild($MACAddress) | Out-Null

                $IPv4Addresses = $SummaryResults.CreateNode("element", "IPv4Addresses", $null)
                $IPv4Addresses.InnerText = $Adapter.IPv4
                $NetworkElement.AppendChild($IPv4Addresses) | Out-Null

                $IPv6Addresses = $SummaryResults.CreateNode("element", "IPv6Addresses", $null)
                $IPv6Addresses.InnerText = $Adapter.IPv6
                $NetworkElement.AppendChild($IPv6Addresses) | Out-Null

                $Element.AppendChild($NetworkElement) | Out-Null
            }
        }
        ElseIf ($Key.Key -eq "DiskDrives") {
            ForEach ($Disk in $ComputerData.DiskDrives.Disk) {
                $DiskElement = $SummaryResults.CreateNode("element", "Disk", $null)
                $DiskElement.SetAttribute("Index", $Disk.Index)

                $DeviceID = $SummaryResults.CreateNode("element", "DeviceID", $null)
                $DeviceID.InnerText = $Disk.DeviceID
                $DiskElement.AppendChild($DeviceID) | Out-Null

                $Size = $SummaryResults.CreateNode("element", "Size", $null)
                $Size.InnerText = $Disk.Size
                $DiskElement.AppendChild($Size) | Out-Null

                $Caption = $SummaryResults.CreateNode("element", "Caption", $null)
                $Caption.InnerText = $Disk.Caption
                $DiskElement.AppendChild($Caption) | Out-Null

                $SerialNumber = $SummaryResults.CreateNode("element", "SerialNumber", $null)
                $SerialNumber.InnerText = $Disk.SerialNumber
                $DiskElement.AppendChild($SerialNumber) | Out-Null

                $MediaType = $SummaryResults.CreateNode("element", "MediaType", $null)
                $MediaType.InnerText = $Disk.MediaType
                $DiskElement.AppendChild($MediaType) | Out-Null

                $InterfaceType = $SummaryResults.CreateNode("element", "InterfaceType", $null)
                $InterfaceType.InnerText = $Disk.InterfaceType
                $DiskElement.AppendChild($InterfaceType) | Out-Null

                $Element.AppendChild($DiskElement) | Out-Null
            }
        }
        Else {
            $Element.InnerText = ($Key.Value)
        }
        $Computer.AppendChild($Element) | Out-Null
    }
    $Root.AppendChild($Computer) | Out-Null

    # Create Results element
    $Results = $SummaryResults.CreateNode("element", "Results", $null)

    ForEach ($Item in $ScanResult) {
        # Create node for result
        $ResultNode = $SummaryResults.CreateNode("element", "Result", $null)
        $ResultNode.SetAttribute("STIG", "$($Item.STIGInfo.STIGID)") | Out-Null
        $ResultNode.SetAttribute("Version", $Item.STIGInfo.Version) | Out-Null
        $ResultNode.SetAttribute("Release", $Item.STIGInfo.Release) | Out-Null
        $ResultNode.SetAttribute("Site", $Item.TargetData.Site) | Out-Null
        $ResultNode.SetAttribute("Instance", $Item.TargetData.Instance) | Out-Null
        $ResultNode.SetAttribute("StartTime", $Item.ESData.StartTime) | Out-Null

        $SeverityList = @("high", "medium", "low")
        ForEach ($Severity in $SeverityList) {
            Switch ($Severity) {
                "high" {$Cat = "CAT_I"}
                "medium" {$Cat = "CAT_II"}
                "low" {$Cat = "CAT_III"}
            }
            # Create CAT node
            $CatNode = $SummaryResults.CreateNode("element", $Cat, $null)

            # Get CAT totals
            [hashtable]$StatusTotals = @{ }
            $AllCat = $Item.VulnResults | Where-Object Severity -EQ $Severity
            $StatusTotals.NR = ($AllCat | Where-Object Status -EQ "Not_Reviewed" | Measure-Object).Count
            $StatusTotals.NF = ($AllCat | Where-Object Status -EQ "NotAFinding" | Measure-Object).Count
            $StatusTotals.O = ($AllCat | Where-Object Status -EQ "Open" | Measure-Object).Count
            $StatusTotals.NA = ($AllCat | Where-Object Status -EQ "Not_Applicable" | Measure-Object).Count
            $StatusTotals.Total = ($AllCat | Measure-Object).Count

            # Populate CAT node
            $CatNode.SetAttribute("Total", $StatusTotals.Total) | Out-Null
            $CatNode.SetAttribute("Not_Applicable", $StatusTotals.NA) | Out-Null
            $CatNode.SetAttribute("Open", $StatusTotals.O) | Out-Null
            $CatNode.SetAttribute("NotAFinding", $StatusTotals.NF) | Out-Null
            $CatNode.SetAttribute("Not_Reviewed", $StatusTotals.NR) | Out-Null

            If ($Detail) {
                # Create Vuln node and populate
                ForEach ($Vuln in $AllCat) {
                    $VulnNode = $SummaryResults.CreateNode("element", "Vuln", $null)
                    $VulnNode.SetAttribute("RuleTitle", $Vuln.RuleTitle) | Out-Null
                    $VulnNode.SetAttribute("Status", $Vuln.Status) | Out-Null
                    $VulnNode.SetAttribute("ID", $Vuln.GroupID) | Out-Null
                    $CatNode.AppendChild($VulnNode) | Out-Null
                }
            }
            $ResultNode.AppendChild($CatNode) | Out-Null
        }
        $Results.AppendChild($ResultNode) | Out-Null
    }

        $Root.AppendChild($Results) | Out-Null
    $SummaryResults.AppendChild($Root) | Out-Null
    if ($Marking) {
        $MarkingFooter = $SummaryResults.CreateComment("                                                                                          $Marking                                                                                          ")
        $null = $SummaryResults.InsertAfter($MarkingFooter, $SummaryResults.Summary)
    }
    $SummaryResults.Save($ResultsFile)
}

Function Get-IniContent ($FilePath) {
    $Ini = @{ }
    Switch -Regex -File $FilePath {
        "^\[(.+)\]" {
            # Section
            $Section = $Matches[1]
            $Ini[$Section] = @{ }
            $CommentCount = 0
        }
        "^(;.*)$" {
            # Comment
            $Value = $Matches[1]
            $CommentCount = $CommentCount + 1
            $Name = "Comment" + $CommentCount
            If ($Section) {
                $Ini[$Section][$Name] = $Value
            }
            Else {
                $Ini[$Name] = $Value
            }
        }
        "(.+?)\s*=\s*(.*)" {
            # Key
            $Name, $Value = $Matches[1..2]
            If ($Section) {
                $Ini[$Section][$Name] = $Value
            }
            Else {
                $Ini[$Name] = $Value
            }
        }
    }
    Return $Ini
}

Function Get-UsersToEval {
    <#
    .DESCRIPTION
        Returns either a single user profile or all user profiles in order of preference.
        Profiles that have a NTUSER.POL modified within the last 14 days are preferred as best
        representation for current STIG user settings.

        NOTE:  Previous version referenced LastUseTime from Win32_UserProfile.
        With Windows 10 and greater, LastUseTime is updated every time the profile
        is queried from Win32_UserProfile thus not providing a true last use of the profile.
    #>

    [cmdletbinding()]
    Param (
        [Switch]$ProvideSingleUser
    )

    $ProfileList = New-Object System.Collections.Generic.List[System.Object]
    $RegexSID = '^S-1-[0-59]-\d{2}-\d{8,10}-\d{8,10}-\d{8,10}-[1-9]\d{3}'
    $UserProfiles = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | Where-Object PSChildName -Match $RegexSID

    ForEach ($Profile in $UserProfiles) {
        Remove-Variable -Force LTH, LTL, LocalPath -ErrorAction SilentlyContinue

        # Get username
        Try {
            $Username = (New-Object System.Security.Principal.SecurityIdentifier($Profile.PSChildName)).Translate([System.Security.Principal.NTAccount]).value
            If ($Username -match " ") {
                $Username = [Char]34 + $Username + [Char]34
            }
        }
        Catch {
            $Username = "[UNKNOWN]"
        }

        # Get profile path
        $LocalPath = (Get-ItemProperty -Path $Profile.PSPath -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath

        # Verify NTUSER.DAT exists.  If not, ignore profile as there are no user registry settings to import.
        If (Test-Path "$($LocalPath)\ntuser.dat") {
            # Get NTUSER.POL
            $NTUserPol = @()
            If (Test-Path "$env:ProgramData\Microsoft\GroupPolicy\Users\$($Profile.PSChildName)\ntuser.pol") {
                $NTUserPol += Get-ChildItem -Path "$env:ProgramData\Microsoft\GroupPolicy\Users\$($Profile.PSChildName)\ntuser.pol" -Force
            }
            If (Test-Path "$($LocalPath)\ntuser.pol") {
                $NTUserPol += Get-ChildItem -Path "$($LocalPath)\ntuser.pol" -Force
            }
            If (($NTUserPol | Measure-Object).Count -gt 0) {
                $LastPolicyUpdate = ($NtuserPol | Sort-Object LastWriteTime -Descending)[0].LastWriteTime
            }
            Else {
                $LastPolicyUpdate = Get-Date 01/01/1900
            }

            # Determine if preferred
            If (($UserName -ne "[UNKNOWN]") -and ($UserName.Split("\")[0] -ne $([Environment]::MachineName) -and ($LastPolicyUpdate -ne (Get-Date 01/01/1900)) -and (New-TimeSpan -Start $LastPolicyUpdate -End (Get-Date)).Days -le 14)) {
                $Preferred = $true
            }
            Else {
                $Preferred = $false
            }

            # Get profile last load time
            $LTH = '{0:X8}' -f (Get-ItemProperty -Path $Profile.PSPath -Name LocalProfileLoadTimeHigh -ErrorAction SilentlyContinue).LocalProfileLoadTimeHigh
            $LTL = '{0:X8}' -f (Get-ItemProperty -Path $Profile.PSPath -Name LocalProfileLoadTimeLow -ErrorAction SilentlyContinue).LocalProfileLoadTimeLow
            If ($LTH -and $LTL) {
                $ProfileLoadTime = [datetime]::FromFileTime("0x$LTH$LTL")
            }
            Else {
                $ProfileLoadTime = Get-Date 01/01/1900
            }

            # Get NTUSER.DAT LastWriteTime
            $NTUserDatUpdate = Get-Date ((Get-ChildItem -Path "$($LocalPath)\ntuser.dat" -Force).LastWriteTime)

            $NewObj = [PSCustomObject]@{
                Username         = $Username
                LastPolicyUpdate = $LastPolicyUpdate
                SID              = $Profile.PSChildName
                LocalPath        = $LocalPath
                ProfileLoadTime  = $ProfileLoadTime
                NTuserDatUpdate  = $NTUserDatUpdate
                Preferred        = $Preferred
            }
            $ProfileList.Add($NewObj)
        }
    }

    # Sort results
    $ProfileList = ($ProfileList | Sort-Object Preferred, LastPolicyUpdate, ProfileLoadTime, NTuserDatUpdate -Descending)

    If ($ProvideSingleUser -and $ProfileList) {
        Return $ProfileList[0]
    }
    Else {
        Return $ProfileList
    }
}

Function Get-GroupMembership ($Group) {
    $GroupMembers = New-Object System.Collections.Generic.List[System.Object]

    $Computer = [ADSI]"WinNT://$env:COMPUTERNAME,Computer"
    $Object = $Computer.psbase.Children | Where-Object { $_.psbase.schemaClassName -eq "group" -and $_.Name -eq $Group }
    ForEach ($Item In $Object) {
        $Members = @($Item.psbase.Invoke("Members"))
        ForEach ($Member In $Members) {
            $ObjectSID = $Member.GetType().InvokeMember("objectSid", 'GetProperty', $Null, $Member, $Null)
            $Name = ($Member.GetType().InvokeMember("AdsPath", 'GetProperty', $Null, $Member, $Null))
            If ($Name -match $env:COMPUTERNAME) {
                $Name = "$env:COMPUTERNAME" + (($Name -split $env:COMPUTERNAME)[1]).Replace("/", "\")
            }
            Else {
                $Name = ($Name).Replace("WinNT://", "").Replace("/", "\")
            }
            $NewObj = [PSCustomObject]@{
                Name        = $Name
                objectClass = $Member.GetType().InvokeMember("Class", 'GetProperty', $Null, $Member, $Null)
                objectSID   = (New-Object System.Security.Principal.SecurityIdentifier($objectSID, 0))
            }
            $GroupMembers.Add($NewObj)
        }
    }

    Return $GroupMembers
}

Function Search-AD {
    Param (
        [String[]]$Filter,
        [String[]]$Properties,
        [String]$SearchRoot
    )

    If ($SearchRoot) {
        $Root = [ADSI]$SearchRoot
    }
    Else {
        $Root = [ADSI]''
    }

    If ($Filter) {
        $LDAP = "(&({0}))" -f ($Filter -join ')(')
    }
    Else {
        $LDAP = "(name=*)"
    }

    If (-Not($Properties)) {
        $Properties = 'Name', 'ADSPath'
    }

    (New-Object ADSISearcher -ArgumentList @($Root, $LDAP, $Properties) -Property @{PageSize = 1000 }).FindAll() | ForEach-Object {
        $ObjectProps = @{ }
        $_.Properties.GetEnumerator() | ForEach-Object {
            $ObjectProps.Add($_.Name, (-join $_.Value))
        }
        New-Object PSObject -Property $ObjectProps | Select-Object $Properties
    }
}

Function Get-MembersOfADGroup {
    # Function simulate Get-ADGroupMember but not fail on ForeignSecurityPrincipals
    Param (
        [Parameter(Mandatory = $true)]
        [String]$Identity,

        [Parameter(Mandatory = $false)]
        [Switch]$Recursive
    )

    Try {
        $ADObjectPropertiesList = @(
            'Name'
            'DistinguishedName'
            'objectClass'
            'objectGUID'
            'objectSID'
        )
        $Result = [System.Collections.Generic.List[System.Object]]::new()

        $ADGroupInfo = Get-ADGroup -Identity $Identity -Properties Members -ErrorAction Stop
        $GroupPrimaryGroupID = ($ADGroupInfo.Sid -split '-')[-1]

        If ($Recursive) {
            $ldapFilter = '(|(memberof:1.2.840.113556.1.4.1941:={0})(primaryGroupID={1}))' -f $ADGroupInfo.DistinguishedName, $GroupPrimaryGroupID
            $ADGroupMembership = Get-ADObject -LDAPFilter $ldapFilter -Properties $ADObjectPropertiesList -ErrorAction Stop | Where-Object objectClass -NE 'group' | Select-Object -Property $ADObjectPropertiesList
        }
        Else {
            $ldapFilter = '(|(memberof={0})(primaryGroupID={1}))' -f $ADGroupInfo.DistinguishedName, $GroupPrimaryGroupID
            $ADGroupMembership = Get-ADObject -LDAPFilter $ldapFilter -Properties $ADObjectPropertiesList -ErrorAction Stop | Select-Object -Property $ADObjectPropertiesList
        }

        Foreach ($Obj in $ADGroupMembership) {
            Try {
                $NameFromSID = ([System.Security.Principal.SecurityIdentifier]$Obj.objectSID).Translate([System.Security.Principal.NTAccount]).Value
            }
            Catch {
                $NameFromSID = "[UNABLE TO RESOLVE]"
            }
            $NewObj = [PSCustomObject]@{
                Name              = $NameFromSID
                DistinguishedName = $Obj.DistinguishedName
                objectSID         = $Obj.objectSID
                objectClass       = $Obj.objectClass
                objectGUID        = $Obj.objectGUID
            }
            [void]$Result.Add($NewObj)
        }

        Return $Result

    }
    Catch {
        Return $_.Exception.Message
    }
}

Function Get-ADDomainControllerCertificate {
    # Derived from: https://github.com/roggenk/PowerShell/tree/master/LDAPS
    <#
        .SYNOPSIS
            Retrieves the LDAPS certificate properties.
        .PARAMETER ComputerName
            Specifies the Active Directory domain controller.
        .PARAMETER Domain
            Specifies the Active Directory DNS name.
        .PARAMETER Port
            LDAPS port for domain controller: 636 (default)
            LDAPS port for global catalog: 3269
        .DESCRIPTION
            The cmdlet 'Get-ADDomainControllerCertificate' retrieves the LDAP over TSL/SSL certificate properties.
        .EXAMPLE
            Get-ADDomainControllerCertificate -ComputerName DC01
        .EXAMPLE
            Get-ADDomainControllerCertificate -ComputerName DC01,DC02 | Select ComputerName,Port,Subject,Thumbprint
        .EXAMPLE
            Get-ADDomainControllerCertificate DC01,DC02
        .EXAMPLE
            Get-ADDomainControllerCertificate DC01 -Port 3269
        .EXAMPLE
            Get-ADDomainControllerCertificate -Domain domain.local
        .EXAMPLE
            Get-ADDomainControllerCertificate -Domain domain.local | Select-Object ComputerName,Port,Subject,Thumbprint
        .EXAMPLE
            Get-ADDomainControllerCertificate -Domain domain.local -Port 3269 | Select-Object ComputerName,Port,Subject,Thumbprint
    #>
    [Cmdletbinding(DefaultParameterSetName = 'ComputerName')]
    Param(
        [Parameter(ParameterSetName = 'ComputerName', Mandatory, Position = 0)]
        [Alias('CN')]
        [String[]]$ComputerName,

        [Parameter(ParameterSetName = 'DomainName', Mandatory, Position = 0)]
        [String]$Domain,

        [String]$Port = "636"
    )

    $DomainDCs = @()
    If ($ComputerName) {
        ForEach ($Computer in $ComputerName) {
            $DomainDCs += (Get-ADDomainController -Identity $Computer).HostName
        }
    }

    If ($Domain) {
        $DomainDCs += (Get-ADDomainController -DomainName $Domain -Discover).HostName
    }

    $KDCCert = @()
    ForEach ($DomainDC in $DomainDCs) {
        Try {
            $Connection = New-Object System.Net.Sockets.TcpClient($DomainDC, $Port)
            $TLSStream = New-Object System.Net.Security.SslStream($Connection.GetStream())
            # Try to validate certificate, break out if we don't
            Try {
                $TLSStream.AuthenticateAsClient($DomainDC)
            }
            Catch {
                $Connection.Close
                Break
            }
            #Grab the Cert and it's Basic Properties
            $KDCCert += New-Object system.security.cryptography.x509certificates.x509certificate2($TLSStream.get_remotecertificate())
            $Connection.Close()
        }
        Catch {
            If ($Connection) {
                $Connection.Close()
            }
            Throw $_.Exception.Message
        }
    }
    Return $KDCCert
}

Function Get-AssetData {
    param
    (
        [Parameter(Mandatory)]
        [ValidateSet("Windows", "Linux", "Cisco", "VMWare")]
        [String]$OSPlatform,

        [Parameter()]
        [String]$Marking,


        # Cisco-specific
        [Parameter()]
        [psobject]$ShowRunningConfig,

        [Parameter()]
        [psobject]$DeviceInfo,

        # VMWare-Specific
        [Parameter()]
        [PSObject]$VMWareInfo
    )

    Try {
        Switch ($OSPlatform) {
            "Windows" {
                $MachineName = ([Environment]::MachineName).ToUpper()
                $NetAdapter = Get-CimInstance -Namespace root\cimv2 -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | Sort-Object Index
                $IPAddress = ($NetAdapter.IPAddress -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}") -join ", "
                $MACAddress = ($NetAdapter.MACAddress) -join ", "
                $FQDN = ("$((Get-CimInstance -Namespace root\cimv2 -ClassName Win32_ComputerSystem).DNSHostName).$((Get-CimInstance -Namespace root\cimv2 -ClassName Win32_ComputerSystem).Domain)").ToLower()

                Switch ((Get-CimInstance Win32_ComputerSystem).DomainRole) {
                    { $_ -eq 1 } {
                        $Role = "Workstation"
                    }
                    { $_ -eq 3 } {
                        $Role = "Member Server"
                    }
                    { ($_ -eq 4) -or ($_ -eq 5) } {
                        $Role = "Domain Controller"
                    }
                    Default {
                        $Role = "None"
                    }
                }
            }
            "Linux" {
                $MachineName = ([Environment]::MachineName).ToUpper()
                $Release = ""
                $Role = ""
                if (((Get-Content /etc/os-release) -like '*VERSION_ID="8.*') -or ((Get-Content /etc/os-release) -like '*VERSION_ID="9.*')) {
                    $release = "Workstation"
                }
                else {
                    $release = (Get-Content /etc/os-release | egrep -i "VARIANT=|^ID=").replace("VARIANT=", "").replace('"', "").replace("ID=", "").replace("rhel", "") | Where-Object { $_ -ne "" }
                }
                switch ($release) {
                    {($_ -in @("Workstation","ubuntu"))} {
                        $Role = "Workstation"
                    }
                    "Server" {
                        $Role = "Member Server"
                    }
                    default {
                        $Role = "None"
                    }
                }

                (lshw -C network -short | awk '!(NR<=2) {print $2}') | ForEach-Object { if ((Get-Content /sys/class/net/$_/operstate) -eq "up") {
                    $NetAdapter = $_
                } }
                $IPAddress = (ip -4 addr show dev $NetAdapter | grep "inet " | cut -d ' ' -f 6 | cut -f 1 -d '/')
                $MACAddress = (ip addr show dev $NetAdapter | grep "link/ether" | cut -d ' ' -f 6)
                $FQDN = hostname --fqdn
            }
            "Cisco" {
                If (-Not($DeviceInfo -and $ShowRunningConfig)) {
                    Throw "-DeviceInfo and -ShowRunningConfig required."
                }
                Else {
                    $MachineName = $DeviceInfo.Hostname
                    $RouterIPs = (((Get-Section $ShowRunningConfig "interface loopback0" | Select-String -Pattern "ip address" | Out-String).Trim()).Replace("ip address ", "")).Split([char[]]"")[0]
                    If (-Not($RouterIPs -match "\d+\.\d+\.\d+\.\d+")) {
                        $Interfaces = $ShowRunningConfig | Select-String -Pattern "^interface"
                        $RouterIPs = @()
                        ForEach ($Interface in $Interfaces) {
                            $IP = (((Get-Section $ShowRunningConfig $Interface | Select-String -Pattern "ip address" | Out-String).Trim()).Replace("ip address ", "")).Split([char[]]"")[0]
                            If ($IP -match "\d+\.\d+\.\d+\.\d+") {
                                $RouterIPs += $IP
                            }
                        }
                    }
                    $IPAddress = $RouterIPs -join ", "
                    $Role = "None"
                    $MACAddress = $DeviceInfo.MACAddress
                    If ($DeviceInfo.Hostname -and $DeviceInfo.DomainName) {
                        $FQDN = "$($DeviceInfo.Hostname).$($DeviceInfo.DomainName)"
                    }
                    Else {
                        $FQDN = ""
                    }
                }
            }
            "VMWare_VM" {

            }
            "VMWare_ESXi" {

            }
        }

        $AssetData = [ordered]@{
            Marking       = $Marking
            HostName      = $MachineName
            IpAddress     = $IPAddress
            MacAddress    = $MACAddress
            FQDN          = $FQDN
            Role          = $Role
        }

        Return $AssetData
    }
    Catch {
        Throw $_.Exception.Message
    }
}

Function Invoke-STIGScan {
    param
    (
        [Parameter(Mandatory)]
        [string]$StigXmlPath,

        [Parameter(Mandatory)]
        [int]$VulnTimeout,

        [Parameter()]
        [Array]$SelectVuln,

        [Parameter()]
        [Array]$ExcludeVuln,

        [Parameter()]
        [Switch]$Deprecated,

        [Parameter()]
        [Switch]$Forced,

        [Parameter(Mandatory)]
        [String]$ModulesPath,

        [Parameter(Mandatory)]
        [String]$PsModule,

        [Parameter(Mandatory)]
        [string]$LogPath,

        [Parameter(Mandatory)]
        [ValidateSet("Windows", "Linux")]
        [String]$OSPlatform,

        [Parameter()]
        [Int]$ProgressId,

        [Parameter(Mandatory)]
        [hashtable]$ModuleArgs
    )

    # Get the available commands to a variable.  This reduces scan times.
    $PsModuleCommands = Get-Command -Module $PsModule

    # Pull function parameters first from Get-V#### function
    ### TODO : Explore standardized function params and everthing else as a variable
    $CommonArgs = ($PsModuleCommands | Where-Object Name -Match "Get-V\d{4,}").Parameters.Keys | Where-Object {$_ -notin [System.Management.Automation.PSCmdlet]::CommonParameters} | Select-Object -Unique

    # Build command arguments for scan module parameters.
    $CommandArgs = ""
    ForEach ($Item in $CommonArgs) {
        If ($ModuleArgs.$Item -eq "") {
            $CommandArgs += " -$($Item) " + [char]34 + [char]34
        }
        Else {
            #$CommandArgs += " -$($Item) $($ModuleArgs.$Item)"
            $CommandArgs += ' -{0} {1}' -f ($Item), $($ModuleArgs.$Item)
        }
    }

    # Create global variable objects that need passed to runspace session
    $i = 1
    $GlobalVars = @{}
    ForEach ($Key in $ModuleArgs.Keys) {
        If ($Key -notin $CommonArgs) {
            $GlobalVars.Add($i,[System.Management.Automation.Runspaces.SessionStateVariableEntry]::new($Key, $ModuleArgs.$Key, "", [System.Management.Automation.ScopedItemOptions]::AllScope))
            $i++
        }
    }

    # Create runspace pool to include required modules.
    $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $SessionState.ImportPSModule($(Join-Path -Path $ModulesPath -ChildPath Master_Functions))
    $SessionState.ImportPSModule($(Join-Path -Path $ModulesPath -ChildPath $PsModule))
    If ($ShowTech) {
        $SessionState.ImportPSModule($(Join-Path -Path $ModulesPath -ChildPath Cisco_Functions))
    }
    ForEach ($Key in $GlobalVars.Keys) {
        $SessionState.Variables.Add($GlobalVars.$Key)
    }
    $RunspacePool = [runspacefactory]::CreateRunspacePool(1, 1, $SessionState, $Host)
    $RunspacePool.Open()

    # Get inventory of Group IDs from STIG xccdf
    $STIGVulns = [System.Collections.Generic.List[System.Object]]::new()
    (Select-Xml -Path $StigXmlPath -XPath "/" | Select-Object -ExpandProperty Node).Benchmark.Group | ForEach-Object {
        $NewObj = [PSCustomObject]@{
            ID        = $_.id
            RuleID    = $_.rule.id
            STIGID    = $_.rule.version
            Severity  = $_.rule.severity
            RuleTitle = $_.rule.title
        }
        $STIGVulns.Add($NewObj)
    }

    # Build list of vulns to scan
    $VulnsToScan = [System.Collections.Generic.List[System.Object]]::new()
    [int]$TotalSubSteps = ($STIGVulns | Measure-Object).Count
    [Int]$CurrentSubStep = 1
    # Add either Selected Vulns or All Vulns to list of those to be scanned
    ForEach ($Vuln in $STIGVulns) {
        If ($SelectVuln) {
            If ($Vuln.ID -in $SelectVuln) {
                $VulnsToScan.Add($Vuln)
            }
        }
        Else {
            $VulnsToScan.Add($Vuln)
        }
    }

    $ScanResults  = [System.Collections.Generic.List[System.Object]]::new()
    ForEach ($Vuln in $VulnsToScan) {
        # Initialize STIGManMetaData
        $STIGManMetaData = [ordered]@{}

        If ($Vuln.ID -in $ExcludeVuln) {
            Write-Log -Path $LogPath -Message "Group ID : $($Vuln.ID)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            Write-Log -Path $LogPath -Message "    Excluded due to -ExcludeVuln parameter" -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
            Continue
        }
        Else {
            # If an Evaluate-STIG function exists for STIG item, process it here
            If ($PsModuleCommands | Where-Object Name -EQ "Get-$($Vuln.ID.Replace('-',''))") {
                Write-Progress -Id ($ProgressId + 1) -ParentId $ProgressId -Activity "Evaluating..." -Status "$($Vuln.ID)" -PercentComplete ($CurrentSubStep / $TotalSubSteps * 100)
                Write-Log -Path $LogPath -Message "Group ID : $($Vuln.ID)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                Write-Log -Path $LogPath -Message "    Running $($PsModule)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                Try {
                    $FindingDetailsPreText = ""
                    $CommentPreText = ""

                    # Run check code
                    $CheckCommand = "Get-$($Vuln.ID.Replace('-',''))$($CommandArgs)"
                    $RSCodeText = 'Try {' + $CheckCommand + '} Catch {$Result=@{CodeFail=$true;Message=$($_.Exception.Message);ScriptName=$($Error[0].InvocationInfo.ScriptName);ScriptLineNumber=$($Error[0].InvocationInfo.ScriptLineNumber);Line=$(($Error[0].InvocationInfo.Line).Trim())}; Return $Result}' | Out-String
                    $RSCodeSB = [scriptblock]::Create($RSCodeText)
                    $Result = Invoke-CodeWithTimeout -Code $RSCodeSB -Timeout $VulnTimeout -RunspacePool $RunspacePool
                    $Result = $Result | Where-Object {$null -ne $_.Status}

                    If ($Result.CodeFail) {
                        Throw "CodeFail"
                    }
                    ElseIf ($Result.Status -ne "Not_Reviewed") {
                        Write-Log -Path $LogPath -Message "    Scan Module determined Status is '$($Result.Status)'" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    }
                    Else {
                        Write-Log -Path $LogPath -Message "    Scan Module unable to determine Status" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    }

                    # Process any answer file mods
                    If ($Result.Comments) {
                        Write-Log -Path $LogPath -Message "    Adding Comment from answer file for Key '$($Result.AFKey)'" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        If ($Result.AFStatus -notin @("",$Result.Status)) {
                            Write-Log -Path $LogPath -Message "    Answer file for Key '$($Result.AFKey)' is changing the Status from '$($Result.Status)' to '$($Result.AFStatus)'" -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                            $CommentPreText += "Evaluate-STIG answer file for Key '$($Result.AFKey)' is changing the Status from '$($Result.Status)' to '$($Result.AFStatus)' and providing the below comment on $($ScanStartDate):`r`n" | Out-String
                            $Result.Comments = $CommentPreText + $Result.Comments

                            # Set Metadata for STIGMAN
                            $STIGManMetaData = [ordered]@{
                                AnswerFile = $(Split-Path $ModuleArgs.AnswerFile -Leaf).TrimEnd('"').TrimEnd("'")
                                AFMod      = $true
                                OldStatus  = $(Convert-Status -InputObject $Result.Status -Output STIGMAN)
                                NewStatus  = $(Convert-Status -InputObject $Result.AFStatus -Output STIGMAN)
                            }

                            # Change Status per answer file
                            $Result.Status = $Result.AFStatus
                        }
                        Else {
                            $CommentPreText += "Evaluate-STIG answer file for Key '$($Result.AFKey)' is providing the below comment on $($ScanStartDate):`r`n" | Out-String
                            $Result.Comments = $CommentPreText + $Result.Comments
                        }
                    }

                    # Check for Severity Override
                    If ($Result.SeverityOverride) {
                        If (-Not($Result.Justification)) {
                            Throw "Module setting 'SeverityOverride' without justification.  This is not acceptable.  Skipping."
                        }
                        Else {
                            Write-Log -Path $LogPath -Message "    Overriding Severity to '$($Result.SeverityOverride)'" -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                            Write-Log -Path $LogPath -Message "    Justification: $($Result.Justification)" -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                        }
                    }

                    # If STIG was forced with -ForceSTIG, prepend FindingDetails with warning
                    If ($Forced) {
                        $FindingDetailsPreText += "*** Evaluate-STIG determined this STIG as not required.  CKL generated with -ForceSTIG ***`r`n" | Out-String
                    }

                    # If STIG is deprecated prepend FindingDetails with warning
                    If ($Deprecated) {
                        $FindingDetailsPreText += "*** This STIG has been deprecated on cyber.mil ***`r`n" | Out-String
                    }

                    # If FindingDetails needs PreText, add it
                    If ($FindingDetailsPreText) {
                        $Result.FindingDetails = $FindingDetailsPreText + $Result.FindingDetails
                    }

                    # Truncate FindingDetails and Comments if over 32767 characters
                    If (($Result.FindingDetails | Measure-Object -Character).Characters -gt 32767) {
                        $Result.FindingDetails = $Result.FindingDetails.Substring(0, [System.Math]::Min(32767, $Result.FindingDetails.Length)) + "`r`n`r`n---truncated results. met character limit---" | Out-String
                    }
                    If (($Result.Comments | Measure-Object -Character).Characters -gt 32767) {
                        $Result.Comments = $Result.Comments.Substring(0, [System.Math]::Min(32767, $Result.Comments.Length)) + "`r`n`r`n---truncated results. met character limit---" | Out-String
                    }

                    $NewObj = [PSCustomObject]@{
                        GroupID          = $Vuln.ID
                        RuleID           = $Vuln.RuleID
                        STIGID           = $Vuln.STIGID
                        RuleTitle        = $Vuln.RuleTitle
                        Severity         = $Vuln.Severity
                        SeverityOverride = $Result.SeverityOverride
                        Justification    = $Result.Justification
                        Status           = $Result.Status
                        FindingDetails   = $Result.FindingDetails
                        Comments         = $Result.Comments
                        STIGMan          = $STIGManMetaData
                        CheckError       = $false
                    }
                    $ScanResults.Add($NewObj)
                }
                Catch {
                    Write-Log -Path $LogPath -Message "    Failed to execute vuln scan" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    If ($($_.Exception.Message) -eq "Job timed out.") {
                        Write-Host "$PsModule (Get-$($Vuln.ID.Replace('-',''))) : Timeout of $VulnTimeout minutes reached." -ForegroundColor Yellow
                        Write-Log -Path $LogPath -Message "    Check Timeout of $VulnTimeout minutes reached. Aborting." -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                        $NewObj = [PSCustomObject]@{
                            GroupID          = $Vuln.ID
                            RuleID           = $Vuln.RuleID
                            STIGID           = $Vuln.STIGID
                            RuleTitle        = $Vuln.RuleTitle
                            Severity         = $Vuln.Severity
                            SeverityOverride = ""
                            Justification    = ""
                            Status           = ""
                            FindingDetails   = [String]"Evaluate-STIG check timeout of $VulnTimeout minutes reached and scan for this check aborted.  Either increase the timeout with '-VulnTimeout' or complete this check manually."
                            Comments         = ""
                            STIGMan          = ""
                            CheckError       = $false
                        }
                        $ScanResults.Add($NewObj)
                    }
                    ElseIf ($_.Exception.Message -eq "CodeFail") {
                        Write-Host "$PsModule (Get-$($Vuln.ID.Replace('-',''))) : Failed. See Evaluate-STIG.log for details." -ForegroundColor Red
                        Write-Log -Path $LogPath -Message "    $($Result.Message)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                        Write-Log -Path $LogPath -Message "    $($Result.ScriptName)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                        Write-Log -Path $LogPath -Message "    Line: $($Result.ScriptLineNumber)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                        Write-Log -Path $LogPath -Message "    $($Result.Line)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                        $NewObj = [PSCustomObject]@{
                            GroupID          = $Vuln.ID
                            RuleID           = $Vuln.RuleID
                            STIGID           = $Vuln.STIGID
                            RuleTitle        = $Vuln.RuleTitle
                            Severity         = $Vuln.Severity
                            SeverityOverride = ""
                            Justification    = ""
                            Status           = ""
                            FindingDetails   = ""
                            Comments         = ""
                            STIGMan          = ""
                            CheckError       = $true
                        }
                        $ScanResults.Add($NewObj)
                    }
                    Else {
                        Write-Host "$PsModule (Get-$($Vuln.ID.Replace('-',''))) : Failed. See Evaluate-STIG.log for details." -ForegroundColor Red
                        Write-Log -Path $LogPath -Message "    $($_.Exception.Message)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                        Write-Log -Path $LogPath -Message "    $($_.InvocationInfo.ScriptName)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                        Write-Log -Path $LogPath -Message "    Line: $($_.InvocationInfo.ScriptLineNumber)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                        Write-Log -Path $LogPath -Message "    $(($_.InvocationInfo.Line).Trim())" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                        $NewObj = [PSCustomObject]@{
                            GroupID          = $Vuln.ID
                            RuleID           = $Vuln.RuleID
                            STIGID           = $Vuln.STIGID
                            RuleTitle        = $Vuln.RuleTitle
                            Severity         = $Vuln.Severity
                            SeverityOverride = ""
                            Justification    = ""
                            Status           = ""
                            FindingDetails   = ""
                            Comments         = ""
                            STIGMan          = ""
                            CheckError       = $true
                        }
                        $ScanResults.Add($NewObj)
                    }
                }
            }
            ElseIf ($ModuleArgs.AnswerFile) {
                # If not checked by Evaluate-STIG function, look to see if there is an answer in an answer file for this STIG item
                $GetCorpParams = @{
                    AnswerFile   = $ModuleArgs.AnswerFile
                    VulnID       = $Vuln.ID
                    AnswerKey    = $ModuleArgs.AnswerKey
                    LogPath      = $LogPath
                    LogComponent = $LogComponent
                    OSPlatform   = $OSPlatform
                }
                <#
                Space save for having more Site/DB/Apache specific keys
                if ($ModuleArgs.SiteName){
                    $GetCorpParams.Sitename = $ModuleArgs.SiteName
                }
                if ($ModuleArgs.Instance){
                    $GetCorpParams.Instance = $ModuleArgs.Instance
                    $GetCorpParams.Database = $ModuleArgs.Database
                }
                #>
                $AnswerData = (Get-CorporateComment @GetCorpParams)
                If ($AnswerData) {
                    If ($AnswerData.ExpectedStatus -eq "Not_Reviewed") {
                        $StatusChange = $false
                        $PreComment = ""
                        Write-Log -Path $LogPath -Message "Group ID : $($Vuln.ID)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        Write-Log -Path $LogPath -Message "    Adding Comment from answer file for Key '$($AnswerData.AFKey)'" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        If ($AnswerData.AFStatus -notin @("", "Not_Reviewed")) {
                            $StatusChange = $true
                            $PreComment = "Evaluate-STIG answer file for Key '$($AnswerData.AFKey)' is changing the Status from 'Not_Reviewed' to '$($AnswerData.AFStatus)' and providing the below comment on $($ScanStartDate):`r`n" | Out-String

                            # Set Metadata for STIGMAN
                            $STIGManMetaData = [ordered]@{
                                AnswerFile = $(Split-Path $ModuleArgs.AnswerFile -Leaf).TrimEnd('"').TrimEnd("'")
                                AFMod      = $true
                                OldStatus  = $(Convert-Status -InputObject NR -Output STIGMAN)
                                NewStatus  = $(Convert-Status -InputObject $AnswerData.AFStatus -Output STIGMAN)
                            }
                        }
                    }
                    Else {
                        $PreComment = "Evaluate-STIG answer file for Key '$($AnswerData.AFKey)' is providing the below comment on $($ScanStartDate):`r`n" | Out-String
                    }

                    # If Answer File is changing status, log a warning.
                    If ($StatusChange -eq $true) {
                        Write-Log -Path $LogPath -Message "    Answer file for Key '$($AnswerData.AFKey)' is changing the Status from 'Not_Reviewed' to '$($AnswerData.AFStatus)'" -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                    }

                    # Set the final comment data
                    [String]$FinalComments = $PreComment + $AnswerData.AFComment
                    # Truncate Comment if over 32767 characters
                    If (($FinalComments | Measure-Object -Character).Characters -gt 32767) {
                        $FinalComments = $FinalComments.Substring(0, [System.Math]::Min(32767, $FinalComments.Length)) + "`r`n`r`n---truncated results. met character limit---" | Out-String
                    }

                    $NewObj = [PSCustomObject]@{
                        GroupID          = $Vuln.ID
                        RuleID           = $Vuln.RuleID
                        STIGID           = $Vuln.STIGID
                        RuleTitle        = $Vuln.RuleTitle
                        Severity         = $Vuln.Severity
                        SeverityOverride = ""
                        Justification    = ""
                        Status           = $AnswerData.AFStatus
                        FindingDetails   = $FinalComments
                        Comments         = $FinalComments
                        STIGMan          = $STIGManMetaData
                        CheckError       = $false
                    }
                    $ScanResults.Add($NewObj)
                }
            }
            else{
                $NewObj = [PSCustomObject]@{
                    GroupID          = $Vuln.ID
                    RuleID           = $Vuln.RuleID
                    STIGID           = $Vuln.STIGID
                    RuleTitle        = $Vuln.RuleTitle
                    Severity         = $Vuln.Severity
                    SeverityOverride = ""
                    Justification    = ""
                    Status           = "Not_Reviewed"
                    FindingDetails   = ""
                    Comments         = ""
                    STIGMan          = ""
                    CheckError       = $false
                }
                $ScanResults.Add($NewObj)
            }
        }
        $CurrentSubStep++
    }
    Write-Progress -Id ($ProgressId + 1) -ParentId $ProgressId -Activity "Evaluating..." -Status "$($Vuln.ID)" -Completed
    $RunspacePool.Close()
    $RunspacePool.Dispose()

    Return $ScanResults
}

Function Invoke-CodeWithTimeout {
    Param
    (
        [Parameter(Mandatory)]
        [ScriptBlock]$Code,

        [Parameter(Mandatory)]
        [int]$Timeout,

        [Parameter(Mandatory)]
        $RunspacePool
    )

    $ps = [PowerShell]::Create()
    $ps.Runspacepool = $RunspacePool
    $null = $ps.AddScript($Code)
    $handle = $ps.BeginInvoke()
    $start = Get-Date
    do {
        $timeConsumed = (Get-Date) - $start
        if ($timeConsumed.TotalMinutes -ge $Timeout) {
            $ps.Stop()
            $ps.Dispose()
            throw "Job timed out."
        }
        Start-Sleep -Milliseconds 50
    } until ($handle.isCompleted)

    $ps.EndInvoke($handle)
    $ps.Dispose()
}

Function Initialize-PreviousProcessing {
    Param (
        [Parameter(Mandatory)]
        [String]$ResultsPath,

        [Parameter(Mandatory)]
        [Int]$PreviousToKeep,

        [Parameter()]
        [PSObject]$SelectedShortNames,

        [Parameter()]
        [Switch]$SelectedCombinedCKL,

        [Parameter()]
        [Switch]$SelectedCombinedCKLB,

        [Parameter()]
        [Switch]$SelectedSummary,

        [Parameter()]
        [Switch]$SelectedOQE,

        [Parameter(Mandatory)]
        [String]$LogPath,

        [Parameter(Mandatory)]
        [String]$LogComponent,

        [Parameter(Mandatory)]
        [String]$OSPlatform
    )

    $PreviousPath = $(Join-Path -Path $ResultsPath -ChildPath "Previous")
    If ($PreviousToKeep -eq 0) {
        Write-Log -Path $LogPath -Message "Parameter -PreviousToKeep is '0'.  Removing all previous scan results." -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
        Get-ChildItem -Path $ResultsPath | Remove-Item -Recurse -Force
    }
    Else {
        # Get all recent results
        $PreviousResult = Get-ChildItem $ResultsPath -Recurse | Where-Object {$_.FullName -notlike "*Previous*"}

        If ($SelectedShortNames) {
            [array]$SelectedMatches = $SelectedShortNames
            $SelectedMatches += "Evaluate-STIG\.log"
            If ($SelectedCombinedCKL) { # Add combined .ckl to items to be moved
                $SelectedMatches += "COMBINED.{0,}\.ckl"
            }
            If ($SelectedCombinedCKLB) { # Add combined .cklb to items to be moved
                $SelectedMatches += "COMBINED.{0,}\.cklb"
            }
            If ($SelectedSummary) { # Add summary report files to items to be moved
                $SelectedMatches += "SummaryReport"
            }
            If ($SelectedOQE) { # Add OQE files to items to be moved
                $SelectedMatches += "AppLockerPol.{0,}\.xml"
                $SelectedMatches += "GPResult.{0,}\.html"
                $SelectedMatches += "SecPol.{0,}\.ini"
            }
            $PreviousResult = $PreviousResult | Where-Object {$_.Name -match ($SelectedMatches -join "|")}
        }

        If ($PreviousResult) {
            # Move recent results to previous
            $PreviousDate = Get-Date ($PreviousResult.LastWriteTime | Sort-Object -Descending)[0] -Format yyyyMMdd-HHmmss
            $PreviousSession = $(Join-Path -Path $PreviousPath -ChildPath $PreviousDate)
            Write-Log -Path $LogPath -Message "Moving previous scan result to '$PreviousSession'" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            If (-Not(Test-Path $PreviousSession)) {
                $null = New-Item -Path $PreviousSession -ItemType Directory
            }

            $PreviousResult | Where-Object {$null -ne $_.DirectoryName} | ForEach-Object {
                If ($($_.DirectoryName) -ireplace [regex]::Escape($ResultsPath),"") {
                    # Create subfolder in PreviousSession
                    If (-Not(Test-Path $(Join-Path -Path $PreviousSession -ChildPath $(($_.DirectoryName) -ireplace [regex]::Escape($ResultsPath),"")))) {
                        $null = New-Item -Path $(Join-Path -Path $PreviousSession -ChildPath $(($_.DirectoryName) -ireplace [regex]::Escape($ResultsPath),"")) -ItemType Directory
                    }
                }
                Copy-Item -Path $_.FullName -Destination $(Join-Path -Path $PreviousSession -ChildPath $(($_.DirectoryName) -ireplace [regex]::Escape($ResultsPath),""))
                Remove-Item -Path $_.FullName -Force
            }
        }

        # Clean up previous path to only retain number of folders specified by -PreviousToKeep or all folder if -PreviousToKeep is negative value
        If ($PreviousToKeep -lt 0) {
            Write-Log -Path $LogPath -Message "Retaining ALL previous scans per -PreviousToKeep parameter being a negative value" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        }
        Else {
            Write-Log -Path $LogPath -Message "Retaining a maximum of '$PreviousToKeep' previous scans per -PreviousToKeep parameter" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
            If (Test-Path $PreviousPath) {
                $i = 0
                ForEach ($Item in (Get-ChildItem -Path $PreviousPath | Sort-Object -Descending).FullName) {
                    $i++
                    If ($i -gt $PreviousToKeep) {
                        Write-Log -Path $LogPath -Message "Removing previous result: '$Item'" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        Remove-Item $Item -Recurse -Force
                    }
                }
            }
        }
    }
}

Function Convert-Status {
    # Super simple function to save space. Converts freely between Status for Evaluate-STIG, CKL, CKLB, STIGMAN.
    [cmdletbinding()]
    Param (
        [Parameter(ValueFromPipeline)]
        [ValidateSet(
            'NR', 'NF', 'NA', 'O', # Evaluate-STIG
            'Not_Reviewed', 'NotAFinding', 'Not_Applicable', 'Open', # CKL/CKLB (except 'NotAFinding')
            'not_a_finding', # CKLB only
            'notchecked', 'pass', 'notapplicable', 'fail' # STIG Manager
        )]
        $InputObject,

        [ValidateSet('EvalSTIG', 'CKL', 'CKLB', 'STIGMAN')]
        [String]
        $Output
    )

    $SortingHat = @{
        'EvalSTIG' = @{
            # Input = CKL
            'Not_Reviewed'   = 'NR'
            'NotAFinding'    = 'NF'
            'Not_Applicable' = 'NA'
            'Open'           = 'O'
            # Input = CKLB
            'not_a_finding'  = 'NF'
            # Input = STIGMAN
            'notchecked'     = 'NR'
            'pass'           = 'NF'
            'notapplicable'  = 'NA'
            'fail'           = 'O'
        }
        'CKL'      = @{
            # Input = Evaluate-STIG
            'NR'             = 'Not_Reviewed'
            'NF'             = 'NotAFinding'
            'NA'             = 'Not_Applicable'
            'O'              = 'Open'
            # Input = CKLB
            'not_a_finding'  = 'NotAFinding'
            # Input = STIGMAN
            'notchecked'     = 'Not_Reviewed'
            'pass'           = 'NotAFinding'
            'notapplicable'  = 'Not_Applicable'
            'fail'           = 'Open'
        }
        'CKLB'     = @{
            # Input = Evaluate-STIG
            'NR'             = 'Not_Reviewed'
            'NF'             = 'not_a_finding'
            'NA'             = 'Not_Applicable'
            'O'              = 'Open'
            # Input = CKLB
            'NotAFinding'    = 'not_a_finding'
            # Input = STIGMAN
            'notchecked'     = 'Not_Reviewed'
            'pass'           = 'not_a_finding'
            'notapplicable'  = 'Not_Applicable'
            'fail'           = 'Open'
        }
        'STIGMAN'  = @{
            # Input = Evaluate-STIG
            'NR'             = 'notchecked'
            'NF'             = 'pass'
            'NA'             = 'notapplicable'
            'O'              = 'fail'
            # Input = CKL
            'Not_Reviewed'   = 'notchecked'
            'NotAFinding'    = 'pass'
            'Not_Applicable' = 'notapplicable'
            'Open'           = 'fail'
            # Input = CKLB
            'not_a_finding'  = 'pass'
        }
    }

    $result = $SortingHat[$Output][$InputObject]
    If (-not($result)) {
        $result = $InputObject
    }
    Return $result
}

Function Format-CKL {
    param
    (
        [Parameter(Mandatory)]
        [string]$SchemaPath,

        [Parameter(Mandatory)]
        [psobject]$ScanObject,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter()]
        [string]$Marking = "",

        [Parameter(Mandatory = $true)]
        [String]$WorkingDir,

        [Parameter(Mandatory = $true)]
        [String]$ESPath,

        [Parameter(Mandatory = $true)]
        [String]$LogComponent,

        [Parameter(Mandatory = $true)]
        [String]$OSPlatform
    )

    # Read the schema
    [xml]$Schema = Get-Content $SchemaPath

    # Get Target Data
    If (($ScanObject | Measure-Object).Count -gt 1) {
        If ($ScanObject | Where-Object {($_.ESData.CanCombine -eq $true)}) {
            $TargetData = ($ScanObject | Where-Object {($_.ESData.CanCombine -eq $true)})[0].TargetData
            $TargetKey = ($ScanObject | Where-Object {($_.ESData.CanCombine -eq $true)})[0].TargetData.Target_Key
            $ScanObject = ($ScanObject | Where-Object {($_.ESData.CanCombine -eq $true)})
        }
        Else {
            Throw "None of the scanned STIGs can be combined."
        }
    }
    Else {
        $TargetData = $ScanObject.TargetData
        $TargetKey = $ScanObject.TargetData.Target_Key
    }

    # Build the XML data
    $Encoding = [System.Text.UTF8Encoding]::new($false)
    $xmlSettings = New-Object System.Xml.XmlWriterSettings
    $xmlSettings.Encoding = $Encoding
    $xmlSettings.Indent = $true
    $xmlSettings.IndentChars = "`t"
    $xmlSettings.NewLineHandling = "None"

    $xmlWriter = [System.Xml.XmlWriter]::Create($($OutputPath),$xmlSettings)

    $rootnode = $Schema.SelectSingleNode("//*")

    $xpath = "*[local-name()='element' or local-name()='complexType' or local-name()='sequence' or local-name()='attribute']"
    $nodes = $rootnode.SelectNodes($xpath)

    # Create Evaluate-STIG comment
    $xmlWriter.WriteComment("<Evaluate-STIG><version>$($ScanObject[0].ESData.ESVersion)</version></Evaluate-STIG>")

    #We know Checklist is the root node and has "ASSET" and "STIGS" as sub nodes
    $xmlWriter.WriteStartElement("CHECKLIST")

    $xmlWriter.WriteStartElement("ASSET")
    # Specify elements and order from STIG Viewer saved CKL.  May differ from STIG Viewer schema.
    $SortOrder = @("ROLE", "ASSET_TYPE", "MARKING", "HOST_NAME", "HOST_IP", "HOST_MAC", "HOST_FQDN", "TARGET_COMMENT", "TECH_AREA", "TARGET_KEY", "WEB_OR_DATABASE", "WEB_DB_SITE", "WEB_DB_INSTANCE")
    Foreach ($node in $(($nodes | Where-Object {$_.Name -eq "ASSET"}).complexType.sequence.element) | Sort-Object {$SortOrder.IndexOf($_.ref)}) {
        If ($node.ref -in $SortOrder) {
            Switch ($Node.ref) {
                "ROLE" {
                    $ValidValues = @("None", "Workstation", "Member Server", "Domain Controller")
                    If ($TargetData.Role -and $TargetData.Role -notin $ValidValues) {
                        Throw "Invalid value for property [$($_)]: '$($TargetData.Role)'"
                    }
                    Else {
                        $xmlWriter.WriteElementString($Node.ref, $($TargetData.Role))
                    }
                }
                "ASSET_TYPE" {
                    $xmlWriter.WriteElementString($Node.ref, "Computing")
                }
                "MARKING" {
                    $xmlWriter.WriteElementString($Node.ref, $($Marking))
                }
                "HOST_NAME" {
                    $xmlWriter.WriteElementString($Node.ref, $($TargetData.Hostname))
                }
                "HOST_IP" {
                    $xmlWriter.WriteElementString($Node.ref, $($TargetData.IpAddress))
                }
                "HOST_MAC" {
                    $xmlWriter.WriteElementString($Node.ref, $($TargetData.MacAddress))
                }
                "HOST_FQDN" {
                    $xmlWriter.WriteElementString($Node.ref, $($TargetData.FQDN))
                }
                "TARGET_KEY" {
                    $xmlWriter.WriteElementString($Node.ref, $TargetKey)
                }
                "WEB_OR_DATABASE" {
                    If ($TargetData.WebOrDatabase -notin @("true", "false")) {
                        Throw "Invalid value for property [$($_)]: '$($TargetData.WebOrDatabase )'"
                    }
                    Else {
                        $xmlWriter.WriteElementString($Node.ref, $(([String]($Targetdata.WebOrDatabase)).ToLower()))
                    }
                }
                "WEB_DB_SITE" {
                    $xmlWriter.WriteElementString($Node.ref, $($TargetData.Site))
                }
                "WEB_DB_INSTANCE" {
                    $xmlWriter.WriteElementString($Node.ref, $($TargetData.Instance))
                }
                default {
                    $xmlWriter.WriteStartElement($Node.ref)
                    $xmlWriter.WriteFullEndElement()
                }
            }
        }
    }
    $xmlWriter.WriteEndElement() #ASSET

    $xmlWriter.WriteStartElement("STIGS")

    ForEach ($Scan in $ScanObject) {
        # Read the STIG content
        $STIGXMLPath = $(Join-Path -Path $ESPath -ChildPath StigContent | Join-Path -ChildPath $Scan.ESData.STIGXMLName)
        # https://stackoverflow.com/questions/71847945/strange-characters-found-in-xml-file-and-powershell-output-after-exporting-from
        ($Content = [xml]::new()).Load($STIGXMLPath)

        # Set STIG Classification
        Switch -Regex ($Content.'xml-stylesheet') {
            'STIG_unclass.xsl' {
                $Classification = "UNCLASSIFIED"
            }
            'STIG_cui.xsl' {
                $Classification = "CUI"
            }
            DEFAULT {
                Throw "Unable to determine STIG classification."
            }
        }

        $xmlWriter.WriteStartElement("iSTIG")

        # Create Evaluate-STIG comment
        $xmlWriter.WriteComment("<Evaluate-STIG><time>$($Scan.ESData.StartTime)</time><module><name>$($Scan.ESData.ModuleName)</name><version>$([String]$Scan.ESData.ModuleVersion)</version></module></Evaluate-STIG>")

        $xmlWriter.WriteStartElement("STIG_INFO")
        # Specify elements and order from STIG Viewer saved CKL.  May differ from STIG Viewer schema.
        $SortOrder = @("version", "classification", "customname", "stigid", "description", "filename", "releaseinfo", "title", "uuid", "notice", "source")
        Foreach ($node in $(($nodes | Where-Object { $_.Name -eq "SID_NAME"}).simpleType.restriction.enumeration) | Sort-Object {$SortOrder.IndexOf($_.value)}) {
            If ($node.value -in $SortOrder) {
                $xmlWriter.WriteStartElement("SI_DATA")
                $xmlWriter.WriteElementString("SID_NAME", $Node.value)
                Switch ($Node.value) {
                    "version" {
                        $xmlWriter.WriteElementString("SID_DATA", $Content.Benchmark.version)
                    }
                    "classification" {
                        $xmlWriter.WriteElementString("SID_DATA", $Classification)
                    }
                    "customname" {
                        # Do Nothing
                    }
                    "stigid" {
                        $xmlWriter.WriteElementString("SID_DATA", $Content.Benchmark.id)
                    }
                    "description" {
                        $xmlWriter.WriteElementString("SID_DATA", $Content.Benchmark.description)
                    }
                    "filename" {
                        $xmlWriter.WriteElementString("SID_DATA", $(Split-Path $STIGXMLPath -Leaf))
                    }
                    "releaseinfo" {
                        $xmlWriter.WriteElementString("SID_DATA", ($Content.Benchmark.'plain-text' | Where-Object { $_.id -eq "release-info" }).'#text')
                    }
                    "title" {
                        $xmlWriter.WriteElementString("SID_DATA", $Content.Benchmark.title)
                    }
                    "uuid" {
                        $xmlWriter.WriteElementString("SID_DATA", $([guid]::NewGuid()))
                    }
                    "notice" {
                        $xmlWriter.WriteElementString("SID_DATA", $Content.Benchmark.notice.id)
                    }
                    "source" {
                        $xmlWriter.WriteElementString("SID_DATA", $Content.Benchmark.reference.source)
                    }
                }
                $xmlWriter.WriteEndElement() #SI_DATA
            }
        }
        $xmlWriter.WriteEndElement() #STIG_INFO
        # Specify elements and order from STIG Viewer saved CKL.  May differ from STIG Viewer schema.
        $SortOrder = @("STIG_DATA", "STATUS", "FINDING_DETAILS", "COMMENTS", "SEVERITY_OVERRIDE", "SEVERITY_JUSTIFICATION")
        $AttribSortOrder = @("Vuln_Num", "Severity", "Group_Title", "Rule_ID", "Rule_Ver", "Rule_Title", "Vuln_Discuss", "IA_Controls", "Check_Content", "Fix_Text", "False_Positives", "False_Negatives", "Documentable", "Mitigations", "Potential_Impact", "Third_Party_Tools", "Mitigation_Control", "Responsibility", "Security_Override_Guidance", "Check_Content_Ref", "Weight", "Class", "STIGRef", "TargetKey", "STIG_UUID", "LEGACY_ID", "CCI_REF")
        Foreach ($Vuln in $Content.Benchmark.Group) {
            # Get results from scan object
            $ScanResult = $Scan.VulnResults | Where-Object GroupID -eq $Vuln.id
            $xmlWriter.WriteStartElement("VULN")

            If ($ScanResult.STIGMan.AFMod -eq $true) {
                # Create Evaluate-STIG comment
                $xmlWriter.WriteComment("<Evaluate-STIG><AnswerFile>$($ScanResult.STIGMan.AnswerFile)</AnswerFile><AFMod>$(([String]$ScanResult.STIGMan.AFMod).ToLower())</AFMod><OldStatus>$($ScanResult.STIGMan.OldStatus)</OldStatus><NewStatus>$($ScanResult.STIGMan.NewStatus)</NewStatus></Evaluate-STIG>")
            }

            Foreach ($node in $(($nodes | Where-Object { $_.Name -eq "VULN"}).complexType.sequence.element) | Sort-Object {$SortOrder.IndexOf($_.ref)}) {
                If ($node.ref -in $SortOrder) {
                    Switch ($Node.ref) {
                        "STIG_DATA" {
                            Foreach ($subnode in $(($nodes | Where-Object {$_.Name -eq "VULN_ATTRIBUTE"}).simpleType.restriction.enumeration) | Sort-Object {$AttribSortOrder.IndexOf($_.value)}) {
                                If ($subnode.value -in $AttribSortOrder) {
                                    Switch ($subnode.value) {
                                        "Vuln_Num" {
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Vuln.id)
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Severity" {
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Vuln.Rule.severity)
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Group_Title" {
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Vuln.title)
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Rule_ID" {
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Vuln.Rule.id)
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Rule_Ver" {
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Vuln.Rule.version)
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Rule_Title" {
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Vuln.Rule.title)
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Vuln_Discuss" {
                                            $Tag = "VulnDiscussion"
                                            $Value = [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag)
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            If ($Value) {
                                                $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Value)
                                            }
                                            Else {
                                                $xmlWriter.WriteStartElement("ATTRIBUTE_DATA")
                                                $xmlWriter.WriteFullEndElement() #ATTRIBUTE_DATA
                                            }
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "IA_Controls" {
                                            $Tag = "IAControls"
                                            $Value = [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag)
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            If ($Value) {
                                                $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Value)
                                            }
                                            Else {
                                                $xmlWriter.WriteStartElement("ATTRIBUTE_DATA")
                                                $xmlWriter.WriteFullEndElement() #ATTRIBUTE_DATA
                                            }
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Check_Content" {
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Vuln.Rule.check.'check-content')
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Fix_Text" {
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Vuln.Rule.fixtext.'#text')
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "False_Positives" {
                                            $Tag = "FalsePositives"
                                            $Value = [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag)
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            If ($Value) {
                                                $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Value)
                                            }
                                            Else {
                                                $xmlWriter.WriteStartElement("ATTRIBUTE_DATA")
                                                $xmlWriter.WriteFullEndElement() #ATTRIBUTE_DATA
                                            }
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "False_Negatives" {
                                            $Tag = "FalseNegatives"
                                            $Value = [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag)
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            If ($Value) {
                                                $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Value)
                                            }
                                            Else {
                                                $xmlWriter.WriteStartElement("ATTRIBUTE_DATA")
                                                $xmlWriter.WriteFullEndElement() #ATTRIBUTE_DATA
                                            }
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Documentable" {
                                            $Tag = "Documentable"
                                            $Value = [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag)
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            If ($Value) {
                                                $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Value)
                                            }
                                            Else {
                                                $xmlWriter.WriteStartElement("ATTRIBUTE_DATA")
                                                $xmlWriter.WriteFullEndElement() #ATTRIBUTE_DATA
                                            }
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Mitigations" {
                                            $Tag = "Mitigations"
                                            $Value = [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag)
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            If ($Value) {
                                                $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Value)
                                            }
                                            Else {
                                                $xmlWriter.WriteStartElement("ATTRIBUTE_DATA")
                                                $xmlWriter.WriteFullEndElement() #ATTRIBUTE_DATA
                                            }
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Potential_Impact" {
                                            $Tag = "PotentialImpacts"
                                            $Value = [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag)
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            If ($Value) {
                                                $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Value)
                                            }
                                            Else {
                                                $xmlWriter.WriteStartElement("ATTRIBUTE_DATA")
                                                $xmlWriter.WriteFullEndElement() #ATTRIBUTE_DATA
                                            }
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Third_Party_Tools" {
                                            $Tag = "ThirdPartyTools"
                                            $Value = [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag)
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            If ($Value) {
                                                $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Value)
                                            }
                                            Else {
                                                $xmlWriter.WriteStartElement("ATTRIBUTE_DATA")
                                                $xmlWriter.WriteFullEndElement() #ATTRIBUTE_DATA
                                            }
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Mitigation_Control" {
                                            $Tag = "MitigationControl"
                                            $Value = [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag)
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            If ($Value) {
                                                $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Value)
                                            }
                                            Else {
                                                $xmlWriter.WriteStartElement("ATTRIBUTE_DATA")
                                                $xmlWriter.WriteFullEndElement() #ATTRIBUTE_DATA
                                            }
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Responsibility" {
                                            $Tag = "Responsibility"
                                            $Value = [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag)
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            If ($Value) {
                                                $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Value)
                                            }
                                            Else {
                                                $xmlWriter.WriteStartElement("ATTRIBUTE_DATA")
                                                $xmlWriter.WriteFullEndElement() #ATTRIBUTE_DATA
                                            }
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Security_Override_Guidance" {
                                            $Tag = "SeverityOverrideGuidance"
                                            $Value = [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag)
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            If ($Value) {
                                                $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Value)
                                            }
                                            Else {
                                                $xmlWriter.WriteStartElement("ATTRIBUTE_DATA")
                                                $xmlWriter.WriteFullEndElement() #ATTRIBUTE_DATA
                                            }
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Check_Content_Ref" {
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Vuln.Rule.check.'check-content-ref'.name)
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Weight" {
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Vuln.rule.weight)
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "Class" {
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            Switch ($Classification) {
                                                "CUI" {
                                                    $xmlWriter.WriteElementString("ATTRIBUTE_DATA", "CUI")
                                                }
                                                default {
                                                    $xmlWriter.WriteElementString("ATTRIBUTE_DATA", "Unclass")
                                                }
                                            }
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "STIGRef" {
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            $xmlWriter.WriteElementString("ATTRIBUTE_DATA", "$($Content.Benchmark.title) :: Version $($Content.Benchmark.version), $(($Content.Benchmark.'plain-text' | Where-Object { $_.id -eq 'release-info' }).'#text')")
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "TargetKey" {
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $Vuln.rule.reference.identifier)
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "STIG_UUID" {
                                            $xmlWriter.WriteStartElement("STIG_DATA")
                                            $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                            $xmlWriter.WriteElementString("ATTRIBUTE_DATA", $([guid]::NewGuid()))
                                            $xmlWriter.WriteEndElement() #STIG_DATA
                                        }
                                        "LEGACY_ID" {
                                            If ($Vuln.Rule.ident | Where-Object {$_.system -eq "http://cyber.mil/legacy"}) {
                                                Foreach ($legacy in ($Vuln.Rule.ident | Where-Object {$_.system -eq "http://cyber.mil/legacy"} | Sort-Object '#text' -Descending)) {
                                                    $xmlWriter.WriteStartElement("STIG_DATA")
                                                    $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                                    $xmlWriter.WriteElementString("ATTRIBUTE_DATA", "$($legacy.'#text')")
                                                    $xmlWriter.WriteEndElement() #STIG_DATA
                                                }
                                            }
                                            Else {
                                                # Write two empty LEGACY_ID nodes
                                                $xmlWriter.WriteStartElement("STIG_DATA")
                                                $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                                $xmlWriter.WriteStartElement("ATTRIBUTE_DATA")
                                                $xmlWriter.WriteFullEndElement() #ATTRIBUTE_DATA
                                                $xmlWriter.WriteEndElement() #STIG_DATA

                                                $xmlWriter.WriteStartElement("STIG_DATA")
                                                $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                                $xmlWriter.WriteStartElement("ATTRIBUTE_DATA")
                                                $xmlWriter.WriteFullEndElement() #ATTRIBUTE_DATA
                                                $xmlWriter.WriteEndElement() #STIG_DATA
                                            }
                                        }
                                        "CCI_REF" {
                                            Foreach ($CCI in ($Vuln.Rule.ident | Where-Object {$_.system -like "http://*.mil/cci"} | Sort-Object '#text')) {
                                                $xmlWriter.WriteStartElement("STIG_DATA")
                                                $xmlWriter.WriteElementString("VULN_ATTRIBUTE", $subnode.value)
                                                $xmlWriter.WriteElementString("ATTRIBUTE_DATA", "$($CCI.'#text')")
                                                $xmlWriter.WriteEndElement() #STIG_DATA
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        "STATUS" {
                            $ValidValues = @("NR", "NF", "NA", "O", "Not_Reviewed", "NotAFinding", "Not_Applicable", "Open", "not_a_finding", "notchecked", "pass", "notapplicable", "fail")
                            If (-Not($ScanResult.Status)) {
                                $Status = "Not_Reviewed"
                            }
                            ElseIf ($ScanResult.Status -and $ScanResult.Status -notin $ValidValues) {
                                Throw "Invalid value for property [$($_)]: '$($ScanResult.Status)'"
                            }
                            Else {
                                $Status = $(Convert-Status -InputObject $ScanResult.Status -Output CKL)
                            }
                            $xmlWriter.WriteElementString("STATUS", $Status)
                        }
                        "FINDING_DETAILS" {
                            If ($ScanResult.FindingDetails) {
                                $xmlWriter.WriteElementString("FINDING_DETAILS", $($ScanResult.FindingDetails))
                            }
                            Else {
                                $xmlWriter.WriteElementString("FINDING_DETAILS", "")
                            }
                        }
                        "COMMENTS" {
                            If ($ScanResult.Comments) {
                                $xmlWriter.WriteElementString("COMMENTS", $($ScanResult.Comments))
                            }
                            Else {
                                $xmlWriter.WriteElementString("COMMENTS", "")
                            }
                        }
                        "SEVERITY_OVERRIDE" {
                            If ($ScanResult.SeverityOverride) {
                                $ValidValues = @("low","medium","high")
                                If ($ScanResult.SeverityOverride -notin $ValidValues) {
                                    Throw "Invalid value for property [$($_)]: '$($ScanResult.SeverityOverride)'"
                                }
                                Else {
                                    $xmlWriter.WriteElementString("SEVERITY_OVERRIDE", $($ScanResult.SeverityOverride))
                                }
                            }
                            Else {
                                $xmlWriter.WriteElementString("SEVERITY_OVERRIDE", "")
                            }
                        }
                        "SEVERITY_JUSTIFICATION" {
                            If ($ScanResult.Justification) {
                                $xmlWriter.WriteElementString("SEVERITY_JUSTIFICATION", $($ScanResult.Justification))
                            }
                            Else {
                                $xmlWriter.WriteElementString("SEVERITY_JUSTIFICATION", "")
                            }
                        }
                        default {
                            $xmlWriter.WriteStartElement($Node.ref)
                            $xmlWriter.WriteFullEndElement()
                        }
                    }
                }
            }
            $xmlWriter.WriteEndElement() #VULN
        }

        $xmlWriter.WriteEndElement() #iSTIG
    }

    $xmlWriter.WriteEndElement() #STIGS

    $xmlWriter.WriteEndElement() #CHECKLIST
    $xmlWriter.WriteEndDocument()
    $xmlWriter.Flush()
    $xmlWriter.Close()

    Write-Log -Path $STIGLog -Message "Validating CKL File" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
    $ChecklistValid = Test-XmlValidation -XmlFile $OutputPath -SchemaFile $SchemaPath

    # Action for validation result
    If ($ChecklistValid) {
        Write-Log -Path $STIGLog -Message "'$(Split-Path $OutputPath -Leaf)' : Passed." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
    }
    Else {
        $BadFileDestination = Join-Path -Path $WorkingDir -ChildPath "Bad_CKL"
        Write-Log -Path $STIGLog -Message "ERROR: '$(Split-Path $OutputPath -Leaf)' : failed schema validation. Moving to $BadFileDestination." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
        ForEach ($Item in $ChecklistValid.Message) {
            Write-Log -Path $STIGLog -Message $Item -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
        }
        If (-Not(Test-Path $BadFileDestination)) {
            $null = New-Item -Path $BadFileDestination -ItemType Directory
        }
        Copy-Item -Path $OutputPath -Destination $BadFileDestination -Force
        Remove-Item $OutputPath -Force
    }

    Return $ChecklistValid
}

Function Format-CKLB {
    # https://mattou07.net/posts/creating-complex-json-with-powershell/
    param
    (
        [Parameter(Mandatory)]
        [string]$SchemaPath,

        [Parameter(Mandatory)]
        [psobject]$ScanObject,

        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter(Mandatory = $true)]
        [String]$WorkingDir,

        [Parameter(Mandatory = $true)]
        [String]$ESPath,

        [Parameter(Mandatory = $true)]
        [String]$LogComponent,

        [Parameter(Mandatory = $true)]
        [String]$OSPlatform
    )

    $Schema = Get-Content $SchemaPath -Raw | ConvertFrom-Json

    # Get Target Data
    If (($ScanObject | Measure-Object).Count -gt 1) {
        If ($ScanObject | Where-Object {($_.ESData.CanCombine -eq $true)}) {
            $TargetData = ($ScanObject | Where-Object {($_.ESData.CanCombine -eq $true)})[0].TargetData
            $ScanObject = ($ScanObject | Where-Object {($_.ESData.CanCombine -eq $true)})
        }
        Else {
            Throw "None of the scanned STIGs can be combined."
        }
    }
    Else {
        $TargetData = $ScanObject.TargetData
    }

    $objCKLB = [ordered]@{}
    $RootProps = ($Schema.properties.PsObject.Members | Where-Object MemberType -EQ "NoteProperty").Name
    ForEach ($P1 in $RootProps) {
        Switch ($P1) {
            "evaluate-stig" {
                $objES = [ordered]@{}
                $ESProps = ($Schema.properties.$P1.properties.psobject.members | Where-Object MemberType -EQ "NoteProperty").Name
                ForEach ($P2 in $ESProps) {
                    Switch ($P2) {
                        "version" {
                            $objES.Add($_, $($ScanObject[0].ESData.ESVersion))
                        }
                        Default {
                            $Message = "Unexpected CKLB schema property: '$_'"
                            Throw $Message
                        }
                    }
                }
                $objCKLB.Add("evaluate-stig", $objES)
            }
            "title" {
                If (($ScanObject | Measure-Object).Count -gt 1) {
                    $objCKLB.Add($_, "Evaluate-STIG_COMBINED")
                }
                Else {
                    $objCKLB.Add($_, "Evaluate-STIG_$($ScanObject.ESData.STIGShortName)")
                }
            }
            "id" {
                $objCKLB.Add($_, $([guid]::NewGuid()))
            }
            "stigs" {
                $arrSTIGs = New-Object System.Collections.ArrayList
                ForEach ($Scan in $ScanObject) {
                    # Read the STIG content
                    $STIGXMLPath = $(Join-Path -Path $ESPath -ChildPath StigContent | Join-Path -ChildPath $Scan.ESData.STIGXMLName)
                    # https://stackoverflow.com/questions/71847945/strange-characters-found-in-xml-file-and-powershell-output-after-exporting-from
                    ($Content = [xml]::new()).Load($STIGXMLPath)

                    # Set STIG Classification
                    Switch -Regex ($Content.'xml-stylesheet') {
                        'STIG_unclass.xsl' {
                            $Classification = "UNCLASSIFIED"
                        }
                        'STIG_cui.xsl' {
                            $Classification = "CUI"
                        }
                        DEFAULT {
                            Throw "Unable to determine STIG classification."
                        }
                    }

                    $objSTIG = [ordered]@{}
                    $STIGUUID = [guid]::NewGuid()
                    $StigProps = ($Schema.properties.$P1.items.properties.psobject.members | Where-Object MemberType -EQ "NoteProperty").Name
                    ForEach ($P2 in $StigProps) {
                        Switch ($P2) {
                            "evaluate-stig" {
                                $objES = [ordered]@{}
                                $ESProps = ($Schema.properties.$P1.items.properties.$P2.properties.psobject.members | Where-Object MemberType -EQ "NoteProperty").Name
                                ForEach ($P3 in $ESProps) {
                                    Switch ($P3) {
                                        "time" {
                                            $objES.Add($_, $($Scan.ESData.StartTime))
                                        }
                                        "module" {
                                            $objModule = [ordered]@{}
                                            $ModuleProps = ($Schema.properties.$P1.items.properties.$P2.properties.$P3.properties.psobject.members | Where-Object MemberType -EQ "NoteProperty").Name
                                            ForEach ($P4 in $ModuleProps) {
                                                Switch ($P4) {
                                                    "name" {
                                                        $objModule.Add($_, $($Scan.ESData.ModuleName))
                                                    }
                                                    "version" {
                                                        $objModule.Add($_, $([String]$Scan.ESData.ModuleVersion))
                                                    }
                                                    Default {
                                                        $Message = "Unexpected CKLB schema property: '$_'"
                                                        Throw $Message
                                                    }
                                                }
                                            }
                                            $objES.Add($_, $($objModule))
                                        }
                                        Default {
                                            $Message = "Unexpected CKLB schema property: '$_'"
                                            Throw $Message
                                        }
                                    }
                                }
                                $objSTIG.Add("evaluate-stig", $objES)
                            }
                            "stig_name" {
                                $objSTIG.Add($_, $Content.Benchmark.title)
                            }
                            "display_name" {
                                $objSTIG.Add($_, $(($Content.Benchmark.id).Replace("_", " "))) # Best guess on the source
                            }
                            "stig_id" {
                                $objSTIG.Add($_, $Content.Benchmark.id)
                            }
                            "release_info" {
                                $objSTIG.Add($_, $($Content.Benchmark.'plain-text' | Where-Object { $_.id -eq "release-info" }).'#text')
                            }
                            "uuid" {
                                $objSTIG.Add($_, $STIGUUID)
                            }
                            "reference_identifier" {
                                $objSTIG.Add($_, $($Content.Benchmark.Group)[0].Rule.reference.identifier)
                            }
                            "size" {
                                $objSTIG.Add($_, 12) # What does this property do and what is the source?
                            }
                            "rules" {
                                $arrRules = New-Object System.Collections.ArrayList
                                $RuleProps = ($Schema.properties.$P1.items.properties.$P2.items.properties.psobject.members | Where-Object MemberType -EQ "NoteProperty").Name
                                ForEach ($Vuln in $Content.Benchmark.Group) {
                                    $ScanResult = $Scan.VulnResults | Where-Object GroupID -EQ $Vuln.id
                                    $objRule = [ordered]@{}
                                    ForEach ($P3 in $RuleProps) {
                                        Switch ($P3) {
                                            "evaluate-stig" {
                                                If ($ScanResult.STIGMan.AFMod -eq $true) {
                                                    $objES = [ordered]@{}
                                                    $ESProps = ($Schema.properties.$P1.items.properties.$P2.items.properties.$P3.properties.psobject.members | Where-Object MemberType -EQ "NoteProperty").Name
                                                    ForEach ($P4 in $ESProps) {
                                                        Switch ($P4) {
                                                            "answer_file" {
                                                                $objES.Add($_, $($ScanResult.STIGMan.AnswerFile))
                                                            }
                                                            "afmod" {
                                                                $objES.Add($_, $ScanResult.STIGMan.AFMod)
                                                            }
                                                            "old_status" {
                                                                $objES.Add($_, $($ScanResult.STIGMan.OldStatus))
                                                            }
                                                            "new_status" {
                                                                $objES.Add($_, $($ScanResult.STIGMan.NewStatus))
                                                            }
                                                            Default {
                                                                $Message = "Unexpected CKLB schema property: '$_'"
                                                                Throw $Message
                                                            }
                                                        }
                                                    }
                                                    $objRule.Add("evaluate-stig", $objES)
                                                }
                                            }
                                            "group_id_src" {
                                                $objRule.Add($_, $($Vuln.id))
                                            }
                                            "group_tree" {
                                                $objGroupTree = [ordered]@{}
                                                $arrGroupTree = New-Object System.Collections.ArrayList
                                                $GroupTreeProps = ($Schema.properties.$P1.items.properties.$P2.items.properties.$P3.items.properties.psobject.members | Where-Object MemberType -EQ "NoteProperty").Name
                                                ForEach ($P4 in $GroupTreeProps) {
                                                    Switch ($P4) {
                                                        "id" {
                                                            $objGroupTree.Add($_, $($Vuln.id))
                                                        }
                                                        "title" {
                                                            $objGroupTree.Add($_, $($Vuln.title))
                                                        }
                                                        "description" {
                                                            $objGroupTree.add($_, $($Vuln.description))
                                                        }
                                                        Default {
                                                            $Message = "Unexpected CKLB schema property: '$_'"
                                                            Throw $Message
                                                        }
                                                    }
                                                }
                                                $null = $arrGroupTree.Add($objGroupTree)
                                                $objRule.Add("group_tree", $arrGroupTree)
                                            }
                                            "group_id" {
                                                $objRule.Add($_, $($Vuln.id))
                                            }
                                            "severity" {
                                                $objRule.Add($_, $($Vuln.rule.severity))
                                            }
                                            "group_title" {
                                                $objRule.Add($_, $($Vuln.rule.title))
                                            }
                                            "rule_id_src" {
                                                $objRule.Add($_, $($Vuln.rule.id))
                                            }
                                            "rule_id" {
                                                $objRule.Add($_, $($Vuln.rule.id -replace "_rule", ""))
                                            }
                                            "rule_version" {
                                                $objRule.Add($_, $($Vuln.rule.version))
                                            }
                                            "rule_title" {
                                                $objRule.Add($_, $($Vuln.rule.title))
                                            }
                                            "fix_text" {
                                                $objRule.Add($_, $($Vuln.rule.fixtext.'#text'))
                                            }
                                            "weight" {
                                                $objRule.Add($_, $($Vuln.rule.weight))
                                            }
                                            "check_content" {
                                                $objRule.Add($_, $($Vuln.Rule.check.'check-content'))
                                            }
                                            "check_content_ref" {
                                                $objCCRef = [ordered]@{}
                                                $CCRefProps = ($Schema.properties.$P1.items.properties.$P2.items.properties.$P3.properties.psobject.members | Where-Object MemberType -EQ "NoteProperty").Name
                                                ForEach ($P4 in $CCRefProps) {
                                                    Switch ($P4) {
                                                        "href" {
                                                            $objCCRef.Add($_, $($Vuln.rule.check.'check-content-ref'.href))
                                                        }
                                                        "name" {
                                                            $objCCRef.Add($_, $($Vuln.rule.check.'check-content-ref'.name))
                                                        }
                                                        Default {
                                                            $Message = "Unexpected CKLB schema property: '$_'"
                                                            Throw $Message
                                                        }
                                                    }
                                                }
                                                $objRule.Add($_, $objCCRef)
                                            }
                                            "classification" {
                                                $objRule.Add($_, $Classification)
                                            }
                                            "discussion" {
                                                $Tag = "VulnDiscussion"
                                                $objRule.Add($_, [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag))
                                            }
                                            "false_positives" {
                                                $Tag = "FalsePositives"
                                                $objRule.Add($_, [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag))
                                            }
                                            "false_negatives" {
                                                $Tag = "FalseNegatives"
                                                $objRule.Add($_, [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag))
                                            }
                                            "documentable" {
                                                $Tag = "Documentable"
                                                $objRule.Add($_, [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag))
                                            }
                                            "security_override_guidance" {
                                                $Tag = "SeverityOverrideGuidance"
                                                $objRule.Add($_, [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag))
                                            }
                                            "potential_impacts" {
                                                $Tag = "PotentialImpacts"
                                                $objRule.Add($_, [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag))
                                            }
                                            "third_party_tools" {
                                                $Tag = "ThirdPartyTools"
                                                $objRule.Add($_, [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag))
                                            }
                                            "ia_controls" {
                                                $Tag = "IAControls"
                                                $objRule.Add($_, [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag))
                                            }
                                            "responsibility" {
                                                $Tag = "Responsibility"
                                                $objRule.Add($_, [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag))
                                            }
                                            "mitigations" {
                                                $Tag = "Mitigations"
                                                $objRule.Add($_, [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag))
                                            }
                                            "mitigation_control" {
                                                $Tag = "MitigationControl"
                                                $objRule.Add($_, [String](Get-InnerXml -InnerXml $Vuln.rule.description -Tag $Tag))
                                            }
                                            "legacy_ids" {
                                                $arrLegacy = New-Object System.Collections.ArrayList
                                                If ($Vuln.Rule.ident | Where-Object {$_.system -eq "http://cyber.mil/legacy"}) {
                                                    Foreach ($legacy in ($Vuln.Rule.ident | Where-Object {$_.system -eq "http://cyber.mil/legacy"} | Sort-Object '#text')) {
                                                        $null = $arrLegacy.Add($($legacy.'#text'))
                                                    }
                                                }
                                                Else {
                                                    $null = $arrLegacy.Add("")
                                                }
                                                $objRule.Add($_, $arrLegacy)
                                            }
                                            "ccis" {
                                                $arrCCIs = New-Object System.Collections.ArrayList
                                                Foreach ($CCI in ($Vuln.Rule.ident | Where-Object {$_.system -like "http://*.mil/cci"} | Sort-Object '#text')) {
                                                    $null = $arrCCIs.Add($($CCI.'#text'))
                                                }
                                                $objRule.Add($_, $arrCCIs)
                                            }
                                            "reference_identifier" {
                                                $objRule.Add($_, $($Vuln.Rule.reference.identifier))
                                            }
                                            "uuid" {
                                                $objRule.Add($_, $([guid]::NewGuid()))
                                            }
                                            "stig_uuid" {
                                                $objRule.Add($_, $STIGUUID)
                                            }
                                            "status" {
                                                $ValidValues = @("NR", "NF", "NA", "O", "Not_Reviewed", "NotAFinding", "Not_Applicable", "Open", "not_a_finding", "notchecked", "pass", "notapplicable", "fail")
                                                If (-Not($ScanResult.Status)) {
                                                    $Status = "not_reviewed"
                                                }
                                                ElseIf ($ScanResult.Status -and $ScanResult.Status -notin $ValidValues) {
                                                    Throw "Invalid value for property [$($_)]: '$($ScanResult.Status)'"
                                                }
                                                Else {
                                                    $Status = $(Convert-Status -InputObject $ScanResult.Status -Output CKLB)
                                                }
                                                $objRule.Add($_, $Status.ToLower())
                                            }
                                            "overrides" {
                                                $objOverrides = @{}
                                                If ($ScanResult.SeverityOverride) {
                                                    $ValidValues = @("low", "medium", "high")
                                                    $dataObject = [ordered]@{}
                                                    If ($ScanResult.SeverityOverride -notin $ValidValues) {
                                                        Throw "Invalid value for property [$($_)]: '$($ScanResult.SeverityOverride)'"
                                                    }
                                                    Else {
                                                        $dataObject.Add("severity", $($ScanResult.SeverityOverride).ToLower())
                                                    }
                                                    If ($ScanResult.Justification) {
                                                        $dataObject.Add("reason", $($ScanResult.Justification))
                                                    }
                                                    Else {
                                                        $dataObject.Add("reason", "No reason provided")
                                                    }
                                                    $objOverrides.Add("severity", $dataObject)
                                                }
                                                $objRule.Add($_, $objOverrides)
                                            }
                                            "comments" {
                                                If ($ScanResult.Comments) {
                                                    $objRule.Add($_, $($ScanResult.Comments))
                                                }
                                                Else {
                                                    $objRule.Add($_, "")
                                                }
                                            }
                                            "finding_details" {
                                                If ($ScanResult.FindingDetails) {
                                                    $objRule.Add($_, $($ScanResult.FindingDetails))
                                                }
                                                Else {
                                                    $objRule.Add($_, "")
                                                }
                                            }
                                            Default {
                                                $Message = "Unexpected CKLB schema property: '$_'"
                                                Throw $Message
                                            }
                                        }
                                    }
                                    $null = $arrRules.Add($objRule)
                                }
                                $objSTIG.Add("rules", $arrRules)
                            }
                        }
                    }
                    $null = $arrSTIGs.Add($objSTIG)
                }
                $objCKLB.Add("stigs", $arrSTIGs)
            }
            "active" {
                $objCKLB.Add($_, $false)
            }
            "mode" {
                $objCKLB.Add($_, 1)
            }
            "has_path" {
                $objCKLB.Add($_, $true)
            }
            "target_data" {
                $objTargetData = [ordered]@{}
                $TargetDataProps = ($Schema.properties.$P1.properties.psobject.members | Where-Object MemberType -EQ "NoteProperty").Name
                ForEach ($P2 in $TargetDataProps) {
                    Switch ($P2) {
                        "target_type" {
                            $objTargetData.Add($_, "Computing")
                        }
                        "host_name" {
                            $objTargetData.Add($_, $($TargetData.Hostname))
                        }
                        "ip_address" {
                            $objTargetData.Add($_, $($TargetData.IpAddress))
                        }
                        "mac_address" {
                            $objTargetData.Add($_, $($TargetData.MacAddress))
                        }
                        "fqdn" {
                            $objTargetData.Add($_, $($TargetData.FQDN))
                        }
                        "comments" {
                            $objTargetData.Add($_, "")
                        }
                        "role" {
                            $ValidValues = @("None", "Workstation", "Member Server", "Domain Controller")
                            If ($TargetData.Role -and $TargetData.Role -notin $ValidValues) {
                                Throw "Invalid value for property [$($_)]: '$($TargetData.Role)'"
                            }
                            Else {
                                $objTargetData.Add($_, $($TargetData.Role))
                            }
                        }
                        "is_web_database" {
                            If ($TargetData.WebOrDatabase.GetType().Name -ne "Boolean") {
                                Throw "Invalid value type for property [$($_)]: '$($TargetData.WebOrDatabase.GetType().Name)'"
                            }
                            Else {
                                $objTargetData.Add($_, $($TargetData.WebOrDatabase))
                            }
                        }
                        "technology_area" {
                            $objTargetData.Add($_, "None")
                        }
                        "web_db_site" {
                            $objTargetData.Add($_, $($TargetData.Site))
                        }
                        "web_db_instance" {
                            $objTargetData.Add($_, $($TargetData.Instance))
                        }
                        Default {
                            $Message = "Unexpected CKLB schema property: '$_'"
                            Throw $Message
                        }
                    }
                }
                $objCKLB.Add($_, $objTargetData)
            }
            "cklb_version" {
                $objCKLB.Add($_, "1.0")
            }
            Default {
                $Message = "Unexpected CKLB schema property: '$_'"
                Throw $Message
            }
        }
    }

    # Convert to JSON and preserve some characters - https://stackoverflow.com/a/53644601/45375
    $CKLB = [regex]::replace($($objCKLB | ConvertTo-Json -Depth 10 -Compress), '\\u[0-9a-fA-F]{4}', {param($match) [char] [int] ('0x' + $match.Value.Substring(2))})

    # CKLB file must be 'UTF-8' and no BOM
    [System.IO.File]::WriteAllLines($OutputPath, $CKLB)

    Write-Log -Path $STIGLog -Message "Validating CKLB File" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
    $ChecklistValid = $true
    If ([Version]$PSVersionTable.PSVersion -lt [Version]"7.0") {
        Write-Log -Path $STIGLog -Message "PowerShell $($PSVersionTable.PSVersion -join ".") not supported for Json validation" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
    }
    Else {
        $ChecklistValid = Test-JsonValidation -JsonFile $OutputPath -SchemaFile $SchemaPath

        # Action for validation result
        If ($ChecklistValid) {
            Write-Log -Path $STIGLog -Message "'$(Split-Path $OutputPath -Leaf)' : Passed." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        }
        Else {
            $BadFileDestination = Join-Path -Path $WorkingDir -ChildPath "Bad_CKL"
            Write-Log -Path $STIGLog -Message "ERROR: '$(Split-Path $OutputPath -Leaf)' : failed schema validation. Moving to $BadFileDestination." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
            ForEach ($Item in $ChecklistValid.Message) {
                Write-Log -Path $STIGLog -Message $Item -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
            }
            If (-Not(Test-Path $BadFileDestination)) {
                New-Item -Path $BadFileDestination -ItemType Directory | Out-Null
            }
            Copy-Item -Path $OutputPath -Destination $BadFileDestination -Force
            Remove-Item $OutputPath -Force
        }
    }

    Return $ChecklistValid
}

Function Get-InnerXml {
    # Function to extract data from InnerXml objects (e.g. Benchmark.Group.Rule.Description from STIG XCCDF).
    param
    (
        [Parameter(Mandatory)]
        [string]$InnerXml,

        [Parameter(Mandatory)]
        [psobject]$Tag
    )

    $Value = ""
    #$MatchString = "<$Tag>.{0,}\n{0,}\r{0,}.{0,}</$Tag>"
    $MatchString = "(?sm)<$Tag>.{0,}</$Tag>"
    If ($InnerXml -match $MatchString) {
        $Value = $Matches[0] -replace "</{0,}$Tag>", ""
    }

    Return $Value
}

Function Invoke-CombinedCKL {
    Param (
        [Parameter(Mandatory = $true)]
        [PSObject]$STIGsToProcess,

        [Parameter(Mandatory = $true)]
        [String]$CklDestinationPath,

        [Parameter(Mandatory = $true)]
        [String]$CKLResultsPath,

        [Parameter(Mandatory = $true)]
        [String]$CombinedFile,

        [Parameter(Mandatory = $false)]
        [String]$Marking
    )

    Try {
        $CklOutFile = Join-Path -Path $CklDestinationPath -ChildPath $CombinedFile

        # Build list of STIGs that cannot combine
        $ShortNamesToExclude = @()
        ForEach ($Item in ($STIGsToProcess | Where-Object CanCombine -NE $true)) {
            $ShortNamesToExclude += $Item.ShortName
        }

        # Build list of CKLs to preserve
        $ChecklistsToCombine = @()
        ForEach ($Item in (Get-ChildItem -Path $CKLResultsPath -Filter "*.ckl" | Where-Object Name -NotLike "*_COMBINED_*.ckl")) {
            $Exclude = $false
            ForEach ($ShortName in $ShortNamesToExclude) {
                If ($Item.Name -match $ShortName) {
                    $EXclude = $true
                }
            }
            If ($Exclude -ne $true) {
                $ChecklistsToCombine += $Item
            }
        }

        # Get CKL framework from first discovered CKL
        $NewCKL = (Select-Xml -Path $ChecklistsToCombine[0].FullName -XPath /).Node

        # Remove Comments
        $NewCKL.SelectNodes("//comment()") | ForEach-Object {$null = $_.ParentNode.RemoveChild($_)}

        If ($Marking) {
            # Add marking header
            $MarkingHeader = $NewCKL.CreateComment("                                                                                          $Marking                                                                                          ")
            $null = $NewCKL.InsertBefore($MarkingHeader, $NewCKL.CHECKLIST)
        }

        # Add Evaluate-STIG comment
        $ESVersionXML = $NewCKL.CreateComment("<Evaluate-STIG><global><version>$ESVersion</version><time>$(Get-Date -Format 'o')</time></global><module><name></name><version></version></module><stiglist><name>COMBINED_CKL</name><shortname>COMBINED_CKL</shortname><template>COMBINED_CKL</template></stiglist></Evaluate-STIG>")
        $null = $NewCKL.InsertBefore($ESVersionXML, $NewCKL.CHECKLIST)

        # Initialize WEB_OR_DATABASE, WEB_DB_SITE, and WEB_DB_INSTANCE elements
        $NewCKL.CHECKLIST.ASSET.WEB_OR_DATABASE = "false"
        $NewCKL.CHECKLIST.ASSET.WEB_DB_SITE = ""
        $NewCKL.CHECKLIST.ASSET.WEB_DB_INSTANCE = ""
        $NewCKL.CHECKLIST.ASSET.MARKING = [string]$Marking

        # Remove iSTIG node.  Will replace later
        $NodesToDelete = $NewCKL.SelectNodes("//iSTIG")
        ForEach ($Node in $NodesToDelete) {
            $Node.ParentNode.RemoveChild($Node) | Out-Null
        }

        If (($ChecklistsToCombine | Measure-Object).Count -gt 1) {
            ForEach ($Checklist in $ChecklistsToCombine) {
                $CKL = (Select-Xml -Path $Checklist.Fullname -XPath /).Node

                # Add iSTIG node to combined CKL
                $iSTIG = $NewCKL.ImportNode($CKL.SelectSingleNode("//iSTIG"), $true)
                $NewCKL.CHECKLIST.STIGS.AppendChild($iSTIG) | Out-Null
            }

            If ($Marking) {
                # Add marking footer
                $MarkingFooter = $NewCKL.CreateComment("                                                                                          $Marking                                                                                          ")
                $null = $NewCKL.InsertAfter($MarkingFooter, $NewCKL.CHECKLIST)
            }

            # Save the combined CKL
            $NewCKL.Save($CklOutFile)
        }
        Else {
            Throw "Only one (1) checklist found.  Nothing to combine."
        }
    }
    Catch {
        Throw $_.Exception.Message
    }
}

function Repair-XmlString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$string
    )

    # $pattern = "(?<=\&).+?(?=\;)"
    $pattern = "(?<=\&)\d+?(?=\;)" # proposed solution from ticket 1401
    $hex = "$([regex]::matches($string, $pattern).value)"
    if ($hex){
        $hex -split " " | Foreach-Object {
            $string = $string -replace "&$_;", [char[]]$([BYTE][CHAR]([CONVERT]::toint16($($_ -replace "#","0"),16)))
        }
    }

    Return ($string -Replace "`0", "[null]")
}

Function Send-CheckResult {
    # Returns custom check data to Write-Ckl for inclusion into the checklist file
    Param (
        # Scan Module Name
        [Parameter(Mandatory = $true)]
        [String]$Module,

        # Status of check
        [Parameter(Mandatory = $true)]
        [String]$Status,

        # Finding Details of check
        [Parameter(Mandatory = $false)]
        [String]$FindingDetails,

        # Answer File Source Key
        [Parameter(Mandatory = $false)]
        [String]$AFKey,

        # Answer File FinalStatus
        [Parameter(Mandatory = $false)]
        [String]$AFStatus,

        # Approved Comments of check
        [Parameter(Mandatory = $false)]
        [String]$Comments,

        # SeverityOverride Change
        [Parameter(Mandatory = $false)]
        [String]$SeverityOverride,

        # SeverityOverride Justification
        [Parameter(Mandatory = $false)]
        [String]$Justification
    )

    [hashtable]$CheckResults = @{ }
    $CheckResults.Status = "Not_Reviewed" #acceptable values are "Not_Reviewed", "Open", "NotAFinding", "Not_Applicable"
    $CheckResults.FindingDetails = ""
    $CheckResults.AFKey = ""
    $CheckResults.AFStatus = ""
    $CheckResults.Comments = ""

    $FindingDetailsText = ""

    Switch ($Status) {
        "Open" {
            $CheckResults.Status = "Open"
            $FindingDetailsText += "Evaluate-STIG $($ESVersion) ($($Module)) found this to be OPEN on $(Get-Date -Format MM/dd/yyyy):" | Out-String
            $FindingDetailsText += "---------------------------------------------------------------" | Out-String
        }
        "NotAFinding" {
            $CheckResults.Status = "NotAFinding"
            $FindingDetailsText += "Evaluate-STIG $($ESVersion) ($($Module)) found this to be NOT A FINDING on $(Get-Date -Format MM/dd/yyyy):" | Out-String
            $FindingDetailsText += "------------------------------------------------------------------------" | Out-String
        }
        "Not_Applicable" {
            $CheckResults.Status = "Not_Applicable"
            $FindingDetailsText += "Evaluate-STIG $($ESVersion) ($($Module)) found this to be NOT APPLICABLE on $(Get-Date -Format MM/dd/yyyy):" | Out-String
            $FindingDetailsText += "-------------------------------------------------------------" | Out-String
        }
        DEFAULT {
            $CheckResults.Status = "Not_Reviewed"
            If ($FindingDetails.Trim().Length -gt 0) {
                $FindingDetailsText += "Evaluate-STIG $($ESVersion) ($($Module)) was unable to determine a Status but found the below configuration on $(Get-Date -Format MM/dd/yyyy):" | Out-String
                $FindingDetailsText += "-------------------------------------------------------------" | Out-String
            }
        }
    }

    If ($FindingDetails) {
        $FindingDetailsText += Repair-XmlString -String $FindingDetails
    }
    $CheckResults.FindingDetails = $FindingDetailsText

    If ($AFKey) {
        $CheckResults.AFKey = Repair-XmlString -String $AFKey
    }

    If ($AFStatus) {
        $CheckResults.AFStatus = Repair-XmlString -String $AFStatus
    }

    If ($Comments) {
        $CheckResults.Comments = Repair-XmlString -String $Comments
    }

    Switch ($SeverityOverride) {
        "CAT_I" {
            $CheckResults.SeverityOverride = "high"
        }
        "CAT_II" {
            $CheckResults.SeverityOverride = "medium"
        }
        "CAT_III" {
            $CheckResults.SeverityOverride = "low"
        }
    }

    If ($Justification) {
        $CheckResults.Justification = Repair-XmlString -String $Justification
    }

    Return $CheckResults
}

Function Write-Log {
    <#
    .Synopsis
        Write to a CMTrace friendly .log file.
    .DESCRIPTION
        Takes the input and generates an entry for a CMTrace friendly .log file
        by utilizing a PSCustomObject and Generic List to hold the data.
        A string is created and added to the .log file.
    .EXAMPLE
       PS C:\> Write-Log -Path 'C:\Temp\sample.log' -Message 'Test Message' -Component 'Write-Log' -MessageType Verbose -OSPlatform Windows
    .INPUTS
        -Path
            Use of this parameter is required. Forced to be a String type. The path to where the .log file is located.
        -Message
            Use of this parameter is required. Forced to be a String type. The message to pass to the .log file.
        -Component
            Use of this parameter is required. Forced to be a String type. What is providing the Message.
            Typically this is the script or function name.
        -Type
            Use of this parameter is required. Forced to be a String type. What type of output to be. Choices are
            Info, Warning, Error and Verbose.
        -OSPlatform
            Use of this parameter is required. Forced to be a String type. What OS platform the system is. Choices are Windows or Linux.
        -TemplateMessage <"LineBreak-Dash" | "LineBreak-Text">
            Write a standardized line/section break to the log.
        -WriteOutToStream
            Write message to both log and console.
    .OUTPUTS
        No output. Writes an entry to a .log file via Add-Content.
    .NOTES
        Resources/Credits:
            Dan Ireland - daniel.ireland@navy.mil
            Brent Betts - brent.betts@navy.mil
        Helpful URLs:
            Russ Slaten's Blog Post - Logging in CMTrace format from PowerShell
            https://blogs.msdn.microsoft.com/rslaten/2014/07/28/logging-in-cmtrace-format-from-powershell/
    #>

    Param (
        [Parameter(Mandatory = $true)]
        [String]$Path,

        [Parameter(Mandatory = $true)]
        [String]$Message,

        [Parameter(Mandatory = $true)]
        [String]$Component,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Info", "Warning", "Error", "Verbose")]
        [String]$Type,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Windows", "Linux")]
        [String]$OSPlatform,

        [Parameter(Mandatory = $false)]
        [ValidateSet('LineBreak-Dash', 'LineBreak-Text')]
        [String]$TemplateMessage,

        [Parameter(Mandatory = $false)]
        [Switch]$WriteOutToStream,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Black', 'DarkBlue', 'DarkGreen', 'DarkCyan', 'DarkRed', 'DarkMagenta', 'DarkYellow', 'Gray', 'DarkGray', 'Blue', 'Green', 'Cyan', 'Red', 'Magenta', 'Yellow', 'White')]
        [String]$FGColor
    )

    Switch ($Type) {
        'Info' {
            [Int]$Type = 1
            If (-Not($FGColor)) {
                $FGColor = "White"
            }
        }
        'Warning' {
            [Int]$Type = 2
            If (-Not($FGColor)) {
                $FGColor = "Yellow"
            }
        }
        'Error' {
            [Int]$Type = 3
            If (-Not($FGColor)) {
                $FGColor = "Red"
            }
        }
        'Verbose' {
            [Int]$Type = 4
            If (-Not($FGColor)) {
                $FGColor = "DarkGray"
            }
        }
    }

    # Obtain date/time
    Switch ($OSPlatform) {
        "Windows" {
            $DateTime = New-Object -ComObject WbemScripting.SWbemDateTime
            $DateTime.SetVarDate($(Get-Date))
            $UtcValue = $DateTime.Value
            $UtcOffset = [Math]::Abs($UtcValue.Substring(21, $UtcValue.Length - 21))
            $user_name = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        }
        "Linux" {
            $UtcOffset = (date +%z_).Trim("-")
            $user_name = whoami
        }
    }

    Switch ($TemplateMessage) {
        'LineBreak-Dash' {
            $Message = '----------------------------------'
        }
        'LineBreak-Text' {
            $Message = '==========[{0}]==========' -f $Message
        }
    }

    # Create Object to hold items to log
    $LogItems = [System.Collections.Generic.List[System.Object]]::new()
    $NewObj = [PSCustomObject]@{
        Message   = $Message
        Time      = [Char]34 + (Get-Date -Format "HH:mm:ss.fff") + "+$UtcOffset" + [Char]34
        Date      = [Char]34 + (Get-Date -Format "MM-dd-yyyy") + [Char]34
        Component = [Char]34 + $Component + [Char]34
        Context   = [Char]34 + $user_name + [Char]34
        Type      = [Char]34 + $Type + [Char]34
        Thread    = [Char]34 + [Threading.Thread]::CurrentThread.ManagedThreadId + [Char]34
        File      = [Char]34 + [Char]34
    }
    $LogItems.Add($NewObj)

    # Format Log Entry
    $Entry = "<![LOG[$($LogItems.Message)]LOG]!><time=$($LogItems.Time) date=$($LogItems.Date) component=$($LogItems.Component) context=$($LogItems.Context) type=$($LogItems.Type) thread=$($logItems.Thread) file=$($LogItems.File)>"

    # Write to the Console
    If ($WriteOutToStream) {
        Write-Host $Message -ForegroundColor $FGColor
    }

    # Add to Log
    Add-Content -Path $Path -Value $Entry -ErrorAction SilentlyContinue | Out-Null
}

Function Invoke-TaskAsSYSTEM {
    # Creates a self-deleting scheduled task that will run as the SYSTEM account and executes it.
    Param (
        [Parameter(Mandatory = $true)]
        [String]$TaskName,

        [Parameter(Mandatory = $true)]
        [String]$FilePath,

        [Parameter(Mandatory = $false)]
        [String]$ArgumentList,

        [Parameter(Mandatory = $false)]
        [Int]$MaxRunInMinutes
    )

    If (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue) {
        $TaskTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date)
        $TaskAction = New-ScheduledTaskAction -Execute $FilePath -Argument $ArgumentList
        $TaskSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes $MaxRunInMinutes) -AllowStartIfOnBatteries
        $TaskObj = Register-ScheduledTask -TaskName $TaskName -Trigger $TaskTrigger -Action $TaskAction -Settings $TaskSettings -User "SYSTEM" -Force

        $RegisteredTask = Get-ScheduledTask -TaskName $TaskName
        $RegisteredTask.Triggers[0].EndBoundary = ((Get-Date).AddMinutes($MaxRunInMinutes)).ToString('s')
        $RegisteredTask.Settings.DeleteExpiredTaskAfter = 'PT0S'
        $RegisteredTask | Set-ScheduledTask

        Start-ScheduledTask -InputObject $TaskObj
        While ((Get-ScheduledTask -TaskName $TaskName).State -eq "Running") {
            Start-Sleep -Seconds 1
        }
        $TaskResult = Get-ScheduledTaskInfo -InputObject $TaskObj
        Unregister-ScheduledTask -InputObject $TaskObj -Confirm:$false
    }
    Else {
        $OutXml = "$env:temp\Eval-STIG_Task.xml"
        $StartTime = (Get-Date).AddMinutes($MaxRunInMinutes)
        $EndTime = (Get-Date $StartTime).AddMinutes($MaxRunInMinutes)

        # Create XML stream
        $xmlWriter = New-Object System.Xml.XmlTextWriter($OutXml, $null)
        $xmlWriter.Formatting = "Indented"
        $xmlWriter.Indentation = 2
        $XmlWriter.IndentChar = " "
        $xmlWriter.WriteStartDocument()

        # Start 'Task' Element
        $xmlWriter.WriteStartElement("Task")
        $XmlWriter.WriteAttributeString("version", "1.3")
        $XmlWriter.WriteAttributeString("xmlns", "http://schemas.microsoft.com/windows/2004/02/mit/task")
        # Start 'Triggers' Element
        $xmlWriter.WriteStartElement("Triggers")
        # Start 'TimeTrigger' Element
        $xmlWriter.WriteStartElement("TimeTrigger")
        # Create Child Elements
        $xmlWriter.WriteElementString("StartBoundary", $(Get-Date $StartTime -Format yyyy-MM-ddTHH:mm:ssK))
        $xmlWriter.WriteElementString("EndBoundary", $(Get-Date $EndTime -Format yyyy-MM-ddTHH:mm:ss))
        $xmlWriter.WriteElementString("Enabled", "true")
        # End 'TimeTrigger' Element
        $xmlWriter.WriteEndElement()
        # End 'Triggers' Element
        $xmlWriter.WriteEndElement()
        # Start 'Settings' Element
        $xmlWriter.WriteStartElement("Settings")
        # Create Child Elements
        $xmlWriter.WriteElementString("MultipleInstancesPolicy", "IgnoreNew")
        $xmlWriter.WriteElementString("DisallowStartIfOnBatteries", "false")
        $xmlWriter.WriteElementString("StopIfGoingOnBatteries", "false")
        $xmlWriter.WriteElementString("AllowHardTerminate", "true")
        $xmlWriter.WriteElementString("AllowStartOnDemand", "true")
        $xmlWriter.WriteElementString("Enabled", "true")
        $xmlWriter.WriteElementString("UseUnifiedSchedulingEngine", "true")
        $xmlWriter.WriteElementString("ExecutionTimeLimit", "PT$($MaxRunInMinutes)M")
        $xmlWriter.WriteElementString("DeleteExpiredTaskAfter", "PT0S")
        # End 'Settings' Element
        $xmlWriter.WriteEndElement()
        # Start 'Actions' Element
        $xmlWriter.WriteStartElement("Actions")
        # Start 'Exec' Element
        $xmlWriter.WriteStartElement("Exec")
        # Create Child Elements
        $xmlWriter.WriteElementString("Command", $FilePath)
        $xmlWriter.WriteElementString("Arguments", $ArgumentList)
        # End 'Exec' Element
        $xmlWriter.WriteEndElement()
        # End 'Actions' Element
        $xmlWriter.WriteEndElement()
        # End 'Task' Element
        $xmlWriter.WriteEndElement()

        # Save file and close the stream
        $xmlWriter.WriteEndDocument()
        $xmlWriter.Flush()
        $xmlWriter.Close()

        $null = SCHTASKS /Create /TN $TaskName /RU SYSTEM /XML $OutXml /F
        $null = SCHTASKS /Run /TN $TaskName /I
        While (((SCHTASKS /Query /TN $TaskName /V /FO List) -match "Status:").Split(":")[1].Trim() -eq "Running") {
            Start-Sleep -Seconds 1
        }
        $TaskResult = @{
            LastTaskResult = ((SCHTASKS /Query /TN $TaskName /V /FO List 2>&1) -match "Last Result:").Split(":")[1].Trim()
        }
        $null = SCHTASKS /Delete /TN $TaskName /F
        Remove-Item $OutXml -Force
    }
    Return $TaskResult
}

Function Get-RegistryResult {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$Path,

        [Parameter(Mandatory = $false)]
        [String]$ValueName
    )

    $Value = $null
    $Type = $null
    If ($ValueName -eq "(default)") {
        $ValueNameToCheck = ""
    }
    ElseIf (-Not($ValueName)) {
        $ValueName = "(default)"
        $ValueNameToCheck = ""
    }
    Else {
        $ValueNameToCheck = $ValueName
    }

    $Output = New-Object System.Collections.Generic.List[System.Object]
    If (Test-Path $Path) {
        If (Get-ItemProperty -Path $Path -Name $ValueNameToCheck -ErrorAction SilentlyContinue) {
            $RegistryKey = Get-Item -Path $Path -ErrorAction SilentlyContinue
            If (-Not($null -eq $RegistryKey.GetValue($ValueNameToCheck))) {
                $Value = Get-ItemPropertyValue -Path $Path -Name $ValueNameToCheck
                $ValueType = $RegistryKey.GetValueKind($ValueNameToCheck)
                Switch ($ValueType) {
                    "Binary" {
                        $Type = "REG_BINARY"
                    }
                    "Dword" {
                        $Type = "REG_DWORD"
                    }
                    "ExpandString" {
                        $Type = "REG_EXPAND_SZ"
                        $Value = $Value.Trim()
                    }
                    "MultiString" {
                        $Type = "REG_MULTI_SZ"
                        If (-Not([String]::IsNullOrEmpty($Value))) {
                            $Value = $Value.Trim()
                        }
                    }
                    "Qword" {
                        $Type = "REG_QWORD"
                    }
                    "String" {
                        $Type = "REG_SZ"
                        $Value = $Value.Trim()
                    }
                }
            }
        }

        If (-Not($Value) -and $ValueName -eq "(default)") {
            $Value = "(value not set)"
            $Type = "REG_SZ"
        }
        ElseIf (-Not($Type)) {
            $ValueName = "(NotFound)"
            $Value = "(NotFound)"
            $Type = "(NotFound)"
        }
        ElseIf (($Type -in @("REG_EXPAND_SZ", "REG_MULTI_SZ", "REG_SZ")) -and ([String]::IsNullOrEmpty($Value))) {
            $Value = "(blank)"
        }

    }
    Else {
        $Path = "(NotFound)"
        $ValueName = "(NotFound)"
        $Value = "(NotFound)"
        $Type = "(NotFound)"
    }

    $NewObj = [PSCustomObject]@{
        Key       = ($Path)
        ValueName = ($ValueName)
        Value     = ($Value)
        Type      = ($Type)
    }
    $Output.Add($NewObj)

    Return $Output
}

Function Get-InstalledSoftware {
    If ($null -ne $Global:InstalledSoftware) {
        Return $Global:InstalledSoftware
    }
    Else {
        $SoftwareList = New-Object System.Collections.Generic.List[System.Object]
        $OSArch = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
        Switch ($OSArch) {
            "64-Bit" {
                $RegPath = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
            }
            Default {
                $RegPath = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
            }
        }
        ForEach ($Path in $RegPath) {
            $RegKeys += (Get-ChildItem -Path $Path -ErrorAction SilentlyContinue).Name.Replace("HKEY_LOCAL_MACHINE", "HKLM:")
        }

        ForEach ($Key in $RegKeys) {
            Try {
                $Properties = Get-ItemProperty -Path $Key -ErrorAction SilentlyContinue # A corrupt registry value will cause this to fail.  If so then we do this a different, though slower way, below.

                If ($Properties.DisplayName) {
                    $DisplayName = ($Properties.DisplayName).Trim()
                }
                Else {
                    $DisplayName = ""
                }

                If ($Properties.DisplayVersion) {
                    $DisplayVersion = ($Properties.DisplayVersion -replace "[^a-zA-Z0-9.-_()]").Trim()
                }
                Else {
                    $DisplayVersion = ""
                }

                If ($Properties.Publisher) {
                    $Publisher = ($Properties.Publisher).Trim()
                }
                Else {
                    $Publisher = ""
                }

                If ($Properties.InstallLocation) {
                    $InstallLocation = ($Properties.InstallLocation).Trim()
                }
                Else {
                    $InstallLocation = ""
                }

                If ($Properties.SystemComponent) {
                    $SystemComponent = $Properties.SystemComponent
                }
                Else {
                    $SystemComponent = ""
                }

                If ($Properties.ParentKeyName) {
                    $ParentKeyName = $Properties.ParentKeyName
                }
                Else {
                    $ParentKeyName = ""
                }
            }
            Catch {
                # If above method fails, then do this
                Try {
                    $DisplayName = (Get-ItemPropertyValue $Key -Name DisplayName).Trim()
                }
                Catch {
                    $DisplayName = ""
                }

                Try {
                    $DisplayVersion = (Get-ItemPropertyValue $Key -Name DisplayVersion).Replace("[^a-zA-Z0-9.-_()]", "").Trim()
                }
                Catch {
                    $DisplayVersion = ""
                }

                Try {
                    $Publisher = (Get-ItemPropertyValue $Key -Name Publisher).Trim()
                }
                Catch {
                    $Publisher = ""
                }

                Try {
                    $InstallLocation = (Get-ItemPropertyValue $Key -Name InstallLocation).Trim()
                }
                Catch {
                    $InstallLocation = ""
                }

                Try {
                    $SystemComponent = (Get-ItemPropertyValue $Key -Name SystemComponent).Trim()
                }
                Catch {
                    $SystemComponent = ""
                }

                Try {
                    $ParentKeyName = (Get-ItemPropertyValue $Key -Name ParentKeyName).Trim()
                }
                Catch {
                    $ParentKeyName = ""
                }
            }

            If ($DisplayName -and $SystemComponent -ne 1 -and (-Not($ParentKeyName))) {
                $NewObj = [PSCustomObject]@{
                    DisplayName     = $DisplayName
                    DisplayVersion  = $DisplayVersion
                    Publisher       = $Publisher
                    InstallLocation = $InstallLocation
                }
                $SoftwareList.Add($NewObj)
            }
        }
        $Global:InstalledSoftware = $SoftwareList  | Select-Object * -Unique | Sort-Object DisplayName
        Return $Global:InstalledSoftware
    }
}

Function Get-InstalledO365Apps {
    $RegPaths = @("HKLM:\SOFTWARE\Microsoft\Office\16.0", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\16.0")
    $PossibleApps = @("Access", "Excel", "Groove", "Lync", "OneNote", "Outlook", "PowerPoint", "Project", "Publisher", "Visio", "Word")
    $InstalledApps = New-Object System.Collections.Generic.List[System.Object]

    ForEach ($App in $PossibleApps) {
        ForEach ($Path in $RegPaths) {
            If (Test-Path "$($Path)\$($App)\InstallRoot") {
                $InstallRoot = (Get-ItemProperty "$($Path)\$($App)\InstallRoot").Path
                Switch ($App) {
                    "Access" {
                        $Exe = "msaccess.exe"
                    }
                    "Excel" {
                        $Exe = "excel.exe"
                    }
                    "Lync" {
                        $Exe = "lync.exe"
                    }
                    "OneNote" {
                        $Exe = "onenote.exe"
                    }
                    "Outlook" {
                        $Exe = "outlook.exe"
                    }
                    "PowerPoint" {
                        $Exe = "powerpnt.exe"
                    }
                    "Project" {
                        $Exe = "winproj.exe"
                    }
                    "Publisher" {
                        $Exe = "mspub.exe"
                    }
                    "Visio" {
                        $Exe = "visio.exe"
                    }
                    "Word" {
                        $Exe = "winword.exe"
                    }
                }
                $NewObj = [PSCustomObject]@{
                    Name = $App
                    Exe  = $Exe
                    Path = $InstallRoot
                }
                $InstalledApps.Add($NewObj)
            }
        }
    }
    Return $InstalledApps
}

Function Get-AdobeReaderProInstalls {
    $InstalledVersions = New-Object System.Collections.Generic.List[System.Object]

    $64bitAcrobatDC = @(Get-InstalledSoftware | Where-Object DisplayName -Like "Adobe Acrobat*(64-bit)*")
    If (($64bitAcrobatDC | Measure-Object).Count -ge 1) {
        # 64-bit Adobe Acrobat DC
        $Path = "HKLM:\SOFTWARE\Adobe\Adobe Acrobat\DC"
        If (Test-Path (Join-Path -Path $((Get-ItemProperty "$($Path)\InstallPath").'(Default)') -ChildPath "Acrobat.exe") -ErrorAction SilentlyContinue) {
            # 64-bit Adobe Pro and Reader are a unified application and SCAPackageLevel identifies which product is intalled.
            # https://helpx.adobe.com/acrobat/kb/about-acrobat-reader-dc-migration-to-64-bit.html
            $SCAPackageLevel = [Int]((Get-ItemProperty "$($Path)\Installer" -ErrorAction SilentlyContinue)).SCAPackageLevel
            Switch ($SCAPackageLevel) {
                { $_ -gt 1 } {
                    $NewObj = [PSCustomObject]@{
                        Name           = "Adobe Acrobat DC"
                        Version        = "DC"
                        Track          = "Continuous"
                        DisplayVersion = $64bitAcrobatDC[0].DisplayVersion
                        Architecture   = "x64"
                    }
                    If ($NewObj.Name -notin $InstalledVersions.Name) {
                        $InstalledVersions.Add($NewObj)
                    }
                }
                { $_ -eq 1 } {
                    $NewObj = [PSCustomObject]@{
                        Name           = "Adobe Reader DC"
                        Version        = "DC"
                        Track          = "Continuous"
                        DisplayVersion = $64bitAcrobatDC[0].DisplayVersion
                        Architecture   = "x64"
                    }
                    If ($NewObj.Name -notin $InstalledVersions.Name) {
                        $InstalledVersions.Add($NewObj)
                    }
                }
            }
        }
    }

    # 32-bit Adobe Acrobat and Adobe Reader
    $Paths = @("HKLM:\SOFTWARE\WOW6432Node\Adobe\Adobe Acrobat", "HKLM:\SOFTWARE\WOW6432Node\Adobe\Acrobat Reader")
    ForEach ($Path in $Paths) {
        If (Test-Path $Path) {
            Switch (Split-Path $Path -Leaf) {
                "Adobe Acrobat" {
                    $InstallPaths = @((Get-ChildItem $Path -Recurse | Where-Object { $_.Name -like "*InstallPath" -and $null -ne $_.GetValue("") }).Name)
                    ForEach ($Object in ($InstallPaths | Where-Object { $null -ne $_ })) {
                        If (Test-Path (Join-Path -Path $((Get-ItemProperty $($Object.Replace("HKEY_LOCAL_MACHINE", "HKLM:"))).'(Default)') -ChildPath "Acrobat.exe") -ErrorAction SilentlyContinue) {
                            Switch (Split-Path ($Object -split "Installer")[0] -Leaf) {
                                "11.0" {
                                    $NewObj = [PSCustomObject]@{
                                        Name           = "Adobe Acrobat XI"
                                        Version        = "XI"
                                        Track          = ""
                                        DisplayVersion = (Get-InstalledSoftware | Where-Object { ($_.DisplayName -Like "Adobe Acrobat XI*") }).DisplayVersion
                                        Architecture   = "x86"
                                    }
                                }
                                { ($_ -in @("2015", "2017", "2020")) } {
                                    $NewObj = [PSCustomObject]@{
                                        Name           = "Adobe Acrobat $_"
                                        Version        = $_
                                        Track          = "Classic"
                                        DisplayVersion = (Get-InstalledSoftware | Where-Object { ($_.DisplayName -Like "Adobe Acrobat DC*" -and $_.DisplayVersion -match "15.") -or ($_.DisplayName -Like "Adobe Acrobat 2017*" -and $_.DisplayVersion -match "17.") -or ($_.DisplayName -Like "Adobe Acrobat 2020*" -and $_.DisplayVersion -match "20.") }).DisplayVersion
                                        Architecture   = "x86"
                                    }
                                }
                                "DC" {
                                    $NewObj = [PSCustomObject]@{
                                        Name           = "Adobe Acrobat $_"
                                        Version        = $_
                                        Track          = "Continuous"
                                        DisplayVersion = (Get-InstalledSoftware | Where-Object { ($_.DisplayName -Like "Adobe Acrobat*" -and $_.DisplayName -NotLike "Adobe Acrobat Reader*" -and $_.DisplayVersion -gt 20) }).DisplayVersion
                                        Architecture   = "x86"
                                    }
                                }
                            }
                        }
                        If ($NewObj.Name -notin $InstalledVersions.Name) {
                            $InstalledVersions.Add($NewObj)
                        }
                    }
                }
                "Acrobat Reader" {
                    $InstallPaths = @((Get-ChildItem $Path -Recurse | Where-Object { $_.Name -like "*InstallPath" -and $null -ne $_.GetValue("") }).Name)
                    ForEach ($Object in ($InstallPaths | Where-Object { $null -ne $_ })) {
                        If (Test-Path (Join-Path -Path $((Get-ItemProperty $($Object.Replace("HKEY_LOCAL_MACHINE", "HKLM:"))).'(Default)') -ChildPath "AcroRd32.exe") -ErrorAction SilentlyContinue) {
                            Switch (Split-Path ($Object -split "InstallPath")[0] -Leaf) {
                                "11.0" {
                                    $NewObj = [PSCustomObject]@{
                                        Name           = "Adobe Reader XI"
                                        Version        = "XI"
                                        Track          = ""
                                        DisplayVersion = (Get-InstalledSoftware | Where-Object { ($_.DisplayName -Like "Adobe Reader XI*") }).DisplayVersion
                                        Architecture   = "x86"
                                    }
                                }
                                { ($_ -in @("2015", "2017", "2020")) } {
                                    $NewObj = [PSCustomObject]@{
                                        Name           = "Adobe Reader $_"
                                        Version        = $_
                                        Track          = "Classic"
                                        DisplayVersion = (Get-InstalledSoftware | Where-Object { ($_.DisplayName -Like "Adobe Acrobat Reader DC*" -and $_.DisplayVersion -match "15.") -or ($_.DisplayName -Like "Adobe Acrobat Reader 2017*" -and $_.DisplayVersion -match "17.") -or ($_.DisplayName -Like "Adobe Acrobat Reader 2020*" -and $_.DisplayVersion -match "20.") }).DisplayVersion
                                        Architecture   = "x86"
                                    }
                                }
                                "DC" {
                                    $NewObj = [PSCustomObject]@{
                                        Name           = "Adobe Reader $_"
                                        Version        = $_
                                        Track          = "Continuous"
                                        DisplayVersion = (Get-InstalledSoftware | Where-Object { ($_.DisplayName -Like "Adobe Acrobat Reader*" -and $_.DisplayVersion -gt 20) }).DisplayVersion
                                        Architecture   = "x86"
                                    }
                                }
                            }
                            If ($NewObj.Name -notin $InstalledVersions.Name) {
                                $InstalledVersions.Add($NewObj)
                            }
                        }
                    }
                }
            }
        }
    }

    If ($InstalledVersions) {
        Return $InstalledVersions | Sort-Object Version -Descending
    }
}

Function Confirm-DefaultAcl {
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("FileSystem", "Registry")]
        [String]$Type,

        [Parameter(Mandatory = $true)]
        [String]$Path,

        [Parameter(Mandatory = $true)]
        [Array]$DefaultAcl
    )

    $IsDefault = $true
    $AclFindings = @()
    [hashtable]$AclResults = @{}

    Switch ($Type) {
        "FileSystem" {
            # Any SIDs in DefaultAcl must first be resolved
            $i = 0
            ForEach ($Acl in $DefaultAcl) {
                Try {
                    If ($Acl.Split(":")[0] -match "^S-\d+-\d+-\d+-\d+") {
                        $SID = $Acl.Split(":")[0]
                        $Rights = $Acl.Split(":")[1]
                        # Resolve SID
                        $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
                        $Identity = $objSID.Translate( [System.Security.Principal.NTAccount]).Value

                        $DefaultAcl[$i] = "$($Identity):$($Rights)"
                    }
                    $i++
                }
                Catch {
                    # Do Nothing
                }
            }

            $AclList = icacls $Path
            $AclList = $AclList.Replace($Path, "").Trim() | Select-Object -Index (0..$(($AclList | Measure-Object).Count - 3))
            $AclEnum = @()
            ForEach ($Acl in $AclList) {
                $Rights = ""
                $Identity = $Acl.Split(":")[0]
                $Flags = $Acl.Split(":")[1].Trim()
                ForEach ($Flag in $Flags.Split(")").Replace("(", "")) {
                    If ($Flag -ne "") {
                        $Rights += "("
                        If ($Flag -match ",") {
                            $Multiflags = $Flag.Split(",")
                            $Rights += ($Multiflags | Where-Object { $_ -ne "S" }) -join "," # Ignore the Synchronize (S) flag which can be part of the ACL - especially when configured via group policy
                        }
                        Else {
                            $Rights += $Flag
                        }
                        $Rights += ")"
                    }
                }
                $AclEnum += "$($Identity):$($Rights)"
            }

            # Check default permissions exist
            ForEach ($Acl in $DefaultAcl) {
                If ($Acl -notin $AclEnum) {
                    $IsDefault = $false
                    $AclFindings += $Acl + " - Missing Default Rule"
                }
            }

            # Check for non-default permissions
            ForEach ($Acl in $AclEnum) {
                If ($Acl -notin $DefaultAcl) {
                    $IsDefault = $false
                    $AclFindings += $Acl + " - Non-Default Rule"
                }
            }
        }
        "Registry" {
            # Any SIDs in DefaultAcl must first be resolved
            $i = 0
            ForEach ($Acl in $DefaultAcl) {
                If ($Acl.IdentityReference -match "^S-\d+-\d+-\d+-\d+") {
                    Try {
                        # Resolve SID
                        $objSID = New-Object System.Security.Principal.SecurityIdentifier($Acl.IdentityReference)
                        $Identity = $objSID.Translate( [System.Security.Principal.NTAccount]).Value

                        $DefaultAcl[$i].IdentityReference = $Identity
                    }
                    Catch {
                        # Do Nothing
                    }
                }
                $i++
            }

            #Default ACL is to always be written as if only 1 ACL per acct exist
            <#
	        Translation of permissions:
		        Applies to 						                | Inheritance Flags 	| Propagation Flags
		        ------------------------------------------------------------------------------
		        "This key (folder) only" 						| "None" 				| "None"
		        "This key (folder) and subkeys (subfolders)" 	| "ContainerInherit"	| "None"
		        "Subkeys (subfolders) only"						| "ContainerInherit"	| "InheritOnly"

	        Translation of properties:
		        STIG / GUI Option Name	| PowerShell Option Name
		        --------------------------------------------------------------
		        Principal			| IdentityReference
		        Type 				| AccessControlType
		        Access 				| RegistryRights
		        Read Access			| ReadKey

	        RegistryRights can hold multiple values and sometimes create multiple entries for the same ACL when querying.
	        Specifically, the RegistryRights can be returned as a human readable string (ReadOnly, FullControl) or as a Two's Complement number.
	        The Two's compliment aligns with the permissions described in the "Access Mask Format" in Windows Documentation
	        (https://docs.microsoft.com/en-us/windows/win32/secauthz/access-mask-format)

	        Permission Values of Interest:
		        Two's Complement	| Human Readable Equivalent
		        -----------------------------------------------------------
			        -2147483648		| 	Read (Called "ReadKey" for registry keys)
			        -1610612736		| 	Read + Execute
			        1073741824		| 	Write
			        268435456		| 	FullControl





	        DEFINITION OF A 'SPLIT ACL'
		        A split ACL can sometimes occur when a permission has been applied to "this key (folder) and subkeys (subfolders)".
		        The Get-ACL cmdlet will sometimes return a single ACL, as expected with inheritanceFlags = ContainerInherit and propagationFlags = None,
		        but other times will return two ACLs. One ACL will have inheritanceFlags = ContainerInherit and propagationFlags = InheritOnly;
		        the other ACL will have inheritanceFlags = None and propagationFlags = None), which when combined apply the expected permissions.
	        #>

            $Hive = $Path.Replace("HKLM:\", "")
            If (($PsVersionTable.PSVersion -join ".") -lt [Version]"6.0") {
                $Key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$($Hive)", "Default", "ReadPermissions")
                $CollectedAcl = $Key.GetAccessControl() | Select-Object -ExpandProperty Access | Sort-Object IdentityReference
            }
            Else {
                $PSCommand = 'PowerShell.exe -Command {$Key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("'+$Hive+'", "Default", "ReadPermissions"); $Key.GetAccessControl() | Select-Object -ExpandProperty Access | Sort-Object IdentityReference}'
                $CollectedAcl = Invoke-Expression $PSCommand
            }

            $CurrentAcl = New-Object System.Collections.Generic.List[System.Object]
            ForEach ($Obj in $CollectedAcl) {
                $NewObj = New-Object -TypeName PsObject
                ForEach ($Prop in ($Obj | Get-Member -MemberType Properties).Name) {
                    If ("Value" -in ($Obj.$Prop | Get-Member -MemberType Properties).Name) {
                        $NewObj | Add-Member -MemberType NoteProperty -Name $Prop -Value $Obj.$Prop.Value
                    }
                    Else {
                        $NewObj | Add-Member -MemberType NoteProperty -Name $Prop -Value $Obj.$Prop
                    }
                }
                $CurrentAcl.Add($NewObj)
            }

            $CurrentRightsType = ($CurrentAcl | Get-Member * | Where-Object Name -Like "*Rights").Name
            $DefaultRightsType = ($DefaultAcl | Get-Member * | Where-Object Name -Like "*Rights").Name

            #-------------------------
            #Access Rights Translation
            #-------------------------
            $TranslatedACL = New-Object System.Collections.Generic.List[System.Object]
            ForEach ($Obj in $CurrentAcl) {
                #Translate all Two's Compliment Rights into human readable rights
                If ($Obj.$CurrentRightsType -Match "^-?\d+$") {
                    #If the RightsType is a number
                    Switch ($Obj.$CurrentRightsType) {
                        -2147483648 {
                            If ($CurrentRightsType -eq "RegistryRights") {
                                $TranslatedRightsType = "ReadKey"
                            }
                            Else {
                                $TranslatedRightsType = "Read"
                            }
                        }
                        -1610612736 {
                            If ($CurrentRightsType -eq "RegistryRights") {
                                $TranslatedRightsType = "ReadKey"
                            }
                            Else {
                                $TranslatedRightsType = "ReadAndExecute"
                            }
                        }
                        1073741824 {
                            $TranslatedRightsType = "Write"
                        }
                        268435456 {
                            $TranslatedRightsType = "FullControl"
                        }
                    }
                }
                Else {
                    $TranslatedRightsType = $Obj.$CurrentRightsType
                }

                $NewObj = [PSCustomObject]@{
                    $($CurrentRightsType) = $TranslatedRightsType
                    AccessControlType     = $($Obj.AccessControlType)
                    IdentityReference     = $($Obj.IdentityReference)
                    IsInherited           = $($Obj.IsInherited)
                    InheritanceFlags      = $($Obj.InheritanceFlags)
                    PropagationFlags      = $($Obj.PropagationFlags)
                }
                $TranslatedACL.Add($NewObj)
            }

            #----------------------------------------------
            #Combine split ACLs and update $CurrentACL
            #----------------------------------------------
            $AclList = New-Object System.Collections.Generic.List[System.Object]
            $UniqueIDs = $TranslatedACL.IdentityReference | Select-Object -Unique
            ForEach ($ID in $UniqueIDs) {
                #Used to grab unique IdentityReference
                $Rule = ($TranslatedACL | Where-Object { ($_.IdentityReference -eq $ID) -and (($_.InheritanceFlags -eq "ContainerInherit" -and $_.PropagationFlags -eq "InheritOnly") -or ($_.InheritanceFlags -eq "None" -and $_.PropagationFlags -eq "None")) }) #Query for split ACLs
                If (($Rule | Measure-Object).Count -eq 2) {
                    #If the ACL is split (this key only + subkeys only)
                    #If the two records match in all but InhertianceFlags and PropagationFlags
                    If (($Rule[0].$CurrentRightsType -eq $Rule[1].$CurrentRightsType) -and ($Rule[0].IsInherited -eq $Rule[1].IsInherited) -and ($Rule[0].AccessControlType -eq $Rule[1].AccessControlType)) {
                        #New Combined ACL object (Applies to this key and subkeys)
                        $NewObj = [PSCustomObject]@{
                            $($CurrentRightsType) = $Rule[0].$CurrentRightsType
                            AccessControlType     = $Rule[0].AccessControlType
                            IdentityReference     = $Rule[0].IdentityReference
                            IsInherited           = $Rule[0].IsInherited
                            InheritanceFlags      = "ContainerInherit"
                            PropagationFlags      = "None"
                        }
                        $AclList.Add($NewObj)
                    }
                }
                Else {
                    $Rule = ($TranslatedACL | Where-Object { ($_.IdentityReference -eq $ID) })
                    ForEach ($r in $Rule) {
                        $NewObj = [PSCustomObject]@{
                            $($CurrentRightsType) = $($r.$CurrentRightsType)
                            AccessControlType     = $($r.AccessControlType)
                            IdentityReference     = $($r.IdentityReference)
                            IsInherited           = $($r.IsInherited)
                            InheritanceFlags      = $($r.InheritanceFlags)
                            PropagationFlags      = $($r.PropagationFlags)
                        }
                        $AclList.Add($NewObj)
                    }
                }
            }

            #--------------------------
            #Proceed as normal
            #--------------------------
            # Look for missing default rules
            ForEach ($Object in $DefaultAcl) {
                If ($Object.Mandatory -eq $true -and (-Not($AclList | Where-Object { ($_.IdentityReference -eq $Object.IdentityReference) -and ($_.$($CurrentRightsType) -eq $Object.$($DefaultRightsType)) -and ($_.AccessControlType -eq $Object.AccessControlType) -and ($_.InheritanceFlags -eq $Object.InheritanceFlags) -and ($_.PropagationFlags -in $Object.PropagationFlags) }))) {
                    $IsDefault = $false
                    $AclObj = New-Object -TypeName PsObject
                    $AclObj | Add-Member -MemberType NoteProperty -Name "Reason" -Value "Missing Default Rule"
                    $AclObj | Add-Member -MemberType NoteProperty -Name "$($DefaultRightsType)" -Value $Object.$($DefaultRightsType)
                    $AclObj | Add-Member -MemberType NoteProperty -Name "AccessControlType" -Value $Object.AccessControlType
                    $AclObj | Add-Member -MemberType NoteProperty -Name "IdentityReference" -Value $Object.IdentityReference
                    $AclObj | Add-Member -MemberType NoteProperty -Name "IsInherited" -Value $Object.IsInherited
                    $AclObj | Add-Member -MemberType NoteProperty -Name "InheritanceFlags" -Value $Object.InheritanceFlags
                    $AclObj | Add-Member -MemberType NoteProperty -Name "PropagationFlags" -Value ($Object.PropagationFlags -Join " or ")
                    $AclFindings += $AclObj
                }
            }

            # Compare rules
            ForEach ($Object in $AclList) {
                If (-Not($DefaultAcl | Where-Object { ($_.IdentityReference -eq $Object.IdentityReference) -and ($_.$($DefaultRightsType) -contains $Object.$($CurrentRightsType)) -and ($_.AccessControlType -eq $Object.AccessControlType) -and ($_.InheritanceFlags -contains $Object.InheritanceFlags) -and ($_.PropagationFlags -contains $Object.PropagationFlags) })) {
                    # Look for unexpected rule
                    $IsDefault = $false
                    $AclObj = New-Object -TypeName PsObject
                    $AclObj | Add-Member -MemberType NoteProperty -Name "Reason" -Value "Non-Default Rule"
                    $AclObj | Add-Member -MemberType NoteProperty -Name "$($CurrentRightsType)" -Value $Object.$($CurrentRightsType)
                    $AclObj | Add-Member -MemberType NoteProperty -Name "AccessControlType" -Value $Object.AccessControlType
                    $AclObj | Add-Member -MemberType NoteProperty -Name "IdentityReference" -Value $Object.IdentityReference
                    $AclObj | Add-Member -MemberType NoteProperty -Name "IsInherited" -Value $Object.IsInherited
                    $AclObj | Add-Member -MemberType NoteProperty -Name "InheritanceFlags" -Value $Object.InheritanceFlags
                    $AclObj | Add-Member -MemberType NoteProperty -Name "PropagationFlags" -Value $Object.PropagationFlags
                    $AclFindings += $AclObj
                }
            }
        }
    }

    $AclResults.IsDefault = $IsDefault
    $AclResults.AclFindings = $AclFindings
    $AclResults.Acl = $AclList
    Return $AclResults
}

Function Get-CorporateComment {
    # Function for getting standarized comments from answer file.
    Param (
        [Parameter(Mandatory = $true)]
        [String]$AnswerFile,

        [Parameter(Mandatory = $true)]
        [String]$VulnID,

        [Parameter(Mandatory = $true)]
        [String]$AnswerKey,

        [Parameter(Mandatory = $false)]
        [String]$UserSID,

        [Parameter(Mandatory = $false)]
        [String]$SiteName,

        [Parameter(Mandatory = $false)]
        [String]$Instance,

        [Parameter(Mandatory = $false)]
        [String]$Database,

        [Parameter(Mandatory = $false)]
        [String]$LogPath,

        [Parameter(Mandatory = $true)]
        [String]$LogComponent,

        [Parameter(Mandatory = $true)]
        [String]$OSPlatform
    )

    $ErrorActionPreference = "SilentlyContinue"

    [hashtable]$AnswerResults = @{ }
    $AnswerResults.AFKey = ""
    $AnswerResults.AFComment = ""
    $AnswerResults.ExpectedStatus = ""
    $AnswerResults.AFStatus = ""

    Try {
        [XML]$AnswerData = Get-Content -Path $($AnswerFile -replace ("'",""))
        $AllAFKeys = $($AnswerData.STIGComments.Vuln | Where-Object ID -EQ $VulnID | Select-Object -ExpandProperty AnswerKey).Name -replace ","," "

        if ($([Environment]::MachineName) -in -split $AllAFKeys){
            $AnswerKey = $([Environment]::MachineName)
        }
        <#
        Space save for having more Site/DB/Apache specific keys
        If ($SiteName -in -split $AllAFKeys){
            $AnswerKey = $SiteName
        }
        If ("$Instance/$Database" -in -split $AllAFKeys){
            $AnswerKey = "$Instance/$Database"
        }
        #>
        If ($AnswerKey -in -split $AllAFKeys -or "DEFAULT" -in -split $AllAFKeys) {
            $VulnKey = $AnswerData.STIGComments.Vuln | Where-Object ID -EQ $VulnID | Select-Object -ExpandProperty AnswerKey
            If ($AnswerKey -in $($VulnKey.Name -replace (" ", ",") -split(","))){
                $AnswerResults.AFKey = $AnswerKey
                $ValidKey = $true
            }
            elseif ($VulnKey.Name -EQ "DEFAULT"){
                $AnswerResults.AFKey = "DEFAULT"
                $ValidKey = $true
            }
            else{
                $ValidKey = $false
            }

            if ($ValidKey){
                $VulnKey | Foreach-Object {if ($AnswerResults.AFKey -in $($_.Name -replace (" ", ",") -split(","))){$AnswerObject = $_}}
                $AnswerResults.ExpectedStatus = $AnswerObject.ExpectedStatus
                If (($AnswerObject.ValidationCode).Trim()) {
                    $ValidationResult = (Invoke-Expression $AnswerObject.ValidationCode)
                    if ($ValidationResult -is [PSCustomObject]){
                        $ValidationCodeResults = "`r`n`r`n[Validation Code Results]:`r`n$($ValidationResult.Results)"
                        $Validated = $ValidationResult.Valid
                    }
                    elseif ($ValidationResult -is [boolean]){
                        $ValidationCodeResults = "`r`n`r`n[Validation Code Results]:`r`n$($ValidationResult)"
                        $Validated = $ValidationResult
                    }

                    If ($Validated -eq $true) {
                        If ($AnswerObject.ValidTrueStatus -eq "") {
                            $AnswerResults.AFStatus = $AnswerObject.ExpectedStatus
                        }
                        Else {
                            $AnswerResults.AFStatus = $AnswerObject.ValidTrueStatus
                        }
                        $AnswerResults.AFComment = "`r`nAnswer File: $AnswerFile`r`n`r`n[ValidTrueComment]:`r`n" + ($AnswerObject.ValidTrueComment).Replace('$UserSID', "$UserSID") + $ValidationCodeResults| Out-String
                    }
                    Else {
                        If ($AnswerObject.ValidFalseStatus -eq "") {
                            $AnswerResults.AFStatus = $AnswerObject.ExpectedStatus
                        }
                        Else {
                            $AnswerResults.AFStatus = $AnswerObject.ValidFalseStatus
                        }
                        $AnswerResults.AFComment = "`r`nAnswer File: $AnswerFile`r`n`r`n[ValidFalseComment]:`r`n" + ($AnswerObject.ValidFalseComment).Replace('$UserSID', "$UserSID") + $ValidationCodeResults| Out-String
                    }
                }
                Else {
                    If ($AnswerObject.ValidTrueStatus -eq "") {
                        $AnswerResults.AFStatus = $AnswerObject.ExpectedStatus
                    }
                    Else {
                        $AnswerResults.AFStatus = $AnswerObject.ValidTrueStatus
                    }
                    $AnswerResults.AFComment = "[ValidTrueComment]:`r`n" + ($AnswerObject.ValidTrueComment).Replace('$UserSID', "$UserSID") | Out-String
                }
            }
            else{
                $AnswerResults = $null
            }
        }
        Else {
            $AnswerResults = $null
        }
    }
    Catch {
        $AnswerResults = $null
        Write-Log -Path $LogPath -Message "    Answer File ValidationCode failed" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
        Write-Log -Path $LogPath -Message "    Answer File: $AnswerFile" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
        Write-Log -Path $LogPath -Message "    Answer Key: $AnswerKey" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
        Write-Log -Path $LogPath -Message "    $($_.Exception.Message)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
    }

    Return $AnswerResults
}

Function Get-ErrorInformation {
    <#
    .SYNOPSIS
        Parses the provided Error Record for useful information and outputs as PSCustomObject
    .DESCRIPTION
        Function that ingests a single Error Record and parses out useful information to include the Exception Message, Exception Type, Script Name, Script Line Number, the command and, if available, the Target Object of the failed line.
    .NOTES
        Springboarded off GngrNinja
            https://www.gngrninja.com/script-ninja/2016/6/5/powershell-getting-started-part-11-error-handling
    .LINK
    .EXAMPLE
        Get-ErrorInformation -IncomingError $Error[0]
        Ingests the first error in the automatic variable $Error and outputs useful properties.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.ErrorRecord]
        $IncomingError,

        [Parameter(Mandatory = $false)]
        [Switch]
        $IncludeRawError
    )

    $ErrorPSObject = [PSCustomObject]@{
        ExceptionMessage = $IncomingError.Exception.Message
        ExceptionType    = $IncomingError.Exception | Get-Member | Select-Object -ExpandProperty TypeName -Unique
        ScriptName       = $IncomingError.Exception.ErrorRecord.InvocationInfo.ScriptName
        ScriptLineNumber = $IncomingError.InvocationInfo.ScriptLineNumber
        Command          = $IncomingError.InvocationInfo.Line.Trim()
        TargetObject     = $IncomingError.TargetObject
    }
    If ($IncludeRawError) {
        $ErrorPSObject | Add-Member -MemberType NoteProperty -Name RawError -Value $IncomingError
    }

    Return $ErrorPSObject
} # END FUNCTION Get-ErrorInformation

############################################################
## SQL Functions                                        #
############################################################
Function Get-AllInstances {
    # Generate list of valid instances.  Exclude SQL Server 2014 Express edition.
    $ValidInstances = New-Object System.Collections.Generic.List[System.Object]
    $KeysToCheck = @("HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server")
    ForEach ($Key in $KeysToCheck) {
        $Instances = (Get-ItemProperty $Key).InstalledInstances
        ForEach ($Instance in $Instances) {
            $p = (Get-ItemProperty "$($Key)\Instance Names\SQL").$Instance
            $Edition = (Get-ItemProperty "$($Key)\$($p)\Setup").Edition
            $Version = [Version](Get-ItemProperty "$($Key)\$($p)\Setup").Version
            If (-Not($Version -like "12.0*" -and $Edition -like "*Express*")) {
                $NewObj = [PSCustomObject]@{
                    InstanceName = $Instance
                    Edition      = $Edition
                    Version      = $Version
                }
                $ValidInstances.Add($NewObj)
            }
        }
    }

    # Get instance names and service status
    $allInstances = New-Object System.Collections.Generic.List[System.Object]
    $KeysToCheck = @("HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL")
    ForEach ($Key in $KeysToCheck) {
        If (Test-Path $Key) {
            (Get-Item $Key).GetValuenames() | Where-Object { $_ -notlike '*#*' } | ForEach-Object {
                If ($_ -in $ValidInstances.InstanceName) {
                    # Grab the version from the array built earlier
                    $tmpVersion = ($ValidInstances | Where-Object InstanceName -EQ $_).Version

                    # Determine the server Name
                    $tsname = (Get-Item $Key).GetValue($_)
                    If ($Key -like "*WOW6432Node*") {
                        If (Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server\$tsname\cluster") {
                            $cname = (Get-Item "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server\$tsname\cluster").GetValue('ClusterName')
                        }
                        Else {
                            $cname = $env:computername
                        }
                    }
                    Else {
                        If (Test-Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$tsname\cluster") {
                            $cname = (Get-Item "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$tsname\cluster").GetValue('ClusterName')
                        }
                        Else {
                            $cname = $env:computername
                        }
                    }

                    # Determine the Windows Service Name and Status
                    If ($_ -eq 'MSSQLSERVER') {
                        $tmpServiceName = 'MSSQLSERVER'
                        $tmpInstanceName = $cname
                    }
                    else {
                        $tmpServiceName = "mssql`$$_"
                        $tmpInstanceName = "$cname\$_"
                    }
                    $oService = Get-Service $tmpServiceName -ErrorAction SilentlyContinue
                    if ($oService) {
                        $tmpStatus = $oService.Status
                    }
                    else {
                        $tmpServiceName = "NotFound"
                        $tmpStatus = 'NA'
                    }

                    $NewObj = [PSCustomObject]@{
                        Name    = $tmpInstanceName
                        Service = $tmpServiceName
                        Status  = $tmpStatus
                        Version = $tmpVersion
                    }
                    $allInstances.Add($NewObj)
                }
            }
        }
    }
    Return $allInstances
}

Function Get-InstanceVersion {
    param (
        [Parameter(Mandatory = $true)]
        [String]$Instance
    )

    $InstanceVersion = (Get-ISQL -ServerInstance "$Instance" -Qry "select @@version").column1
    $null = $InstanceVersion -match "SQL Server \d{4}"
    $VersionToReturn = $Matches.Values -replace "[^0-9]"
    Return $VersionToReturn
}

Function Get-ISQL {
    <#
        .SYNOPSIS
            Wrapper function for the invoke-sqlcmd cmdlet.
        .DESCRIPTION
            Get-ISQL is merely a wrapper function for the invoke-sqlcmd cmdlet.
        .PARAMETER Query
            Specifies a query to run against MSSQL.
        .PARAMETER ServerInstance
            Sspecifies the server/instance to query.
        .PARAMETER Database
            Specifies the database to query. If omitted, then "master" will be used.
    #>

    Param (
        # A valid SQL or DDL statement must either be piped in or specified via the qry parameter.
        [Parameter(Mandatory = $true)]
        [String] $Qry,

        [Parameter(Mandatory = $true)]
        [String] $ServerInstance,

        [Parameter(Mandatory = $false)]
        [String] $Database = "master"
    )

    Write-Verbose "Running against server $ServerInstance, database $Database"
    If ("TrustServerCertificate" -in (Get-Command Invoke-Sqlcmd).Parameters.Keys) {
        # -TrustServerCertificate is a valid parameter so use it.
        Invoke-Sqlcmd -ServerInstance $ServerInstance -SuppressProviderContextWarning -Query "use [$Database]; $Qry" -QueryTimeout 65535 -TrustServerCertificate
    }
    Else {
        Invoke-Sqlcmd -ServerInstance $ServerInstance -SuppressProviderContextWarning -Query "use [$Database]; $Qry" -QueryTimeout 65535
    }
}

function Confirm-TraceAuditSetting {
    <#
        .SYNOPSIS
            Examines a MSSQL server's trace and audit settings to verify STIG adherance.
        .DESCRIPTION
            Confirm-TraceAuditSettings will first determine whether audits or traces are being used, and then will inspect the configuration of the audits or traces to verify all required events are being audited.  A report of any un-audited events is returned as a string.
        .INPUTS
            None. Does not accept piped-in input.
        .OUTPUTS
            Returns a string detailing any findings.
    #>
    Param (
        [Parameter(Mandatory = $true)]
        [String]$Instance,
        [Parameter(Mandatory = $true)]
        [String]$Database
    )
    $ResultData = ""
    # Iterate through each of the servers on this instance
    # 20201106 JJS Added Instance Database
    $servers = (Get-ISQL -ServerInstance $Instance -Database $Database 'select @@servername')
    if ($servers) {
        foreach ($instance in $servers.column1) {
            # First, check to see if the server is compliant in audits
            $res = Get-ISQL -serverinstance $instance "
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
        union select 'FAILED_LOGIN_GROUP'
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
        union select 'SERVER_PRINCIPAL_CHANGE_GROUP'
        union select 'SERVER_PRINCIPAL_IMPERSONATION_GROUP'
        union select 'SERVER_ROLE_MEMBER_CHANGE_GROUP'
        union select 'SERVER_STATE_CHANGE_GROUP'
        union select 'SUCCESSFUL_LOGIN_GROUP'
        union select 'TRACE_CHANGE_GROUP'
       except
	          select audit_action_name
	            from sys.server_audit_specification_details d
			   inner join sys.server_audit_specifications s	on d.server_specification_id = s.server_specification_id
			   inner join sys.server_audits a on s.audit_guid = a.audit_guid
			   where s.is_state_enabled = 1
			     and a.is_state_enabled = 1
    )
    select @@SERVERNAME as InstanceName, Audit_Action_Name from q
    "
            if ($res) {
                # Deficiencies were found in the audits, check traces
                $qry = "
        with q as (
                select 14 as eventid
          union select 15
          union select 18
          union select 20
          union select 102
          union select 103
          union select 104
          union select 105
          union select 106
          union select 107
          union select 108
          union select 109
          union select 110
          union select 111
          union select 112
          union select 113
          union select 115
          union select 116
          union select 117
          union select 118
          union select 128
          union select 129
          union select 130
          union select 131
          union select 132
          union select 133
          union select 134
          union select 135
          union select 152
          union select 153
          union select 170
          union select 171
          union select 172
          union select 173
          union select 175
          union select 176
          union select 177
          union select 178
      "
                Get-ISQL -serverinstance $instance 'select id from sys.traces' | ForEach-Object {
                    $qry += "except select eventid from sys.fn_trace_geteventinfo(" + $_.id + ") "
                }
                $qry += ")
        select @@SERVERNAME as InstanceName, eventid from q
      "
                $restrace = Get-ISQL -serverinstance $instance $qry
                if ($restrace) {
                    if ($ResultData -eq "") {
                        $ResultData = "The check found events that are not being audited by SQL traces:`n"
                    }
                    $ResultData += "$($restrace | Format-Table | Out-String)"
                }
            }
        }
    }
    Write-Output $ResultData
}

Function Get-AccessProblem (
    [parameter(mandatory = $true)][System.Security.AccessControl.AuthorizationRuleCollection]$CurrentAuthorizations
    , [parameter(mandatory = $true)][System.Collections.Hashtable]$AllowedAuthorizations
    , [parameter(mandatory = $true)][string]$FilePath
    , [parameter(mandatory = $true)][string]$InstanceName
    ) {
    Set-StrictMode -Version 2.0
    $fSQLAdminFull = $fSysAdminFull = $false
    $ResultData = ''

    function AppendResultData (
        [parameter(mandatory = $true)][ref]    $ResultData
        , [parameter(mandatory = $true)][string] $FilePath
        , [parameter(mandatory = $true)][string] $Message
    ) {
        Set-StrictMode -Version 2.0
        if ($ResultData.value -eq '') {
            $ResultData.value = "In directory ${FilePath}:`n`n"
        }
        $ResultData.value += "$Message`n"
    }

    $CurrentAuthorizations | ForEach-Object {
        $arrRights = $_.FileSystemRights -split ', *'
        $sUser = $_.IdentityReference.value
        if ($sUser -match "\`$${InstanceName}$") {
            # This is a service-based account (e.g. NT SERVER\SQLAgent$SQL01), replace the service w/ <INSTANCE> when checking the hash table
            $sSearchUser = $sUser -replace "\`$${InstanceName}$", "$<INSTANCE>"
            $arrAuthPerms = $AllowedAuthorizations[$sSearchUser]
        }
        elseif ($sUser -eq 'NT SERVICE\MSSQLSERVER' -and $InstanceName -eq 'MSSQLSERVER' ) {
            $arrAuthPerms = $AllowedAuthorizations['NT SERVICE\MSSQL$<INSTANCE>']
        }
        else {
            $arrAuthPerms = $AllowedAuthorizations[$sUser]
        }

        try {
            $iAuth = ($arrAuthPerms | Measure-Object).count
        }
        catch {
            $iAuth = 0
        }

        if ($iAuth -gt 0) {
            if ('FullControl' -in $arrAuthPerms) {
                # This user is allowed FULL CONTROL, so no need to check further
                switch ($sUser) {
                    #$C_ACCT_SQLADMINS        { $fSQLAdminFull = $true } # JJS Removed
                    'BUILTIN\Administrators' {
                        $fSysAdminFull = $true
                    }
                }
            }
            else {
                # Let's try to identify perms held by the user, but not in the list of authorized perms
                $arrTemp = $arrRights -ne 'Synchronize' # Get a copy of rights assigned to the user, less 'Synchronize' which seems innocuous.
                foreach ($p in $arrAuthPerms) {
                    $arrTemp = $arrTemp -ne $p # rebuild the array without $p in it
                    foreach ($psub in get-subperm($p)) {
                        $arrTemp = $arrTemp -ne $p
                    }
                }
                if (($arrTemp | Measure-Object).count -gt 0) {
                    # We removed any permissions that were authorized, so the only ones left should be the unauthorized perms
                    AppendResultData ([ref]$ResultData) $FilePath "$sUser has $($arrTemp -join ',') rights (should be $($arrAuthPerms -ne 'Synchronize' -join ','))."
                }
                else {
                    if (! ($_.inheritanceflags -eq 'ContainerInherit, ObjectInherit' -and $_.propagationflags -eq 'None')) {
                        if (! ($FilePath -match '\.trc$' -or $FilePath -match '\.sqlaudit$')) {
                            AppendResultData ([ref]$ResultData) $FilePath "$sUser seems to have appropriate rights, but those rights are not properly propogated."
                        }
                    }
                }
            }
        }
        else {
            AppendResultData ([ref]$ResultData) $FilePath "$sUser has $($arrRights -join ',') rights (should be NO rights)."
        }
    }

    if ($fSQLAdminFull -and $fSysAdminFull) {
        # If we have a custom SQLAdmins group, then they should have full control and the built-in admin group should be read-only.
        AppendResultData ([ref]$ResultData) $FilePath "Both $C_ACCT_SQLADMINS and BUILTIN\Administrators have full control"
    }

    if ($ResultData -gt '') {
        $ResultData += "`n"
    }

    Return $ResultData
}

function Get-SubPerm {
    <#
        .SYNOPSIS
            Returns an array of file-access permissions that are included with the passed-in permission.
        .PARAMETER perm
            [Mandatory] A file-access permission.
        .INPUTS
            None. Get-SubPerm does not accept piped-in input.
        .OUTPUTS
            An array of permissions.
        .EXAMPLE
            Get-SubPerm 'ReadAndExecute'
            Returns all file access permissions that are included with 'ReadAndExecute'.
    #>
    param(
        [parameter(mandatory = $true)] [string] $perm
    )

    $hashSubPerms = @{
        'Modify'         = @('ReadAndExecute', 'Write', 'Delete')
        'Read'           = @('ReadData', 'ReadExtendedAttributes', 'ReadAttributes', 'ReadPermissions')
        'ReadAndExecute' = @('Read', 'ExecuteFile')
        'Write'          = @('WriteData', 'AppendData', 'WriteExtendedAttributes', 'WriteAttributes')
    }

    $arrResult = $arrPerms = $hashSubPerms[$perm]
    foreach ($p in $arrPerms) {
        $arr = get-SubPerm($p);
        try {
            $iCnt = ($arr | Measure-Object).count
        }
        catch {
            $iCnt = 0
        }

        if ($iCnt -gt 0) {
            $arrResult += $arr
        }
    }
    return $arrResult
}

function Get-SqlVersion {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$Instance
    )

    $res = Get-ISQL -ServerInstance $Instance -Database "Master" "select @@version"

    $sqlVersion = ""
    if ($res.column1 -like "Microsoft SQL Server 2014*") {
        $sqlVersion = "120"
    }
    elseif ($res.column1 -like "Microsoft SQL Server 2016*") {
        $sqlVersion = "130"
    }
    elseif ($res.column1 -like "Microsoft SQL Server 2017*") {
        $sqlVersion = "140"
    }
    elseif ($res.column1 -like "Microsoft SQL Server 2019*") {
        $sqlVersion = "150"
    }
    elseif ($res.column1 -like "Microsoft SQL Server 2022*") {
        $sqlVersion = "160"
    }
    return $sqlVersion
}

function Get-SqlVersionInstance {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$Instance
    )

    $sqlVersion = Get-SqlVersion $Instance
    #$sqlVersionInstance = left($sqlVersion,2)+$Instance
    #$sqlVersionInstance = $sqlVersion.Substring(0,2)
    #$sqlVersionInstance = "MSSQL"+$sqlVersion.Substring(0,2)+".$instance"
    # need to remove hostname\
    $HostName = (Get-CimInstance Win32_Computersystem).name
    $InstanceOnly = $Instance.Replace($HostName + "\", "")
    $sqlVersionInstance = "MSSQL" + $sqlVersion.Substring(0, 2) + ".$instanceOnly"
    return $sqlVersionInstance
}


function Get-SqlProductFeatures {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$Instance,
        [Parameter(Mandatory = $false)]
        [String]$Database = "master"
    )

    $sqlVersion = Get-SqlVersion $Instance

    $SqlInstallSummaryFile = "$env:programfiles\Microsoft SQL Server\$sqlVersion\Setup Bootstrap\Log\Summary.txt"

    $ProductFeaturesLineCount = 0
    $ProductFeatures = "Using file ($SqlInstallSummaryFile) for SQL Product Features.`n"

    if (Test-Path -Path $SqlInstallSummaryFile) {
        # read SqlInstallSummaryFile for section "Product features discovered:"
        try {
            $SqlInstallSummaryFileLines = Get-Content "$SqlInstallSummaryFile"

            $ProductFeaturesFound = $false

            foreach ($SqlInstallSummaryFileLine in $SqlInstallSummaryFileLines) {
                if ($SqlInstallSummaryFileLine -like "Product features discovered*" -or $ProductFeaturesFound -eq $True) {
                    $ProductFeaturesFound = $true
                    if ($ProductFeaturesFound -eq $true) {
                        if ($SqlInstallSummaryFileLine -like "Package properties*" ) {
                            break
                        }
                        else {
                            $ProductFeaturesLineCount += 1
                            $ProductFeatures += $SqlInstallSummaryFileLine + "`n"
                        }
                    }
                }
            }

            If ($ProductFeaturesLineCount -eq 0) {
                $ProductFeatures = "ERROR: No SQL Product Features Found in File ($SqlInstallSummaryFile)"
            }

        }
        catch {
            $ProductFeatures = "ERROR: Reading SQL Product Features File ($SqlInstallSummaryFile)"
        }
    }
    else {
        $ProductFeatures = "ERROR: Could not find SQL Product Features File ($SqlInstallSummaryFile)"
    }

    return $ProductFeatures
}

function Get-LeftNumbers {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$StringToScan
    )

    $returnValue = ""
    for ($i = 0; $i -lt $StringToScan.Length; $i++) {
        if ($StringToScan[$i] -like "[0-9]*") {
            $returnValue += $StringToScan[$i]
        }
        else {
            break
        }
    }
    return $returnValue
}

Function Get-DeepCopy {
    # Source : https://powershellexplained.com/2016-11-06-powershell-hashtable-everything-you-wanted-to-know-about/#deep-copies
    [cmdletbinding()]
    Param(
        $InputObject
    )

    Process {
        If ($InputObject -is [hashtable] -or $InputObject -is [System.Collections.Specialized.OrderedDictionary] ) {
            If ($InputObject -is [System.Collections.Specialized.OrderedDictionary]) {
                $copy = [ordered]@{}
            }
            Else {
                $copy = @{}
            }

            ForEach ($key in $InputObject.keys) {
                $copy[$key] = Get-DeepCopy $InputObject[$key]
            }
            Return $copy
        }
        Else {
            Return $InputObject
        }
    }
}

Function Get-TextHash {
    # https://gist.github.com/WalternativE/450b155c45f81b14290f8ded8324a283
    Param (
        [Parameter(Mandatory = $true)]
        [string]$Text,

        [Parameter(Mandatory = $false)]
        [ValidateSet("MD5", "SHA256", "SHA384", "SHA512")]
        [string]$Algorithm = "MD5"
    )

    $hasher = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)
    $hash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))

    $hashString = [System.BitConverter]::ToString($hash)
    Return $hashString.Replace('-', '')
}

############################################################
## Apache Functions                                        #
############################################################

function Get-ApacheUnixExecutablePaths {
    $Command = "netstat -pant | grep LISTEN | awk '{print `$7}' | grep -Pv `"^-`$`" | awk -F`"/`" `'{print `$1}`'"
    $ListenPids = @(Invoke-Expression -Command $Command) | Sort-Object -Unique

    $Executables = [System.Collections.ArrayList]@()
    foreach ($listenPid in $ListenPids) {
        $binCommand = "readlink /proc/$($listenPid)/exe"
        $bin = Invoke-Expression -Command $binCommand

        $binInfoCommand = "timeout 3s $($bin) -v 2>&1 | grep -Pi `"^Server\s*version:\s*Apache/2\.4`""
        $binInfo = Invoke-Expression -Command $binInfoCommand

        if ([string]::IsNullOrEmpty($binInfo)) {
            continue
        }

        [void]$Executables.Add($bin.Trim())
    }

    return $Executables
}

function Test-IsApacheInstalled {
    param (
        [Parameter(Mandatory)]
        [string] $OnOS
    )

    $STIGRequired = $false
    Try {
        if ($OnOS -eq "Unix") {
            if (-not ($IsLinux)) {
                return $STIGRequired
            }

            $ExecutablePaths = Get-ApacheUnixExecutablePaths
            if (($ExecutablePaths | Measure-Object).Count -gt 0) {
                $STIGRequired = $True
            }

            return $STIGRequired
        }
        elseif ($OnOS -eq "Windows") {
            if ($IsLinux) {
                return $STIGRequired
            }

            $Services = Get-CimInstance -ClassName win32_service
            If ($null -eq $Services) {
                Return $STIGRequired
            }

            Foreach ($service in $Services) {
                $PathName = $service.PathName
                $Path = ($PathName -split '"')[1]
                If ($null -eq $Path -or $Path -eq "") {
                    # If a path can't be parsed (because we know what it looks like) ignore.
                    Continue
                }

                If (-not (Test-Path -Path $Path -PathType Leaf)) {
                    # If a path is parsed and it doesn't lead to a file, ignore.
                    Continue
                }

                $Extension = (Get-ItemProperty -Path $Path -Name Extension).Extension
                If ($Extension -ne '.exe') {
                    # If the file is not an .exe, ignore.
                    Continue
                }

                $VersionInfo = (Get-Item -Path $Path).VersionInfo;
                $FileDescription = $VersionInfo.FileDescription;
                If ($FileDescription -notlike "*Apache*HTTP*Server") {
                    # If the file descriptor is not anything related to apache server, ignore.
                    Continue
                }

                $Param = '-v'
                $VersionOutput = (& "$($Path)" $Param)
                If ($VersionOutput | Select-String -Pattern '2.4' -Quiet) {
                    # If we get no version as output or if the version is incorrect, ignore.
                    $STIGRequired = $true
                }
            }
        }

        Return $STIGRequired
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

function Get-ApacheVersionTable {
    param (
        [Parameter(Mandatory)]
        [string] $ExecutablePath
    )

    $Param = '-V'
    $Version = & "$ExecutablePath" $Param 2>/dev/null

    return $Version
}

Function Get-ApacheConfigs {
    Param (
        [Parameter(Mandatory = $false)]
        [String]$RootPath,

        [Parameter(Mandatory = $true)]
        [String]$SearchPath,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [System.Collections.ArrayList]$FoundConfigs
    )

    $SearchPattern = "^(Include|IncludeOptional)\s+\S*"

    if ( $null -eq $FoundConfigs) {
        $FoundConfigs = [System.Collections.ArrayList]::new()
    }

    if ($SearchPath | Select-String -Pattern "\*") {
        if (Test-Path -Path $SearchPath) {
            $path = $SearchPath
        } else {
            $path = Join-Path -Path $RootPath -ChildPath $SearchPath
            if (-not (Test-Path -Path $path)) {
                return
            }
        }

        $paths = (Get-ChildItem -Path $path).FullName
        foreach ($p in $paths) {
            if (($FoundConfigs | Where-Object { $_.Contains($p)}).Length -eq 0 ) {
                Get-ApacheConfigs -RootPath $rootPath -SearchPath $p -FoundConfigs $FoundConfigs
            }
        }
    }
    else {
        if (Test-Path -Path $SearchPath) {
            $path = $SearchPath
        } else {
            $path = Join-Path -Path $RootPath -ChildPath $SearchPath
            if (-not (Test-Path -Path $path)) {
                return
            }
        }

        if (($FoundConfigs | Where-Object { $_.Contains($path)}).Length -eq 0 ) {
            Write-Output $path
            $null = $FoundConfigs.Add($path)
        }

        $foundIncludes = (Select-String -Path $path -Pattern $SearchPattern -AllMatches).Matches.Value

        ForEach ($found in $foundIncludes) {

            $foundPath = $found.Split(" ")[1]

            if (Test-Path -Path $foundPath) {
                $foundPath = $foundPath
            } else {
                $foundPath = Join-Path -Path $RootPath -ChildPath $foundPath
            }

            if (Test-Path -Path $foundPath) {
                if (($FoundConfigs | Where-Object { $_.Contains($foundPath)}).Length -eq 0 ) {
                    Get-ApacheConfigs -RootPath $rootPath -SearchPath $foundPath -FoundConfigs $FoundConfigs
                }
            }
        }
    }
}

function Get-ConfigFilePaths {
    param (
        [Parameter(Mandatory)]
        [string] $ExecutablePath
    )

    $Param = '-t'
    $Param2 = '-D'
    $Param3 = 'DUMP_INCLUDES'
    $Configs = & "$ExecutablePath" $Param $Param2 $Param3 2>/dev/null

    if ($Configs | Select-String -Pattern "Syntax OK") {
        $RootPath = Get-HttpdRootPath -ExecutablePath $executablePath
        $ServerConfigFile = Get-RootServerConfigFile -ExecutablePath $executablePath

        $Configs = Get-ApacheConfigs -RootPath $RootPath -SearchPath $ServerConfigFile -FoundConfigs $null
    }

    $ConfigArray = [System.Collections.ArrayList]@()
    foreach ($string in $Configs) {
        if ($string | Select-String -SimpleMatch 'Included configuration files') {
            continue
        }

        # Get rid of those weird numbers before the path and preserve numbers in the path.
        # Example '(*) C:\Program Files (x86)\blah\blahblah' is converted to 'C:\Program Files (x86)\blah\blahblah'
        $Filtered = $string -replace '^\s*\(\*\)|^\s*\(\d+\)'
        $MoreFiltered = $Filtered.Trim().Replace('\', '/')
        if ($ConfigArray.Contains($MoreFiltered)) {
            continue
        }

        [void]$ConfigArray.Add($MoreFiltered)
    }

    return $ConfigArray
}

function Get-HttpdRootPath {
    param (
        [Parameter(Mandatory)]
        [string] $ExecutablePath
    )

    $Param = '-S'
    $Output = & "$ExecutablePath" $Param 2>/dev/null
    $HttpdRootPath = (($Output | Select-String "ServerRoot" | Out-String).split('"')[1]).Replace('/', '\')
    $HttpdRootPath = $HttpdRootPath + '\'
    $Formatted = $HttpdRootPath.Replace('\\', '\')

    return $Formatted.Trim().Replace('\', '/')
}

function Get-RootServerConfigFile {
    param (
        [Parameter(Mandatory)]
        [string] $ExecutablePath
    )

    $HttpdRootPath = Get-HttpdRootPath -ExecutablePath $ExecutablePath
    $VersionTable = Get-ApacheVersionTable -ExecutablePath $ExecutablePath
    $RootServerConfigFile = (($VersionTable | Select-String -Pattern "SERVER_CONFIG_FILE" | Out-String).Split('"')[1]).Replace('/', '\')
    $RootServerConfigFile = $HttpdRootPath + $RootServerConfigFile
    $Formatted = $RootServerConfigFile.Replace('\\', '\')

    return $Formatted.Trim().Replace('\', '/')
}

function Get-Modules {
    param (
        [Parameter(Mandatory)]
        [string] $ExecutablePath
    )

    $Param = '-M'
    $Modules = & "$ExecutablePath" $Param 2>/dev/null

    return $Modules
}

function Get-VirtualHosts {
    param (
        [Parameter(Mandatory)]
        [string] $ExecutablePath
    )

    $Param = '-t'
    $Param2 = '-D'
    $Param3 = 'DUMP_VHOSTS'
    $VirtualHosts = & "$ExecutablePath" $Param $Param2 $Param3 2>/dev/null

    $Index = 0
    $VirtualHostArray = [System.Collections.ArrayList]@()
    $AddedVhosts = [System.Collections.ArrayList]@()
    foreach ($line in $VirtualHosts) {
        $IsHeader = $line | Select-String -Pattern "VirtualHost configuration" -Quiet
        if ($IsHeader -eq $true ) {
            continue
        }

        # Get the Path and
        $Original = $line -replace '(^.*\()', '' -replace '[()]', ''
        if ($IsLinux) {
            $Path = $Original.Split(':')[0]
            $LineNumber = $Original.Split(':')[1]
        }
        else {
            $Path = $Original.Split(':')[0] + ':' + $Original.Split(':')[1]
            $LineNumber = $Original.Split(':')[2]
        }

        if (-not(Test-Path -Path $Path -PathType Leaf)) {
            continue
        }

        if ($AddedVhosts.Contains($Original.ToString())) {
            continue
        }

        $TotalLines = (Get-Content -Path $Path).Length + 1
        $StartingLine = $TotalLines - $LineNumber
        $fileData = Get-Content -Path $Path -Tail $StartingLine

        $LineInFile = $LineNumber - 1
        $startPrinting = $false
        $LinesInBlock = [System.Collections.ArrayList]@()
        foreach ($line in $fileData) {
            $LineInFile++

            $isEnd = $line | Select-String -Pattern "\<\/VirtualHost>" | Select-String -Pattern '^\s{0,}#' -NotMatch
            if ($null -ne $isEnd -and $isEnd -ne "") {
                $startPrinting = $false
                $BlockLine = [PSCustomObject]@{
                    LineNumber = $LineInFile
                    Line       = $line
                }
                [void]$LinesInBlock.Add($BlockLine)
                break
            }

            $isStart = $line | Select-String -Pattern "\<VirtualHost.*\>" | Select-String -Pattern '^\s{0,}#' -NotMatch
            if ($null -ne $isStart -and $isStart -ne "") {
                $startPrinting = $true

                $SitePortLine = $line -replace '^\<VirtualHost\s+', '' -replace '>', ''
                $SitePortArray = $SitePortLine.Split(':')

                $SiteName = ($SitePortArray[0]).Trim()
                if ($SiteName -eq "*") {
                    $SiteName = "_default_"
                }

                $SitePort = ($SitePortArray[1]).Trim()
            }

            if ($startPrinting -eq $true) {
                $ServerNameLine = ($line | Select-String -Pattern "\bServerName\b.*" -Raw)
                if ($null -ne $ServerNameLine -and $ServerNameLine -ne "") {
                    $SiteName = ($ServerNameLine.Trim() -split "\s+")[1]
                }

                $BlockLine = [PSCustomObject]@{
                    LineNumber = $LineInFile
                    Line       = $line
                }
                [void]$LinesInBlock.Add($BlockLine)
            }
        }

        $VirtualHostObject = [PSCustomObject]@{
            SiteName           = $SiteName
            SitePort           = $SitePort
            Index              = $Index
            ConfigFile         = $Path
            StartingLineNumber = $LineNumber
            Block              = $LinesInBlock
        }

        [void]$AddedVhosts.Add($Original.ToString())
        [void]$VirtualHostArray.Add($VirtualHostObject)
        $Index++
    }

    if (($VirtualHostArray | Measure-Object).Count -eq 0) {
        $RootPath = Get-RootServerConfigFile $ExecutablePath
        $VirtualHostObject = [PSCustomObject]@{
            Index              = -1
            ConfigFile         = $RootPath
            StartingLineNumber = -1
            Block              = ""
        }

        [void]$VirtualHostArray.Add($VirtualHostObject)
    }

    # Add Root Server as additional VHOST.
    return $VirtualHostArray
}

function Get-ApacheInstances {
    $Index = 1
    $ApacheObjects = [System.Collections.ArrayList]@()
    $ExecutablePaths = [System.Collections.ArrayList]@()
    if ($IsLinux) {
        $ExecutablePaths = Get-ApacheUnixExecutablePaths
    }
    else {
        $ApacheServices = Get-CimInstance -Class Win32_Service | Where-Object { $_.Name -like '*Apache*' -and $_.State -like 'Running'}
        foreach ($service in $ApacheServices) {
            $ExecutablePath = ($service.PathName -split'"')[1]
            if ($ExecutablePath -eq "") {
                continue
            }

            if (-not (Test-Path -Path $ExecutablePath -PathType Leaf)) {
                # If the path parsed from the PathName is not a valid path does not lead to a file.
                continue
            }

            [void]$ExecutablePaths.Add($ExecutablePath)
        }
    }

    foreach ($executablePath in $ExecutablePaths) {
        $HttpdRootPath = Get-HttpdRootPath -ExecutablePath $executablePath
        $RootServerConfigFile = Get-RootServerConfigFile -ExecutablePath $executablePath
        $ConfigFilePaths = Get-ConfigFilePaths -ExecutablePath $executablePath
        $Modules = Get-Modules -ExecutablePath $executablePath
        $VirtualHosts = Get-VirtualHosts -ExecutablePath $executablePath

        $ApacheInstance = [PSCustomObject]@{
            Index                = $Index
            ExecutablePath       = $executablePath
            HttpdRootPath        = $HttpdRootPath
            RootServerConfigFile = $RootServerConfigFile
            ConfigFilePaths      = $ConfigFilePaths
            Modules              = $Modules
            VirtualHosts         = $VirtualHosts
        }

        [void]$ApacheObjects.Add($ApacheInstance)
        $Index++
    }

    return $ApacheObjects
}

function Get-ApacheModule {
    param (
        [Parameter(Mandatory)]
        [psobject] $ApacheInstance,
        [Parameter(Mandatory)]
        [string] $ModuleName
    )

    $Status = "Disabled"
    $ConfigFileLine = "Not Found"
    $LineNumber = "Not Found"
    $ConfigFile = "Not Found"

    if ($null -eq $ApacheInstance) {

        $Module = [PSCustomObject]@{
            Name           = $ModuleName
            Status         = $Status # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
            ConfigFileLine = $ConfigFileLine # Actual Line in the config file
            LineNumber     = $LineNumber
            ConfigFile     = $ConfigFile # Absolute File path
        }

        return $Module
    }

    $ModuleFound = $ApacheInstance.Modules | Select-String -Pattern $ModuleName
    if ($null -eq $ModuleFound -or $ModuleFound -eq "") {
        $Status = "Disabled"
    }
    else {
        $Status = "Enabled"
    }

    # Check the config files to see if the LoadModule Line with the module name is present.
    $Pattern = "LoadModule\b\s*$($ModuleName)\b"
    foreach ($aConfigFile in $ApacheInstance.ConfigFilePaths) {

        $Test = Select-String -Path $aConfigFile -Pattern $Pattern | Select-String -Pattern '^\s{0,}#' -NotMatch #| Select-Object -ExpandProperty Line,LineNumber
        if ($null -eq $Test -or $Test -eq "") {
            continue
        }

        $ConfigFileLine = $Test.Line
        $LineNumber = $Test.LineNumber
        $ConfigFile = $aConfigFile
        break
    }

    $Module = [PSCustomObject]@{
        Name           = $ModuleName
        Status         = $Status # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
        ConfigFileLine = $ConfigFileLine # Actual Line in the config file
        LineNumber     = $LineNumber
        ConfigFile     = $ConfigFile # Absolute File path
    }

    return $Module
}

function Get-ApacheDirectiveFromGlobalConfig {
    param (
        [Parameter(Mandatory)]
        [psobject] $ApacheInstance,
        [Parameter(Mandatory)]
        [string] $DirectiveName
    )

    $Status = "Not Found"
    $ConfigFileLine = "Not Found"
    $LineNumber = "Not Found"
    $ConfigFile = "Not Found"

    $FoundCount = 0
    $Pattern = "^\s*$($DirectiveName)\b.*$"
    $BackslashPattern = '\\$'
    $DirectivesFound = [System.Collections.ArrayList]@()
    foreach ($aConfigFile in $ApacheInstance.ConfigFilePaths) {
        $LineInFile = 0
        $startReading = $true
        $LineContinues = $false
        foreach ($line in Get-Content -Path $aConfigFile) {
            $LineInFile++

            $isStart = $line | Select-String -Pattern "\<VirtualHost.*\>" | Select-String -Pattern '^\s{0,}#' -NotMatch
            if ($null -ne $isStart -and $isStart -ne "") {
                $startReading = $false
            }

            $isEnd = $line | Select-String -Pattern "\<\/VirtualHost>" | Select-String -Pattern '^\s{0,}#' -NotMatch
            if ($null -ne $isEnd -and $isEnd -ne "") {
                $startReading = $true
                continue
            }

            if ($startReading -eq $true) {
                # This is where we would check for the directive.
                $Test = $line | Select-String -Pattern $Pattern | Select-String -Pattern '^\s{0,}#' -NotMatch
                $EOLBackslash = $line | Select-String -Pattern $BackslashPattern | Select-String -Pattern '^\s{0,}#' -NotMatch
                if ($null -eq $Test -or $Test -eq "") {
                    if ($LineContinues -eq $true) {
                        $line = $line -replace $BackslashPattern, ""
                        $Directive.ConfigFileLine += $line
                        $LineContinues = $false
                        if ( $null -ne $EOLBackslash -and $EOLBackslash -ne "") {
                            $LineContinues = $true
                        }
                    }
                }
                else {
                    #The directive exists
                    $Directive = [PSCustomObject]@{
                        Name           = $DirectiveName
                        Status         = "Found" # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
                        ConfigFileLine = $line.Trim() # Actual Line in the config file
                        LineNumber     = $LineInFile
                        ConfigFile     = $aConfigFile # Absolute File path
                        VirtualHost    = $null
                    }
                    [void]$DirectivesFound.Add($Directive)
                    $FoundCount++

                    if ( $null -ne $EOLBackslash -and $EOLBackslash -ne "") {
                        $LineContinues = $true
                        $Directive.ConfigFileLine = $Directive.ConfigFileLine -replace $BackslashPattern, ""
                    }
                }
            }
        }
    }

    #IF we STILL haven't found anything. Use our default values of not found.
    if ($FoundCount -le 0) {
        $Directive = [PSCustomObject]@{
            Name           = $DirectiveName
            Status         = $Status # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
            ConfigFileLine = $ConfigFileLine # Actual Line in the config file
            LineNumber     = $LineNumber
            ConfigFile     = $ConfigFile # Absolute File path
            VirtualHost    = $null
        }
        [void]$DirectivesFound.Add($Directive)
    }

    return $DirectivesFound
}

function Get-ApacheBlockFromGlobalConfig {
    param (
        [Parameter(Mandatory)]
        [psobject] $ApacheInstance,
        [Parameter(Mandatory)]
        [string] $BlockStart,
        [Parameter(Mandatory)]
        [string] $BlockEnd,
        [Parameter(Mandatory)]
        [string] $DirectiveName
    )

    $Status = "Not Found"
    $ConfigFileLine = "Not Found"
    $LineNumber = "Not Found"
    $ConfigFile = "Not Found"

    $Pattern = "^\s*$($DirectiveName)\b.*$"
    $DirectivesFound = [System.Collections.ArrayList]@()
    foreach ($aConfigFile in $ApacheInstance.ConfigFilePaths) {
        $LineInFile = 0
        $startReading = $true
        foreach ($line in Get-Content -Path $aConfigFile) {
            $LineInFile++

            $isStart = $line | Select-String -Pattern "\<VirtualHost.*\>" | Select-String -Pattern '^\s{0,}#' -NotMatch
            if ($null -ne $isStart -and $isStart -ne "") {
                $startReading = $false
                Continue
            }

            $isEnd = $line | Select-String -Pattern "\<\/VirtualHost>" | Select-String -Pattern '^\s{0,}#' -NotMatch
            if ($null -ne $isEnd -and $isEnd -ne "") {
                $startReading = $true
                continue
            }

            if ($startReading -eq $true) {
                $isBlockStart = $line | Select-String -Pattern "\<$BlockStart.*\>" | Select-String -Pattern '^\s{0,}#' -NotMatch
                if ($null -ne $isBlockStart -and $isBlockStart -ne "") {
                    $inBlock = $true
                }

                if ($inBlock -eq $true) {
                    # This is where we would check for the directive.
                    $found = $line | Select-String -Pattern $Pattern | Select-String -Pattern '^\s{0,}#' -NotMatch
                    if ($null -ne $found -and $found -ne "") {
                        $Directive = [PSCustomObject]@{
                            Name           = $DirectiveName
                            Status         = "Found" # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
                            ConfigFileLine = $line.Trim() # Actual Line in the config file
                            LineNumber     = $LineInFile
                            ConfigFile     = $aConfigFile # Absolute File path
                            VirtualHost    = $null
                        }
                        [void]$DirectivesFound.Add($Directive)
                    }

                    $isEnd = $line | Select-String -Pattern "\<\/$BlockEnd>" | Select-String -Pattern '^\s{0,}#' -NotMatch
                    if ($null -ne $isEnd -and $isEnd -ne "") {
                        $inBlock = $false
                    }
                }
            }
        }
    }

    #IF we STILL haven't found anything. Use our default values of not found.
    if (($DirectivesFound | Measure-Object).Count -le 0) {
        $Directive = [PSCustomObject]@{
            Name           = $DirectiveName
            Status         = $Status # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
            ConfigFileLine = $ConfigFileLine # Actual Line in the config file
            LineNumber     = $LineNumber
            ConfigFile     = $ConfigFile # Absolute File path
            VirtualHost    = $null
        }
        [void]$DirectivesFound.Add($Directive)
    }

    return $DirectivesFound
}

function Get-ApacheDirectiveFromVirtualBlock {
    param (
        [Parameter(Mandatory)]
        [psobject] $VirtualHost,
        [Parameter(Mandatory)]
        [string] $DirectiveName
    )

    $Status = "Not Found"
    $ConfigFileLine = "Not Found"
    $LineNumber = "Not Found"
    $ConfigFile = "Not Found"

    $FoundCount = 0
    $Pattern = "^\s*$($DirectiveName)\b.*$"
    $BackslashPattern = '\\$'
    $DirectivesFound = [System.Collections.ArrayList]@()
    if ($VirtualHost.Index -ne -1) {
        # We need to check the Virtual Host Block
        $LineContinues = $false
        foreach ($line in $VirtualHost.Block) {
            $Test = $line.Line | Select-String -Pattern $Pattern | Select-String -Pattern '^\s{0,}#' -NotMatch
            $EOLBackslash = $line.Line | Select-String -Pattern $BackslashPattern | Select-String -Pattern '^\s{0,}#' -NotMatch
            if ($null -eq $Test -or $Test -eq "") {
                if ($LineContinues -eq $true) {
                    $line.Line = $line.Line -replace $BackslashPattern, ""
                    $Directive.ConfigFileLine += $line.Line
                    $LineContinues = $false
                    if ( $null -ne $EOLBackslash -and $EOLBackslash -ne "") {
                        $LineContinues = $true
                    }
                }
                continue
            }

            $Directive = [PSCustomObject]@{
                Name           = $DirectiveName
                Status         = "Found" # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
                ConfigFileLine = $line.Line.Trim() # Actual Line in the config file
                LineNumber     = $line.LineNumber
                ConfigFile     = $VirtualHost.ConfigFile # Absolute File path
                VirtualHost    = $VirtualHost
            }
            [void]$DirectivesFound.Add($Directive)
            $FoundCount++

            if ( $null -ne $EOLBackslash -and $EOLBackslash -ne "") {
                $LineContinues = $true
                $Directive.ConfigFileLine = $Directive.ConfigFileLine -replace $BackslashPattern, ""
            }

        }
    }

    if ($FoundCount -le 0) {
        $Directive = [PSCustomObject]@{
            Name           = $DirectiveName
            Status         = $Status # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
            ConfigFileLine = $ConfigFileLine # Actual Line in the config file
            LineNumber     = $LineNumber
            ConfigFile     = $ConfigFile # Absolute File path
            VirtualHost    = $VirtualHost
        }
        [void]$DirectivesFound.Add($Directive)
    }

    return $DirectivesFound
}

function Get-ApacheBlockFromVirtualBlock {
    param (
        [Parameter(Mandatory)]
        [psobject] $VirtualHost,
        [Parameter(Mandatory)]
        [string] $BlockStart,
        [Parameter(Mandatory)]
        [string] $BlockEnd,
        [Parameter(Mandatory)]
        [string] $DirectiveName
    )

    $Status = "Not Found"
    $ConfigFileLine = "Not Found"
    $LineNumber = "Not Found"
    $ConfigFile = "Not Found"

    $FoundCount = 0
    $foundit = $false
    $inBlock = $false
    $Pattern = "^\s*$($DirectiveName)\b.*$"
    $DirectivesFound = [System.Collections.ArrayList]@()
    foreach ($line in $VirtualHost.Block) {
        $isStart = $line.line | Select-String -Pattern "\<$BlockStart.*\>" | Select-String -Pattern '^\s{0,}#' -NotMatch
        if ($null -ne $isStart -and $isStart -ne "") {
            $inBlock = $true
            $foundIt = $false
            Continue
        }

        if ($inBlock -eq $true) {
            # This is where we would check for the directive.
            $found = $line.line | Select-String -Pattern $Pattern | Select-String -Pattern '^\s{0,}#' -NotMatch
            if ($null -ne $found -and $found -ne "") {
                $foundIt = $true

                $Directive = [PSCustomObject]@{
                    Name           = $DirectiveName
                    Status         = "Found" # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
                    ConfigFileLine = $line.Line.Trim() # Actual Line in the config file
                    LineNumber     = $line.LineNumber
                    ConfigFile     = $VirtualHost.ConfigFile # Absolute File path
                    VirtualHost    = $VirtualHost
                }
                [void]$DirectivesFound.Add($Directive)
                $FoundCount++
            }

            $isEnd = $line.line | Select-String -Pattern "\<\/$BlockEnd>" | Select-String -Pattern '^\s{0,}#' -NotMatch
            if ($null -ne $isEnd -and $isEnd -ne "") {
                $inBlock = $false

                if ($foundIt -eq $false) {
                    $Directive = [PSCustomObject]@{
                        Name           = $DirectiveName
                        Status         = "Not Found" # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
                        ConfigFileLine = $ConfigFileLine
                        LineNumber     = $Linenumber
                        ConfigFile     = $VirtualHost.ConfigFile # Absolute File path
                        VirtualHost    = $VirtualHost
                    }
                    [void]$DirectivesFound.Add($Directive)
                }
            }
        }
    }

    if ($FoundCount -le 0) {
        $Directive = [PSCustomObject]@{
            Name           = $DirectiveName
            Status         = $Status # Can be 'Enabled', 'Disabled', 'Found', 'Not Found'
            ConfigFileLine = $ConfigFileLine # Actual Line in the config file
            LineNumber     = $LineNumber
            ConfigFile     = $ConfigFile # Absolute File path
            VirtualHost    = $VirtualHost
        }
        [void]$DirectivesFound.Add($Directive)
    }

    return $DirectivesFound
}

function Get-ApacheDirective {
    param (
        [Parameter(Mandatory)]
        [psobject] $ApacheInstance,
        [Parameter(Mandatory)]
        [AllowNull()]
        [psobject] $VirtualHost,
        [Parameter(Mandatory)]
        [string] $DirectiveName
    )

    $DirectivesFound = [System.Collections.ArrayList]@()
    if ($null -eq $VirtualHost) {
        # This will always be a server check.
        $DirectivesInGlobalConfig = [System.Collections.ArrayList]@(Get-ApacheDirectiveFromGlobalConfig -ApacheInstance $ApacheInstance -DirectiveName $DirectiveName)
        $DirectivesFound.AddRange($DirectivesInGlobalConfig)
        foreach ($vhost in $ApacheInstance.VirtualHosts) {
            if ($vhost.Index -eq -1) {
                continue
            }

            $DirectivesInVirtualHosts = [System.Collections.ArrayList]@(Get-ApacheDirectiveFromVirtualBlock -VirtualHost $vhost -DirectiveName $DirectiveName)
            $DirectivesFound.AddRange($DirectivesInVirtualHosts)
        }
    }
    else {
        $FoundCount = 0

        # This will execute if you pass in a Virtual Host to the funciton.
        # Check the Virtual Host for the Directive first.
        if ($VirtualHost.Index -ne -1) {
            $DirectivesInVirtualHosts = [System.Collections.ArrayList]@(Get-ApacheDirectiveFromVirtualBlock -VirtualHost $VirtualHost -DirectiveName $DirectiveName)
            $DirectivesFound.AddRange($DirectivesInVirtualHosts)

            # If the Directive is not found in the Virtual Host, set the FoundCount to 0 and move on.
            foreach ($found in $DirectivesInVirtualHosts) {
                if ($found.Status -eq "Not Found") {
                    $FoundCount = 0
                    break
                }

                $FoundCount++
            }
        }

        # If we haven't found anything in the Virtual Host, try to find it in the global config.
        if ($FoundCount -le 0) {
            # If nothing is found, check the config files ommiting Vhost blocks.
            $DirectivesInGlobalConfig = [System.Collections.ArrayList]@(Get-ApacheDirectiveFromGlobalConfig -ApacheInstance $ApacheInstance -DirectiveName $DirectiveName)
            $DirectivesFound.AddRange($DirectivesInGlobalConfig)
        }
    }

    return $DirectivesFound
}

function Get-ApacheDirectiveFromBlock {
    param (
        [Parameter(Mandatory)]
        [psobject] $ApacheInstance,
        [Parameter(Mandatory)]
        [AllowNull()]
        [psobject] $VirtualHost,
        [Parameter(Mandatory)]
        [string] $BlockStart,
        [Parameter(Mandatory)]
        [string] $BlockEnd,
        [Parameter(Mandatory)]
        [string] $DirectivePattern
    )

    $DirectivesFound = [System.Collections.ArrayList]@()
    if ($null -eq $VirtualHost) {
        # This will always be a server check.
        $DirectivesInGlobalConfig = [System.Collections.ArrayList]@(Get-ApacheBlockFromGlobalConfig -ApacheInstance $ApacheInstance -BlockStart $BlockStart -BlockEnd $BlockEnd -DirectiveName $DirectivePattern)
        $DirectivesFound.AddRange($DirectivesInGlobalConfig)
        foreach ($vhost in $ApacheInstance.VirtualHosts) {
            if ($vhost.Index -eq -1) {
                continue
            }

            $DirectivesInVirtualHosts = [System.Collections.ArrayList]@(Get-ApacheBlockFromVirtualBlock -VirtualHost $vhost -BlockStart $BlockStart -BlockEnd $BlockEnd -DirectiveName $DirectivePattern)
            $DirectivesFound.AddRange($DirectivesInVirtualHosts)
        }
    }
    else {
        $FoundCount = 0

        # This will execute if you pass in a Virtual Host to the funciton.
        # Check the Virtual Host for the Directive first.
        if ($VirtualHost.Index -ne -1) {
            $DirectivesInVirtualHosts = [System.Collections.ArrayList]@(Get-ApacheBlockFromVirtualBlock -VirtualHost $VirtualHost -BlockStart $BlockStart -BlockEnd $BlockEnd -DirectiveName $DirectivePattern)
            $DirectivesFound.AddRange($DirectivesInVirtualHosts)

            # If the Directive is not found in the Virtual Host, set the FoundCount to 0 and move on.
            foreach ($found in $DirectivesInVirtualHosts) {
                if ($found.Status -eq "Not Found") {
                    $FoundCount = 0
                    break
                }

                $FoundCount++
            }
        }

        # If we haven't found anyything in the Virtual Host, try to find it in the global config.
        if ($FoundCount -le 0) {
            # If nothing is found, check the config files ommiting Vhost blocks.
            $DirectivesInGlobalConfig = [System.Collections.ArrayList]@(Get-ApacheBlockFromGlobalConfig -ApacheInstance $ApacheInstance -BlockStart $BlockStart -BlockEnd $BlockEnd -DirectiveName $DirectivePattern)
            $DirectivesFound.AddRange($DirectivesInGlobalConfig)
        }
    }

    return $DirectivesFound
}

function Get-ApacheFormattedOutput {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [psobject[]] $FoundValues,
        [Parameter(Mandatory)]
        [string] $ExpectedValue,
        [Parameter(Mandatory = $false)]
        [bool] $IsInGlobalConfig,
        [Parameter(Mandatory = $false)]
        [bool] $IsInAllVirtualHosts
    )

    Process {
        $Output = "" # Start with a clean slate.
        foreach ($FoundValue in $FoundValues) {
            #This is a Directive
            if ($FoundValue.Status -eq "Found") {
                $Output += "Directive:`t`t`t$($FoundValue.Name)" | Out-String
                $Output += "Expected Value:`t$($ExpectedValue)" | Out-String
                $Output += "Detected Value:`t$($FoundValue.ConfigFileLine)" | Out-String
                $Output += "In File:`t`t`t$($FoundValue.ConfigFile)" | Out-String
                $Output += "On Line:`t`t`t$($FoundValue.LineNumber)" | Out-String

                if ($null -ne $FoundValue.VirtualHost) {
                    $Output += "Config Level:`t`tVirtual Host" | Out-String
                    $SiteName = $FoundValue.VirtualHost.SiteName + ":" + $FoundValue.VirtualHost.SitePort
                    $Output += "Site Name:`t`t$SiteName" | Out-String
                }
                else {
                    $Output += "Config Level:`t`tGlobal" | Out-String
                }
                $Output += "" | Out-String
            }
            #This is a Directive
            elseif ($FoundValue.Status -eq "Not Found") {
                if (((($null -eq $FoundValue.VirtualHost) -and ($IsInAllVirtualHosts -ne "$false")) -or (($null -ne $FoundValue.VirtualHost) -and ($IsInGlobalConfig -ne "$false")))) {

                    $Output += "Directive:`t`t`t$($FoundValue.Name)" | Out-String
                    $Output += "Expected Value:`t$($ExpectedValue)" | Out-String
                    $Output += "Detected Value:`t$($FoundValue.ConfigFileLine)" | Out-String

                    if ($null -ne $FoundValue.VirtualHost) {
                        $Output += "Config Level:`t`tVirtual Host" | Out-String
                        $SiteName = $FoundValue.VirtualHost.SiteName + ":" + $FoundValue.VirtualHost.SitePort
                        $Output += "Site Name:`t`t$SiteName" | Out-String
                    }
                    else {
                        $Output += "Config Level:`t`tGlobal" | Out-String
                    }
                    $Output += "" | Out-String
                }
            }
            else {
                #This is a Module (Should be  'Enabled' or 'Disabled')
                $Output += "Module:`t`t`t$($FoundValue.Name)" | Out-String
                $Output += "Expected Status:`t$($ExpectedValue)" | Out-String
                $Output += "Detected Status:`t$($FoundValue.Status)" | Out-String
                if ($FoundValue.ConfigFileLine -ne "Not Found") {
                    $Output += "Config File Line:`t$($FoundValue.ConfigFileLine)" | Out-String
                    $Output += "In File:`t`t`t$($FoundValue.ConfigFile)" | Out-String
                    $Output += "On Line:`t`t`t$($FoundValue.LineNumber)" | Out-String
                }
                $Output += "" | Out-String
            }
        }
        return $Output
    }
}

function Test-ApacheDirectiveInAllVirtualHosts {
    param (
        [Parameter(Mandatory)]
        [psobject] $ApacheInstance,
        [Parameter(Mandatory)]
        [psobject[]] $ApacheDirectives
    )

    $VhostCount = 0
    $VirtualHostArray = [System.Collections.ArrayList]@()
    $ApacheVhostsCount = ($ApacheInstance.VirtualHosts | Measure-Object).Count - 1 # -1 to exclude the global config.

    if ($ApacheVhostsCount -eq 0) {
        return $false
    }

    foreach ($directive in $ApacheDirectives) {
        if (($null -eq $directive.VirtualHost) -or ($directive.Status -eq "Not Found")) {
            continue
        }

        $SiteName = $directive.VirtualHost.SiteName + ":" + $directive.VirtualHost.SitePort

        if ($VirtualHostArray.Contains($SiteName)) {
            continue
        }

        $VhostCount++
        [void]$VirtualHostArray.Add($SiteName)
    }

    return ($VhostCount -eq $ApacheVhostsCount)
}

function Test-ApacheDirectiveInGlobal {
    param (
        [Parameter(Mandatory)]
        [psobject[]] $ApacheDirectives
    )

    foreach ($directive in $ApacheDirectives) {
        if ($null -eq $directive.VirtualHost) {
            return ($directive.Status -eq "Found")
        }
    }

    return $false
}

function Get-ApacheLogDirs {
    param (
        [Parameter(Mandatory)]
        [psobject] $ApacheInstance
    )

    $LogDirs = [System.Collections.ArrayList]@()
    $Null = Get-ChildItem -Path $ApacheInstance.HttpdRootPath -Directory | ForEach-Object {
        if ($_.Name -like "log*") {
            $LogDirs.Add($_.FullName)
        }
    }

    $LogLine = & "$($ApacheInstance.ExecutablePath)" -S

    # Assume we are dealing with a path.
    $PathPattern = '(?=[a-z|A-Z]\:)'
    $ErrorLogLine = (((($LogLine | Select-String -Pattern "ErrorLog:") -replace '"') -replace ".*ErrorLog\:\s+") -replace "Program Files", "PROGRA~1") -replace "Program Files \(x86\)", "PROGRA~2"
    $ErrorLogSplit = $ErrorLogLine -split $PathPattern

    $PipePattern = "\||\|\$"
    # Test for a pipe. It will look something like this "|C:\Some\Path\Here"  or "|$\Some\Path\Here"
    # If we split on white space, test the first path to see if it's a pipe.
    $IsPipePattern = [bool]($ErrorLogSplit[0] | Select-String -Pattern $PipePattern -Quiet)
    if ($IsPipePattern) {
        # At this point I feel like the best we can do is loop over the split values.
        # Skip the first value because we know it's the path to the piped executable.
        for ($i = 2; $i -le ($ErrorLogSplit | Measure-Object).Count; $i++) {
            if ([string]::IsNullOrEmpty($ErrorLogSplit[$i])) {
                continue
            }

            # Resolve the path to get rid of stuff like "PROGRA~1" for comparison.
            $SystemErrorLog = [System.IO.Path]::GetFullPath((Split-Path -Path $ErrorLogSplit[$i]))
            if (Test-Path -Path $SystemErrorLog -PathType Container) {
                if (-not ($LogDirs.Contains($SystemErrorLog))) {
                    [void]$LogDirs.Add($SystemErrorLog)
                }
            }
        }
    }
    else {
        $SystemErrorLog = [System.IO.Path]::GetFullPath((Split-Path -Path $ErrorLogLine))
        if (Test-Path -Path $SystemErrorLog -PathType Container) {
            if (-not ($LogDirs.Contains($SystemErrorLog))) {
                [void]$LogDirs.Add($SystemErrorLog)
            }
        }
    }

    return $LogDirs
}

############################################################
## Apache Functions                                        #
############################################################

############################################################
## ArcGIS Functions                                        #
############################################################

function Test-IsArcGISInstalled {
    $STIGRequired = $false
    Try {
		if (($PsVersionTable.PSVersion).ToString() -match "5.*") {
			$IsArcGISInstalled = (Get-WmiObject Win32_Process -Filter "Name= 'ArcGISServer.exe'" | ForEach-Object {Write-Output "$($_.Name)"})
		}
		else{
			$IsArcGISInstalled = ((Get-Process).ProcessName -Match "ArcGIS\s?Server" )
		}

		if ($IsArcGISInstalled) {
               $STIGRequired = $true
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

############################################################
## ArcGIS Functions                                        #
############################################################

############################################################
## Postgres Functions                                      #
############################################################

function Test-IsPostgresInstalled {
    $STIGRequired = $false
    Try {
        if ($IsLinux) {
            $IsPostgresInstalled = (ps f -opid','cmd -C 'postgres,postmaster' --no-headers)
			if($IsPostgresInstalled) {
				$STIGRequired = $true
			}
		}
		else {
			$IsPostgresInstalled = (Get-InstalledSoftware | Where-Object DisplayName -Like "Postgres*")
			if($IsPostgresInstalled){
				$STIGRequired = $true
			}
		}
	}

	Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

Function Get-ProcessCommandLine {
    Param (
        [Parameter(Mandatory = $false)]
        [int]$ProcessId,
        [Parameter(Mandatory = $false)]
        [string]$ProcessName
    )

    $retValue = ""
    $commandLine = ""

    if ($ProcessId -gt 0) {
        if (($PsVersionTable.PSVersion).ToString() -like "5.*") {
            $process = Get-WmiObject Win32_Process -Filter "ProcessId = '$($ProcessId)'" -ErrorAction SilentlyContinue | Select-Object ProcessId, CommandLine
            if ($null -ne $process) {
                $commandLine = ($process | Select-Object CommandLine).CommandLine
                if ([string]::IsNullOrEmpty($commandLine)) {
                    $commandLine = ""
                }
            }
        }
        else {
            $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
            if ($null -ne $process) {
                $commandLine = $process.CommandLine
                if ([string]::IsNullOrEmpty($commandLine)) {
                    $commandLine = ""
                }
            }
        }

        $retValue = "$($ProcessId)|$($commandLine)"
    }
    elseif ($null -ne $ProcessName -and $ProcessName -ne "") {
        if (($PsVersionTable.PSVersion).ToString() -like "5.*") {
            $process = Get-WmiObject Win32_Process -Filter "name LIKE '$($ProcessName)%'" -ErrorAction SilentlyContinue | Select-Object ProcessId, CommandLine
            if ($null -ne $process) {
                $retValue = $process | ForEach-Object {
                    $commandLine = $_.CommandLine
                    if ([string]::IsNullOrEmpty($commandLine)) {
                        $commandLine = ""
                    }
                    Write-Output "$($_.ProcessId)|$($commandLine)"
                }
            }
        }
        else {
            $process = Get-Process -Name "$($ProcessName)" -ErrorAction SilentlyContinue
            $retValue = $process | ForEach-Object {
                $commandLine = $_.CommandLine
                if ([string]::IsNullOrEmpty($commandLine)) {
                    $commandLine = ""
                }
                Write-Output "$($_.Id)|$($commandLine)"
            }
        }
    }

    return $retValue
}

############################################################
## Postgres Functions                                      #
############################################################

############################################################
## JBoss Functions                                         #
############################################################
function Test-IsJBossInstalled {
    $STIGRequired = $false
    Try {
        if ($IsLinux) {
            $IsJBossInstalled = (ps -ef | grep -i jboss.home.dir | grep -v grep)
            if ($IsJBossInstalled) {
                $STIGRequired = $true
            }
        }
        else {
			if (($PsVersionTable.PSVersion).ToString() -match "5.*") {
				$IsJBossInstalled = (Get-WmiObject Win32_Process -Filter "Name= 'java.exe'" -ErrorAction SilentlyContinue | ForEach-Object { if ($_.CommandLine | Select-String -Pattern "jboss.home.dir") {Write-Output "$($_.CommandLine)}" }})
			}
			else{
				$IsJBossInstalled = (Get-Process -Name "java" -ErrorAction SilentlyContinue | ForEach-Object { if ($_.CommandLine | Select-String -Pattern "jboss.home.dir") {Write-Output "$($_.Id) $($_.CommandLine)}" }})
			}

			if ($IsJBossInstalled) {
                $STIGRequired = $true
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

############################################################
## JBoss Functions                                         #
############################################################

############################################################
## Trellix ENS 10x Functions                                #
############################################################

function Get-TrellixOptDirs {
    return @(pgrep -f mfe | xargs ps -h -o cmd | Sort-Object -u | ForEach-Object { Split-Path -Path $_ })
}

function Test-IsTrellixInstalled {
    $STIGRequired = $false
    Try {
        if ($IsLinux) {
            $IsTrellixInstalled = ((Get-TrellixOptDirs | Measure-Object).Count -ge 1)
            $IsENSInstalled = (((find /opt -type d -name ens) | Measure-Object).Count -ge 1)
            if ($IsTrellixInstalled -eq $true -and $IsENSInstalled -eq $true) {
                $Parameters = "-i"
                $Exec = (find /opt -type f -name cmdagent)
                $AgentModeString = (Invoke-Expression "$($Exec) $($Parameters)") | Select-String -Pattern AgentMode -Raw
                if ($null -ne $AgentModeString -and $AgentModeString -ne "") {
                    $AgentMode = ($AgentModeString.Split(":")[1]).Trim()
                    if ($AgentMode -eq "0") {
                        $STIGRequired = $true
                    }
                }
            }
        }
        else {
            $RegistryPath = "HKLM:\SOFTWARE\McAfee\Endpoint\Common"
            $RegistryValueName = "ProductVersion"
            $IsVersionTenPlus = ((Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName).Value -Like "10.*")
            if ($IsVersionTenPlus -eq $true) {
                $RegistryPath = "HKLM:\SOFTWARE\WOW6432Node\McAfee\Agent"
                $RegistryValueName = "AgentMode"
                $AgentMode = (Get-RegistryResult -Path $RegistryPath -ValueName $RegistryValueName).Value
                if ($null -eq $AgentMode -or $AgentMode -eq "(NotFound)") {
                    $STIGRequired = $true
                }
                else {
                    $IsAgentModeZero = ($AgentMode -eq "0")
                    if ($IsAgentModeZero -eq $true) {
                        $STIGRequired = $true
                    }
                }
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

############################################################
## Trellix ENS 10x Functions                                #
############################################################

############################################################
## Apache Tomcat Functions                                 #
############################################################
function Test-IsTomcatInstalled {
    $STIGRequired = $false
    Try {
        if ($IsLinux) {
            $IsTomcatRunning = 0

            if ((Get-Process).ProcessName -match "tomcat") {
                $IsTomcatRunning += 1
            }

            Get-Process | ForEach-Object {
                if (($_.Name -match "^java\d{0,}\b") -and ($_.CommandLine -match "catalina.base|catalina.home")) {
                    $IsTomcatRunning += 1
                }
            }

            if ($IsTomcatRunning -gt 0) {
                $STIGRequired = $true
            }
        }
    }

    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}

############################################################
## Tomcat Functions                                      #
############################################################

############################################################
## Rancher RKE2 Functions                                  #
############################################################
Function Test-IsRKE2Installed {
    $STIGRequired = $false
    Try {
        If ($IsLinux) {
            If ((Get-Process).ProcessName -match "rke2 agent|rke2 server") {
                $STIGRequired = $true
            }
        }
    }
    Catch {
        Return $STIGRequired
    }

    Return $STIGRequired
}
############################################################
## Rancher RKE2 Functions                                  #
############################################################

# SIG # Begin signature block
# MIIL+QYJKoZIhvcNAQcCoIIL6jCCC+YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBBuP/k3JoG2+2j
# KXmMGIrZ+7DxzAVJCLCK60fRfXNynqCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCB7ChzGD2C68ZgbAv6VAmGzraZlcRmU
# I6K57ZIBo7WfBDANBgkqhkiG9w0BAQEFAASCAQBQSM4OIKFFxCqMmHMxnd7C3Soh
# jMaVPhTagA1LCcijxVBaBfJixy4sjm8XZuiHbFP6QitCjLGwBhAC7Cd1CC6e9t00
# nTv3LYusIu7qDSd2z8S08jYmsZzNeo+e4Rjiv+uysz8NAY2xPTr4mAnLYxKdRjbn
# wvUehjATtT+d7gsjIddosfyJ/4wnGMkqdXL4q++APbMs8Q8/vg401BEaQ6WL0WXz
# p0BSBeYJEjIssPUnldegxZp+impv9qj/2FrArRTitEDBpQ1okbF7p/0TKHRqi0YO
# YZjvQZsedmdarotbCfnuLuP6sVNtkjV3by5wyQJbzjbtXweriAkxOSruoxM8
# SIG # End signature block
