Function Get-CiscoShowTechData {
    Param (
        [Parameter(Mandatory = $true)]
        [psobject]$ShowTech,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Inventory", "RunningConfig", "Version")]
        [String]$DataType
    )

    Try {
        Switch ($DataType) {
            "Inventory" {
                #This pulls show inventory section from show tech config file
                $startSTR = "^-{18} show inventory -{18}"
                $endSTR = "^-{18} show *"
                $startIndex = ($ShowTech | Select-String $startSTR | Select-Object -First 1).LineNumber[0]
                $endIndex = ($ShowTech | Select-String ($ShowTech | Select-Object -Index ($startIndex..$ShowTech.Count) | Select-String $endSTR | Select-Object -First 1)[0]).LineNumber[0]
                $Result = $ShowTech | Select-Object -Index (($startIndex - 1)..($endIndex - 2))
            }
            "RunningConfig" {
                #This pulls show running-config section from show tech config file
                $startSTR = "^-{18} show running-config -{18}"
                $endSTR = "^-{18} show *"
                $startIndex = ($ShowTech | Select-String $startSTR | Select-Object -First 1).LineNumber[0]
                $endIndex = ($ShowTech | Select-String ($ShowTech | Select-Object -Index ($startIndex..$ShowTech.Count) | Select-String $endSTR | Select-Object -First 1)[0]).LineNumber[0]
                $Result = $ShowTech | Select-Object -Index (($startIndex - 1)..($endIndex - 2))
            }
            "Version" {
                #This pulls show version section from show tech config file
                Switch -Regex ($ShowTech) {
                    "^-{18} show version -{18}" {
                        $startSTR = "^-{18} show version -{18}"
                    }
                    # Maybe ASA here one day? {}
                }

                $endSTR = "^-{18} show *"
                $startIndex = ($ShowTech | Select-String $startSTR | Select-Object -First 1).LineNumber[0]
                $endIndex = ($ShowTech | Select-String ($ShowTech | Select-Object -Index ($startIndex..$ShowTech.Count) | Select-String $endSTR | Select-Object -First 1)[0]).LineNumber[0]
                $Result = $ShowTech | Select-Object -Index (($startIndex - 1)..($endIndex - 2))
            }
        }

        Return $Result
    }
    Catch {
        Return "Unable to find 'show version' section"
    }
}

Function Get-CiscoDeviceInfo {
    Param (
        [Parameter(Mandatory = $true)]
        [psobject]$ShowTech
    )

    Try {
        $Result = New-Object System.Collections.Generic.List[System.Object]

        # Get software information from Version data
        $ShowVersion = Get-CiscoShowTechData -ShowTech $ShowTech -DataType Version
        If ($ShowVersion) {
            # Determine software type
            Switch -Regex ($ShowVersion) {
                "^Cisco IOS[ -]XE [Ss]oftware, Copyright" {
                    $CiscoOS = "IOS-XE"
                }
                "^Cisco IOS [Ss]oftware," {
                    $CiscoOS = "IOS"
                }
            }
            If (-Not($CiscoOS)) {
                Throw "Unable to determine IOS type"
            }

            # Get software info
            $Pattern1 = "^Cisco IOS.*\(.*\), Version" # Pattern for line that has all of the info we need.
            $Pattern2 = ", Version .*\s{1}" # Pattern for Version
            $Pattern3 = "\s{1,}\w{1,}\s{1,}Software \(.*\)," # Pattern for Software
            $StartLine = ($ShowVersion | Select-String $Pattern1).LineNumber - 1
            $DeviceSoftwareInfo = ($ShowVersion[$($StartLine)].Split(",")).Trim()
            If ($ShowVersion[$($StartLine)] -match $Pattern2) {
                $CiscoOSVer = (($matches[0] -replace ",", "" -replace "Version\s{1,}", "").TrimStart()).Split(" ")[0]
            }
            Else {
                Throw "Unable to determine IOS version"
            }
            If ($ShowVersion[$($StartLine)] -match $Pattern3) {
                $CiscoSoftware = ($matches[0] -replace ",", "" -replace "\s{2,}", " ").Trim()
            }
            Else {
                Throw "Unable to determine Cisco software"
            }

            # Determine if Router Operating Mode exists
            If ($ShowVersion -match "Router Operating Mode") {
                $IsRouter = $true
            }

            # Get device type
            Switch -WildCard ($CiscoSoftware) {
                {($_ -like "*Switch*Software*")} {
                    $DeviceType = "Switch"
                }
                {($_ -like "*ASR*Software*") -or ($_ -like "*CSR*Software*") -or ($_ -like "*ISR*Software*") -or ($_ -like "*Virtual*XE*Software*") -or $IsRouter} {
                    $DeviceType = "Router"
                }
                Default {
                    Throw
                }
            }
        }
        Else {
            Throw "Unable to find 'Show Version' section"
        }

        # Get the serial number from Inventory data
        $Inventory = Get-CiscoShowTechData -ShowTech $ShowTech -DataType Inventory
        If ($Inventory) {
            Switch -Regex ($Inventory) {
                "Name: `"{1}Chassis`"{1}," {
                    $Model = ((($Inventory[($Inventory | Select-String "Name: `"{1}Chassis`"{1},").LineNumber]) -Split "PID:")[1] -split ",")[0].Trim()
                    $SerialNumber = (($Inventory[($Inventory | Select-String "Name: `"{1}Chassis`"{1},").LineNumber]) -Split "SN:")[1].Trim()
                }
                "Name: `"{1}Switch System`"{1}," {
                    $Model = ((($Inventory[($Inventory | Select-String "Name: `"{1}Switch System`"{1},").LineNumber]) -Split "PID:")[1] -split ",")[0].Trim()
                    $SerialNumber = (($Inventory[($Inventory | Select-String "Name: `"{1}Switch System`"{1},").LineNumber]) -Split "SN:")[1].Trim()
                }
                "Name: `"{1}\w{1,} Stack`"{1}" {
                    $Model = ((($Inventory[($Inventory | Select-String "Name: `"{1}\w{1,} Stack`"{1}").LineNumber]) -Split "PID:")[1] -split ",")[0].Trim()
                    $SerialNumber = (($Inventory[($Inventory | Select-String "Name: `"{1}\w{1,} Stack`"{1}").LineNumber]) -Split "SN:")[1].Trim()
                }
            }
        }
        Else {
            Throw "unable to find 'Show Inventory' section"
        }

        # Get hostname
        $Hostname = ((Get-CiscoShowTechData -ShowTech $ShowTech -DataType RunningConfig | Select-String -Pattern "^hostname" | Out-String).Replace("hostname", "")).Trim().ToUpper()
        If (-Not($Hostname)) {
            # If 'hostname' not found, try Device Name in Show Version
            $Hostname = ((Get-CiscoShowTechData -ShowTech $ShowTech -DataType Version | Select-String -Pattern "^\s*Device name:" | Out-String).Replace("Device name:", "")).Trim().ToUpper()
        }
        If (-Not($Hostname)) {
            # If 'hostname'STILL empty set static
            $Hostname = "NameNotFound"
        }

        # Get domain
        $DomainName = ((Get-CiscoShowTechData -ShowTech $ShowTech -DataType RunningConfig | Select-String -Pattern "^ip domain-name" | Out-String).Replace("ip domain-name", "")).Trim()

        # Get MAC (if available)
        $MACAddress = ((Get-CiscoShowTechData -ShowTech $ShowTech -DataType Version | Select-String -Pattern "^Base Ethernet MAC Address\s*:" | Out-String) -Replace "Base Ethernet MAC Address\s*:", "").Trim()

        # Put found data into an object and return it
        $NewObj = [PSCustomObject]@{
            Hostname      = $Hostname
            DomainName    = $DomainName
            MACAddress    = $MACAddress
            DeviceInfo    = $DeviceSoftwareInfo
            CiscoOS       = $CiscoOS
            CiscoOSVer    = $CiscoOSVer
            CiscoSoftware = $CiscoSoftware
            SerialNumber  = $SerialNumber
            Model         = $Model
            DeviceType    = $DeviceType
        }
        $Result.Add($NewObj)

        Return $Result
    }
    Catch {
        Return $_.Exception.Message
    }
}

Function Get-Section {
    param(
        [String[]] $configData,
        [String] $sectionName
    )

    $pattern = '(?:^(!)\s*$)|(?:^[\s]+(.+)$)'
    $inSection = $false
    ForEach ($line in $configData) {
        # Skip empty lines
        If ($line -match '^\s*$') {
            Continue
        }
        If ($line -eq $sectionName) {
            $inSection = $true
            Continue
        }
        If ($inSection) {
            If ($line -match $pattern) {
                [Regex]::Matches($line, $pattern) | ForEach-Object {
                    If ($_.Groups[1].Success) {
                        $_.Groups[1].Value
                    }
                    Else {
                        $_.Groups[2].Value
                    }
                }
            }
            Else {
                $inSection = $false
            }
            If (-not($inSection)) {
                Break
            }
        }
    }
}

Function Invoke-ConfigFileScan {
    Param (
        # Evaluate-STIG parameters
        [Parameter(Mandatory = $true)]
        [String[]]$CiscoConfig,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Unclassified", "Classified")]
        [String]$ScanType = "Unclassified",

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
        [Int]$ThrottleLimit = 10,

        # Config file scan parameters
        [Parameter(Mandatory = $true)]
        [String]$ESVersion,

        [Parameter(Mandatory = $true)]
        [String]$LogComponent,

        [Parameter(Mandatory = $true)]
        [String]$OSPlatform,

        [Parameter(Mandatory = $true)]
        [String] $ES_Path,

        [Parameter(Mandatory = $true)]
        [String] $PowerShellVersion,

        [Parameter(Mandatory = $true)]
        [String] $CiscoScanDir,

        [Parameter(Mandatory = $true)]
        [String] $CiscoWorkingDir
    )

    Try {
        $ConfigEvalStart = Get-Date
        $ProgressId = 1
        $ProgressActivity = "Evaluate-STIG (Version: $ESVersion | Scan Type: $ScanType | Answer Key: $AnswerKey)"

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
                {($_ -in @("String[]", "Object[]"))} {
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

        $STIGLog_Cisco = Join-Path -Path $CiscoScanDir -ChildPath "Evaluate-STIG_Cisco.log"
        If (Test-Path $STIGLog_Cisco) {
            Remove-Item $STIGLog_Cisco -Force
        }
        $STIGLog_STIGManager = Join-Path -Path $CiscoScanDir -ChildPath "Evaluate-STIG_STIGManager.log"
        If (Test-Path $STIGLog_STIGManager) {
            Remove-Item $STIGLog_STIGManager -Force
        }

        # Begin logging
        Write-Log -Path $STIGLog_Cisco -Message "Executing: $($CommandLine)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Cisco -Message "-" -TemplateMessage LineBreak-Dash -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

        # Verify Evaluate-STIG files integrity
        $Verified = $true
        Write-Log -Path $STIGLog_Cisco -Message "Verifying Evaluate-STIG file integrity" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        If (Test-Path (Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "FileList.xml")) {
            [XML]$FileListXML = Get-Content -Path (Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "FileList.xml")
            If ((Test-XmlSignature -checkxml $FileListXML -Force) -ne $true) {
                Write-Log -Path $STIGLog_Cisco -Message "ERROR: 'FileList.xml' failed authenticity check. Unable to verify content integrity." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
            }
            Else {
                ForEach ($File in $FileListXML.FileList.File) {
                    $Path = (Join-Path -Path $ES_Path -ChildPath $File.Path | Join-Path -ChildPath $File.Name)
                    If (Test-Path $Path) {
                        If ((Get-FileHash -Path $Path -Algorithm SHA256).Hash -ne $File.SHA256Hash) {
                            $Verified = $false
                            Write-Log -Path $STIGLog_Cisco -Message "WARNING: '$($Path)' failed integrity check." -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                        }
                    }
                    Else {
                        If ($File.ScanReq -eq "Required") {
                            $Verified = $false
                            Write-Log -Path $STIGLog_Cisco -Message "ERROR: '$($File.Name)' is a required file but not found. Scan results may be incomplete." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                        }
                    }
                }
                If ($Verified -eq $true) {
                    Write-Log -Path $STIGLog_Cisco -Message "Evaluate-STIG file integrity check passed." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                }
                Else {
                    Write-Log -Path $STIGLog_Cisco -Message "WARNING: One or more Evaluate-STIG files failed integrity check." -WriteOutToStream -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                }
            }
        }
        Else {
            Throw "'FileList.xml' not found."
        }

        # Schema Files
        $STIGList_xsd = Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "Schema_STIGList.xsd"
        $AnswerFile_xsd = Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "Schema_AnswerFile.xsd"
        $Checklist_xsd = Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "U_Checklist_Schema_V2.xsd"
        $Checklist_json = Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "CKLB.schema.json"
        If (-Not(Test-Path $STIGList_xsd)) {
            Throw "'$STIGList_xsd' - file not found."
        }
        ElseIf (-Not(Test-Path $AnswerFile_xsd)) {
            Throw "'$AnswerFile_xsd' - file not found."
        }
        ElseIf (-Not(Test-Path $Checklist_xsd)) {
            Throw "'$Checklist_xsd' - file not found."
        }
        ElseIf (-Not(Test-Path $Checklist_json)) {
            Throw "'$Checklist_json' - file not found."
        }

        # STIGList.xml validation
        $XmlFile = Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "STIGList.xml"
        If (-Not(Test-Path $XmlFile)) {
            Throw "'$XmlFile' - file not found."
        }
        Else {
            $Result = Test-XmlValidation -XmlFile $XmlFile -SchemaFile $STIGList_xsd
            If ($Result -ne $true) {
                ForEach ($Item in $Result.Message) {
                    Write-Log -Path $STIGLog_Cisco -Message $Item -Component $LogComponent -Type "Error" -WriteOutToStream -OSPlatform $OSPlatform
                }
                Throw "'$($XmlFile)' failed XML validation"
            }
        }

        Write-Log -Path $STIGLog_Cisco -Message "Evaluate-STIG Version: $ESVersion" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Cisco -Message "Launching User: $([Environment]::Username)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Cisco -Message "OS Platform: $OSPlatform" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Cisco -Message "PS Version: $PowerShellVersion" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Cisco -Message "Scan Type: $ScanType" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Cisco -Message "Answer Key: $AnswerKey" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Cisco -Message "Answer File Path: $AFPath" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Cisco -Message "Output Path: $OutputPath" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Cisco -Message "-" -TemplateMessage LineBreak-Dash -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

        # ++++++++++++++++++++++ Begin processing ++++++++++++++++++++++
        Write-Progress -Id $ProgressId -Activity $ProgressActivity -Status "Initializing and generating list of required STIGs"

        # --- Begin Answer File validation
        Write-Log -Path $STIGLog_Cisco -Message "Validating answer files" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        $AnswerFileList = New-Object System.Collections.Generic.List[System.Object]
        $XmlFiles = Get-ChildItem -Path $AFPath | Where-Object Extension -EQ ".xml"
        # Verify answer files for proper format
        ForEach ($Item in $XmlFiles) {
            $Validation = (Test-XmlValidation -XmlFile $Item.FullName -SchemaFile $AnswerFile_xsd)
            If ($Validation -eq $true) {
                Write-Log -Path $STIGLog_Cisco -Message "$($Item.Name) : Passed" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                [XML]$Content = Get-Content $Item.FullName
                If ($Content.STIGComments.Name) {
                    $NewObj = [PSCustomObject]@{
                        STIG          = $Content.STIGComments.Name
                        Name          = $Item.Name
                        FullName      = $Item.FullName
                        LastWriteTime = $Item.LastWriteTime
                    }
                    $AnswerFileList.Add($NewObj)
                }
            }
            Else {
                Write-Log -Path $STIGLog_Cisco -Message "ERROR: $($Item.Name) : Error - Answer file failed schema validation and will be ignored.  Please correct or remove." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                Write-Log -Path $STIGLog_Cisco -Message "$($Validation.Message)" -Component $LogComponent -Type "Error" -WriteOutToStream -OSPlatform $OSPlatform
                Write-Host ""
            }
        }
        $AnswerFileList = $AnswerFileList | Sort-Object LastWriteTime -Descending
        Write-Log -Path $STIGLog_Cisco -Message "-" -TemplateMessage LineBreak-Dash -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        # --- End Answer File validation

        # Build list of valid configs to scan
        [XML]$STIGList = Get-Content (Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath "STIGList.xml")
        $STIGsToDetect = New-Object System.Collections.Generic.List[System.Object]

        If ($SelectSTIG) {
            ForEach ($Item in $SelectSTIG) {
                If (($STIGList.List.STIG | Where-Object ShortName -EQ $Item).AssetType -notin @('Cisco')) {
                    Write-Log -Path $STIGLog_Cisco -Message "WARNING: Scan for '$(($STIGList.List.STIG | Where-Object ShortName -EQ $Item).Name)' request with SelectSTIG but cannot be performed in this context. Ignoring." -WriteOutToStream -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                }
                Else {
                    $Node = $STIGList.List.STIG | Where-Object ShortName -EQ $Item
                    $NewObj = [PSCustomObject]@{
                        Name           = $Node.Name
                        Shortname      = $Node.ShortName
                        StigContent    = $Node.StigContent
                        DetectionCode  = $Node.DetectionCode
                        PsModule       = $Node.PsModule
                        PsModuleVer    = $Node.PsModuleVer
                        CanCombine     = $Node.CanCombine
                        Classification = $Node.Classification
                        Deprecated     = [System.Convert]::ToBoolean($Node.Deprecated)
                        Forced         = $false
                    }
                    $STIGsToDetect.Add($NewObj)
                }
            }
        }
        Else {
            ForEach ($Node in ($STIGList.List.STIG | Where-Object {($_.AssetType -in @("Cisco") -and $_.ShortName -notin $ExcludeSTIG)})) {
                $NewObj = [PSCustomObject]@{
                    Name           = $Node.Name
                    Shortname      = $Node.ShortName
                    StigContent    = $Node.StigContent
                    DetectionCode  = $Node.DetectionCode
                    PsModule       = $Node.PsModule
                    PsModuleVer    = $Node.PsModuleVer
                    CanCombine     = $Node.CanCombine
                    Classification = $Node.Classification
                    Deprecated     = [System.Convert]::ToBoolean($Node.Deprecated)
                    Forced         = $false
                }
                $STIGsToDetect.Add($NewObj)
            }
        }

        If ($ForceSTIG) {
            ForEach ($Item in $ForceSTIG) {
                If (($STIGList.List.STIG | Where-Object ShortName -EQ $Item).AssetType -notin @("Cisco")) {
                    Write-Log -Path $STIGLog_Cisco -Message "WARNING: Scan for '$(($STIGList.List.STIG | Where-Object ShortName -EQ $Item).Name)' request with -ForceSTIG but cannot be performed in this context. Ignoring." -WriteOutToStream -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                }
                Else {
                    If ($STIGsToDetect.ShortName -eq $Item) {
                        ($STIGsToDetect | Where-Object Shortname -EQ $Item).Forced = $true
                    }
                    Else {
                        $Node = $STIGList.List.STIG | Where-Object ShortName -EQ $Item
                        $NewObj = [PSCustomObject]@{
                            Name           = $Node.Name
                            Shortname      = $Node.ShortName
                            StigContent    = $Node.StigContent
                            DetectionCode  = $Node.DetectionCode
                            PsModule       = $Node.PsModule
                            PsModuleVer    = $Node.PsModuleVer
                            CanCombine     = $Node.CanCombine
                            Classification = $Node.Classification
                            Deprecated     = [System.Convert]::ToBoolean($Node.Deprecated)
                            Forced         = $true
                        }
                        $STIGsToDetect.Add($NewObj)
                    }
                }
            }
        }
        If (-Not($STIGsToDetect)) {
            Throw "No config file based STIGs selected to scan."
        }
        $ConfigFiles = New-Object System.Collections.Generic.List[System.Object]
        Write-Log -Path $STIGLog_Cisco -Message "Looking for supported Cisco files" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Host "Refer to '$($CiscoScanDir)\Evaluate-STIG_Cisco.log' for info on detected files" -ForegroundColor DarkGray
        ForEach ($Item in $CiscoConfig) {
            [System.GC]::Collect()
            $CurrentSubStep = 1
            Write-Progress $ProgressId -Activity $ProgressActivity -Status "Looking for supported Cisco files in $Item"
            $Files = Get-ChildItem $Item -Recurse -File
            ForEach ($File in $Files.FullName) {
                $TCLOutput = $false
                Write-Progress -Id ($ProgressId + 1) -ParentId $ProgressId -Activity " " -Status $File -PercentComplete ($CurrentSubStep / $Files.Count * 100)
                $ShowTech = [System.IO.File]::OpenText($File).ReadToEnd() -split "`r`n" -split "`r" -split "`n"
                # If 'show inventory', 'show running-config', and 'show version' sections do not exist then this file isn't a valid show tech-support file.
                If (-Not(($ShowTech | Select-String "^-{18} show inventory -{18}") -and ($ShowTech | Select-String "^-{18} show running-config -{18}") -and ($ShowTech | Select-String "^-{18} show version -{18}"))) {
                    Write-Log -Path $STIGLog_Cisco -Message "ERROR: Unsupported file : $($File) [Not an output produced by Get-ESCiscoConfig.tcl or 'show tech-support'.]" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    Continue
                }

                # If this is an Evaluate-STIG TCL output file, get just the Evaluate-STIG section.
                $startSTR = "^-{18} Show Evaluate-STIG Cisco .* -{18}$"
                $endSTR = "^-{18} End Evaluate-STIG Cisco Configuration -{18}$"
                If (($ShowTech | Select-String $startSTR) -and ($ShowTech | Select-String $endSTR)) {
                    $TCLOutput = $true
                    $startIndex = ($ShowTech | Select-String $startSTR | Select-Object -First 1).LineNumber
                    $endIndex = ($ShowTech | Select-String ($ShowTech | Select-Object -Index ($startIndex..$ShowTech.Count) | Select-String $endSTR | Select-Object -First 1)[0]).LineNumber
                    $ShowTech = $ShowTech | Select-Object -Index (($startIndex - 1)..($endIndex - 1))
                }

                $DeviceInfo = Get-CiscoDeviceInfo -ShowTech $ShowTech
                If (($DeviceInfo).DeviceType -notin @("Router", "Switch")) {
                    Write-Log -Path $STIGLog_Cisco -Message "ERROR: Unsupported file : $($File) [File is not from a supported device. Refer to the supported STIGs list.]" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                }
                Else {
                    If ($File -notin $ConfigFiles.File) {
                        If ($TCLOutput -eq $true) {
                            Write-Log -Path $STIGLog_Cisco -Message "Supported TCL file : $($File)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        }
                        Else {
                            Write-Log -Path $STIGLog_Cisco -Message "WARNING: Supported Non-TCL file : $($File) [Please consider generating output with Get-ESCiscoConfig.tcl for maximum compatibility.]" -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                        }
                        $NewObj = [PSCustomObject]@{
                            ShowTech          = $ShowTech
                            DeviceInfo        = $DeviceInfo
                            ShowRunningConfig = $(Get-CiscoShowTechData -ShowTech $ShowTech -DataType RunningConfig)
                            File              = $File
                        }
                        $ConfigFiles.Add($NewObj)
                    }
                }
                $CurrentSubStep++
                Write-Progress -Id ($ProgressId + 1) -ParentId $ProgressId -Activity " " -Completed
            }
        }
        Write-Log -Path $STIGLog_Cisco -Message "-" -TemplateMessage LineBreak-Dash -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Progress -Id $ProgressId -Activity $ProgressActivity -Completed

        # Create runspace pool to include required modules.
        $runspaces = New-Object System.Collections.ArrayList
        $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $SessionState.ImportPSModule($(Join-Path -Path $ES_Path -ChildPath Modules | Join-Path -ChildPath Master_Functions))
        $SessionState.ImportPSModule($(Join-Path -Path $ES_Path -ChildPath Modules | Join-Path -ChildPath Cisco_Functions))
        $RunspacePool = [runspacefactory]::CreateRunspacePool(1, $throttlelimit, $SessionState, $Host)
        $RunspacePool.Open()
        $RunspaceResults = @{}

        # Create pipeline input and output (results) object
        $RSObject = New-Object 'System.Management.Automation.PSDataCollection[PSObject]'

        ForEach ($Item in $ConfigFiles) {
            # Build arguments hashtable
            $HashArguments = @{
                ShowTech          = $($Item.ShowTech)
                ShowRunningConfig = $($Item.ShowRunningConfig)
                DeviceInfo        = $($Item.DeviceInfo)
                CiscoConfig       = $($Item.File)
                ScanType          = $($ScanType)
                VulnTimeout       = $($VulnTimeout)
                AFPath            = $($AFPath)
                AnswerKey         = $($AnswerKey)
                OutputPath        = $($OutputPath)
                ESVersion         = $($ESVersion)
                LogComponent      = $($LogComponent)
                OSPlatform        = $($OSPlatform)
                ES_Path           = $($ES_Path)
                PowerShellVersion = $($PowerShellVersion)
                CiscoWorkingDir   = $($CiscoWorkingDir)
                Checklist_xsd     = $($Checklist_xsd)
                Checklist_json    = $($Checklist_json)
                STIGsToDetect     = $($STIGsToDetect)
                STIGLog_Cisco     = $($STIGLog_Cisco)
                CiscoConfigLog    = $(Join-Path -Path $CiscoWorkingDir -ChildPath "Evaluate-STIG_Cisco_$(Split-Path $Item.File -Leaf).log")
            }
            If ($Marking) {
                $HashArguments.Add("Marking", $Marking)
            }
            If ($Output) {
                $HashArguments.Add("Output", $Output)

                If (($Output -split ",").Trim() -match @("(^CKL$|^CKLB$|^CombinedCKL$|^CombinedCKLB$|^Summary$|^OQE$)")) {
                    $HashArguments.Add("PreviousToKeep", $PreviousToKeep)
                }

                If ("STIGManager" -in $Output) {
                    if ($SMPassphrase){
                        $HashArguments.Add("SMPassphrase", $SMPassphrase)
                    }
                    if ($SMCollection){
                        $HashArguments.Add("SMCollection", $SMCollection)
                    }
                }
            }
            If ($AllowDeprecated) {
                $HashArguments.Add("AllowDeprecated", $true)
            }
            If ($SelectSTIG) {
                $HashArguments.Add("SelectSTIG", $SelectSTIG)
            }
            If ($SelectVuln) {
                $HashArguments.Add("SelectVuln", $SelectVuln)
            }
            If ($ExcludeVuln) {
                $HashArguments.Add("ExcludeVuln", $ExcludeVuln)
            }
            If ($ForceSTIG) {
                $HashArguments.Add("ForceSTIG", $ForceSTIG)
            }
            If ($AnswerFileList) {
                $HashArguments.Add("AnswerFileList", $AnswerFileList)
            }

            $CiscoBlock = {
                Param (
                    # Evaluate-STIG parameters
                    $ShowTech,
                    $ShowRunningConfig,
                    $DeviceInfo,
                    $ScanType,
                    $Marking,
                    $VulnTimeout,
                    $AFPath,
                    $AnswerKey,
                    $Output,
                    $OutputPath,
                    $PreviousToKeep,
                    $SMPassphrase,
                    $SMCollection,
                    $AllowDeprecated,
                    $SelectSTIG,
                    $SelectVuln,
                    $ExcludeVuln,
                    $ForceSTIG,
                    $ThrottleLimit,
                    # Config file scan parameters
                    $ESVersion,
                    $LogComponent,
                    $OSPlatform,
                    $ES_Path,
                    $PowerShellVersion,
                    $Checklist_xsd,
                    $Checklist_json,
                    $CiscoWorkingDir,
                    $CiscoConfigLog,
                    $STIGLog_Cisco,
                    $CiscoConfig,
                    $STIGsToDetect,
                    $AnswerFileList
                )

                Try {
                    $EvalStart = Get-Date
                    $ScanStartDate = (Get-Date -Format "MM/dd/yyyy")
                    If (Test-Path $CiscoConfigLog) {
                        Remove-Item $CiscoConfigLog -Force
                    }
                    Write-Log -Path $CiscoConfigLog -Message "Begin Config File Logging" -TemplateMessage LineBreak-Text -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                    $ProgressPreference = "SilentlyContinue"
                    [int]$TotalMainSteps = 1
                    [int]$CurrentMainStep = 1
                    $STIGsToProcess = New-Object System.Collections.Generic.List[System.Object]
                    ForEach ($Node in $STIGsToDetect) {
                        If ($Node.DetectionCode -and (Invoke-Expression $Node.DetectionCode) -eq $true) {
                            If ((Test-STIGDependencyFiles -RootPath $ES_Path -STIGData $Node -LogPath $CiscoConfigLog -OSPlatform $OSPlatform) -eq $true) {
                                If ($AnswerFileList | Where-Object {($_.STIG -eq $Node.ShortName -or $_.STIG -eq $Node.Name)}) {
                                    $AFtoUse = ($AnswerFileList | Where-Object {($_.STIG -eq $Node.ShortName -or $_.STIG -eq $Node.Name)})[0]
                                }
                                Else {
                                    $AFtoUse = ""
                                }
                                $NewObj = [PSCustomObject]@{
                                    Name           = $Node.Name
                                    Shortname      = $Node.ShortName
                                    StigContent    = $Node.StigContent
                                    AnswerFile     = $AFtoUse
                                    PsModule       = $Node.PsModule
                                    PsModuleVer    = $Node.PsModuleVer
                                    CanCombine     = $Node.CanCombine
                                    Classification = $Node.Classification
                                    Deprecated     = [System.Convert]::ToBoolean($Node.Deprecated)
                                    Forced         = $false
                                }
                                $STIGsToProcess.Add($NewObj)
                            }
                        }
                        ElseIf ($Node.Forced -eq $true) {
                            Write-Log -Path $CiscoConfigLog -Message "WARNING: Scan for '$($Node.Name)' forced with -ForceSTIG. Evaluate-STIG results are not guaranteed with this option. Use at own risk." -WriteOutToStream -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                            If ((Test-STIGDependencyFiles -RootPath $ES_Path -STIGData $Node -LogPath $CiscoConfigLog -OSPlatform $OSPlatform) -eq $true) {
                                If ($AnswerFileList | Where-Object {($_.STIG -eq $Node.ShortName -or $_.STIG -eq $Node.Name)}) {
                                    $AFtoUse = ($AnswerFileList | Where-Object {($_.STIG -eq $Node.ShortName -or $_.STIG -eq $Node.Name)})[0]
                                }
                                Else {
                                    $AFtoUse = ""
                                }
                                $NewObj = [PSCustomObject]@{
                                    Name           = $Node.Name
                                    Shortname      = $Node.ShortName
                                    StigContent    = $Node.StigContent
                                    AnswerFile     = $AFtoUse
                                    PsModule       = $Node.PsModule
                                    PsModuleVer    = $Node.PsModuleVer
                                    CanCombine     = $Node.CanCombine
                                    Classification = $Node.Classification
                                    Deprecated     = [System.Convert]::ToBoolean($Node.Deprecated)
                                    Forced         = $true
                                }
                                $STIGsToProcess.Add($NewObj)
                            }
                        }
                    }
                    $CurrentSubStep++
                    [int]$TotalMainSteps = $TotalMainSteps + $STIGsToProcess.Count

                    $MachineName = $DeviceInfo.Hostname
                    $WorkingDir = Join-Path -Path $CiscoWorkingDir -ChildPath $MachineName
                    If (Test-Path $WorkingDir) {
                        Remove-Item $WorkingDir -Recurse -Force
                    }
                    $null = New-Item -Path $WorkingDir -ItemType Directory -ErrorAction Stop

                    If ($OutputPath) {
                        If ($SelectVuln) {
                            $ResultsPath = Join-Path -Path $OutputPath -ChildPath "_Partial_$MachineName"
                        }
                        Else {
                            $ResultsPath = Join-Path -Path $OutputPath -ChildPath $MachineName
                        }
                    }

                    Write-Log -Path $CiscoConfigLog -Message "Hostname: $MachineName" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    Write-Log -Path $CiscoConfigLog -Message "File: $($CiscoConfig)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    Write-Log -Path $CiscoConfigLog -Message "Executing scan" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                    $STIGLog = Join-Path -Path $WorkingDir -ChildPath "Evaluate-STIG.log"
                    If ($Marking) {
                        Write-Log -Path $STIGLog -Message "                                                                                          $Marking                                                                                          " -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    }
                    Write-Log -Path $STIGLog -Message "Begin Local Logging" -TemplateMessage LineBreak-Text -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    Write-Log -Path $STIGLog -Message "Evaluate-STIG Version: $ESVersion" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    Write-Log -Path $STIGLog -Message "Launching User: $([Environment]::Username)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    Write-Log -Path $STIGLog -Message "Hostname: $MachineName" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    Write-Log -Path $STIGLog -Message "File: $($CiscoConfig)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    Write-Log -Path $STIGLog -Message "Cisco OS: $($DeviceInfo.CiscoOS) ($($DeviceInfo.CiscoOSVer))" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    Write-Log -Path $STIGLog -Message "Cisco Software: $($DeviceInfo.CiscoSoftware)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    Write-Log -Path $STIGLog -Message "Cisco Model: $($DeviceInfo.Model)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    Write-Log -Path $STIGLog -Message "Device Type: $($DeviceInfo.DeviceType)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    Write-Log -Path $STIGLog -Message "-" -TemplateMessage LineBreak-Dash -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                    # Write list of STIGs that will be evaluated to log
                    ForEach ($STIG in ($STIGsToProcess | Where-Object Forced -EQ $true)) {
                        Write-Log -Path $STIGLog -Message "WARNING: Scan for '$($Node.Name)' forced with -ForceSTIG. Evaluate-STIG results are not guaranteed with this option. Use at own risk." -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                    }
                    Write-Log -Path $STIGLog -Message "The following STIGs will be evaluated:" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    ForEach ($STIG in $STIGsToProcess) {
                        Write-Log -Path $STIGLog -Message "STIG: $($STIG.Name)  |  AnswerFile: $($STIG.AnswerFile.Name)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                    }
                    Write-Log -Path $STIGLog -Message "-" -TemplateMessage LineBreak-Dash -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                    # If no supported STIGs are applicable, log it and continue
                    If (($STIGsToProcess | Measure-Object).Count -eq 0) {
                        Write-Log -Path $STIGLog -Message "WARNING: $($CiscoConfig) : No Evaluate-STIG supported STIGs are applicable to this system." -WriteOutToStream -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                        Write-Log -Path $CiscoConfigLog -Message "WARNING: No Evaluate-STIG supported STIGs are applicable to this system." -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                        Write-Log -Path $CiscoConfigLog -Message "End Config File Logging" -TemplateMessage LineBreak-Text -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                        Add-Content -Path $STIGLog_Cisco -Value $(Get-Content $CiscoConfigLog)
                        Remove-Item $CiscoConfigLog

                        $TempFiles = Get-Item -Path $WorkingDir
                        If ($TempFiles) {
                            ForEach ($Item in $TempFiles) {
                                Try {
                                    $null = Remove-Item -Path $Item.FullName -Recurse -ErrorAction Stop
                                }
                                Catch {
                                    Write-Log -Path $STIGLog -Message "$($_.Exception.Message)" -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                                    Write-Log -Path $CiscoConfigLog -Message "$($_.Exception.Message)" -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                                }
                            }
                        }
                    }
                    Else {
                        Write-Log -Path $STIGLog -Message "Applicable STIGs to process - $(($STIGsToProcess | Measure-Object).Count)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                        # Test connectivity to OutputPath and create folder for computer
                        Try {
                            If (($Output -split ",").Trim() -match @("(^CKL$|^CKLB$|^CombinedCKL$|^CombinedCKLB$|^Summary$|^OQE$)")) {
                                If (-Not(Test-Path $ResultsPath)) {
                                    $null = New-Item $ResultsPath -ItemType Directory -ErrorAction Stop
                                    Start-Sleep 5
                                }
                            }
                        }
                        Catch {
                            Write-Log -Path $STIGLog -Message "ERROR: Failed to create output path $($ResultsPath)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                            Throw $_
                        }

                        # =========== Run the scans ===========
                        If (($Output -split ",").Trim() -match @("(^CKL$|^CKLB$|^CombinedCKL$|^CombinedCKLB$|^Summary$|^OQE$)")) {
                            # $tmpResultsPath is needed for all filetype Outputs needed for all filetype Outputs
                            $tmpResultsPath = $(Join-Path -Path $WorkingDir -ChildPath "Results")
                            If (-Not(Test-Path $tmpResultsPath)) {
                                $null = New-Item -Path $tmpResultsPath -ItemType Directory
                            }
                        }

                        $ScanObjects = [System.Collections.Generic.List[System.Object]]::new()
                        $ScanJobs = [System.Collections.Generic.List[System.Object]]::new()
                        ForEach ($Item in $STIGsToProcess) {
                            $SubJobs = [System.Collections.Generic.List[System.Object]]::new()

                            # Set path to STIG .xccdf.xml and get needed data from it
                            $StigXmlPath = $(Join-Path -Path $ES_Path -ChildPath "StigContent" | Join-Path -ChildPath $Item.StigContent)
                            $STIGID = ((Select-Xml -Path $StigXmlPath -XPath "/" | Select-Object -ExpandProperty Node).Benchmark.id).Trim()
                            $STIGTitle = ((Select-Xml -Path $StigXmlPath -XPath "/" | Select-Object -ExpandProperty Node).Benchmark.Title).Trim()
                            $STIGVer = ((Select-Xml -Path $StigXmlPath -XPath "/" | Select-Object -ExpandProperty Node).Benchmark.Version).Trim()
                            $STIGRel = ((((Select-Xml -Path $StigXmlPath -XPath "/" | Select-Object -ExpandProperty Node).Benchmark.'plain-text' | Where-Object { $_.id -eq "release-info" }).'#text' -split 'Benchmark')[0].Trim() -split ' ')[1].Trim()
                            $STIGDate = (((Select-Xml -Path $StigXmlPath -XPath "/" | Select-Object -ExpandProperty Node).Benchmark.'plain-text' | Where-Object { $_.id -eq "release-info" }).'#text' -split 'Date:')[1].Trim()
                            $STIGVersion = "V$($STIGVer)R$($STIGRel)"

                            # Build STIGInfo Object
                            $STIGInfo = [ordered]@{
                                STIGID      = $STIGID
                                Title       = $STIGTitle
                                Version     = $STIGVer
                                Release     = $STIGRel
                                ReleaseDate = $STIGDate
                            }

                            # Build TargetData Object
                            $TargetData = Get-AssetData -OSPlatform Cisco -Marking $Marking -ShowRunningConfig $ShowRunningConfig -DeviceInfo $DeviceInfo
                            $TargetData.Add("WebOrDatabase", $false) # Initialize 'WebOrDatabase'.  If required, set below.
                            $TargetData.Add("Site", "")              # Initialize 'Site'.  If required, set below.
                            $TargetData.Add("Instance", "")          # Initialize 'Instance'.  If required, set below.

                            $STIGData = @{
                                StigXmlPath = $StigXmlPath
                                StigVersion = $STIGVersion
                                Name        = $Item.Name
                                ShortName   = $Item.ShortName
                                PsModule    = $Item.PsModule
                                CanCombine  = $Item.CanCombine
                            }

                            # Reset WebOrDatabase, Site, and Instance for each STIG.
                            $TargetData.WebOrDatabase = $false
                            $TargetData.Site = ""
                            $TargetData.Instance = ""

                            # Set parameters for Invoke-STIGScan
                            $ScanArgs = @{
                                StigXmlPath = $StigXmlPath
                                VulnTimeout = $VulnTimeout
                                Deprecated  = $Item.Deprecated
                                SelectVuln  = $SelectVuln
                                ExcludeVuln = $ExcludeVuln
                                Forced      = $Item.Forced
                                ModulesPath = $(Join-Path -Path $ES_Path -ChildPath "Modules")
                                PsModule    = $Item.PsModule
                                LogPath     = $STIGLog
                                OSPlatform  = $OSPlatform
                                ProgressId  = $ProgressId
                                ModuleArgs  = @{} # Initialze ModuleArgs object
                            }

                            # Set common arguments for scan module.  Additional variables and parameters may be added.
                            $ScanArgs.ModuleArgs.Add("ScanType", $ScanType)
                            if ($Item.AnswerFile.FullName) {
                                $ScanArgs.ModuleArgs.Add("AnswerFile", "'$($Item.AnswerFile.FullName)'")
                            }
                            else {
                                $ScanArgs.ModuleArgs.Add("AnswerFile", "")
                            }
                            $ScanArgs.ModuleArgs.Add("AnswerKey", $AnswerKey)
                            $ScanArgs.ModuleArgs.Add("Username", "NA")
                            $ScanArgs.ModuleArgs.Add("UserSID", "NA")
                            $ScanArgs.ModuleArgs.Add("ESVersion", $ESVersion)
                            $ScanArgs.ModuleArgs.Add("LogPath", $STIGLog)
                            $ScanArgs.ModuleArgs.Add("OSPlatform", $OSPlatform)
                            $ScanArgs.ModuleArgs.Add("LogComponent", $LogComponent)

                            # Add additional module arguments
                            $ScanArgs.ModuleArgs.Add("DeviceInfo", $DeviceInfo)
                            $ScanArgs.ModuleArgs.Add("ShowTech", $ShowTech)
                            $ScanArgs.ModuleArgs.Add("ShowRunningConfig", $ShowRunningConfig)

                            # Set output filename
                            $BaseFileName = "$($TargetData.HostName)_$($STIGData.ShortName)_$($STIGData.StigVersion)" -replace "\s+", "_"

                            # Build and add sub job
                            $NewObj = [PSCustomObject]@{
                                BaseFileName = $BaseFileName
                                STIGInfo     = $STIGInfo
                                TargetData   = $TargetData
                                ScanArgs     = $ScanArgs
                            }
                            $SubJobs.Add($NewObj)

                            # Add scan job
                            $NewObj = [PSCustomObject]@{
                                STIGData = $STIGData
                                SubJobs  = $SubJobs
                            }
                            $ScanJobs.Add($NewObj)
                        }

                        # Execute the scans
                        $FailedCheck = $false
                        ForEach ($Job in $ScanJobs) {
                            Try {
                                Write-Log -Path $STIGLog -Message "-" -TemplateMessage LineBreak-Dash -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                $CurrentMainStep++

                                Write-Log -Path $STIGLog -Message "Invoking scan" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                $ModError = ""
                                Try {
                                    Write-Log -Path $STIGLog -Message "Importing scan module: $($Job.STIGData.PsModule)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                    If ($PowerShellVersion -lt [Version]"7.0") {
                                        Import-Module (Join-Path -Path $ES_Path -ChildPath "Modules" | Join-Path -ChildPath $($Job.STIGData.PsModule)) -ErrorAction Stop
                                    }
                                    Else {
                                        Import-Module (Join-Path -Path $ES_Path -ChildPath "Modules" | Join-Path -ChildPath $($Job.STIGData.PsModule)) -SkipEditionCheck -ErrorAction Stop
                                    }
                                    $PsModule = (Get-Module $Job.STIGData.PsModule)
                                    Write-Log -Path $STIGLog -Message "Module Version: $($PsModule.Version)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                }
                                Catch {
                                    $ModError = $_.Exception.Message
                                }

                                If ($ModError) {
                                    # If module failed to import, display reason and continue to next STIG.
                                    Write-Log -Path $STIGLog -Message "ERROR: $($ModError)" -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                                }
                                Else {
                                    # Build ESData Object
                                    $ESData = [Ordered]@{
                                        ESVersion     = $ESVersion
                                        StartTime     = (Get-Date -Format 'o')
                                        ModuleName    = $PsModule.Name
                                        ModuleVersion = $PsModule.Version
                                        STIGName      = $Job.STIGData.Name
                                        STIGShortName = $Job.STIGData.ShortName
                                        CanCombine    = $Job.STIGData.CanCombine
                                        STIGXMLName   = $($Job.STIGData.StigXmlPath | Split-Path -Leaf)
                                        FileName      = ""
                                    }

                                    # Set filename and additional requirements
                                    ForEach ($SubJob in $Job.SubJobs) {
                                        # Update BaseFileName if -SelectVuln is used
                                        If ($SelectVuln) {
                                            $SubJob.BaseFileName = "Partial_$($SubJob.BaseFileName)"
                                        }

                                        # Write Site/Intance info to log
                                        If ($SubJob.TargetData.Site) {
                                            Write-Log -Path $STIGLog -Message "Site: $($SubJob.TargetData.Site)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                        }
                                        If ($SubJob.TargetData.Instance) {
                                            Write-Log -Path $STIGLog -Message "Instance: $($SubJob.TargetData.Instance)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                        }

                                        # Execute scan
                                        $ScanArgs = $SubJob.ScanArgs
                                        $VulnResults = Invoke-STIGScan @ScanArgs

                                        # Look for any failed checks
                                        If ($VulnResults | Where-Object CheckError -EQ $true) {
                                            $FailedCheck = $true
                                        }

                                        # Build ScanObject
                                        $ScanObject = [System.Collections.Generic.List[System.Object]]::new()
                                        $NewObj = [PSCustomObject]@{
                                            ESData      = $ESData
                                            STIGInfo    = $SubJob.STIGInfo
                                            TargetData  = $SubJob.TargetData
                                            VulnResults = $VulnResults
                                        }
                                        $ScanObject.Add($NewObj)

                                        # Send ScanObject to outputs (CKL, CKLB)
                                        If (($Output -split ",").Trim() -match @("(^CKL$|^CKLB$|^CombinedCKL$|^CombinedCKLB$)")) {
                                            $tmpChecklistPath = Join-Path -Path $tmpResultsPath -ChildPath "Checklist"
                                            If (-Not(Test-Path $tmpChecklistPath)) {
                                                $null = New-Item -Path $tmpChecklistPath -ItemType Directory
                                            }
                                            $GenerateSingleCKL = $false
                                            $GenerateSingleCKLB = $false
                                            If ("CKL" -in $Output -or $STIGManager) {
                                                $GenerateSingleCKL = $true
                                            }
                                            If ("CombinedCKL" -in $Output) {
                                                If ($ScanObject.ESData.CanCombine -ne $true) {
                                                    $GenerateSingleCKL = $true
                                                }
                                            }
                                            If ("CKLB" -in $Output) {
                                                $GenerateSingleCKLB = $true
                                            }
                                            If ("CombinedCKLB" -in $Output) {
                                                If ($ScanObject.ESData.CanCombine -ne $true) {
                                                    $GenerateSingleCKLB = $true
                                                }
                                            }

                                            If ($GenerateSingleCKL) {
                                                Write-Log -Path $STIGLog -Message "Creating CKL file" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                                Write-Log -Path $STIGLog -Message "ESPath : $ES_Path" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                                $SaveFile = $(Join-Path -Path $tmpChecklistPath -ChildPath "$($SubJob.BaseFileName)_$(Get-Date -Format yyyyMMdd-HHmmss).ckl")
                                                $ChecklistValid = Format-CKL -SchemaPath $Checklist_xsd -ScanObject $ScanObject -OutputPath $SaveFile -Marking $Marking -WorkingDir $WorkingDir -ESPath $ES_Path -OSPlatform $OSPlatform -LogComponent $LogComponent

                                                # Action for validation result
                                                If ($ChecklistValid) {
                                                    $ScanObject.ESData.FileName = $(Split-Path $SaveFile -Leaf)
                                                }
                                            }

                                            If ($GenerateSingleCKLB) {
                                                Write-Log -Path $STIGLog -Message "Creating CKLB file" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                                $SaveFile = $(Join-Path -Path $tmpChecklistPath -ChildPath "$($SubJob.BaseFileName)_$(Get-Date -Format yyyyMMdd-HHmmss).cklb")
                                                $ChecklistValid = Format-CKLB -SchemaPath $Checklist_json -ScanObject $ScanObject -OutputPath $SaveFile -WorkingDir $WorkingDir -ESPath $ES_Path -OSPlatform $OSPlatform -LogComponent $LogComponent

                                                # Action for validation result
                                                If ($ChecklistValid) {
                                                    $ScanObject.ESData.FileName = $(Split-Path $SaveFile -Leaf)
                                                }
                                            }
                                        }
                                        # Add to ScanObjects object console or combined checklist output
                                        $ScanObjects.Add($ScanObject)
                                    }

                                    Write-Log -Path $STIGLog -Message "Removing scan module from memory" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                    Remove-Module $Job.STIGData.PsModule -Force

                                    [System.GC]::Collect()
                                }
                            }
                            Catch {
                                Write-Log -Path $STIGLog -Message "    $($_.Exception.Message)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                                Write-Log -Path $STIGLog -Message "    $($_.InvocationInfo.ScriptName)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                                Write-Log -Path $STIGLog -Message "    Line: $($_.InvocationInfo.ScriptLineNumber)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                                Write-Log -Path $STIGLog -Message "    $(($_.InvocationInfo.Line).Trim())" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                                Write-Log -Path $STIGLog -Message "Continuing Processing" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                                [System.GC]::Collect()
                            }
                        }

                        # Create combined checklists
                        If (($Output -split ",").Trim() -match @("(^CombinedCKL$|^CombinedCKLB$)")) {
                            Write-Log -Path $STIGLog -Message "-" -TemplateMessage  LineBreak-Dash  -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                            If ("CombinedCKL" -in $Output) {
                                Write-Log -Path $STIGLog -Message "Creating combined CKL file" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                # Set combined checklist filename
                                If ($SelectVuln) {
                                    $SaveFile = $(Join-Path -Path $tmpChecklistPath -ChildPath "Partial_$($MachineName)_COMBINED_$(Get-Date -Format yyyyMMdd-HHmmss).ckl")
                                }
                                Else {
                                    $SaveFile = $(Join-Path -Path $tmpChecklistPath -ChildPath "$($MachineName)_COMBINED_$(Get-Date -Format yyyyMMdd-HHmmss).ckl")
                                }
                                Format-CKL -SchemaPath $Checklist_xsd -ScanObject $ScanObjects -OutputPath $SaveFile -Marking $Marking -WorkingDir $WorkingDir -ESPath $ES_Path -OSPlatform $OSPlatform -LogComponent $LogComponent
                            }
                            If ("CombinedCKLB" -in $Output) {
                                Write-Log -Path $STIGLog -Message "Creating combined CKLB file" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                                # Set combined checklist filename
                                If ($SelectVuln) {
                                    $SaveFile = $(Join-Path -Path $tmpChecklistPath -ChildPath "Partial_$($MachineName)_COMBINED_$(Get-Date -Format yyyyMMdd-HHmmss).cklb")
                                }
                                Else {
                                    $SaveFile = $(Join-Path -Path $tmpChecklistPath -ChildPath "$($MachineName)_COMBINED_$(Get-Date -Format yyyyMMdd-HHmmss).cklb")
                                }
                                Format-CKLB -SchemaPath $Checklist_json -ScanObject $ScanObjects -OutputPath $SaveFile -WorkingDir $WorkingDir -ESPath $ES_Path -OSPlatform $OSPlatform -LogComponent $LogComponent
                            }
                        }

                        If ($FailedCheck -eq $true) {
                            Write-Log -Path $STIGLog -Message "Please report issues to https://spork.navsea.navy.mil/nswc-crane-division/evaluate-stig/-/issues" -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                        }

                        # Send results to STIG Manager
                        If ("STIGManager" -in $Output) {
                            Write-Log -Path $STIGLog -Message "-" -TemplateMessage  LineBreak-Dash  -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                            Try {
                                Import-Module (Join-Path -Path $ES_Path -ChildPath "Modules" | Join-Path -ChildPath "STIGManager_Functions") -SkipEditionCheck -ErrorAction Stop

                                if ($SMPassphrase){
                                    $SMImport_Params = Get-SMParameters -SMCollection $SMCollection -SMPassphrase $SMPassphrase -ScanObject $ScanObjects -ScriptRoot $ES_Path -WorkingDir $WorkingDir -OSPlatform $OSPlatform -LogComponent $LogComponent -Logpath $STIGLog
                                }
                                else{
                                    $SMImport_Params = Get-SMParameters -SMCollection $SMCollection -ScanObject $ScanObjects -ScriptRoot $ES_Path -WorkingDir $WorkingDir -OSPlatform $OSPlatform -LogComponent $LogComponent -Logpath $STIGLog
                                }

                                Import-Asset @SMImport_Params

                                # Copy Evaluate-STIG_STIGManager.log to results path
                                Copy-Item $(Join-Path -Path $WorkingDir -ChildPath "Evaluate-STIG_STIGManager.log") -Destination $ResultsPath -Force -ErrorAction Stop
                            }
                            Catch {
                                Write-Log -Path $STIGLog -Message "ERROR: $($_.Exception.Message)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                            }
                        }

                        Write-Log -Path $STIGLog -Message "-" -TemplateMessage LineBreak-Dash -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                        If ($Output -contains "Summary") {
                            # Create summary report
                            Write-Log -Path $STIGLog -Message "Generating summary report" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                            if ($Marking) {
                                Write-SummaryReport -ScanResult $ScanObjects -OutputPath $tmpResultsPath -ProcessedUser "NA" -Detail -OSPlatform $OSPlatform -ScanStartDate $ScanStartDate -ScanType $ScanType -Marking $Marking
                            }
                            else {
                                Write-SummaryReport -ScanResult $ScanObjects -OutputPath $tmpResultsPath -ProcessedUser "NA" -Detail -OSPlatform $OSPlatform -ScanStartDate $ScanStartDate -ScanType $ScanType
                            }

                            # Create Summary HTML
                            $SummaryFile = Join-Path -Path $tmpResultsPath -ChildPath SummaryReport.xml
                            [xml]$TempSR = New-Object xml

                            $null = $TempSR.AppendChild($TempSR.CreateElement('Summaries'))
                            $summary = New-Object xml
                            $Summary.Load($SummaryFile)
                            $ImportedSummary = $TempSR.ImportNode($Summary.DocumentElement, $true)
                            $null = $TempSR.DocumentElement.AppendChild($ImportedSummary)

                            $TempSR.Summaries.Summary.Results.Result | ForEach-Object {
                                #Build STIG name
                                $STIGName = [String]"$($_.STIG -replace '_', ' ') V$($_.Version)R$($_.Release)"
                                If ($_.Site) {
                                    $STIGName = $STIGName + " ($($_.Site))"
                                }
                                If ($_.Instance) {
                                    $STIGName = $STIGName + " ($($_.Instance))"
                                }
                                $_.SetAttribute("STIG", $STIGName)
                                $_.SetAttribute("StartTime", [String]($_.StartTime -replace "\.\d+", ""))
                                $CurrentScoreNode = $_.AppendChild($TempSR.CreateElement('CurrentScore'))
                                $CurrentScore = ([int]$_.CAT_I.NotAFinding + [int]$_.CAT_II.NotAFinding + [int]$_.CAT_III.NotAFinding + [int]$_.CAT_I.Not_Applicable + [int]$_.CAT_II.Not_Applicable + [int]$_.CAT_III.Not_Applicable) / ([int]$_.CAT_I.Total + [int]$_.CAT_II.Total + [int]$_.CAT_III.Total)
                                $CurrentScoreNode.SetAttribute("Score", $CurrentScore)
                            }
                            $TempSR.Save($(Join-Path -Path $WorkingDir -ChildPath TempSR.xml))

                            $SummaryReportXLST = New-Object System.XML.Xsl.XslCompiledTransform
                            $SummaryReportXLST.Load($(Join-Path -Path $ES_Path -ChildPath "xml" | Join-Path -ChildPath SummaryReport.xslt))
                            $SummaryReportXLST.Transform($(Join-Path -Path $WorkingDir -ChildPath TempSR.xml), $(Join-Path -Path $tmpResultsPath -ChildPath SummaryReport.html))

                            if ($Marking) {
                                #Add Marking Header and Footer
                                $SRHTML = $(Join-Path -Path $tmpResultsPath -ChildPath SummaryReport.html)
                                (Get-Content $SRHTML) -replace "<body>", "<body>`n    <header align=`"center`">$Marking</header>" | Set-Content $SRHTML

                                Add-Content $(Join-Path -Path $tmpResultsPath -ChildPath SummaryReport.html) "<footer align=`"center`">$Marking</footer>"
                            }
                        }

                        # Manage previous results and move results to ResultsPath
                        If (($Output -split ",").Trim() -match @("(^CKL$|^CKLB$|^CombinedCKL$|^CombinedCKLB$|^Summary$|^OQE$)")) {
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
                                Initialize-PreviousProcessing -ResultsPath $ResultsPath -PreviousToKeep $PreviousToKeep @PreviousArgs -LogPath $STIGLog -LogComponent $LogComponent -OSPlatform $OSPlatform
                            }
                            Else {
                                Initialize-PreviousProcessing -ResultsPath $ResultsPath -PreviousToKeep $PreviousToKeep -LogPath $STIGLog -LogComponent $LogComponent -OSPlatform $OSPlatform
                            }

                            # Move results to ResultsPath
                            Write-Log -Path $STIGLog -Message "-" -TemplateMessage LineBreak-Dash -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                            Write-Log -Path $STIGLog -Message "Copying output files to $ResultsPath" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                            Get-ChildItem $tmpResultsPath -Recurse | ForEach-Object {
                                If ($_.PSIsContainer) {
                                    If (-Not(Test-Path $(Join-Path $ResultsPath -ChildPath $_.Name))) {
                                        $null = New-Item -Path $(Join-Path $ResultsPath -ChildPath $_.Name) -ItemType Directory
                                    }
                                }
                                Else {
                                    Copy-Item -Path $_.FullName -Destination $(Join-Path -Path $ResultsPath -ChildPath $(($_.DirectoryName) -ireplace [regex]::Escape($tmpResultsPath), ""))
                                }
                            }
                        }

                        # Clean up
                        Invoke-ScanCleanup -WorkingDir $WorkingDir -Logpath $STIGLog -OSPlatform $OSPlatform -LogComponent $LogComponent

                        # Finalize log and get totals
                        $TimeToComplete = New-TimeSpan -Start $EvalStart -End (Get-Date)
                        $FormatedTime = "{0:c}" -f $TimeToComplete
                        Write-Log -Path $STIGLog -Message "Done!" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        Write-Log -Path $STIGLog -Message "Total Time : $($FormatedTime)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        If ($Output -and ($Output -notcontains "STIGManager")) {
                            $TotalChecklists = (Get-ChildItem -Path "$ResultsPath\Checklist" | Where-Object Extension -In @(".ckl", ".cklb") | Measure-Object).Count
                            Write-Log -Path $STIGLog -Message "Total checklists in Results Directory : $($TotalChecklists)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        }
                        Write-Log -Path $STIGLog -Message "End Local Logging" -TemplateMessage LineBreak-Text -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        If ($Marking) {
                            Write-Log -Path $STIGLog -Message "                                                                                          $Marking                                                                                          " -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        }
                        Write-Log -Path $CiscoConfigLog -Message "Scan completed" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        Write-Log -Path $CiscoConfigLog -Message "Total Time : $($FormatedTime)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                        Write-Log -Path $CiscoConfigLog -Message "End Config File Logging" -TemplateMessage LineBreak-Text -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

                        Add-Content -Path $STIGLog_Cisco -Value $(Get-Content $CiscoConfigLog)
                        Remove-Item $CiscoConfigLog

                        # Copy Evaluate-STIG.log to results path
                        If ($Output -and ($Output -notcontains "STIGManager")) {
                            Copy-Item $STIGLog -Destination $ResultsPath -Force -ErrorAction Stop
                        }

                        # Remove temporary files
                        If (Test-Path $(Join-Path -Path $WorkingDir -ChildPath Bad_CKL)) {
                            $TempFiles = Get-Item -Path $WorkingDir\* -Exclude Evaluate-STIG.log, Bad_CKL
                        }
                        ElseIf (-Not($Output)) {
                            $TempFiles = Get-Item -Path $WorkingDir\* -Exclude Evaluate-STIG.log
                        }
                        Else {
                            $TempFiles = Get-Item -Path $WorkingDir
                        }
                        If ($TempFiles) {
                            ForEach ($Item in $TempFiles) {
                                Try {
                                    $null = Remove-Item -Path $Item.FullName -Recurse -ErrorAction Stop
                                }
                                Catch {
                                    Write-Log -Path $STIGLog -Message "$($_.Exception.Message)" -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                                    Write-Log -Path $CiscoConfigLog -Message "$($_.Exception.Message)" -Component $LogComponent -Type "Warning" -OSPlatform $OSPlatform
                                }
                            }
                        }

                        $ProgressPreference = "Continue"

                        # Build ScanResult
                        $ScanResult = @{}
                        $ScanResult.Add($MachineName, $ScanObjects)

                        Return $ScanResult
                    }
                }
                Catch {
                    Write-Log -Path $STIGLog -Message "ERROR: $($_.Exception.Message)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    Write-Log -Path $STIGLog -Message "Terminated Processing" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    Write-Log -Path $CiscoConfigLog -Message "ERROR: $($_.Exception.Message)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    Write-Log -Path $CiscoConfigLog -Message "Terminated Processing" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
                    Write-Log -Path $CiscoConfigLog -Message "End Config File Logging" -TemplateMessage LineBreak-Text -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
                }
            }

            $Job = [powershell]::Create().AddScript($CiscoBlock).AddParameters($HashArguments)
            $Job.Streams.ClearStreams()
            $Job.RunspacePool = $RunspacePool

            # Create a temporary collection for each runspace
            $temp = "" | Select-Object Job, Runspace, Hostname
            $Temp.Hostname = $Item.DeviceInfo.Hostname
            $temp.Job = $Job
            $temp.Runspace = [PSCustomObject]@{
                Instance = $Job
                State    = $Job.BeginInvoke($RSObject, $RSObject)
            }
            $null = $runspaces.Add($temp)
        }

        if (($runspaces | Measure-Object).count -gt 0) {
            Get-RunspaceData -Runspaces $Runspaces -Wait -Usage Cisco
        }

        # Add to results
        ForEach ($Object in $RSObject.Keys) {
            $RunspaceResults.Add($Object,$RSObject.$Object)
        }

        $RunspacePool.Close()
        $RunspacePool.Dispose()

        $TimeToComplete = New-TimeSpan -Start $ConfigEvalStart -End (Get-Date)
        $FormatedTime = "{0:c}" -f $TimeToComplete
        Write-Host "Done!" -ForegroundColor Green
        Write-Host "Total Time : $($FormatedTime)" -ForegroundColor Green
        Write-Host ""
        If (($Output -split ",").Trim() -match @("(^CKL$|^CKLB$|^CombinedCKL$|^CombinedCKLB$|^Summary$|^OQE$)")) {
            Write-Host "Results saved to " -ForegroundColor Green -NoNewline; Write-Host "$($OutputPath)" -ForegroundColor Cyan
            Write-Host ""
        }

        Return $RunspaceResults
    }
    Catch {
        Write-Log -Path $STIGLog_Cisco -Message "    $($_.Exception.Message)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Cisco -Message "    $($_.InvocationInfo.ScriptName)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Cisco -Message "    Line: $($_.InvocationInfo.ScriptLineNumber)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
        Write-Log -Path $STIGLog_Cisco -Message "    $(($_.InvocationInfo.Line).Trim())" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
        Throw $_
    }
}

# SIG # Begin signature block
# MIIL+QYJKoZIhvcNAQcCoIIL6jCCC+YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB1MRx7bKQ/6vBw
# rkaonSIXVy89+Kl2lhLROd9pjIWFu6CCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCAou/7nnGF5r2bsXWfKr3HEtMTlu71
# 6Cl51vGH5EIV7zANBgkqhkiG9w0BAQEFAASCAQA8H707rthLPPdRT/vK3K1eTi4V
# v7xrV1FFFMbhrIEbl2CrxOKIS15bc7ZR0HDwAl4kqBLx/WyGYZkQoCR4my+xRO64
# sHR+3x/xFP9NR8G/5mfijbNuHi/yZN0ZDr8/leeeZmERGEZR/R8sRaCvZKQ7eGi0
# 1ILmdHOlZoTqR64LHgEAfokivayYiDhR1BuFpkXpL/a3Y1VArsdrCxSfX+u6zfTL
# piIpE0/GbIaQRNAWXp6N3MBNuzWzdJqiJLbMWJF9TfNKs3R/DaqLuG1/XjYm63Y6
# AqfpOphVMNs93tJb26iZlsxVuLfxYVvWzyIruHNLm1IlHLy/nMFGsiRez3RC
# SIG # End signature block
