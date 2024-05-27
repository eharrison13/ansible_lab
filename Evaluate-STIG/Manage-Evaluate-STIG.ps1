<#
    .Synopsis
    Manage Evaluate-STIG via GUI
    .DESCRIPTION
    Launches an Evaluate-STIG GUI to more easily execute Evaluate-STIG.ps1
    .EXAMPLE
    PS C:\> Manage-Evaluate-STIG.ps1
#>

Function Invoke-PowerShell {
    param (
        [Parameter(Mandatory = $true)]
        [String]$ESPath,

        [Parameter(Mandatory = $false)]
        [String]$ArgumentList,

        [Parameter(Mandatory = $false)]
        [Switch]$NoNewWindow
    )

    $ESDataBox.Text = "Generating data from `"$(Join-Path $ESPath -ChildPath Evaluate-STIG.ps1)`" $ArgumentList.  `n`nPlease wait"
    Start-Sleep 1 #Give the GUI time to update

    if ($ArgumentList -eq "GetHelp") {
        Write-Verbose "Executing: Start-Process powershell `"Get-Help $(Join-Path $ESPath -ChildPath Evaluate-STIG.ps1) -Full`" -NoNewWindow -Wait"
        $output = Start-Process powershell "Get-Help '$(Join-Path $ESPath -ChildPath Evaluate-STIG.ps1)' -Full" -NoNewWindow -Wait
    }
    else {
        If (($PsVersionTable.PSVersion -join ".") -gt [Version]"7.0") {
            Write-Verbose "Executing: Start-Process pwsh `"-NoProfile -Command & '$(Join-Path $ESPath -ChildPath Evaluate-STIG.ps1)' $ArgumentList`" -Wait -NoNewWindow"
            $output = Start-Process pwsh "-NoProfile -Command & '$(Join-Path $ESPath -ChildPath Evaluate-STIG.ps1)' $ArgumentList" -Wait -NoNewWindow
        }
        else {
            Write-Verbose "Executing: Start-Process powershell `"-NoProfile -File $(Join-Path $ESPath -ChildPath Evaluate-STIG.ps1) $ArgumentList`" -Wait -NoNewWindow"
            $output = Start-Process powershell "-NoProfile -Command & '$(Join-Path $ESPath -ChildPath Evaluate-STIG.ps1)' $ArgumentList" -Wait -NoNewWindow
        }
    }
    Return $output
}

function Get-Path {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$Description,

        [Parameter(Mandatory = $False)]
        [String]$RootDir
    )

    $foldername = New-Object System.Windows.Forms.FolderBrowserDialog -Property @{
        SelectedPath = "$RootDir\"
      }

    if ($foldername.ShowDialog() -eq "OK") {
        return $foldername.SelectedPath
    }
    else {
        return "no_path"
    }
}

function Get-File {

    $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
        InitialDirectory = [Environment]::GetFolderPath("MyComputer")
        Filter           = "TXT Files (*.txt)|*.txt"
        MultiSelect      = $true
    }

    if ($FileBrowser.ShowDialog() -eq "OK") {
        return $FileBrowser.FileNames
    }
    else {
        return "no_path"
    }
}

Function Get-Arguments {
    if ($AllowDeprecated.Checked -eq $true) {
        $ESArgs = "-AllowDeprecated"
    }
    else{
        $ESArgs = ""
    }
    If ($SelectedSTIGS) {
        $ESArgs += " -SelectSTIG $($SelectedSTIGS -join ',')"

        If ($SelectedVulns) {
            $ESArgs += " -SelectVuln $($SelectedVulns -join ',' -replace(' ',''))"
        }
        If ($ExcludedVulns -or $Preferences.Preferences.EvaluateSTIG.ExcludeVuln) {
            if ($Preferences.Preferences.EvaluateSTIG.ExcludeVuln){
                $Preferences.Preferences.EvaluateSTIG.ExcludeVuln | Foreach-Object{$ExcludedVulns += ",$_"}
            }
            $ESArgs += " -ExcludeVuln $(($ExcludedVulns -join ',' -replace(' ','')).TrimStart(','))"
        }
    }
    ElseIf ($ExcludedSTIGS) {
        $ESArgs += " -ExcludeSTIG $($ExcludedSTIGS -join ',')"
    }

    If ($ForcedSTIGS) {
        $ESArgs += " -ForceSTIG $($ForcedSTIGS -join ',')"
    }

    if ($AltCredential.Checked -eq $true) {
        $ESArgs += " -AltCredential"
    }
    if ($ApplyTattoo.Checked -eq $true) {
        $ESArgs += " -ApplyTattoo"
    }

    $OutputOptions = @()
    if ($STIGManager.Checked -eq $true) {
        $OutputOptions += "STIGManager"
    }
    if ($CKLOutput.Checked -eq $true) {
        $OutputOptions += "CKL"
    }
    if ($CKLBOutput.Checked -eq $true) {
        $OutputOptions += "CKLB"
    }
    if ($CombinedCKL.Checked -eq $true) {
        $OutputOptions += "CombinedCKL"
    }
    if ($CombinedCKLB.Checked -eq $true) {
        $OutputOptions += "CombinedCKLB"
    }
    if ($Summary.Checked -eq $true) {
        $OutputOptions += "Summary"
    }
    if ($OQE.Checked -eq $true) {
        $OutputOptions += "OQE"
    }
    if ($OutputOptions){
        $ESArgs += " -Output $($OutputOptions -join ",")"
    }

    if ($VulnTimeoutBox.Text) {
        $ESArgs += " -VulnTimeout $($VulnTimeoutBox.Text)"
    }
    if ($PreviousToKeepBox.Text) {
        $ESArgs += " -PreviousToKeep $($PreviousToKeepBox.Text)"
    }
    if ($ThrottleLimitBox.Text) {
        $ESArgs += " -ThrottleLimit $($ThrottleLimitBox.Text)"
    }
    if ($SMPassphraseBox.Text) {
        $ESArgs += " -SMPassphrase $($SMPassphraseBox.Text)"
    }
    if ($MarkingBox.Text) {
        $ESArgs += " -Marking ""$($MarkingBox.Text)"""
    }
    if ($ScanType.SelectedItem) {
        $ESArgs += " -ScanType $($ScanType.SelectedItem)"
    }
    if ($AFKeys.SelectedItem) {
        $ESArgs += " -AnswerKey $($AFKeys.SelectedItem)"
    }
    if ($SMKeys.SelectedItem) {
        $ESArgs += " -SMCollection $($SMKeys.SelectedItem)"
    }

    $ESArgs += " -AFPath '$ESAFPath'"

    if ($ESOutputPath -ne ""){
        $ESArgs += " -OutputPath '$ESOutputPath'"
    }

    If ($ComputerNames -and $ComputerList) {
        $ESArgs += " -ComputerName $($ComputerNames -join ',' -replace(' ','')),'$($ComputerList -join '","' -replace(' ',''))'"
    }
    elseif ($ComputerNames) {
        $ESArgs += " -ComputerName $($ComputerNames -join ',' -replace(' ',''))"
    }
    elseif ($ComputerList) {
        $ESArgs += " -ComputerName $($ComputerList -join '","' -replace(' ',''))"
    }

    if ($CiscoFileList -and $CiscoDirectory) {
        $ESArgs += " -CiscoConfig '$CiscoDirectory`",`"$($CiscoFileList -join '","' -replace(' ',''))'"
    }
    elseif ($CiscoFileList) {
        $ESArgs += " -CiscoConfig '$($CiscoFileList -join ',' -replace(' ',''))'"
    }
    elseif ($CiscoDirectory) {
        $ESArgs += " -CiscoConfig '$CiscoDirectory'"
    }

    return $ESArgs
}

Function Get-OutputPath {
    if ($CombinedCKL.Checked -or $CombinedCKLB.Checked -or $CKLOutput.Checked -or $CKLBOutput.Checked -or $Summary.Checked -or $OQE.Checked){
        $OutputPathButton.Enabled = $True
        if ($ESOutputPath -eq ""){
            $Script:ESOutputPath = "C:\Users\Public\Documents\STIG_Compliance"
        }
        $OutputPathLabel.Text = "OutputPath:         $ESOutputPath"

        If ($Preferences.Preferences.EvaluateSTIG.PreviousToKeep){
            $PreviousToKeepBox.Text = $Preferences.Preferences.EvaluateSTIG.PreviousToKeep
        }
        $PreviousToKeepBox.Enabled = $true
    }
    else{
        $OutputPathButton.Enabled = $false
        $Script:ESOutputPath = ""
        $OutputPathLabel.Text = "OutputPath:         Not Applicable (Output to Console or STIGManager)"

        $PreviousToKeepBox.Text = ""
    }
    
    & $handler_PreviewESButton_Click
}

Function Set-Initial {

    $form1.Controls | Where-Object { $_ -is [System.Windows.Forms.ComboBox] } | ForEach-Object { $_.Items.Clear() }

    $Script:Preferences = (Select-Xml -Path $(Join-Path $PSScriptRoot -ChildPath Preferences.xml) -XPath /).Node

    ForEach ($Item in ($Preferences.Preferences.EvaluateSTIG | Get-Member -MemberType Property | Where-Object Definition -MATCH string | Where-Object Name -NE '#comment').Name) {
        $Preferences.Preferences.EvaluateSTIG.$Item = $Preferences.Preferences.EvaluateSTIG.$Item -replace '"','' -replace "'",''
    }

    ForEach ($Item in ($Preferences.Preferences.STIGManager | Get-Member -MemberType Property | Where-Object Definition -MATCH string | Where-Object Name -NE '#comment').Name) {
        $Preferences.Preferences.STIGManager.$Item = $Preferences.Preferences.STIGManager.$Item -replace '"','' -replace "'",''
    }

    @("Unclassified", "Classified") | ForEach-Object { $null = $ScanType.Items.Add($_) }

    If ($Preferences.Preferences.EvaluateSTIG.ScanType){
        $index = ($ScanType.Items).ToLower().Indexof($Preferences.Preferences.EvaluateSTIG.ScanType.ToLower())
        if ($index -le ($ScanType.Items | Measure-Object).count){
            $ScanType.SelectedIndex = $index
        }
    }

    If ($Preferences.Preferences.EvaluateSTIG.AFPath){
        $Script:ESAFPath = $Preferences.Preferences.EvaluateSTIG.AFPath
        $AFXMLs = Get-ChildItem -Path $ESAFPath -Filter *.xml
    }
    else{
        $Script:ESAFPath = $(Join-Path $ESFolder -ChildPath AnswerFiles)
        $AFXMLs = Get-ChildItem -Path $(Join-Path $ESFolder -ChildPath AnswerFiles) -Filter *.xml
    }
    $AFPathLabel.Text = "AFPath:             $ESAFPath"

    Foreach ($AFXML in $AFXMLS) {
        [xml]$XML = Get-Content $AFXML.FullName
        $AllAFKeys += $XML.STIGComments.Vuln.AnswerKey.Name
    }
    $AFKeys.Items.Add("")
    $AllAFKeys | Sort-Object -Unique | ForEach-Object { $null = $AFKeys.Items.Add($_) }

    If ($Preferences.Preferences.EvaluateSTIG.AnswerKey){
        $index = ($AFKeys.Items).ToLower().Indexof($Preferences.Preferences.EvaluateSTIG.AnswerKey.ToLower())
        if ($index -le ($AFKeys.Items | Measure-Object).count){
            $AFKeys.SelectedIndex = $index
        }
    }

    If (!(IsAdministrator)) {
        $ListApplicableProductsButton.Enabled = $false
    }

    $SelectSTIGButton.Enabled = $true
    $ExcludeSTIGButton.Enabled = $true
    $ForceSTIGButton.Enabled = $true
    $ExcludeVulnButton.Enabled = $false
    $SelectVulnButton.Enabled = $false
    $AltCredential.Enabled = $false
    $PreviousToKeepBox.Enabled = $false
    $ThrottleLimitBox.Enabled = $false
    $SMPassphraseBox.Enabled = $false
    $SMKeys.Enabled = $False
    $OutputPathButton.Enabled = $False

    $UpdateProxy.Checked = $false
    $AltCredential.Checked = $false

    $OutputNeeded

    If ($Preferences.Preferences.EvaluateSTIG.ApplyTattoo -eq "true"){
        $ApplyTattoo.Checked = $true
    }
    else{
        $ApplyTattoo.Checked = $false
    }

    If ($Preferences.Preferences.EvaluateSTIG.AllowDeprecated -eq "true"){
        $AllowDeprecated.Checked = $true
    }
    else{
        $AllowDeprecated.Checked = $false
    }

    Switch ($($Preferences.Preferences.EvaluateSTIG.Output -split ",")){
        "STIGManager"   {$STIGManager.Checked = $True}
        "CKL"           {$CKLOutput.Checked = $True}
        "CKLB"          {$CKLBOutput.Checked = $True}
        "CombinedCKL"   {$CombinedCKL.Checked = $True}
        "CombinedCKLB"  {$CombinedCKLB.Checked = $True}
        "Summary"       {$CombinedCKLB.Checked = $True}
        "OQE"           {$CombinedCKLB.Checked = $True}
        default         {
            $STIGManager.Checked = $false
            $CKLOutput.Checked = $false
            $CKLBOutput.Checked = $false
            $CombinedCKL.Checked = $false
            $CombinedCKLB.Checked = $false
            $Summary.Checked = $false
            $OQE.Checked = $false
        }
    }

    If ($Preferences.Preferences.EvaluateSTIG.OutputPath){
        $Script:ESOutputPath = $Preferences.Preferences.EvaluateSTIG.OutputPath
        $OutputPathLabel.Text = "OutputPath:         $ESOutputPath"
    }
    else{
        Get-OutputPath
    }

    If ($Preferences.Preferences.EvaluateSTIG.VulnTimeout){
        $VulnTimeoutBox.Text = $Preferences.Preferences.EvaluateSTIG.VulnTimeout
    }
    else{
        $VulnTimeoutBox.Text = ""
    }
    

    $PreviousToKeepBox.Text = ""
    $ThrottleLimitBox.Text = ""
    $SMPassphraseBox.Text = ""

    If ($Preferences.Preferences.EvaluateSTIG.Marking){
        $MarkingBox.Text = $Preferences.Preferences.EvaluateSTIG.Marking
    }
    else{
        $MarkingBox.Text = ""
    }
    $ESDataBox.Text = ""

    $Script:SelectedSTIGS = New-Object System.Collections.ArrayList
    $Script:ExcludedSTIGS = New-Object System.Collections.ArrayList

    if ($Preferences.Preferences.EvaluateSTIG.ExcludeSTIG){
        ($Preferences.Preferences.EvaluateSTIG.ExcludeSTIG).Split(",") | Foreach-Object {$ExcludedSTIGS.Add($_)}
        $SelectSTIGButton.Enabled = $false
    }

    $Script:SelectedVulns = ""
    $Script:ExcludedVulns = ""
    $Script:ComputerNames = ""
    $Script:ComputerList = ""
    $Script:CiscoFileList = ""
    $Script:CiscoDirectory = ""
}

Function Close-Form {
    Param (
        [Parameter(Mandatory = $true)]
        [String]$Message
    )

    [System.Windows.MessageBox]::Show($Message, "Manage Evaluate-STIG Error", "OK", "Error")
    &$handler_formclose
}

function IsAdministrator {
    $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object System.Security.Principal.WindowsPrincipal($Identity)
    $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName Microsoft.VisualBasic
Add-Type -AssemblyName PresentationFramework
Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public class ProcessDPI {
    [DllImport("user32.dll", SetLastError=true)]
    public static extern bool SetProcessDPIAware();
}
'@

$null = [ProcessDPI]::SetProcessDPIAware()

$InitialFormWindowState = New-Object System.Windows.Forms.FormWindowState

$form1 = New-Object System.Windows.Forms.Form
[Windows.Forms.Application]::EnableVisualStyles()

$TitleFont = New-Object System.Drawing.Font("Consolas", 24, [Drawing.FontStyle]::Bold)
$BodyFont = New-Object System.Drawing.Font("Consolas", 18, [Drawing.FontStyle]::Bold)
$BoxFont = New-Object System.Drawing.Font("Consolas", 12, [Drawing.FontStyle]::Regular)
$BoldBoxFont = New-Object System.Drawing.Font("Consolas", 14, [Drawing.FontStyle]::Bold)

$VLineLeft = New-Object System.Windows.Forms.Label
$HLineTop = New-Object System.Windows.Forms.Label
$HLineOptionBottom = New-Object System.Windows.Forms.Label
$HLineBottom = New-Object System.Windows.Forms.Label
$ScanTypeLabel = New-Object System.Windows.Forms.Label
$AFKeysLabel = New-Object System.Windows.Forms.Label
$SMKeysLabel = New-Object System.Windows.Forms.Label
$AFPathLabel = New-Object System.Windows.Forms.Label
$ESPathLabel = New-Object System.Windows.Forms.Label
$OutputPathLabel = New-Object System.Windows.Forms.Label
$VulnTimeoutLabel = New-Object System.Windows.Forms.Label
$PreviousToKeepLabel = New-Object System.Windows.Forms.Label
$ThrottleLimitLabel = New-Object System.Windows.Forms.Label
$MarkingLabel = New-Object System.Windows.Forms.Label
$SMPassphraseLabel = New-Object System.Windows.Forms.Label

$BottomLine = New-Object System.Windows.Forms.Label
$BottomLineVersion = New-Object System.Windows.Forms.Label
$Title = New-Object System.Windows.Forms.Label
$ToolsLabel = New-Object System.Windows.Forms.Label
$OptionsLabel = New-Object System.Windows.Forms.Label
$OutputLabel = New-Object System.Windows.Forms.Label

$UpdateProxy = New-Object System.Windows.Forms.Checkbox
$UpdateLocSource = New-Object System.Windows.Forms.Checkbox
$AltCredential = New-Object System.Windows.Forms.Checkbox
$ApplyTattoo = New-Object System.Windows.Forms.Checkbox
$AllowDeprecated = New-Object System.Windows.Forms.Checkbox
$STIGManager = New-Object System.Windows.Forms.Checkbox
$CKLOutput = New-Object System.Windows.Forms.Checkbox
$CKLBOutput = New-Object System.Windows.Forms.Checkbox
$CombinedCKL = New-Object System.Windows.Forms.Checkbox
$CombinedCKLB = New-Object System.Windows.Forms.Checkbox
$Summary = New-Object System.Windows.Forms.Checkbox
$OQE = New-Object System.Windows.Forms.Checkbox

$ScanType = New-Object System.Windows.Forms.ComboBox
$AFKeys = New-Object System.Windows.Forms.ComboBox
$SMKeys = New-Object System.Windows.Forms.ComboBox

$STIGSelectList = New-Object System.Windows.Forms.CheckedListBox

$VulnTimeoutBox = New-Object System.Windows.Forms.TextBox
$PreviousToKeepBox = New-Object System.Windows.Forms.TextBox
$ThrottleLimitBox = New-Object System.Windows.Forms.TextBox
$MarkingBox = New-Object System.Windows.Forms.TextBox

$SMPassphraseBox = New-Object System.Windows.Forms.MaskedTextBox

$ListSupportedProductsButton = New-Object System.Windows.Forms.Button
$ListApplicableProductsButton = New-Object System.Windows.Forms.Button
$UpdateESButton = New-Object System.Windows.Forms.Button
$GetHelpButton = New-Object System.Windows.Forms.Button
$ContactUsButton = New-Object System.Windows.Forms.Button
$PreviewESButton = New-Object System.Windows.Forms.Button
$ExecuteESButton = New-Object System.Windows.Forms.Button
$ResetESButton = New-Object System.Windows.Forms.Button
$AFPAthButton = New-Object System.Windows.Forms.Button
$SelectSTIGButton = New-Object System.Windows.Forms.Button
$ExcludeSTIGButton = New-Object System.Windows.Forms.Button
$ForceSTIGButton = New-Object System.Windows.Forms.Button
$SelectVulnButton = New-Object System.Windows.Forms.Button
$ExcludeVulnButton = New-Object System.Windows.Forms.Button
$OutputPathButton = New-Object System.Windows.Forms.Button
$ComputerNameButton = New-Object System.Windows.Forms.Button
$ComputerListButton = New-Object System.Windows.Forms.Button
$CiscoFilesButton = New-Object System.Windows.Forms.Button
$CiscoDirectoryButton = New-Object System.Windows.Forms.Button

$ESDataBox = New-Object -TypeName System.Windows.Forms.RichTextBox

#----------------------------------------------
#Generated Event Script Blocks
#----------------------------------------------

$OnLoadForm_StateCorrection =
{ #Correct the initial state of the form to prevent the .Net maximized form issue
    $form1.WindowState = $InitialFormWindowState

    $script:ESFolder = $PSScriptRoot

    if (Test-Path $ESFolder) {
        If (Test-Path (Join-Path -Path $ESFolder -ChildPath "xml" | Join-Path -ChildPath "FileList.xml")) {
            [XML]$FileListXML = Get-Content -Path (Join-Path -Path $ESFolder -ChildPath "xml" | Join-Path -ChildPath "FileList.xml")
            ForEach ($File in $FileListXML.FileList.File) {
                if ($File.ScanReq -eq "Required") {
                    $Path = (Join-Path -Path $ESFolder -ChildPath $File.Path | Join-Path -ChildPath $File.Name)
                    If (!(Test-Path $Path)) {
                        $Verified = $false
                    }
                }
            }
            If ($Verified -eq $False) {
                Write-Host "ERROR: One or more Evaluate-STIG files were not found.  Unable to continue." -ForegroundColor Yellow
                Close-Form -Message "ERROR: One or more Evaluate-STIG files were not found.  Unable to continue."
            }
        }
        Else {
            Write-Host "ERROR: 'FileList.xml' not found.  Unable to verify content integrity." -ForegroundColor Red
            Close-Form -Message "ERROR: 'FileList.xml' not found.  Unable to verify content integrity."
        }
        $evalSTIGVersionNumber = ((Get-Content $(Join-Path $ESFolder -ChildPath Evaluate-STIG.ps1) | Select-String -Pattern ('EvaluateStigVersion = ')) -split ("="))[1]
        $BottomLine.Text = "Evaluate-STIG Version = $evalSTIGVersionNumber"

        $ESPathLabel.Text = "Evaluate-STIG Path: $ESFolder"
    }
    else {

        Close-Form -Message "Evaluate-STIG Path not found"
    }

    #Initial Setup
    Set-Initial
}

$handler_ListSupportedProductsButton_Click = {
    $ESDataBox.Text = (Invoke-PowerShell -ESPath $ESFolder -ArgumentList "-ListSupportedProducts" -NoNewWindow) | Format-Table -AutoSize | Out-String
}

$handler_ListApplicableProductsButton_Click = {
    $ESDataBox.Text = Invoke-PowerShell -ESPath $ESFolder -ArgumentList "-ListApplicableProducts" | Format-Table -AutoSize | Out-String
}

$handler_UpdateESButton_Click = {
    If ($UpdateProxy.Checked -eq $true) {
        $title = "Proxy"
        $msg = "Enter a Proxy for -Update:"

        $Proxy = [Microsoft.VisualBasic.Interaction]::InputBox($msg, $title)
        if ($Proxy){
            $ESDataBox.Text = Invoke-PowerShell -ESPath $ESFolder -ArgumentList "-Update -Proxy $Proxy"
        }
    }
    elseif ($UpdateLocSource.Checked -eq $true){
        $GetPath = Get-Path -Description "Select Local update directory" -RootDir "c:\"

        if ($GetPath -ne "no_path") {
            $ESDataBox.Text = Invoke-PowerShell -ESPath $ESFolder -ArgumentList "-Update -LocalSource $GetPath"
        }
    }
    else {
        $ESDataBox.Text = Invoke-PowerShell -ESPath $ESFolder -ArgumentList "-Update"
    }

    $evalSTIGVersionNumber = ((Get-Content $(Join-Path $ESFolder -ChildPath Evaluate-STIG.ps1) | Select-String -Pattern ('EvaluateStigVersion = ')) -split ("="))[1]
    $BottomLine.Text = "Evaluate-STIG Version = $evalSTIGVersionNumber"
}

$handler_GetHelpButton_Click = {
    $ESDataBox.Text = Invoke-PowerShell -ESPath $ESFolder -ArgumentList "GetHelp" -NoNewWindow | Format-Table -AutoSize | Out-String
}

$handler_ContactUsButton_Click = {
    [System.Windows.MessageBox]::Show("Evaluate-STIG Contact methods:`n`n  email:`t`tEval-STIG_spt@us.navy.mil`n`n  MS Teams:`tNAVSEA_RMF `n`n  Fusion:`t`t#evaluate-stig", "Evaluate-STIG Contact Us", "OK", "Question")
}

$handler_PreviewESButton_Click = {
    $ESDataBox.Text = "Command Line to Execute:`n`n$(Join-Path $ESFolder -ChildPath Evaluate-STIG.ps1) $(Get-Arguments)" | Format-Table -AutoSize | Out-String
}

$handler_AFPathButton_Click = {
    $AFKeys | ForEach-Object {$_.Items.Clear() }

    $GetPath = Get-Path -Description "Select Answer File directory" -RootDir $ESAFPath

    if ($GetPath -ne "no_path") {
        $Script:ESAFPath = $GetPath
    }

    $AFXMLs = Get-ChildItem -Path $ESAFPath -Filter *.xml

    Foreach ($AFXML in $AFXMLS) {
        [xml]$XML = Get-Content $AFXML.FullName
        $AllAFKeys += $XML.STIGComments.Vuln.AnswerKey.Name
    }
    $AFKeys.Items.Add("")
    $AllAFKeys | Sort-Object -Unique | ForEach-Object { $null = $AFKeys.Items.Add($_) }

    $AFPathLabel.Text = "AFPath:             $ESAFPath"
    &$handler_PreviewESButton_Click
}

$handler_OutputPathButton_Click = {
    $GetPath = Get-Path -Description "Select Output Path directory" -RootDir $ESOutputPath

    if ($GetPath -ne "no_path") {
        $Script:ESOutputPath = $GetPath
    }

    $OutputPathLabel.Text = "OutputPath:         $ESOutputPath"
    &$handler_PreviewESButton_Click
}

$handler_SelectVulnButton_Click = {
    $title = "Select Vuln(s)"
    $msg = "Enter Vulnerability IDs (format V-XXXXXX), separate with commas (no spaces):"

    $Script:SelectedVulns = [Microsoft.VisualBasic.Interaction]::InputBox($msg, $title)
    &$handler_PreviewESButton_Click
}

$handler_ExcludeVulnButton_Click = {
    $title = "Exclude Vuln(s)"
    $msg = "Enter Vulnerability IDs (format V-XXXXXX), separate with commas (no spaces):"

    $Script:ExcludedVulns = [Microsoft.VisualBasic.Interaction]::InputBox($msg, $title)
    &$handler_PreviewESButton_Click
}

$handler_ComputerNameButton_Click = {
    $title = "Select Computers"
    $msg = "Enter Computer names, separate with commas (no spaces):"

    $Script:ComputerNames = [Microsoft.VisualBasic.Interaction]::InputBox($msg, $title)

    $AltCredential.Enabled = $true
    $ThrottleLimitBox.Enabled = $true
    &$handler_PreviewESButton_Click
}

$handler_ComputerListButton_Click = {
    $GetPath = Get-File

    if ($GetPath -ne "no_path") {
        $Script:ComputerList = $GetPath
    }

    $AltCredential.Enabled = $true
    $ThrottleLimitBox.Enabled = $true
    &$handler_PreviewESButton_Click
}

$handler_CiscoFilesButton_Click = {
    $GetPath = Get-File

    if ($GetPath -ne "no_path") {
        $Script:CiscoFileList = $GetPath
    }
    &$handler_PreviewESButton_Click
}

$handler_CiscoDirectoryButton_Click = {
    $GetPath = Get-Path -Description "Select Cisco config directory" -RootDir "c:\"

    if ($GetPath -ne "no_path") {
        $Script:CiscoDirectory = $GetPath
    }

    $OutputPathLabel.Text = "OutputPath:         $ESOutputPath"
    &$handler_PreviewESButton_Click
}

$handler_ExecuteESButton_Click = {
    $ESDataBox.Text = Invoke-PowerShell -ESPath $ESFolder -ArgumentList $(Get-Arguments) | Format-Table -AutoSize | Out-String
    Write-Host "Manage Evaluate-STIG GUI Execution Complete" -ForegroundColor Green
    Set-Initial
}

$handler_ResetESButton_Click = {
    Set-Initial
}

$handler_SelectSTIGButton_Click = {

    $ExcludeSTIGButton.Enabled = $false
    $ExcludeVulnButton.Enabled = $true
    $SelectVulnButton.Enabled = $true

    $handler_form2close =
    {
        1..3 | ForEach-Object { [GC]::Collect() }
        if ($SelectedSTIGS.count -eq 0) {
            $ExcludeSTIGButton.Enabled = $true
        }

        $form2.Dispose()
        &$handler_PreviewESButton_Click
    }

    $handler_OKButton_Click = {
        $Script:SelectedSTIGS = $STIGSelectList.Items | Where-Object { $STIGSelectList.CheckedItems -contains $_ }
        if ($SelectedSTIGS.count -eq 0) {
            $ExcludeSTIGButton.Enabled = $true
        }
        &$handler_form2close
    }

    $handler_CancelButton_Click = {
        &$handler_form2close
    }

    $form2 = New-Object System.Windows.Forms.Form

    $form2.Text = "Select STIG(s)"
    $form2.Name = "form2"
    $form2.SuspendLayout()

    $form2.AutoScaleDimensions = New-Object System.Drawing.SizeF(96, 96)
    $form2.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi

    $STIGSelectList = New-Object System.Windows.Forms.CheckedListBox

    $OKButton = New-Object System.Windows.Forms.Button
    $CancelButton = New-Object System.Windows.Forms.Button

    $form2.FormBorderStyle = "Fixed3D"
    $form2.StartPosition = "CenterParent"
    $form2.DataBindings.DefaultDataSourceUpdateMode = 0
    $System_Drawing_Size = New-Object System.Drawing.Size
    $System_Drawing_Size.Width = 1200
    $System_Drawing_Size.Height = 650
    $form2.ClientSize = $System_Drawing_Size

    $System_Drawing_Size = New-Object System.Drawing.Size
    $System_Drawing_Size.Width = 1280
    $System_Drawing_Size.Height = 600
    $STIGSelectList.Size = $System_Drawing_Size
    $STIGSelectList.Font = $BoxFont
    $STIGSelectList.Name = "STIGSelectList"
    $STIGSelectList.MultiColumn = $true
    $STIGSelectList.CheckOnClick = $true
    $STIGSelectList.ColumnWidth = 400
    $System_Drawing_Point = New-Object System.Drawing.Point
    $System_Drawing_Point.X = 10
    $System_Drawing_Point.Y = 10
    $STIGSelectList.Location = $System_Drawing_Point
    $form2.Controls.Add($STIGSelectList)

    $OKButton.Name = "OKButton"
    $System_Drawing_Size = New-Object System.Drawing.Size
    $System_Drawing_Size.Width = 100
    $System_Drawing_Size.Height = 50
    $OKButton.Size = $System_Drawing_Size
    $OKButton.UseVisualStyleBackColor = $True
    $OKButton.Text = "OK"
    $OKButton.Font = $BoxFont
    $System_Drawing_Point = New-Object System.Drawing.Point
    $System_Drawing_Point.X = 495
    $System_Drawing_Point.Y = 600
    $OKButton.Location = $System_Drawing_Point
    $OKButton.DataBindings.DefaultDataSourceUpdateMode = 0
    $OKButton.add_Click($handler_OKButton_Click)
    $form2.Controls.Add($OKButton)

    $CancelButton.Name = "CancelButton"
    $System_Drawing_Size = New-Object System.Drawing.Size
    $System_Drawing_Size.Width = 100
    $System_Drawing_Size.Height = 50
    $CancelButton.Size = $System_Drawing_Size
    $CancelButton.UseVisualStyleBackColor = $True
    $CancelButton.Text = "Cancel"
    $CancelButton.Font = $BoxFont
    $System_Drawing_Point = New-Object System.Drawing.Point
    $System_Drawing_Point.X = 605
    $System_Drawing_Point.Y = 600
    $CancelButton.Location = $System_Drawing_Point
    $CancelButton.DataBindings.DefaultDataSourceUpdateMode = 0
    $CancelButton.add_Click($handler_CancelButton_Click)
    $form2.Controls.Add($CancelButton)

    $STIGListXML = Join-Path -Path $ESFolder -ChildPath "xml" | Join-Path -ChildPath "STIGList.xml"
    $STIGs = ([XML](Get-Content $STIGListXML)).List.STIG | Select-Object ShortName -Unique
    ForEach ($STIG in $STIGs) {
        $STIGSelectList.Items.Add($STIG.Shortname)
    }

    $SelectedSTIGS | ForEach-Object {
        if ($STIGSelectList.Items -contains $_) {
            $index = ($STIGSelectList.Items).ToLower().Indexof($_.ToLower())
            if ($index -le ($STIGSelectList.Items | Measure-Object).count){
                $STIGSelectList.SetItemChecked($index, $true)
            }
        }
    }

    $form2.Add_FormClosed($handler_form2close)

    $null = $form2.ShowDialog()
}

$handler_ExcludeSTIGButton_Click = {

    $SelectSTIGButton.Enabled = $false

    $handler_form3close =
    {
        1..3 | ForEach-Object { [GC]::Collect() }
        if ($ExcludedSTIGS.count -eq 0) {
            $SelectSTIGButton.Enabled = $true
        }

        $form3.Dispose()
        &$handler_PreviewESButton_Click
    }

    $handler_OKButton_Click = {
        $Script:ExcludedSTIGS = $STIGExcludeList.Items | Where-Object { $STIGExcludeList.CheckedItems -contains $_ }
        if ($ExcludedSTIGS.count -eq 0) {
            $SelectSTIGButton.Enabled = $true
        }
        &$handler_form3close
    }

    $handler_CancelButton_Click = {
        &$handler_form3close
    }

    $form3 = New-Object System.Windows.Forms.Form

    $form3.Text = "Select STIG(s)"
    $form3.Name = "form3"
    $form3.SuspendLayout()

    $form3.AutoScaleDimensions = New-Object System.Drawing.SizeF(96, 96)
    $form3.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi

    $STIGExcludeList = New-Object System.Windows.Forms.CheckedListBox

    $OKButton = New-Object System.Windows.Forms.Button
    $CancelButton = New-Object System.Windows.Forms.Button

    $form3.FormBorderStyle = "FixedDialog"
    $form3.StartPosition = "CenterParent"
    $form3.DataBindings.DefaultDataSourceUpdateMode = 0
    $System_Drawing_Size = New-Object System.Drawing.Size
    $System_Drawing_Size.Width = 1200
    $System_Drawing_Size.Height = 650
    $form3.ClientSize = $System_Drawing_Size

    $System_Drawing_Size = New-Object System.Drawing.Size
    $System_Drawing_Size.Width = 1280
    $System_Drawing_Size.Height = 600
    $STIGExcludeList.Size = $System_Drawing_Size
    $STIGExcludeList.Font = $BoxFont
    $STIGExcludeList.Name = "STIGExcludeList"
    $STIGExcludeList.MultiColumn = $true
    $STIGExcludeList.CheckOnClick = $true
    $STIGExcludeList.ColumnWidth = 400
    $System_Drawing_Point = New-Object System.Drawing.Point
    $System_Drawing_Point.X = 10
    $System_Drawing_Point.Y = 10
    $STIGExcludeList.Location = $System_Drawing_Point
    $form3.Controls.Add($STIGExcludeList)

    $OKButton.Name = "OKButton"
    $System_Drawing_Size = New-Object System.Drawing.Size
    $System_Drawing_Size.Width = 100
    $System_Drawing_Size.Height = 50
    $OKButton.Size = $System_Drawing_Size
    $OKButton.UseVisualStyleBackColor = $True
    $OKButton.Text = "OK"
    $OKButton.Font = $BoxFont
    $System_Drawing_Point = New-Object System.Drawing.Point
    $System_Drawing_Point.X = 495
    $System_Drawing_Point.Y = 600
    $OKButton.Location = $System_Drawing_Point
    $OKButton.DataBindings.DefaultDataSourceUpdateMode = 0
    $OKButton.add_Click($handler_OKButton_Click)
    $form3.Controls.Add($OKButton)

    $CancelButton.Name = "CancelButton"
    $System_Drawing_Size = New-Object System.Drawing.Size
    $System_Drawing_Size.Width = 100
    $System_Drawing_Size.Height = 50
    $CancelButton.Size = $System_Drawing_Size
    $CancelButton.UseVisualStyleBackColor = $True
    $CancelButton.Text = "Cancel"
    $CancelButton.Font = $BoxFont
    $System_Drawing_Point = New-Object System.Drawing.Point
    $System_Drawing_Point.X = 605
    $System_Drawing_Point.Y = 600
    $CancelButton.Location = $System_Drawing_Point
    $CancelButton.DataBindings.DefaultDataSourceUpdateMode = 0
    $CancelButton.add_Click($handler_CancelButton_Click)
    $form3.Controls.Add($CancelButton)

    $STIGListXML = Join-Path -Path $ESFolder -ChildPath "xml" | Join-Path -ChildPath "STIGList.xml"
    $STIGs = ([XML](Get-Content $STIGListXML)).List.STIG | Select-Object ShortName -Unique
    ForEach ($STIG in $STIGs) {
        $STIGExcludeList.Items.Add($STIG.Shortname)
    }

    $ExcludedSTIGS | ForEach-Object {
        if ($STIGExcludeList.Items -contains $_) {
            $index = ($STIGExcludeList.Items).ToLower().Indexof($_.ToLower())
            if ($index -le ($STIGExcludeList.Items | Measure-Object).count){
                $STIGExcludeList.SetItemChecked($index, $true)
            }
        }
    }

    $form3.Add_FormClosed($handler_form3close)

    $null = $form3.ShowDialog()
}

$handler_ForceSTIGButton_Click = {

    $handler_form4close =
    {
        1..3 | ForEach-Object { [GC]::Collect() }

        $form4.Dispose()
        &$handler_PreviewESButton_Click
    }

    $handler_OKButton_Click = {
        $Script:ForcedSTIGS = $STIGForceList.Items | Where-Object { $STIGForceList.CheckedItems -contains $_ }
        &$handler_form4close
    }

    $handler_CancelButton_Click = {
        &$handler_form4close
    }

    $form4 = New-Object System.Windows.Forms.Form

    $form4.Text = "Force STIG(s)"
    $form4.Name = "form4"
    $form4.SuspendLayout()

    $form4.AutoScaleDimensions = New-Object System.Drawing.SizeF(96, 96)
    $form4.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi

    $STIGForceList = New-Object System.Windows.Forms.CheckedListBox

    $OKButton = New-Object System.Windows.Forms.Button
    $CancelButton = New-Object System.Windows.Forms.Button

    $form4.FormBorderStyle = "FixedDialog"
    $form4.StartPosition = "CenterParent"
    $form4.DataBindings.DefaultDataSourceUpdateMode = 0
    $System_Drawing_Size = New-Object System.Drawing.Size
    $System_Drawing_Size.Width = 1200
    $System_Drawing_Size.Height = 650
    $form4.ClientSize = $System_Drawing_Size

    $System_Drawing_Size = New-Object System.Drawing.Size
    $System_Drawing_Size.Width = 1280
    $System_Drawing_Size.Height = 600
    $STIGForceList.Size = $System_Drawing_Size
    $STIGForceList.Font = $BoxFont
    $STIGForceList.Name = "STIGForceList"
    $STIGForceList.MultiColumn = $true
    $STIGForceList.CheckOnClick = $true
    $STIGForceList.ColumnWidth = 400
    $System_Drawing_Point = New-Object System.Drawing.Point
    $System_Drawing_Point.X = 10
    $System_Drawing_Point.Y = 10
    $STIGForceList.Location = $System_Drawing_Point
    $form4.Controls.Add($STIGForceList)

    $OKButton.Name = "OKButton"
    $System_Drawing_Size = New-Object System.Drawing.Size
    $System_Drawing_Size.Width = 100
    $System_Drawing_Size.Height = 50
    $OKButton.Size = $System_Drawing_Size
    $OKButton.UseVisualStyleBackColor = $True
    $OKButton.Text = "OK"
    $OKButton.Font = $BoxFont
    $System_Drawing_Point = New-Object System.Drawing.Point
    $System_Drawing_Point.X = 495
    $System_Drawing_Point.Y = 600
    $OKButton.Location = $System_Drawing_Point
    $OKButton.DataBindings.DefaultDataSourceUpdateMode = 0
    $OKButton.add_Click($handler_OKButton_Click)
    $form4.Controls.Add($OKButton)

    $CancelButton.Name = "CancelButton"
    $System_Drawing_Size = New-Object System.Drawing.Size
    $System_Drawing_Size.Width = 100
    $System_Drawing_Size.Height = 50
    $CancelButton.Size = $System_Drawing_Size
    $CancelButton.UseVisualStyleBackColor = $True
    $CancelButton.Text = "Cancel"
    $CancelButton.Font = $BoxFont
    $System_Drawing_Point = New-Object System.Drawing.Point
    $System_Drawing_Point.X = 605
    $System_Drawing_Point.Y = 600
    $CancelButton.Location = $System_Drawing_Point
    $CancelButton.DataBindings.DefaultDataSourceUpdateMode = 0
    $CancelButton.add_Click($handler_CancelButton_Click)
    $form4.Controls.Add($CancelButton)

    $STIGListXML = Join-Path -Path $ESFolder -ChildPath "xml" | Join-Path -ChildPath "STIGList.xml"
    $STIGs = ([XML](Get-Content $STIGListXML)).List.STIG | Select-Object ShortName -Unique
    ForEach ($STIG in $STIGs) {
        $STIGForceList.Items.Add($STIG.Shortname)
    }

    $ForcedSTIGS | ForEach-Object {
        if ($STIGForceList.Items -contains $_) {
            $index = ($STIGForceList.Items).ToLower().Indexof($_.ToLower())
            if ($index -le ($STIGForceList.Items | Measure-Object).count){
                $STIGForceList.SetItemChecked($index, $true)
            }
        }
    }

    $form4.Add_FormClosed($handler_form4close)

    $null = $form4.ShowDialog()
}

$handler_formclose =
{
    1..3 | ForEach-Object { [GC]::Collect() }

    $form1.Dispose()
}

#----------------------------------------------
#region Generated Form Code
#----------------------------------------------

$form1.Text = "Manage Evaluate-STIG"
$form1.Name = "form1"
$ManageESVerson = "1.0"
$form1.SuspendLayout()

$form1.AutoScaleDimensions = New-Object System.Drawing.SizeF(96, 96)
$form1.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi

$form1.FormBorderStyle = "FixedDialog"
$form1.StartPosition = "CenterScreen"
$form1.DataBindings.DefaultDataSourceUpdateMode = 0
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 1750
$System_Drawing_Size.Height = 800
$form1.ClientSize = $System_Drawing_Size

$Title.Text = "Manage Evaluate-STIG"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 1750
$System_Drawing_Size.Height = 55
$Title.Size = $System_Drawing_Size
$Title.Font = $TitleFont
$Title.TextAlign = "TopCenter"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 0
$System_Drawing_Point.Y = 5
$Title.Location = $System_Drawing_Point
$form1.Controls.Add($Title)

$ToolsLabel.Text = "Evaluate-STIG Tools"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 400
$System_Drawing_Size.Height = 40
$ToolsLabel.Size = $System_Drawing_Size
$ToolsLabel.Font = $BodyFont
$ToolsLabel.TextAlign = "TopCenter"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 30
$System_Drawing_Point.Y = 70
$ToolsLabel.Location = $System_Drawing_Point
$form1.Controls.Add($ToolsLabel)

$OptionsLabel.Text = "Evaluate-STIG Options"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 1140
$System_Drawing_Size.Height = 40
$OptionsLabel.Size = $System_Drawing_Size
$OptionsLabel.Font = $BodyFont
$OptionsLabel.TextAlign = "TopCenter"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 500
$System_Drawing_Point.Y = 70
$OptionsLabel.Location = $System_Drawing_Point
$form1.Controls.Add($OptionsLabel)

$OutputLabel.Text = "Output Options"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 250
$System_Drawing_Size.Height = 40
$OutputLabel.Size = $System_Drawing_Size
$OutputLabel.Font = $BodyFont
$OutputLabel.TextAlign = "TopCenter"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 500
$System_Drawing_Point.Y = 255
$OutputLabel.Location = $System_Drawing_Point
$form1.Controls.Add($OutputLabel)

$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 1730
$System_Drawing_Size.Height = 150
$ESDataBox.Size = $System_Drawing_Size
$ESDataBox.Name = "ESDataBox"
$ESDataBox.Font = $BoxFont
$ESDataBox.ReadOnly = $True
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 10
$System_Drawing_Point.Y = 625
$ESDataBox.Location = $System_Drawing_Point
$form1.Controls.Add($ESDataBox)

$ListSupportedProductsButton.Name = "ListSupportedProductsButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 350
$System_Drawing_Size.Height = 30
$ListSupportedProductsButton.Size = $System_Drawing_Size
$ListSupportedProductsButton.UseVisualStyleBackColor = $True
$ListSupportedProductsButton.Text = "List Supported Products"
$ListSupportedProductsButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 55
$System_Drawing_Point.Y = 125
$ListSupportedProductsButton.Location = $System_Drawing_Point
$ListSupportedProductsButton.DataBindings.DefaultDataSourceUpdateMode = 0
$ListSupportedProductsButton.add_Click($handler_ListSupportedProductsButton_Click)
$form1.Controls.Add($ListSupportedProductsButton)

$ListApplicableProductsButton.Name = "ListApplicableProductsButton"
$ListApplicableProductsButton.Size = $System_Drawing_Size
$ListApplicableProductsButton.UseVisualStyleBackColor = $True
$ListApplicableProductsButton.Text = "List Applicable Products"
$ListApplicableProductsButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 55
$System_Drawing_Point.Y = 165
$ListApplicableProductsButton.Location = $System_Drawing_Point
$ListApplicableProductsButton.DataBindings.DefaultDataSourceUpdateMode = 0
$ListApplicableProductsButton.add_Click($handler_ListApplicableProductsButton_Click)
$form1.Controls.Add($ListApplicableProductsButton)

$UpdateESButton.Name = "UpdateESButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 350
$System_Drawing_Size.Height = 30
$UpdateESButton.Size = $System_Drawing_Size
$UpdateESButton.UseVisualStyleBackColor = $True
$UpdateESButton.Text = "Update Evaluate-STIG"
$UpdateESButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 55
$System_Drawing_Point.Y = 205
$UpdateESButton.Location = $System_Drawing_Point
$UpdateESButton.DataBindings.DefaultDataSourceUpdateMode = 0
$UpdateESButton.add_Click($handler_UpdateESButton_Click)
$form1.Controls.Add($UpdateESButton)

$GetHelpButton.Name = "GetHelp"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 350
$System_Drawing_Size.Height = 30
$GetHelpButton.Size = $System_Drawing_Size
$GetHelpButton.UseVisualStyleBackColor = $True
$GetHelpButton.Text = "Get Evaluate-STIG Help"
$GetHelpButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 55
$System_Drawing_Point.Y = 285
$GetHelpButton.Location = $System_Drawing_Point
$GetHelpButton.DataBindings.DefaultDataSourceUpdateMode = 0
$GetHelpButton.add_Click($handler_GetHelpButton_Click)
$form1.Controls.Add($GetHelpButton)

$ContactUsButton.Name = "ContactUs"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 350
$System_Drawing_Size.Height = 30
$ContactUsButton.Size = $System_Drawing_Size
$ContactUsButton.UseVisualStyleBackColor = $True
$ContactUsButton.Text = "Contact Us"
$ContactUsButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 55
$System_Drawing_Point.Y = 325
$ContactUsButton.Location = $System_Drawing_Point
$ContactUsButton.DataBindings.DefaultDataSourceUpdateMode = 0
$ContactUsButton.add_Click($handler_ContactUsButton_Click)
$form1.Controls.Add($ContactUsButton)

$PreviewESButton.Name = "PreviewESButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 150
$System_Drawing_Size.Height = 50
$PreviewESButton.Size = $System_Drawing_Size
$PreviewESButton.UseVisualStyleBackColor = $True
$PreviewESButton.Text = "Preview"
$PreviewESButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 10
$System_Drawing_Point.Y = 385
$PreviewESButton.Location = $System_Drawing_Point
$PreviewESButton.DataBindings.DefaultDataSourceUpdateMode = 0
$PreviewESButton.add_Click($handler_PreviewESButton_Click)
$form1.Controls.Add($PreviewESButton)

$ExecuteESButton.Name = "ExecuteESButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 150
$System_Drawing_Size.Height = 50
$ExecuteESButton.Size = $System_Drawing_Size
$ExecuteESButton.UseVisualStyleBackColor = $True
$ExecuteESButton.Text = "Execute"
$ExecuteESButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 160
$System_Drawing_Point.Y = 385
$ExecuteESButton.Location = $System_Drawing_Point
$ExecuteESButton.DataBindings.DefaultDataSourceUpdateMode = 0
$ExecuteESButton.add_Click($handler_ExecuteESButton_Click)
$form1.Controls.Add($ExecuteESButton)

$ResetESButton.Name = "ResetESButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 150
$System_Drawing_Size.Height = 50
$ResetESButton.Size = $System_Drawing_Size
$ResetESButton.UseVisualStyleBackColor = $True
$ResetESButton.Text = "Reset"
$ResetESButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 310
$System_Drawing_Point.Y = 385
$ResetESButton.Location = $System_Drawing_Point
$ResetESButton.DataBindings.DefaultDataSourceUpdateMode = 0
$ResetESButton.add_Click($handler_ResetESButton_Click)
$form1.Controls.Add($ResetESButton)

$SelectSTIGButton.Name = "SelectSTIGButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 180
$System_Drawing_Size.Height = 50
$SelectSTIGButton.Size = $System_Drawing_Size
$SelectSTIGButton.UseVisualStyleBackColor = $True
$SelectSTIGButton.Text = "Select STIG(s)"
$SelectSTIGButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1200
$System_Drawing_Point.Y = 130
$SelectSTIGButton.Location = $System_Drawing_Point
$SelectSTIGButton.DataBindings.DefaultDataSourceUpdateMode = 0
$SelectSTIGButton.add_Click($handler_SelectSTIGButton_Click)
$form1.Controls.Add($SelectSTIGButton)

$SelectVulnButton.Name = "SelectVulnButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 270
$System_Drawing_Size.Height = 50
$SelectVulnButton.Size = $System_Drawing_Size
$SelectVulnButton.UseVisualStyleBackColor = $True
$SelectVulnButton.Text = "Select Vuln(s)"
$SelectVulnButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1200
$System_Drawing_Point.Y = 190
$SelectVulnButton.Location = $System_Drawing_Point
$SelectVulnButton.DataBindings.DefaultDataSourceUpdateMode = 0
$SelectVulnButton.add_Click($handler_SelectVulnButton_Click)
$form1.Controls.Add($SelectVulnButton)

$ExcludeSTIGButton.Name = "ExcludeSTIGButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 180
$System_Drawing_Size.Height = 50
$ExcludeSTIGButton.Size = $System_Drawing_Size
$ExcludeSTIGButton.UseVisualStyleBackColor = $True
$ExcludeSTIGButton.Text = "Exclude STIG(s)"
$ExcludeSTIGButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1380
$System_Drawing_Point.Y = 130
$ExcludeSTIGButton.Location = $System_Drawing_Point
$ExcludeSTIGButton.DataBindings.DefaultDataSourceUpdateMode = 0
$ExcludeSTIGButton.add_Click($handler_ExcludeSTIGButton_Click)
$form1.Controls.Add($ExcludeSTIGButton)

$ExcludeVulnButton.Name = "ExcludeVulnButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 270
$System_Drawing_Size.Height = 50
$ExcludeVulnButton.Size = $System_Drawing_Size
$ExcludeVulnButton.UseVisualStyleBackColor = $True
$ExcludeVulnButton.Text = "Exclude Vuln(s)"
$ExcludeVulnButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1470
$System_Drawing_Point.Y = 190
$ExcludeVulnButton.Location = $System_Drawing_Point
$ExcludeVulnButton.DataBindings.DefaultDataSourceUpdateMode = 0
$ExcludeVulnButton.add_Click($handler_ExcludeVulnButton_Click)
$form1.Controls.Add($ExcludeVulnButton)

$ForceSTIGButton.Name = "ForceSTIGButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 180
$System_Drawing_Size.Height = 50
$ForceSTIGButton.Size = $System_Drawing_Size
$ForceSTIGButton.UseVisualStyleBackColor = $True
$ForceSTIGButton.Text = "Force STIG(s)"
$ForceSTIGButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1560
$System_Drawing_Point.Y = 130
$ForceSTIGButton.Location = $System_Drawing_Point
$ForceSTIGButton.DataBindings.DefaultDataSourceUpdateMode = 0
$ForceSTIGButton.add_Click($handler_ForceSTIGButton_Click)
$form1.Controls.Add($ForceSTIGButton)

$OutputPathButton.Name = "OutputPathButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 180
$System_Drawing_Size.Height = 50
$OutputPathButton.Size = $System_Drawing_Size
$OutputPathButton.UseVisualStyleBackColor = $True
$OutputPathButton.Text = "Select OutputPath"
$OutputPathButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1200
$System_Drawing_Point.Y = 250
$OutputPathButton.Location = $System_Drawing_Point
$OutputPathButton.DataBindings.DefaultDataSourceUpdateMode = 0
$OutputPathButton.add_Click($handler_OutputPathButton_Click)
$form1.Controls.Add($OutputPathButton)

$AFPathButton.Name = "AFPathButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 180
$System_Drawing_Size.Height = 50
$AFPathButton.Size = $System_Drawing_Size
$AFPathButton.UseVisualStyleBackColor = $True
$AFPathButton.Text = "Select AFPath"
$AFPathButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1380
$System_Drawing_Point.Y = 250
$AFPathButton.Location = $System_Drawing_Point
$AFPathButton.DataBindings.DefaultDataSourceUpdateMode = 0
$AFPathButton.add_Click($handler_AFPathButton_Click)
$form1.Controls.Add($AFPathButton)

$ComputerNameButton.Name = "ComputerNameButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 180
$System_Drawing_Size.Height = 50
$ComputerNameButton.Size = $System_Drawing_Size
$ComputerNameButton.UseVisualStyleBackColor = $True
$ComputerNameButton.Text = "Input Computer(s)"
$ComputerNameButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1560
$System_Drawing_Point.Y = 250
$ComputerNameButton.Location = $System_Drawing_Point
$ComputerNameButton.DataBindings.DefaultDataSourceUpdateMode = 0
$ComputerNameButton.add_Click($handler_ComputerNameButton_Click)
$form1.Controls.Add($ComputerNameButton)

$ComputerListButton.Name = "ComputerListButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 540
$System_Drawing_Size.Height = 50
$ComputerListButton.Size = $System_Drawing_Size
$ComputerListButton.UseVisualStyleBackColor = $True
$ComputerListButton.Text = "Select Computer List Files(s)"
$ComputerListButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1200
$System_Drawing_Point.Y = 320
$ComputerListButton.Location = $System_Drawing_Point
$ComputerListButton.DataBindings.DefaultDataSourceUpdateMode = 0
$ComputerListButton.add_Click($handler_ComputerListButton_Click)
$form1.Controls.Add($ComputerListButton)

$CiscoFilesButton.Name = "CiscoFilesButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 540
$System_Drawing_Size.Height = 50
$CiscoFilesButton.Size = $System_Drawing_Size
$CiscoFilesButton.UseVisualStyleBackColor = $True
$CiscoFilesButton.Text = "Select Cisco File(s)"
$CiscoFilesButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1200
$System_Drawing_Point.Y = 380
$CiscoFilesButton.Location = $System_Drawing_Point
$CiscoFilesButton.DataBindings.DefaultDataSourceUpdateMode = 0
$CiscoFilesButton.add_Click($handler_CiscoFilesButton_Click)
$form1.Controls.Add($CiscoFilesButton)

$CiscoDirectoryButton.Name = "CiscoDirectoryButton"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 540
$System_Drawing_Size.Height = 50
$CiscoDirectoryButton.Size = $System_Drawing_Size
$CiscoDirectoryButton.UseVisualStyleBackColor = $True
$CiscoDirectoryButton.Text = "Select Cisco Directory"
$CiscoDirectoryButton.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1200
$System_Drawing_Point.Y = 440
$CiscoDirectoryButton.Location = $System_Drawing_Point
$CiscoDirectoryButton.DataBindings.DefaultDataSourceUpdateMode = 0
$CiscoDirectoryButton.add_Click($handler_CiscoDirectoryButton_Click)
$form1.Controls.Add($CiscoDirectoryButton)

$UpdateProxy.Name = "UpdateProxy"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 200
$System_Drawing_Size.Height = 50
$UpdateProxy.Size = $System_Drawing_Size
$UpdateProxy.Text = "Use Proxy"
$UpdateProxy.Font = $BoxFont
$UpdateProxy.Checked = $false
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 260
$System_Drawing_Point.Y = 235
$UpdateProxy.Location = $System_Drawing_Point
$UpdateProxy.UseVisualStyleBackColor = $True
$form1.Controls.Add($UpdateProxy)
$UpdateProxy.Add_CheckStateChanged({if ($UpdateProxy.Checked -eq $true){$UpdateLocSource.Checked = $false}})

$UpdateLocSource.Name = "UpdateLocSource"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 200
$System_Drawing_Size.Height = 50
$UpdateLocSource.Size = $System_Drawing_Size
$UpdateLocSource.Text = "Use LocalSource"
$UpdateLocSource.Font = $BoxFont
$UpdateLocSource.Checked = $false
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 80
$System_Drawing_Point.Y = 235
$UpdateLocSource.Location = $System_Drawing_Point
$UpdateLocSource.UseVisualStyleBackColor = $True
$form1.Controls.Add($UpdateLocSource)
$UpdateLocSource.Add_CheckStateChanged({if ($UpdateLocSource.Checked -eq $true){$UpdateProxy.Checked = $false}})

$AltCredential.Name = "AltCredential"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 275
$System_Drawing_Size.Height = 50
$AltCredential.Size = $System_Drawing_Size
$AltCredential.Text = " AltCredential"
$AltCredential.Font = $BoldBoxFont
$AltCredential.Checked = $false
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 500
$System_Drawing_Point.Y = 130
$AltCredential.Location = $System_Drawing_Point
$AltCredential.UseVisualStyleBackColor = $True
$form1.Controls.Add($AltCredential)
$AltCredential.Add_CheckStateChanged({& $handler_PreviewESButton_Click})

$ApplyTattoo.Name = "ApplyTattoo"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 230
$System_Drawing_Size.Height = 40
$ApplyTattoo.Size = $System_Drawing_Size
$ApplyTattoo.Text = " ApplyTattoo"
$ApplyTattoo.Font = $BoldBoxFont
$ApplyTattoo.Checked = $false
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 500
$System_Drawing_Point.Y = 170
$ApplyTattoo.Location = $System_Drawing_Point
$ApplyTattoo.UseVisualStyleBackColor = $True
$form1.Controls.Add($ApplyTattoo)
$ApplyTattoo.Add_CheckStateChanged({& $handler_PreviewESButton_Click})

$AllowDeprecated.Name = "AllowDeprecated"
$AllowDeprecated.Size = $System_Drawing_Size
$AllowDeprecated.Text = " AllowDeprecated"
$AllowDeprecated.Font = $BoldBoxFont
$AllowDeprecated.Checked = $false
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 500
$System_Drawing_Point.Y = 210
$AllowDeprecated.Location = $System_Drawing_Point
$AllowDeprecated.UseVisualStyleBackColor = $True
$form1.Controls.Add($AllowDeprecated)
$AllowDeprecated.Add_CheckStateChanged({& $handler_PreviewESButton_Click})

$VulnTimeoutLabel.Text = "VulnTimeout"
$VulnTimeoutLabel.Size = $System_Drawing_Size
$VulnTimeoutLabel.Font = $BoldBoxFont
$VulnTimeoutLabel.TextAlign = "TopLeft"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 780
$System_Drawing_Point.Y = 135
$VulnTimeoutLabel.Location = $System_Drawing_Point
$form1.Controls.Add($VulnTimeoutLabel)

$PreviousToKeepLabel.Text = "PreviousToKeep"
$PreviousToKeepLabel.Size = $System_Drawing_Size
$PreviousToKeepLabel.Font = $BoldBoxFont
$PreviousToKeepLabel.TextAlign = "TopLeft"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 780
$System_Drawing_Point.Y = 175
$PreviousToKeepLabel.Location = $System_Drawing_Point
$form1.Controls.Add($PreviousToKeepLabel)

$ThrottleLimitLabel.Text = "ThrottleLimit"
$ThrottleLimitLabel.Size = $System_Drawing_Size
$ThrottleLimitLabel.Font = $BoldBoxFont
$ThrottleLimitLabel.TextAlign = "TopLeft"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 780
$System_Drawing_Point.Y = 215
$ThrottleLimitLabel.Location = $System_Drawing_Point
$form1.Controls.Add($ThrottleLimitLabel)

$MarkingLabel.Text = "Marking"
$MarkingLabel.Size = $System_Drawing_Size
$MarkingLabel.Font = $BoldBoxFont
$MarkingLabel.TextAlign = "TopLeft"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 780
$System_Drawing_Point.Y = 255
$MarkingLabel.Location = $System_Drawing_Point
$form1.Controls.Add($MarkingLabel)

$VulnTimeoutBox.Name = "VulnTimeoutBox"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 150
$System_Drawing_Size.Height = 40
$VulnTimeoutBox.Size = $System_Drawing_Size
$VulnTimeoutBox.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1020
$System_Drawing_Point.Y = 135
$VulnTimeoutBox.Location = $System_Drawing_Point
$form1.Controls.Add($VulnTimeoutBox)
$VulnTimeoutBox.Add_KeyDown({if ($_.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {& $handler_PreviewESButton_Click}})

$PreviousToKeepBox.Name = "PreviousToKeepBox"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 150
$System_Drawing_Size.Height = 40
$PreviousToKeepBox.Size = $System_Drawing_Size
$PreviousToKeepBox.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1020
$System_Drawing_Point.Y = 175
$PreviousToKeepBox.Location = $System_Drawing_Point
$form1.Controls.Add($PreviousToKeepBox)
$PreviousToKeepBox.Add_KeyDown({if ($_.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {& $handler_PreviewESButton_Click}})

$ThrottleLimitBox.Name = "ThrottleLimitBox"
$ThrottleLimitBox.Size = $System_Drawing_Size
$ThrottleLimitBox.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1020
$System_Drawing_Point.Y = 215
$ThrottleLimitBox.Location = $System_Drawing_Point
$form1.Controls.Add($ThrottleLimitBox)
$ThrottleLimitBox.Add_KeyDown({if ($_.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {& $handler_PreviewESButton_Click}})

$MarkingBox.Name = "MarkingBox"
$MarkingBox.Size = $System_Drawing_Size
$MarkingBox.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1020
$System_Drawing_Point.Y = 255
$MarkingBox.Location = $System_Drawing_Point
$form1.Controls.Add($MarkingBox)
$MarkingBox.Add_KeyDown({if ($_.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {& $handler_PreviewESButton_Click}})

$ScanTypeLabel.Text = "ScanType"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 175
$System_Drawing_Size.Height = 40
$ScanTypeLabel.Size = $System_Drawing_Size
$ScanTypeLabel.Font = $BoldBoxFont
$ScanTypeLabel.TextAlign = "TopLeft"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 780
$System_Drawing_Point.Y = 295
$ScanTypeLabel.Location = $System_Drawing_Point
$form1.Controls.Add($ScanTypeLabel)

$AFKeysLabel.Text = "AF Keys"
$AFKeysLabel.Size = $System_Drawing_Size
$AFKeysLabel.Font = $BoldBoxFont
$AFKeysLabel.TextAlign = "TopLeft"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 780
$System_Drawing_Point.Y = 335
$AFKeysLabel.Location = $System_Drawing_Point
$form1.Controls.Add($AFKeysLabel)

$SMKeysLabel.Text = "SM Collection"
$SMKeysLabel.Size = $System_Drawing_Size
$SMKeysLabel.Font = $BoldBoxFont
$SMKeysLabel.TextAlign = "TopLeft"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 780
$System_Drawing_Point.Y = 375
$SMKeysLabel.Location = $System_Drawing_Point
$form1.Controls.Add($SMKeysLabel)

$SMPassphraseLabel.Text = "SM Passphrase"
$SMPassphraseLabel.Size = $System_Drawing_Size
$SMPassphraseLabel.Font = $BoldBoxFont
$SMPassphraseLabel.TextAlign = "TopLeft"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 780
$System_Drawing_Point.Y = 415
$SMPassphraseLabel.Location = $System_Drawing_Point
$form1.Controls.Add($SMPassphraseLabel)

$STIGManager.Name = "STIGManager"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 180
$System_Drawing_Size.Height = 40
$STIGManager.Size = $System_Drawing_Size
$STIGManager.Text = " STIGManager"
$STIGManager.Font = $BoldBoxFont
$STIGManager.Checked = $false
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 500
$System_Drawing_Point.Y = 295
$STIGManager.Location = $System_Drawing_Point
$STIGManager.UseVisualStyleBackColor = $True
$form1.Controls.Add($STIGManager)
$STIGManager.Add_CheckStateChanged({if($STIGManager.Checked){
                                        $AllSMKeys = $Preferences.Preferences.STIGManager.SMImport_COLLECTION.Name
                                        $AllSMKeys | ForEach-Object { $null = $SMKeys.Items.Add($_) }
                                        $SMKeys.SelectedItem = $Preferences.Preferences.EvaluateSTIG.SMCOLLECTION
                                        $SMKeys.Enabled = $True
                                    }
                                    else{
                                        $SMKeys.Enabled = $False; $SMKeys | ForEach-Object {$_.Items.Clear()}
                                        $SMPassphraseBox.Enabled = $false
                                    }
                                    Get-OutputPath})

$CombinedCKL.Name = "CombinedCKL"
$CombinedCKL.Size = $System_Drawing_Size
$CombinedCKL.Text = " CombinedCKL"
$CombinedCKL.Font = $BoldBoxFont
$CombinedCKL.Checked = $false
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 500
$System_Drawing_Point.Y = 335
$CombinedCKL.Location = $System_Drawing_Point
$CombinedCKL.UseVisualStyleBackColor = $True
$form1.Controls.Add($CombinedCKL)
$CombinedCKL.Add_CheckStateChanged({Get-OutputPath})

$CombinedCKLB.Name = "CombinedCKLB"
$CombinedCKLB.Size = $System_Drawing_Size
$CombinedCKLB.Text = " CombinedCKLB"
$CombinedCKLB.Font = $BoldBoxFont
$CombinedCKLB.Checked = $false
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 500
$System_Drawing_Point.Y = 375
$CombinedCKLB.Location = $System_Drawing_Point
$CombinedCKLB.UseVisualStyleBackColor = $True
$form1.Controls.Add($CombinedCKLB)
$CombinedCKLB.Add_CheckStateChanged({Get-OutputPath})

$CKLOutput.Name = "CKLOutput"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 120
$System_Drawing_Size.Height = 40
$CKLOutput.Size = $System_Drawing_Size
$CKLOutput.Text = " CKL"
$CKLOutput.Font = $BoldBoxFont
$CKLOutput.Checked = $false
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 500
$System_Drawing_Point.Y = 415
$CKLOutput.Location = $System_Drawing_Point
$CKLOutput.UseVisualStyleBackColor = $True
$form1.Controls.Add($CKLOutput)
$CKLOutput.Add_CheckStateChanged({Get-OutputPath})

$CKLBOutput.Name = "CKLBOutput"
$CKLBOutput.Size = $System_Drawing_Size
$CKLBOutput.Text = " CKLB"
$CKLBOutput.Font = $BoldBoxFont
$CKLBOutput.Checked = $false
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 625
$System_Drawing_Point.Y = 415
$CKLBOutput.Location = $System_Drawing_Point
$CKLBOutput.UseVisualStyleBackColor = $True
$form1.Controls.Add($CKLBOutput)
$CKLBOutput.Add_CheckStateChanged({Get-OutputPath})

$Summary.Name = "Summary"
$Summary.Size = $System_Drawing_Size
$Summary.Text = " Summary"
$Summary.Font = $BoldBoxFont
$Summary.Checked = $false
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 500
$System_Drawing_Point.Y = 445
$Summary.Location = $System_Drawing_Point
$Summary.UseVisualStyleBackColor = $True
$form1.Controls.Add($Summary)
$Summary.Add_CheckStateChanged({Get-OutputPath})

$OQE.Name = "OQE"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 80
$System_Drawing_Size.Height = 40
$OQE.Size = $System_Drawing_Size
$OQE.Text = " OQE"
$OQE.Font = $BoldBoxFont
$OQE.Checked = $false
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 625
$System_Drawing_Point.Y = 445
$OQE.Location = $System_Drawing_Point
$OQE.UseVisualStyleBackColor = $True
$form1.Controls.Add($OQE)
$OQE.Add_CheckStateChanged({Get-OutputPath})

$ScanType.Name = "ScanType"
$ScanType.Font = $BoxFont
$ScanType.Width = 200
$ScanType.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 970
$System_Drawing_Point.Y = 295
$ScanType.Location = $System_Drawing_Point
$form1.Controls.Add($ScanType)
$ScanType.add_SelectedIndexChanged({& $handler_PreviewESButton_Click})

$AFKeys.Name = "AF Keys"
$AFKeys.Font = $BoxFont
$AFKeys.Width = 200
$AFKeys.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 970
$System_Drawing_Point.Y = 335
$AFKeys.Location = $System_Drawing_Point
$form1.Controls.Add($AFKeys)
$AFKeys.add_SelectedIndexChanged({& $handler_PreviewESButton_Click})

$SMKeys.Name = "SM Collection"
$SMKeys.Font = $BoxFont
$SMKeys.Width = 200
$SMKeys.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 970
$System_Drawing_Point.Y = 375
$SMKeys.Location = $System_Drawing_Point
$form1.Controls.Add($SMKeys)
$SMKeys.add_SelectedIndexChanged({$SMPassphraseBox.Enabled = $True;& $handler_PreviewESButton_Click})

$SMPassphraseBox.Name = "SM Passphrase"
$SMPassphraseBox.Size = $System_Drawing_Size
$SMPassphraseBox.Font = $BoxFont
$SMPassphraseBox.Width = 200
$SMPassphraseBox.PasswordChar = '*'
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 970
$System_Drawing_Point.Y = 415
$SMPassphraseBox.Location = $System_Drawing_Point
$form1.Controls.Add($SMPassphraseBox)
$SMPassphraseBox.Add_KeyDown({if ($_.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {& $handler_PreviewESButton_Click}})

$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 1270
$System_Drawing_Size.Height = 30
$ESPathLabel.Size = $System_Drawing_Size
$ESPathLabel.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 5
$System_Drawing_Point.Y = 520
$ESPathLabel.Location = $System_Drawing_Point
$form1.Controls.Add($ESPathLabel)

$AFPathLabel.Size = $System_Drawing_Size
$AFPathLabel.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 5
$System_Drawing_Point.Y = 550
$AFPathLabel.Location = $System_Drawing_Point
$form1.Controls.Add($AFPathLabel)

$OutputPathLabel.Size = $System_Drawing_Size
$OutputPathLabel.Font = $BoxFont
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 5
$System_Drawing_Point.Y = 580
$OutputPathLabel.Location = $System_Drawing_Point
$form1.Controls.Add($OutputPathLabel)

$VLineLeft.Text = ""
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 2
$System_Drawing_Size.Height = 450
$VLineLeft.Size = $System_Drawing_Size
$VLineLeft.BorderStyle = "Fixed3D"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 475
$System_Drawing_Point.Y = 60
$VLineLeft.Location = $System_Drawing_Point
$form1.Controls.Add($VLineLeft)

$HLineTop.Text = ""
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 1920
$System_Drawing_Size.Height = 2
$HLineTop.Size = $System_Drawing_Size
$HLineTop.BorderStyle = "Fixed3D"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 0
$System_Drawing_Point.Y = 60
$HLineTop.Location = $System_Drawing_Point
$form1.Controls.Add($HLineTop)

$HLineOptionBottom.Text = ""
$HLineOptionBottom.Size = $System_Drawing_Size
$HLineOptionBottom.BorderStyle = "Fixed3D"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 0
$System_Drawing_Point.Y = 510
$HLineOptionBottom.Location = $System_Drawing_Point
$form1.Controls.Add($HLineOptionBottom)

$HLineBottom.Text = ""
$HLineBottom.Size = $System_Drawing_Size
$HLineBottom.BorderStyle = "Fixed3D"
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 0
$System_Drawing_Point.Y = 775
$HLineBottom.Location = $System_Drawing_Point
$form1.Controls.Add($HLineBottom)

$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 860
$System_Drawing_Size.Height = 20
$BottomLine.Size = $System_Drawing_Size
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 5
$System_Drawing_Point.Y = 780
$BottomLine.Location = $System_Drawing_Point
$form1.Controls.Add($BottomLine)

$BottomLineVersion.Text = "v $ManageESVerson"
$System_Drawing_Size = New-Object System.Drawing.Size
$System_Drawing_Size.Width = 50
$System_Drawing_Size.Height = 20
$BottomLineVersion.Size = $System_Drawing_Size
$System_Drawing_Point = New-Object System.Drawing.Point
$System_Drawing_Point.X = 1700
$System_Drawing_Point.Y = 780
$BottomLineVersion.Location = $System_Drawing_Point
$form1.Controls.Add($BottomLineVersion)

$form1.ResumeLayout()

#Init the OnLoad event to correct the initial state of the form
$InitialFormWindowState = $form1.WindowState

#Save the initial state of the form
$form1.add_Load($OnLoadForm_StateCorrection)

$form1.Add_FormClosed($handler_formclose)
#Show the Form
$null = [Windows.Forms.Application]::Run($form1)

# SIG # Begin signature block
# MIIL+QYJKoZIhvcNAQcCoIIL6jCCC+YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAOH1Y9qbXb83/8
# MHT82mq7JDsxRJoUqgqppcbWodt8BaCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDm+P3MqwNEkbDO4sODIvYPEWky/zB8
# PjTD7TzZO+NRADANBgkqhkiG9w0BAQEFAASCAQB8fAVzsBqNDwsAENlhpKM9yQaT
# p3ichyneBYd9wdiuctCP8lbBbtCfCImNaJHSxPLQJgYbO6FNaa0CrmiIUMuQ+dUB
# REjvqDxfTb5rzEsNrxX7XrjiMNbs/TE7ijMHVh6b9lTanEuvXUDp51V15etjr5CH
# m2t/b+dCxNghdKb7KbnLIt8inkkcg2wu5nT4fDCGZz7Gk/wObY/He3UdisbOUjur
# LAaG+n+YVE4uJmSRlVo1VIV17u8rt+H9gjFizqozFwSP5O+1rnzi+2uSgHNuo/nq
# 6uq1iMWNySH26Rj0NLt1VeAEsMgCBmj+Wmy3RefolrbVW7yA+7nmIw61Jwdi
# SIG # End signature block
