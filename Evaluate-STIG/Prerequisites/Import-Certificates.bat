::::::::::::::::::::::::::::::::::::::::::
:: Automatcially check & get admin rights
::::::::::::::::::::::::::::::::::::::::::
@echo off
CLS
ECHO.
ECHO =====================================
ECHO Running Admin shell
ECHO =====================================

:init
setlocal DisableDelayedExpansion
set "batchPath=%~0"
for %%k in (%0) do set batchName=%%~nk
set "vbsGetPrivileges=%temp%\OEgetPriv_%batchName%.vbs"
setlocal EnableDelayedExpansion

:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%'=='0' (goto gotPrivileges) else (goto getPrivileges)

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)
ECHO.
ECHO *************************************
ECHO Invoking UAC for Privilege Escalation
ECHO *************************************

ECHO Set UAC = CreateObject^("Shell.Application"^) > %vbsGetPrivileges%"
ECHO args = "ELEV " >> "%vbsGetPrivileges%"
ECHO For Each strArg in WScript.Arguments >> "%vbsGetPrivileges%"
ECHO args = args ^& strArg ^& " " >> "%vbsGetPrivileges%"
ECHO Next >> "%vbsGetPrivileges%"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%vbsGetPrivileges%"
"%SystemRoot%\System32\WScript.exe" "%vbsGetPrivileges%" %*
exit /B

:gotPrivileges
setlocal & pushd .
cd /d %~dp0
if '%1'=='ELEV' (del "%vbsGetPrivileges%" 1>nul 2>nul & shift /1)

::::::::::::::::::::::::::::::::::::::::::
:: START
::::::::::::::::::::::::::::::::::::::::::
ECHO.

SETLOCAL
CALL :GETPARENT PARENT
IF /I "%PARENT%" == "powershell" GOTO :ISPOWERSHELL
IF /I "%PARENT%" == "pwsh" GOTO :ISPWSH
ENDLOCAL

GOTO :ISPOWERSHELL

:GETPARENT
SET "PSCMD=$ppid=$pid;while($i++ -lt 3 -and ($ppid=(Get-CimInstance Win32_Process -Filter ('ProcessID='+$ppid)).ParentProcessId)) {}; (Get-Process -ErrorAction Ignore -ID $ppid).Name"

for /f "tokens=*" %%i in ('powershell -noprofile -command "%PSCMD%"') do SET %1=%%i

GOTO :EOF

:ISPOWERSHELL
SET PSEXE=powershell.exe
GOTO :EXECUTEPS

:ISPWSH
SET PSEXE=pwsh.exe
GOTO :EXECUTEPS

:EXECUTEPS
REM Check for/install DoD Root CA 3 certificate
%PSEXE% -NoProfile -Command "Try {If (Get-ChildItem Cert:\LocalMachine\Root | Where-Object Thumbprint -eq 'D73CA91102A2204A36459ED32213B467D7CE97FB') {Write-Host 'DoD Root CA 3 certificate is already imported to Local Machine\Root store.' -ForegroundColor Cyan} Else {Import-Certificate %~dp0Certificates\DoD_Root_CA_3.cer -CertStoreLocation Cert:\LocalMachine\Root | Out-Null; Write-Host 'DoD_Root_CA_3.cer successfully imported to Local Machine\Root store.' -ForegroundColor Green}} Catch {Write-Host 'Warning: Import-Certificate failed to import DoD_Root_CA_3.cer' -ForegroundColor Yellow; Write-Host $_.Exception.Message -ForegroundColor Yellow; Write-Host 'Attempting with certutil.exe...' -ForegroundColor Yellow; certutil.exe -enterprise -addstore 'Root' %~dp0Certificates\DoD_Root_CA_3.cer}"

REM Check for/install DOD ID CA-59 certificate
%PSEXE% -NoProfile -Command "Try {If (Get-ChildItem Cert:\LocalMachine\CA | Where-Object Thumbprint -eq '1907FC2B223EE0301B45745BDB59AAD90FE7C5D7') {Write-Host 'DOD ID CA-59 certificate is already imported to Local Machine\CA.' -ForegroundColor Cyan} Else {Import-Certificate %~dp0Certificates\DOD_ID_CA-59.cer -CertStoreLocation Cert:\LocalMachine\CA | Out-Null; Write-Host 'DOD_ID_CA-59.cer successfully imported to Local Machine\CA.' -ForegroundColor Green}} Catch {Write-Host 'Warning: Import-Certificate failed to import DOD_ID_CA-59.cer' -ForegroundColor Yellow; Write-Host $_.Exception.Message -ForegroundColor Yellow; Write-Host 'Attempting with certutil.exe...' -ForegroundColor Yellow; certutil.exe -enterprise -addstore 'CA' %~dp0Certificates\DOD_ID_CA-59.cer}"

REM Check for/install CS.NSWCCD.001 certificate
%PSEXE% -NoProfile -Command "Try {If (Get-ChildItem Cert:\LocalMachine\TrustedPublisher | Where-Object Thumbprint -eq 'D95F944E33528DC23BEE8672D6D38DA35E6F0017') {Write-Host 'CS.NSWCCD.001 certificate is already imported to Local Machine\Trusted Publishers store.' -ForegroundColor Cyan} Else {Import-Certificate %~dp0Certificates\CS.NSWCCD.001.cer -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null; Write-Host 'CS.NSWCCD.001.cer successfully imported to Local Machine\Trusted Publishers store.' -ForegroundColor Green}} Catch {Write-Host 'Warning: Import-Certificate failed to import CS.NSWCCD.001.cer' -ForegroundColor Yellow; Write-Host $_.Exception.Message -ForegroundColor Yellow; Write-Host 'Attempting with certutil.exe...' -ForegroundColor Yellow; certutil.exe -enterprise -addstore 'TrustedPublisher' %~dp0Certificates\CS.NSWCCD.001.cer}"

ECHO.
ECHO.
Pause
EXIT /B