#requires -version 7

function ConvertTo-Base64UrlString {
  <#
      .SYNOPSIS
      Base64url encoder.
      .DESCRIPTION
      Encodes a string or byte array to base64url-encoded string.
      .PARAMETER in
      Specifies the input. Must be string, or byte array.
      .INPUTS
      You can pipe the string input to ConvertTo-Base64UrlString.
      .OUTPUTS
      ConvertTo-Base64UrlString returns the encoded string by default.
      .EXAMPLE
      PS Variable:> '{"alg":"RS256","typ":"JWT"}' | ConvertTo-Base64UrlString
      eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9
      .LINK
      https://github.com/SP3269/posh-jwt
      .LINK
      https://jwt.io/
  #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]$in
    )
    if ($in -is [string]) {
        return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($in)) -replace '\+','-' -replace '/','_' -replace '='
    }
    elseif ($in -is [byte[]]) {
        return [Convert]::ToBase64String($in) -replace '\+','-' -replace '/','_' -replace '='
    }
    else {
        Return "ConvertTo-Base64UrlString requires string or byte array input, received $($in.GetType())"
    }
}

function New-Jwt{
  <#
      .SYNOPSIS
      Creates a JWT (JSON Web Token).
      .DESCRIPTION
      Creates signed JWT given a signing certificate and claims in JSON.
      .PARAMETER Payload
      Specifies a JWT header. Optional. Defaults to '{"alg":"RS256","typ":"JWT"}'.
      .PARAMETER Cert
      Specifies the signing certificate of type System.Security.Cryptography.X509Certificates.X509Certificate2. Must be specified and contain the private key if the algorithm in the header is RS256.

      .LINK
      https://github.com/SP3269/posh-jwt
      .LINK
      https://jwt.io/
  #>
  param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)][string]$PayloadJson,
        [Parameter(Mandatory=$false)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert
    )

  $Header = '{"alg":"RS256","typ":"JWT"}'

  $encodedHeader = ConvertTo-Base64UrlString $Header
  $encodedPayload = ConvertTo-Base64UrlString $PayloadJson

  $jwt = $encodedHeader + '.' + $encodedPayload
  $toSign = [System.Text.Encoding]::UTF8.GetBytes($jwt)

  $rsa = $Cert.PrivateKey
  $sig = ConvertTo-Base64UrlString $rsa.SignData($toSign,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)

  $jwt = $jwt + '.' + $sig
  return $jwt
}

Function Get-SMAuthToken {
  Param (
    [Parameter(Mandatory = $true)]
    [String]$LogPath,

    [Parameter(Mandatory = $true)]
    [ValidateSet("Windows", "Linux")]
    [String]$OSPlatform,

    [Parameter(Mandatory=$true)]
    [string]$SMImport_AUTHORITY,

    [Parameter(Mandatory=$true)]
    [string]$SMImport_CLIENT_ID,

    [Parameter(Mandatory=$true)]
    [string]$SMImport_CLIENT_CERT,

    [Parameter(Mandatory=$false)]
    [string]$SMImport_CLIENT_CERT_KEY,

    [Parameter(Mandatory=$false)]
    [securestring]$SMImport_CLIENT_CERT_KEY_PASSPHRASE

  )

  $SMImport_CLIENT_CERT = $SMImport_CLIENT_CERT -replace '"',''  #Deal with quoted paths being passed

  if (!(Test-Path $SMImport_CLIENT_CERT)){
    Write-Log -Path $LogPath -Message "ERROR: $SMImport_CLIENT_CERT not found." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
    Return
  }

  if ($SMImport_CLIENT_CERT_KEY){
    $SMImport_CLIENT_CERT_KEY = $SMImport_CLIENT_CERT_KEY -replace '"',''  #Deal with quoted paths being passed

    if (!(Test-Path $SMImport_CLIENT_CERT_KEY)){
      Write-Log -Path $LogPath -Message "ERROR: $SMImport_CLIENT_CERT_KEY not found." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
      Return
    }
  }

  $apiauthendpoint = "$SMImport_AUTHORITY/protocol/openid-connect/token"

  $oauthScopes = "stig-manager:stig:read stig-manager:collection stig-manager:user:read"
  $contentType = 'application/x-www-form-urlencoded'

  $json = ConvertTo-Json @{
    iss = $SMImport_CLIENT_ID
    sub = $SMImport_CLIENT_ID
    aud = $apiauthendpoint
    jti = (1..16|ForEach-Object{[byte](Get-Random -Max 256)}|ForEach-Object ToString X2) -join ''
    exp = ([DateTimeOffset](Get-Date)).ToUnixTimeSeconds() + 60 #Expire token in 1 minute (good for repeated calls)
  }

  if ($SMImport_CLIENT_CERT_KEY){
    $SMImport_PASSPHRASE = ConvertFrom-SecureString $SMImport_CLIENT_CERT_KEY_PASSPHRASE -AsPlainText
    $cert = [system.security.Cryptography.X509Certificates.X509Certificate2]::CreateFromEncryptedPemFile($SMImport_CLIENT_CERT, $SMImport_PASSPHRASE, $SMImport_CLIENT_CERT_KEY)
  }
  else{
    $cert = [system.security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile($SMImport_CLIENT_CERT)
  }

  $signed = New-Jwt -Cert $Cert -PayloadJson $json

  $body = @{
    grant_type = 'client_credentials'
    client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
    client_assertion = $signed
    scope = $oauthScopes
  }

  Try {
    $accessRequest = Invoke-RestMethod -Method POST -Uri $apiauthendpoint -body $body -ContentType $contentType -ErrorAction STOP
  }
  Catch{
    Write-Log -Path $LogPath -Message "ERROR: Unable to create Access Request Token." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
    Return
  }

  $AccessToken = $accessRequest.access_token

  $authheader = @{
    Authorization="Bearer $AccessToken"
  }

  Return $authheader
}

Function Get-SMParameters {
  Param (
    [Parameter(Mandatory = $true)]
    [String]$SMCollection,

    [Parameter(Mandatory = $false)]
    [SecureString]$SMPassphrase,

    [Parameter(Mandatory)]
    [psobject]$ScanObject,

    [Parameter(Mandatory = $true)]
    [String]$ScriptRoot,

    [Parameter(Mandatory = $true)]
    [String]$WorkingDir,

    [Parameter(Mandatory = $true)]
    [String]$LogComponent,

    [Parameter(Mandatory = $true)]
    [String]$OSPlatform,

    [Parameter(Mandatory = $true)]
    [String]$LogPath
  )

  Write-Log -Path $LogPath -Message "Importing to STIG Manager..." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

  #Get Preferences
  $Preferences = (Select-Xml -Path $(Join-Path $ScriptRoot -ChildPath Preferences.xml) -XPath /).Node

  ForEach ($Item in ($Preferences.Preferences.STIGManager | Get-Member -MemberType Property | Where-Object Definition -MATCH string | Where-Object Name -NE '#comment').Name) {
      $Preferences.Preferences.STIGManager.$Item = $Preferences.Preferences.STIGManager.$Item -replace '"','' -replace "'",''
  }

  Try {
    if ($Preferences.Preferences.STIGManager | Select-Object -ExpandProperty SMImport_Collection | Where-Object Name -EQ $SMCollection){
      $STIGManagerObject = $Preferences.Preferences.STIGManager | Select-Object -ExpandProperty SMImport_Collection | Where-Object Name -EQ $SMCollection
      Write-Log -Path $LogPath -Message "STIGManager Collection: $SMCollection" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
      Write-Log -Path $LogPath -Message "Uploading to STIG Manager..." -WriteOutToStream -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

      Switch ($OSPlatform) {
        "Windows" {
            $TempLogDir = Join-Path -Path (Get-Item $env:TEMP).FullName -ChildPath "Evaluate-STIG"
        }
        "Linux" {
            $TempLogDir = "/tmp/Evaluate-STIG"
        }
    }

      $STIGLog_STIGManager = Join-Path -Path $TempLogDir -ChildPath "Evaluate-STIG_STIGManager.log"

      $SMImport_Params = @{
          LogPath                = $STIGLog_STIGManager
          OSPlatform             = $OSPlatform
          SMImport_API_BASE      = $Preferences.Preferences.STIGManager.SMImport_API_BASE
          SMImport_AUTHORITY     = $Preferences.Preferences.STIGManager.SMImport_AUTHORITY
          SMImport_CLIENT_ID     = $STIGManagerObject.SMImport_CLIENT_ID
          SMImport_CLIENT_CERT   = $STIGManagerObject.SMImport_CLIENT_CERT
          SMImport_COLLECTION_ID = $STIGManagerObject.SMImport_COLLECTION_ID
          Scan_Objects           = $ScanObject
      }

      if ($STIGManagerObject.SMImport_CLIENT_CERT_KEY) {
          $SMImport_Params.SMImport_CLIENT_CERT_KEY = $STIGManagerObject.SMImport_CLIENT_CERT_KEY
          $SMImport_Params.SMImport_CLIENT_CERT_KEY_PASSPHRASE = $SMPassphrase
      }
      
      Return $SMImport_Params
    }
  }
  Catch {
      Write-Log -Path $LogPath -Message "ERROR: $($_.Exception.Message)" -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform

      Throw "Failed to import STIGManager Preferences."
  }
}

Function Import-Asset {
  Param (
    [Parameter(Mandatory = $true)]
    [String]$LogPath,

    [Parameter(Mandatory = $true)]
    [ValidateSet("Windows", "Linux")]
    [String]$OSPlatform,

    [Parameter(Mandatory=$true)]
    [string]$SMImport_API_BASE,

    [Parameter(Mandatory=$true)]
    [string]$SMImport_AUTHORITY,

    [Parameter(Mandatory=$true)]
    [string]$SMImport_CLIENT_ID,

    [Parameter(Mandatory=$true)]
    [string]$SMImport_CLIENT_CERT,

    [Parameter(Mandatory=$false)]
    [string]$SMImport_CLIENT_CERT_KEY,

    [Parameter(Mandatory=$false)]
    [securestring]$SMImport_CLIENT_CERT_KEY_PASSPHRASE,

    [Parameter(Mandatory=$true)]
    [string]$SMImport_COLLECTION_ID,

    [Parameter(Mandatory)]
    [psobject]$Scan_Objects,

    [Parameter(Mandatory=$false)]
    [int]$MaximumRetryCount = 3
  )

  Write-Host "  Processing $(($Scan_Objects.VulnResults | Measure-Object).Count) Vulnerabilities..."

  $Body_Array = New-Object System.Collections.Generic.List[System.Object]
  
  Foreach ($Scan_Object in $Scan_Objects){
    $CKL_HOST_NAME = $Scan_Object.TargetData.HostName
    if ($Scan_Object.TargetData.WebOrDatabase -eq "true"){
      if ($Scan_Object.TargetData.Site){
        $CKL_HOST_NAME = "$($CKL_HOST_NAME)-$($Scan_Object.TargetData.Site)"
      }
      else{
        $CKL_HOST_NAME = "$($CKL_HOST_NAME)-NA"
      }
      if ($Scan_Object.TargetData.Instance){
        $CKL_HOST_NAME = "$($CKL_HOST_NAME)-$($Scan_Object.TargetData.Instance)"
      }
      else{
        $CKL_HOST_NAME = "$($CKL_HOST_NAME)-NA"
      }
    }

    $benchmarkId = $Scan_Object.STIGInfo.STIGID
    
    if ($SMImport_CLIENT_CERT_KEY){
      $authheader = Get-SMAuthToken -LogPath $LogPath -OSPlatform $OSPlatform -SMImport_AUTHORITY $SMImport_AUTHORITY -SMImport_CLIENT_ID $SMImport_CLIENT_ID -SMImport_CLIENT_CERT $SMImport_CLIENT_CERT -SMImport_CLIENT_CERT_KEY $SMImport_CLIENT_CERT_KEY -SMImport_CLIENT_CERT_KEY_PASSPHRASE $SMImport_CLIENT_CERT_KEY_PASSPHRASE
    }
    else{
      $authheader = Get-SMAuthToken -LogPath $LogPath -OSPlatform $OSPlatform -SMImport_AUTHORITY $SMImport_AUTHORITY -SMImport_CLIENT_ID $SMImport_CLIENT_ID -SMImport_CLIENT_CERT $SMImport_CLIENT_CERT
    }

    Try {
      $STIG = Invoke-RestMethod -Uri "$SMImport_API_BASE/stigs/$benchmarkId" -Headers $authHeader -Method GET
    }
    catch {
      Write-Log -Path $LogPath -Message "ERROR: Unable to obtain stig, aborting..." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
      return
    }

    $STIG_Data = @{
      title = $STIG.title
      rulecount = $STIG.rulecount
      benchmarkId = $benchmarkID
      revisionStrs = $STIG.revisionStrs
      lastRevisionStr = $STIG.lastRevisionDate
    }

    $Review_Data = New-Object System.Collections.Generic.List[System.Object]

    Foreach ($Vuln in $Scan_Object.VulnResults){
      Switch ($Vuln.Status){
        "NotAFinding"    {$result = "pass"}
        "Open"           {$result = "fail"}
        "Not_Applicable" {$result = "notapplicable"}
        "Not_Reviewed"   {$result = "notchecked"}
      }

      If (($Vuln.FindingDetails | Measure-Object -Character).Characters -gt 32767) {
          $FindingDetails = $($Vuln.FindingDetails).Substring(0, [System.Math]::Min(32717, $($Vuln.FINDING_DETAILS).Length)) + "`r`n`r`n---truncated results. met character limit---" | Out-String
      }
      else{
        $FindingDetails = $Vuln.FindingDetails
      }
      
      if ($Vuln.STIGMan.AFMod -eq $true){
        $NewObj = [PSCustomObject]@{
            ruleId       = $Vuln.RuleID
            result       = $result
            detail       = $FindingDetails
            comment      = $Vuln_ESComment
            resultEngine = @{
              type         = "script"
              product      = "Evaluate-STIG"
              version      = ($Scan_Object.ESData.ModuleVersion).ToString()
              time         = $Scan_Object.ESData.StartTime
              checkcontent = @{
                location = $Scan_Object.ESData.ModuleName
              }
              overrides = @{
                authority = $Vuln.STIGMan.Answerfile
                oldResult = $Vuln.STIGMan.OldStatus
                newResult = $Vuln.STIGMan.NewStatus
                remark    = "Evaluate-STIG Answer File"
              }
            }
            saved        = "saved"
        }
      }
      else{
        $NewObj = [PSCustomObject]@{
            ruleId       = $Vuln.RuleID
            result       = $result
            detail       = $FindingDetails
            comment      = $Vuln_ESComment
            resultEngine = @{
              type         = "script"
              product      = "Evaluate-STIG"
              version      = ($Scan_Object.ESData.ModuleVersion).ToString()
              time         = $Scan_Object.ESData.StartTime
              checkcontent = @{
                location = $Scan_Object.ESData.ModuleName
              }
            }
            saved        = "saved"
        }
      }

      $null = $Review_Data.Add($NewObj)
    }

    Try {
      $Collections = Invoke-RestMethod -Uri "$SMImport_API_BASE/collections" -Headers $authHeader -Method GET
    }
    catch {
      Write-Log -Path $LogPath -Message "ERROR: Unable to obtain collections, aborting..." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
      return
    }

    Try {
      $Collection = Invoke-RestMethod -Uri "$SMImport_API_BASE/assets?collectionId=$SMImport_COLLECTION_ID" -Headers $authHeader -Method GET
    }
    Catch{
      Write-Log -Path $LogPath -Message "ERROR: Unable to access $SMImport_COLLECTION_ID, aborting..." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
      Return
    }

    $assetid = ($collection | Where-Object { $_.name -eq $CKL_HOST_NAME }).assetid
    
    if (!($assetid)){
      Write-Log -Path $LogPath -Message "$CKL_HOST_NAME not found in $(($Collections | Where-Object {$_.collectionID -eq $SMImport_COLLECTION_ID}).Name). Attempting POST..." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform

      $body = @{
        name = $CKL_HOST_NAME
        fqdn = $Scan_Object.TargetData.FQDN
        collectionId = $SMImport_COLLECTION_ID
        description = ""
        ip = $Scan_Object.TargetData.IPAddress
        mac = $Scan_Object.TargetData.MacAddress
        noncomputing = $false
        metadata = @{
          cklRole = $Scan_Object.TargetData.Role
        }
        stigs = @($STIG_Data.ToString())
      }

      Try {
        $null = Invoke-RestMethod -Uri "$SMImport_API_BASE/assets" -Headers $authHeader -ContentType 'application/json' -Method POST -Body (ConvertTo-Json -InputObject $body -Depth 4) -SkipHTTPErrorCheck -MaximumRetryCount $MaximumRetryCount

        Write-Log -Path $LogPath -Message "Able to access $CKL_HOST_NAME for POST..." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Log -Path $LogPath -Message "$CKL_HOST_NAME posted for $($STIG_Data.Title)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
      }
      catch {
        Write-Log -Path $LogPath -Message "ERROR: Unable to access $CKL_HOST_NAME for POST, aborting..." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
        return
      }
      #Get the collection again after POST
      Try {
        $Collections = Invoke-RestMethod -Uri "$SMImport_API_BASE/collections" -Headers $authHeader -Method GET
      }
      catch {
        Write-Log -Path $LogPath -Message "ERROR: Unable to obtain collections, aborting..." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
        return
      }

      Try {
        $Collection = Invoke-RestMethod -Uri "$SMImport_API_BASE/assets?collectionId=$SMImport_COLLECTION_ID" -Headers $authHeader -Method GET
      }
      Catch{
        Write-Log -Path $LogPath -Message "ERROR: Unable to access $SMImport_COLLECTION_ID, aborting..." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
        Return
      }

      $assetid = ($collection | Where-Object { $_.name -eq $CKL_HOST_NAME }).assetid
    }
    
    $body = @{
      title = $STIG.title
      rulecount = $STIG.rulecount
      benchmarkId = $benchmarkID
      revisionStrs = $STIG.revisionStrs
      lastRevisionStr = $STIG.lastRevisionDate
    }

    Try {
        $null = Invoke-RestMethod -Uri "$SMImport_API_BASE/assets/$assetId/stigs/$benchmarkId" -Headers $authHeader -ContentType 'application/json' -Method PUT -Body (ConvertTo-Json -InputObject $body -Depth 4) -SkipHTTPErrorCheck -MaximumRetryCount $MaximumRetryCount

        Write-Log -Path $LogPath -Message "Able to access $CKL_HOST_NAME for PUT..." -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
        Write-Log -Path $LogPath -Message "$CKL_HOST_NAME posted for $($STIG_Data.Title) ($benchmarkId)" -Component $LogComponent -Type "Info" -OSPlatform $OSPlatform
      }
      catch {
        Write-Log -Path $LogPath -Message "ERROR: Unable to access $CKL_HOST_NAME for STIG assign, aborting..." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
        return
      }

    $Review_Data | Foreach-Object {
        if ($_.resultEngine.product -eq "Evaluate-STIG" ){
          if ($_.resultEngine.overrides){
            $body = @{
              ruleId       = $_.ruleId
              result       = $_.result
              detail       = $_.detail
              comment      = $_.comment
              resultEngine = @{
                type         = $_.resultEngine.type
                product      = $_.resultEngine.product
                version      = $_.resultEngine.version
                time         = $_.resultEngine.time
                checkContent = @{
                  location = $_.resultEngine.checkcontent.location
                }
                overrides = @($_.resultEngine.overrides)
              }
              status       = $_.saved
            }
          }
          else{
            $body = @{
              ruleId       = $_.ruleId
              result       = $_.result
              detail       = $_.detail
              comment      = $_.comment
              resultEngine = @{
                type         = $_.resultEngine.type
                product      = $_.resultEngine.product
                version      = $_.resultEngine.version
                time         = $_.resultEngine.time
                checkContent = @{
                  location = $_.resultEngine.checkcontent.location
                }
              }
              status       = $_.saved
            }
          }
        }
        else{
          $body = @{
            ruleId       = $_.ruleId
            result       = $_.result
            detail       = $_.detail
            comment      = $_.comment
            status       = $_.saved
          }
        }
      $null = $Body_Array.Add($body)
    }
  }

  Try {
      Write-Host "    Attempting upload of $(($Body_Array | Measure-Object).Count) Reviews..." -ForegroundColor DarkYellow
      $null = Invoke-RestMethod -Uri "$SMImport_API_BASE/collections/$SMImport_COLLECTION_ID/reviews/$assetId" -Headers $authHeader -ContentType 'application/json' -Method POST -Body (ConvertTo-Json -InputObject $Body_Array -Depth 4) -SkipHTTPErrorCheck -MaximumRetryCount $MaximumRetryCount
    }
    catch {
      Write-Host "  Upload Failed..." -ForegroundColor Red
      Write-Log -Path $LogPath -Message "ERROR: Unable to access $CKL_HOST_NAME for Reviews, aborting..." -WriteOutToStream -Component $LogComponent -Type "Error" -OSPlatform $OSPlatform
    }
}

# SIG # Begin signature block
# MIIL+QYJKoZIhvcNAQcCoIIL6jCCC+YCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBuMGzvxq+YQuVG
# ydidkCs0aLfpkkw+p72/F5Ig5IWPoqCCCTswggR6MIIDYqADAgECAgQDAgTXMA0G
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
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBcEaQB7lDyqJBMnUwOYTCLQruEtfNu
# Su+/3WMrH73DuzANBgkqhkiG9w0BAQEFAASCAQAKY44ttT3LaeYAiAWcT/gNV00l
# kDMzM9t1nawv8BSnBoX/52WgObsPVv8mrCU0iSE54o0SRWMtek69a1glwDOtAo2j
# XeyPBG9x1pNJ4MCS7PGpbJWtSx5WJReIB2NxtPfZHyoRTblohmYbglu+k6E4GqxL
# GIGZ8WMRLKPC/MAvvwbVIVcBV5iCLSZDKKyYDbmRYO4I9R9liCQInqzG9HO5YJIm
# F9awqKWacGxyKyE2fAhlSQS5P1g7Bppl/kgj4c8Nw9sFBFcTHXU/oAD6Ym/0EzTH
# Y3wW43SxRpphywmOEcaqC1KkD+YYSqa2m6HbvWOutUc6w8/XPXq4xafh1DPx
# SIG # End signature block
