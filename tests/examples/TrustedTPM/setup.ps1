Param(
    [Parameter(Mandatory=$false)] [string]$certificatePath = "."
)

$intermediateStore = "Cert:\LocalMachine\TrustedTpm_IntermediateCA"
$rootStore = "Cert:\LocalMachine\TrustedTpm_RootCA"

function CheckElevated()
{
    $user = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())

    if (!$user.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))
    {
        Write-Error "Please run this script with elevated permissions"
        exit
    }
}

function CreateCertificateStores()
{
    if (!(Test-Path -Path $intermediateStore))
    {
        Write-Output ""
        Write-Output "Create intermediate certificate store"
        New-Item $intermediateStore
    }
    else
    {
        Write-Output "Use existing intermediate certificate store"
    }

    if (!(Test-Path -Path $rootStore))
    {
        Write-Output ""
        Write-Output "Create root certificate store"
        New-Item $rootStore
    }
    else
    {
        Write-Output ""
        Write-Output "Use existing root certificate store"
    }
}

function ProcessCertificates()
{
    foreach ($vendorPath in Get-ChildItem -Directory -Name -Path $certificatePath)
    {
        Write-Output "Processing certificates for vendor $vendorPath"

        $intermediatePath = "$vendorPath\IntermediateCA"

        if (Test-Path $intermediatePath)
        {
            Write-Output ""
            Write-Output "Import intermediate certificates"
            Get-ChildItem -Path "$intermediatePath\*" | Import-Certificate -CertStoreLocation $intermediateStore
        }
        else
        {
            Write-Output ""
            Write-Output "No intermediate certificates found"
        }

        $rootPath = "$vendorPath\RootCA"

        if (Test-Path $rootPath)
        {
            Write-Output ""
            Write-Output "Import root certificates"
            Get-ChildItem -Path "$rootPath\*" | Import-Certificate -CertStoreLocation $rootStore
        }
        else
        {
            Write-Output ""
            Write-Output "No root certificates found"
        }
    }
}

CheckElevated
CreateCertificateStores
ProcessCertificates

# SIG # Begin signature block
# MIIiCAYJKoZIhvcNAQcCoIIh+TCCIfUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDWXnGjF0V12RZ4
# DRtqeoLYFEJaHjncN09ncKM8tsHJUKCCC4swggUYMIIEAKADAgECAhMzAAACNCF7
# RHXHeva8AAAAAAI0MA0GCSqGSIb3DQEBCwUAMHkxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBXaW5kb3dzIFBD
# QSAyMDEwMB4XDTE1MDgxODE3NDIzNFoXDTE2MDgwMTE3NDIzNFowgYMxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIxHjAc
# BgNVBAMTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBALYCPzHD8zEFDWv5bbeOOCk2Il+ymaCMksTPUu7/EdKBl/gJ
# SeILvX+BH0LWLNAu3IMjB3EUsm7+4/u5nvMJr47+Rmes1JTYlX3TZ7BjoOs+LJq6
# 2YUu2/2nVBqvq/N6SYxGbEYsm7ULWRhuHm+LuZbnkSe3Q4hLjFWtI7e+7Ue33HIt
# cM9JZimqRJHlToGU2VAqprIaShAf6wX5c4BUzKuHHbsuloiSHif0n+wo/EOV9Hw4
# xT6PccJev/A9VS8FcmY8AverXhHJnbR2xLf8tv0CJu81LLR2oFVDAPcCNQVoMg6Y
# 9yYc9P9J7eB2o+WNGo3O4I4913ZwAGsqvcrWJSsCAwEAAaOCAYwwggGIMDcGA1Ud
# JQQwMC4GCCsGAQUFBwMDBgorBgEEAYI3PQYBBgorBgEEAYI3CgMNBgorBgEEAYI3
# CgMbMB0GA1UdDgQWBBT7GAsqoWW1QHrWTpBOH5DEUmnVPTBRBgNVHREESjBIpEYw
# RDENMAsGA1UECxMETU9QUjEzMDEGA1UEBRMqNDk4OTcrMzZlNWVjMWEtMDgxMi00
# N2I4LTljMmUtYTRiODAzNDJhYTFhMB8GA1UdIwQYMBaAFNFPqYoHCM70JBiY5QD/
# 89Z5HTe8MFMGA1UdHwRMMEowSKBGoESGQmh0dHA6Ly9jcmwubWljcm9zb2Z0LmNv
# bS9wa2kvY3JsL3Byb2R1Y3RzL01pY1dpblBDQV8yMDEwLTA3LTA2LmNybDBXBggr
# BgEFBQcBAQRLMEkwRwYIKwYBBQUHMAKGO2h0dHA6Ly93d3cubWljcm9zb2Z0LmNv
# bS9wa2kvY2VydHMvTWljV2luUENBXzIwMTAtMDctMDYuY3J0MAwGA1UdEwEB/wQC
# MAAwDQYJKoZIhvcNAQELBQADggEBABeBOp5rE9gkYSX1+FVsLxk3dZVQJYEwp7st
# 89YgH9omla+evYAZjQlS7AUa9RiKaQezkBaNI6MS5CQVSxfS6WUjVK8JBW1IBwoG
# dFzsxFVEhMmhb4078BN8sdajqTp9l8yGL47B/yUefJwiov0PB/iUvJIloxMXCHPx
# m0Wzkcsjg1AYMLNs/XUZa6VjcumqHUh9bxZuNqSZt1ahuwE5loUSnI9NjETNSor6
# VzZ6MQCr4VRte1Z8f6+ComUDt/QvRwy0nhikfPe8EJkLJI5Y3jptzTs1A2w2gZMo
# iunwyeIfv55bus37ulrBeuOvlMyZUu+jBOBFbdrdMj6Nhn3y8EUwggZrMIIEU6AD
# AgECAgphDGoZAAAAAAAEMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBD
# ZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0xMDA3MDYyMDQwMjNaFw0yNTA3
# MDYyMDUwMjNaMHkxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# IzAhBgNVBAMTGk1pY3Jvc29mdCBXaW5kb3dzIFBDQSAyMDEwMIIBIjANBgkqhkiG
# 9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwHm7OrHwD4S4rWQqdRZz0LsH9j4NnRTksZ/B
# yJSwOHwf0DNV9bojZvUuKEhTxxaDuvVRrH6s4CZ/D3T8WZXcycai91JwWiwdlKsZ
# v6+Vfa9moW+bYm5tS7wvNWzepGpjWl/78w1NYcwKfjHrbArQTZcP/X84RuaKx3Np
# dlVplkzk2PA067qxH84pfsRPnRMVqxMbclhiVmyKgaNkd5hGZSmdgxSlTAigg9cj
# H/Nf328sz9oW2A5yBCjYaz74E7F8ohd5T37cOuSdcCdrv9v8HscH2MC+C5MeKOBz
# bdJU6ShMv2tdn/9dMxI3lSVhNGpCy3ydOruIWeGjQm06UFtI0QIDAQABo4IB4zCC
# Ad8wEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNFPqYoHCM70JBiY5QD/89Z5
# HTe8MBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNV
# HRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYG
# A1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3Js
# L3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcB
# AQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kv
# Y2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGdBgNVHSAEgZUwgZIw
# gY8GCSsGAQQBgjcuAzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0HjIg
# HQBMAGUAZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0AC4g
# HTANBgkqhkiG9w0BAQsFAAOCAgEALkGmhrUGb/CAhfo7yhfpyfrkOcKUcMNklMPY
# VqaQjv7kmvRt9W+OU41aqPOu20Zsvn8dVFYbPB1xxFEVVH6/7qWVQjP9DZAkJOP5
# 3JbK/Lisv/TCOVa4u+1zsxfdfoZQI4tWJMq7ph2ahy8nheehtgqcDRuM8wBiQbpI
# dIeC/VDJ9IcpwwOqK98aKXnoEiSahu3QLtNAgfUHXzMGVF1AtfexYv1NSPduQUdS
# HLsbwlc6qJlWk9TG3iaoYHWGu+xipvAdBEXfPqeE0VtEI2MlNndvrlvcItUUI2pB
# f9BCptvvJXsE49KWN2IGr/gbD46zOZq7ifU1BuWkW8OMnjdfU9GjN/2kT+gbDmt2
# 5LiPsMLq/XX3LEG3nKPhHgX+l5LLf1kDbahOjU6AF9TVcvZW5EifoyO6BqDAjtGI
# T5Mg8nBf2GtyoyBJ/HcMXcXH4QIPOEIQDtsCrpo3HVCAKR6kp9nGmiVV/UDKrWQQ
# 6DH5ElR5GvIO2NarHjP+AucmbWFJj/Elwot0md/5kxqQHO7dlDMOQlDbf1D4n2KC
# 7KaCFnxmvOyZsMFYXaiwmmEUkdGZL0nkPoGZ1ubvyuP9Pu7sCYYDBw0bDXzr9FrJ
# lc+HEgpd7MUCks0FmXLKffEqEBg45DGjKLTmTMVSo5xqx33AcQkEDXDeAj+H7lah
# 7Ou1TIUxghXTMIIVzwIBATCBkDB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSMwIQYDVQQDExpNaWNyb3NvZnQgV2luZG93cyBQQ0EgMjAxMAIT
# MwAAAjQhe0R1x3r2vAAAAAACNDANBglghkgBZQMEAgEFAKCBxjAZBgkqhkiG9w0B
# CQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAv
# BgkqhkiG9w0BCQQxIgQgpLwck8uQIHDUkmOf3lVAnH/TYJltU+YQ0+TbDXvUXa8w
# WgYKKwYBBAGCNwIBDDFMMEqgJIAiAE0AaQBjAHIAbwBzAG8AZgB0ACAAVwBpAG4A
# ZABvAHcAc6EigCBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vd2luZG93czANBgkq
# hkiG9w0BAQEFAASCAQA8/myBRPb1zISKK+Az6mrQPqdduUs4pKUw7SkB5bNB2SBC
# u/70dVWCL+XMLlh0O5ymSyDPjPy6+op4/4agKWBWOXXnIPJAr+ryOFebGX3mNtwQ
# /u96cY8ZIUNY4+lzlstgLxevT6V8sa6FreiwElVUvftE0SOJ5AUQggYSbAiRQzGV
# IwLQ+NDlaOOdE0En7PD7fgs/WfoFl4jVwTjbu/ZjTLgxfx0+L4q4q3t5vIOAEpae
# baXUx2eMg6Jnv6o7z9EC1SqIe/rYrlHel1ltyPhBp8pOslX5WT7WvjqjMoUr5HxT
# ztrshlUyJCHMFz4YFl5V1gCp9Si+Yq1KKk+1CJUWoYITSjCCE0YGCisGAQQBgjcD
# AwExghM2MIITMgYJKoZIhvcNAQcCoIITIzCCEx8CAQMxDzANBglghkgBZQMEAgEF
# ADCCAT0GCyqGSIb3DQEJEAEEoIIBLASCASgwggEkAgEBBgorBgEEAYRZCgMBMDEw
# DQYJYIZIAWUDBAIBBQAEIACOePy3qq4EvF4IOV2PDTTqwJ1hlcMmQZ5Z5BtK88OQ
# AgZXIU8krLsYEzIwMTYwNTAxMjExOTE2Ljg5MlowBwIBAYACAfSggbmkgbYwgbMx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1P
# UFIxJzAlBgNVBAsTHm5DaXBoZXIgRFNFIEVTTjpDMEY0LTMwODYtREVGODElMCMG
# A1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCDs0wggZxMIIEWaAD
# AgECAgphCYEqAAAAAAACMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBD
# ZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0xMDA3MDEyMTM2NTVaFw0yNTA3
# MDEyMTQ2NTVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqR0NvHcRijog7PwTl/X6f2mUa3RUENWl
# CgCChfvtfGhLLF/Fw+Vhwna3PmYrW/AVUycEMR9BGxqVHc4JE458YTBZsTBED/Fg
# iIRUQwzXTbg4CLNC3ZOs1nMwVyaCo0UN0Or1R4HNvyRgMlhgRvJYR4YyhB50YWeR
# X4FUsc+TTJLBxKZd0WETbijGGvmGgLvfYfxGwScdJGcSchohiq9LZIlQYrFd/Xcf
# PfBXday9ikJNQFHRD5wGPmd/9WbAA5ZEfu/QS/1u5ZrKsajyeioKMfDaTgaRtogI
# Neh4HLDpmc085y9Euqf03GS9pAHBIAmTeM38vMDJRF1eFpwBBU8iTQIDAQABo4IB
# 5jCCAeIwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFNVjOlyKMZDzQ3t8RhvF
# M2hahW1VMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAP
# BgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjE
# MFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kv
# Y3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEF
# BQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGgBgNVHSABAf8E
# gZUwgZIwgY8GCSsGAQQBgjcuAzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5t
# aWNyb3NvZnQuY29tL1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcC
# AjA0HjIgHQBMAGUAZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUA
# bgB0AC4gHTANBgkqhkiG9w0BAQsFAAOCAgEAB+aIUQ3ixuCYP4FxAz2do6Ehb7Pr
# psz1Mb7PBeKp/vpXbRkws8LFZslq3/Xn8Hi9x6ieJeP5vO1rVFcIK1GCRBL7uVOM
# zPRgEop2zEBAQZvcXBf/XPleFzWYJFZLdO9CEMivv3/Gf/I3fVo/HPKZeUqRUgCv
# OA8X9S95gWXZqbVr5MfO9sp6AG9LMEQkIjzP7QOllo9ZKby2/QThcJ8ySif9Va8v
# /rbljjO7Yl+a21dA6fHOmWaQjP9qYn/dxUoLkSbiOewZSnFjnXshbcOco6I8+n99
# lmqQeKZt0uGc+R38ONiU9MalCpaGpL2eGq4EQoO4tYCbIjggtSXlZOz39L9+Y1kl
# D3ouOVd2onGqBooPiRa6YacRy5rYDkeagMXQzafQ732D8OE7cQnfXXSYIghh2rBQ
# Hm+98eEA3+cxB6STOvdlR3jo+KhIq/fecn5ha293qYHLpwmsObvsxsvYgrRyzR30
# uIUBHoD7G4kqVDmyW9rIDVWZeodzOwjmmC3qjeAzLhIp9cAvVCch98isTtoouLGp
# 25ayp0Kiyc8ZQU3ghvkqmqMRZjDTu3QyS99je/WZii8bxyGvWbWu3EQ8l1Bx16HS
# xVXjad5XwdHeMMD9zOZN+w2/XU/pnR4ZOC+8z1gFLu8NoFA12u8JJxzVs341Hgi6
# 2jbb01+P3nSISRIwggTaMIIDwqADAgECAhMzAAAAcTJFPHbHYvzoAAAAAABxMA0G
# CSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTE1
# MTAwNzE4MTczN1oXDTE3MDEwNzE4MTczN1owgbMxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIxJzAlBgNVBAsTHm5DaXBo
# ZXIgRFNFIEVTTjpDMEY0LTMwODYtREVGODElMCMGA1UEAxMcTWljcm9zb2Z0IFRp
# bWUtU3RhbXAgU2VydmljZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
# ALKjrWi9L5cSfN30tiilz+CvaqSbXcwRRdY3xbL94xLFvT+nEExGLw+8UX1QRuFn
# ZwtysFBgUAV90zyIoppe8xpJR03VoXBtpEm9oGLt/X5ziqGyulcxnIEaFVZOTS4N
# 1MVZKia8/BbUazm972j0u2mReF76lIEyvzlAIReSTqTRvCy2Zl1quObmOeA3ViO8
# mk61HdBL0eHqj/xCYbfTNA1rXDbK8ADzPn8EKeD3r+eca4EPR5SD82FrLKzIiIxs
# wNI7+g7Xp1kCGmKbdAZUW0eD8kAWu/+4AHxpRR0y4blkBaPSLrj4YPv2p3M/VEs9
# GPX2nE9qhQ0NqB6I4plSJOUCAwEAAaOCARswggEXMB0GA1UdDgQWBBTbTHGFb5a7
# tkIAsE5Rx/a22aVAaDAfBgNVHSMEGDAWgBTVYzpcijGQ80N7fEYbxTNoWoVtVTBW
# BgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNUaW1TdGFQQ0FfMjAxMC0wNy0wMS5jcmwwWgYIKwYBBQUH
# AQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtp
# L2NlcnRzL01pY1RpbVN0YVBDQV8yMDEwLTA3LTAxLmNydDAMBgNVHRMBAf8EAjAA
# MBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUAA4IBAQCAahEGwEFp
# AgdGYwQZeCvRlU4KE1u6eRsPHqm6ajdlwRIOrJIfdUGQz13BpEdKQSWBPUV1eCy6
# 28bn5+fsQOb5C4DWvHk+JUOjzokMVy+mFCNX3NaVPojBZrFS8BqdYrkgG9Rjf3NK
# yRfkhGrGr5au6Svd9kkOEghIVJOAjTPx/ViW+khbLjjQy9S0yzBTo1U8H6ExSu6J
# cv8JPYWAARE5TylZUHq15e1bvZo6xHjsHYh1mzTRlgXcyAs3rKkeqQVHT/pLyROk
# e3n0Kegnzrub4BWjdqStP69Cz8Y9v75MVsx2NK5JsgaMPhDnmZRzmMeTrmpF+qpe
# cZTLAxsuqSbSoYIDdjCCAl4CAQEwgeOhgbmkgbYwgbMxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xDTALBgNVBAsTBE1PUFIxJzAlBgNVBAsTHm5D
# aXBoZXIgRFNFIEVTTjpDMEY0LTMwODYtREVGODElMCMGA1UEAxMcTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgU2VydmljZaIlCgEBMAkGBSsOAwIaBQADFQA4M9Lea2GQNBgD
# N+WV1g5uhmCx4KCBwjCBv6SBvDCBuTELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjENMAsGA1UECxMETU9QUjEnMCUGA1UECxMebkNpcGhlciBOVFMg
# RVNOOjU3RjYtQzFFMC01NTRDMSswKQYDVQQDEyJNaWNyb3NvZnQgVGltZSBTb3Vy
# Y2UgTWFzdGVyIENsb2NrMA0GCSqGSIb3DQEBBQUAAgUA2tCz+zAiGA8yMDE2MDUw
# MTE2NTczMVoYDzIwMTYwNTAyMTY1NzMxWjB0MDoGCisGAQQBhFkKBAExLDAqMAoC
# BQDa0LP7AgEAMAcCAQACAgwVMAcCAQACAhgCMAoCBQDa0gV7AgEAMDYGCisGAQQB
# hFkKBAIxKDAmMAwGCisGAQQBhFkKAwGgCjAIAgEAAgMW42ChCjAIAgEAAgMHoSAw
# DQYJKoZIhvcNAQEFBQADggEBAJ0481831xMvwCRfG0q8+L4FAtGCtboXhzzu/KoB
# efjDsti0xI/iYVuPFFfjO+M1596A1zFuBh5FfwdfvNdaIMFlq947AmPWpAXNmJoB
# rfbRgR586Y976jnktck+H6GHWxdwjKSVQ+4B7kRLQYa5uzv9t7SRA94UvD1cs/QV
# h+52IxMoHbova6Pt5xH/jMrRX3SpRnd+2sG8KeudOlW+FS+bRI485EZAG3Whu+zr
# h07kdXjaUfJsZxz5V7g/PTr22aD0EqipsEqsBUJSPiMpGWEWreje98vaw1OvsUgF
# mYYXODdMXrDsleBS50ytSFGl2YtJeNa0pP2u4hAjLQHG4NMxggL1MIIC8QIBATCB
# kzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAHEyRTx2x2L86AAA
# AAAAcTANBglghkgBZQMEAgEFAKCCATIwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJ
# EAEEMC8GCSqGSIb3DQEJBDEiBCDJw5MYGWbwjn+ykia7smh5TBXpCxupOvUPVuGO
# 21vU/zCB4gYLKoZIhvcNAQkQAgwxgdIwgc8wgcwwgbEEFDgz0t5rYZA0GAM35ZXW
# Dm6GYLHgMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AABxMkU8dsdi/OgAAAAAAHEwFgQU1SDrleFKvGKPKsMyA/IBO/vPQoUwDQYJKoZI
# hvcNAQELBQAEggEASl3qmiSWzMO9Wboh6WarUkhGS8yTd2u2Nd7x9aYi2fkVPWed
# hvhzsJ401GvIyZDfNcUUukkfTsXeSQkfPDBl1RnNA17BcSNvjHY26ysi5XjsZWDM
# W+p/avi5b2StevevFTWW0VBisMZpINKk+CcYxCI9jaoji+UkOjXHzjhJHKfzdPxc
# FkCFFEjlzwHyLANoQJ6srUHge4En9VOEFUMCRw6Qf54qOUiczxgKOJlvmsNSgNY8
# IKCJGc7cEl6Mynz9SzBP3CQgRslsK2aQJ6VPoMj1lF0xoLYSJ4hKD10eY0JZCbXg
# /T3z6vmnTOtS42GGvZcI31WUy0AX50XV+JxjOQ==
# SIG # End signature block
