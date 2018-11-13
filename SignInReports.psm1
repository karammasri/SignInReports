#requires -Version 3.0

Set-StrictMode -Version 'Latest'

$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

$ClientId    = "1b730954-1685-4b74-9bfd-dac224a7b894"
$RedirectUri = "urn:ietf:wg:oauth:2.0:oob"
$MSGraphURI  = "https://graph.microsoft.com"
$Authority   = "https://login.microsoftonline.com/common"

$AccessToken  = ""
$RefreshToken = ""

$AuthenticationContext = $null

$Headers = ""

$SignInReportsEndpoint = 'https://graph.microsoft.com/beta/auditLogs/signIns'

$MaxRetries = 5

function Load-ADAL
{
    [CmdletBinding()]
    
    param()

    $ADALFiles = @('Microsoft.IdentityModel.Clients.ActiveDirectory.dll', 'Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll')

    try
    {
        foreach ($DLLToLoad in $ADALFiles)
        {
            if (Test-Path -Path $DLLToLoad -PathType Leaf)
            {
                $FullDLLName = Resolve-Path -Path $DLLToLoad
                #$AssemblyName = [System.Reflection.AssemblyName]::GetAssemblyName($FullDLLName)
                
                # TODO: Check if the same assembly is already loaded but with a different version
                
                [System.Reflection.Assembly]::LoadFrom($FullDLLName) | Out-Null
            }
            else
            {
                throw "Unable to load ADAL DLL $DLLToLoad"
            }           
        }
    }
    catch
    {
        return $false
    }

    return $true
}

Function Build-Headers
{
    [CmdletBinding()]
    
    param()

    $Script:Headers = @{"Authorization" = "Bearer $AccessToken"; "Content-Type" = "application/json"}
}


Function Get-AccessTokenByPrompt
{
    [CmdletBinding()]
    
    param()

    try
    {
        $Script:AuthenticationContext = New-Object -TypeName Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext -ArgumentList $Authority
        if (!$AuthenticationContext)
        {
            throw
        }

        $AuthenticationResult = $AuthenticationContext.AcquireToken($MSGraphURI, $ClientId, $RedirectUri,[Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Always)
        if (!$AuthenticationResult)
        {
            throw
        }

        if (!($AuthenticationResult.AccessToken) -or ($AuthenticationResult.AccessToken.Length -eq 0))
        {
            throw
        }

        $Script:AccessToken = $AuthenticationResult.AccessToken
        $Script:RefreshToken = $AuthenticationResult.RefreshToken
    }
    catch
    {
        return $false
    }

    Build-Headers

    return $true
}

Function Get-AccessTokenByRefreshToken
{
    [CmdletBinding()]
    
    param()

    try
    {
        if (($RefreshToken.Length -eq 0) -or (!$AuthenticationContext))
        {
            throw
        }

        $AuthenticationResult = $AuthenticationContext.AcquireTokenByRefreshToken($RefreshToken, $ClientId, $MSGraphURI)
        if (!$AuthenticationResult)
        {
            throw
        }

        if (!($AuthenticationResult.AccessToken) -or ($AuthenticationResult.AccessToken.Length -eq 0))
        {
            throw
        }

        $Script:AccessToken = $AuthenticationResult.AccessToken
        $Script:RefreshToken = $AuthenticationResult.RefreshToken
    }
    catch
    {
        return $false
    }

    Build-Headers

    return $true
}

function Get-SummarySignInReport
{
    [CmdletBinding()]
    
    param
    (
        [Parameter()]
        [datetime]
        $FromDateUTC,

        [Parameter()]
        [datetime]
        $ToDateUTC,

        [Parameter()]
        [string[]]
        $UserPrincipalName,

        [Parameter()]
        [string[]]
        $ClientAppUsed,

        [Parameter()]
        [int[]]
        $StatusCode
    )
    
    # Build Filter
    $Filter = ""
    $ANDJoin = " and "
    $ORJoin = " or "

    if ($FromDateUTC)
    {
        if ($Filter.Length -gt 0)
        {
            $Filter += $ANDJoin
        }
        $Filter += "createdDateTime ge $($FromDateUTC.ToString('s'))Z"
    }

    if ($ToDateUTC)
    {
        if ($Filter.Length -gt 0)
        {
            $Filter += $ANDJoin
        }
        $Filter += "createdDateTime le $($ToDateUTC.ToString('s'))Z"
    }
    
    if ($UserPrincipalName)
    {
        $UPNFilter = ""
        foreach ($u in $UserPrincipalName)
        {
            if ($UPNFilter.Length -gt 0)
            {
                $UPNFilter += $ORJoin
            }

            $UPNFilter += "userPrincipalName eq '$u'"
        }

        if ($UPNFilter.Length -gt 0)
        {
            if ($Filter.Length -gt 0)
            {
                $Filter += $ANDJoin
            }

            $Filter += "($UPNFilter)"
        }
    }

    if ($ClientAppUsed)
    {
        $ClientAppFilter = ""

        foreach ($App in $ClientAppUsed)
        {
            if ($ClientAppFilter.Length -gt 0)
            {
                $ClientAppFilter += $ORJoin
            }

            $ClientAppFilter += "clientAppUsed eq '$App'"
        }

        if ($ClientAppFilter.Length -gt 0)
        {
            if ($Filter.Length -gt 0)
            {
                $Filter += $ANDJoin
            }

            $Filter += "($ClientAppFilter)"
        }
    }
    
    if ($StatusCode)
    {
        $StatusCodeFilter = ""

        foreach ($s in $StatusCode)
        {
            if ($StatusCodeFilter.Length -gt 0)
            {
                $StatusCodeFilter += $ORJoin
            }

            $StatusCodeFilter += "status/errorCode eq $($s.ToString())"
        }

        if ($StatusCodeFilter.Length -gt 0)
        {
            if ($Filter.Length -gt 0)
            {
                $Filter += $ANDJoin
            }

            $Filter += "($StatusCodeFilter)"
        }
    }
    
    # Write-Debug $Filter

    if ($AccessToken.Length -eq 0)
    {
        if (!(Get-AccessTokenByPrompt))
        {
            return
        }
    }
    
    $QueryURL = $SignInReportsEndpoint

    if ($Filter.Length -gt 0)
    {
        $QueryURL += '?$Filter=' + [uri]::EscapeUriString($Filter)
    }
    
    Write-Verbose "Using query: $QueryURL"
    
    while ($true)
    {
        try
        {
            # $Response = Invoke-RestMethod -Headers $Headers -UseBasicParsing -Uri $QueryURL -Method Get
            $Response = Invoke-RestMethod -Headers $Headers -UseBasicParsing -Uri $QueryURL -Method Get -Verbose:$false
        }
        catch [System.Net.WebException]
        {
            if (([int]$_.Exception.Response.StatusCode) -eq [System.Net.HttpStatusCode]::Unauthorized)
            {
                if (Get-AccessTokenByRefreshToken)
                {
                    continue
                }
            }
            
            Write-Error "WebException: Code: $($_.Exception.Response.StatusCode) Message: $($_.Exception.Message)"
            break
        }
        catch 
        {
            Write-Error "NonWebException: Message: $($_.Exception.Message)"
            break
        }

        if ($Response.psobject.properties.name -contains 'value')
        {
            foreach ($V in $Response.value)
            {
                # remove properties that are complex objects or that require additional formatting
                $Result = $V | Select-Object -Property * -ExcludeProperty conditionalAccessPolicies, createdDateTime, deviceDetail, location, mfaDetail, status

                # Add the datetime information
                $DateCreated = [datetime]$V.createdDateTime
                Add-Member -InputObject $Result -MemberType NoteProperty -Name 'DateCreatedLocal' -Value $DateCreated.ToString('d')
                Add-Member -InputObject $Result -MemberType NoteProperty -Name 'DateCreatedUTC' -Value $DateCreated.ToUniversalTime().ToString('d')
                Add-Member -InputObject $Result -MemberType NoteProperty -Name 'TimeCreatedLocal' -Value $DateCreated.ToString('HH:mm:ss')
                Add-Member -InputObject $Result -MemberType NoteProperty -Name 'TimeCreatedUTC' -Value $DateCreated.ToUniversalTime().ToString('HH:mm:ss')

                # Expand the status information if present
                if ($V.status)
                {
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'Status_errorCode' -Value $V.status.errorCode.ToString()
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'Status_failureReason' -Value $V.status.failureReason
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'Status_additionalDetails' -Value $V.status.additionalDetails
                }
                else
                {
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'Status_errorCode' -Value $null
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'Status_failureReason' -Value $null
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'Status_additionalDetails' -Value $null

                }

                # Add the device information if present
                if ($V.deviceDetail)
                {
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'Device_browser' -Value $V.deviceDetail.browser
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'Device_deviceid' -Value $V.deviceDetail.deviceid
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'Device_displayName' -Value $V.deviceDetail.displayName
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'Device_isCompliant' -Value $V.deviceDetail.isCompliant
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'Device_isManaged' -Value $V.deviceDetail.isManaged
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'Device_operatingSystem' -Value $V.deviceDetail.operatingSystem
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'Device_trustType' -Value $V.deviceDetail.trustType
                }
                else
                {
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'Device_browser' -Value $null
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'Device_deviceid' -Value $null
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'Device_displayName' -Value $null
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'Device_isCompliant' -Value $null
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'Device_isManaged' -Value $null
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'Device_operatingSystem' -Value $null
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'Device_trustType' -Value $null
                }

                # Add location information if present
                if ($V.location)
                {
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'Location_countryOrRegion' -Value $V.location.countryOrRegion
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'Location_city' -Value $V.location.city
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'Location_state' -Value $V.location.state
                }
                else
                                    {
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'Location_countryOrRegion' -Value $null
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'Location_city' -Value $null
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'Location_state' -Value $null
                }

                # Add MFA status if present
                if ($V.mfaDetail)
                {
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'MFA_auhtDetail' -Value $V.mfaDetail.authDetail
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'MFA_authMethod' -Value $V.mfaDetail.authMethod
                }
                else
                                    {
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'MFA_auhtDetail' -Value $null
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'MFA_authMethod' -Value $null
                }

                # Add summary information about conditional access policies
                if ($V.conditionalAccessPolicies)
                {
                    # It would be more efficient to use just one pipeline and a Group-Object, but then I will have to check the resulting properties
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'TotalConditionalAccessPolicies' -Value $V.conditionalAccessPolicies.Count
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'TotalSuccessConditionalAccessPolicies' -Value $(@($V.conditionalAccessPolicies | Where-Object { $_.result -eq 'success' }).Count)
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'TotalFailConditionalAccessPolicies' -Value $(@($V.conditionalAccessPolicies | Where-Object { $_.result -eq 'failure' }).Count)
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'TotalNotAppliedConditionalAccessPolicies' -Value $(@($V.conditionalAccessPolicies | Where-Object { $_.result -eq 'notApplied' }).Count)
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'TotalNotEnabledConditionalAccessPolicies' -Value $(@($V.conditionalAccessPolicies | Where-Object { $_.result -eq 'notEnabled' }).Count)
                }
                else
                {
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'TotalConditionalAccessPolicies' -Value 0
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'TotalSuccessConditionalAccessPolicies' -Value 0
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'TotalFailConditionalAccessPolicies' -Value 0
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'TotalNotAppliedConditionalAccessPolicies' -Value 0
                    Add-Member -InputObject $Result -MemberType NoteProperty -Name 'TotalNotEnabledConditionalAccessPolicies' -Value 0
                }

                Write-Output $Result                   
            }
        }
        Write-Verbose "Fetched: $($Response.value.Count) new records"

        if ($Response.psobject.properties.name -contains '@odata.nextLink')
        {
            $QueryURL = $Response.'@odata.nextLink'
        }
        else
        {
            break
        }
    }
}
Export-ModuleMember -Function 'Get-SummarySignInReport'

if (!(Load-ADAL))
{
    throw "Unable to load ADAL DLLs"
}
