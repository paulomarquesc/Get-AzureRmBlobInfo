<#
.SYNOPSIS
   This sample script lists all page blobs from all storage accounts and containers located in a subscription on ARM.
.DESCRIPTION
    This sample script lists all page blobs from all storage accounts and containers located in a subscription on ARM.
.PARAMETER AzureAdTenant
    Name of your azure AD, e.g. pmcazureme1.onmicrosoft.com
.PARAMETER SubsriptionId
   Subsription Id of your subscription, can be obtained from the portal
.PARAMETER IncludeBlockBlob
   Results will contain block blobs too, like jpeg or any document.
.EXAMPLE
   Get-AzureRmBlobInfo.ps1 -AzureAdTenant contoso.onmicrosoft.com -SubscriptionId aaaaaaaa-bbbb-cccc-dddd-eeeeeeee
.NOTE
   This script does not return snapshot blobs, in order to do that you need to modify current URI query for blobs.
.DISCLAIMER
    This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment.
    THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
    INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  
    We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object
    code form of the Sample Code, provided that You agree: (i) to not use Our name, logo, or trademarks to market Your software
    product in which the Sample Code is embedded; (ii) to include a valid copyright notice on Your software product in which the
    Sample Code is embedded; and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims
    or lawsuits, including attorneys’ fees, that arise or result from the use or distribution of the Sample Code.
    Please note: None of the conditions outlined in the disclaimer above will supersede the terms and conditions contained
    within the Premier Customer Services Description.
#>
[CmdletBinding()]
param
(
    [Parameter(Mandatory=$true)]
    [string]$AzureAdTenant,
    
    [Parameter(Mandatory=$true)]
    [string]$SubscriptionId,

    [Parameter(Mandatory=$false)]
    [switch]$IncludeBlockBlob
)

function GetAuthToken
{
   param
   (
        [Parameter(Mandatory=$true)]
        $ApiEndpointUri,
        
        [Parameter(Mandatory=$true)]
        $AADTenant
   )

   $adal = "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\Services\" + `
            "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
   $adalforms = "${env:ProgramFiles(x86)}\Microsoft SDKs\Azure\PowerShell\ServiceManagement\Azure\Services\" + `
                "Microsoft.IdentityModel.Clients.ActiveDirectory.WindowsForms.dll"
   
   [System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
   [System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
   
   $clientId = "1950a258-227b-4e31-a9cf-717495945fc2"
   $redirectUri = "urn:ietf:wg:oauth:2.0:oob"
   $authorityUri = “https://login.windows.net/$aadTenant”
   
   $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authorityUri
   
   $authResult = $authContext.AcquireToken($ApiEndpointUri, $clientId,$redirectUri, "Auto")

   return $authResult
} 

function GetContainerName
{
    # if URI contains up to the container, this needs to end with /
    # e.g.https://pmcstorage05.blob.core.windows.net/vhds/
	param
	(
		[Parameter(Mandatory=$true)]
		[string]$uri
	)

	$startIndex = 0

	for ($i=0;$i -lt 4;$i++)
	{
		[int]$startIndex = $uri.IndexOf("/",$startIndex)
	    $startIndex++  
	}
    
    return &{if ($startIndex -gt 0) {($uri.Substring(8,($startIndex-1)-8)).Split("/")[1]} else {$null}}
}

function GetStorageAccountName
{
	param
	(
		[Parameter(Mandatory=$true)]
		[string]$uri
	)

    return $uri.Substring(8,$uri.IndexOf(".")-8)
}

function GetBlobName
{
	param
	(
		[Parameter(Mandatory=$true)]
		[string]$uri
	)

	$startIndex = 0

	for ($i=0;$i -lt 4;$i++)
	{
		[int]$startIndex = $uri.IndexOf("/",$startIndex)
	    $startIndex++  
	}
    
    if ($startIndex -gt 0)
    {
        $container = $uri.Substring($startIndex)
        if ($container.Contains("?"))
        {
            $container = $container.Split("?")[0]
        }
    }
    else
    {
        $container = $null
    }

	return $container
}

function GetRestApiParameters
{
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$uri
    )

    return ($uri.Split("?")[1]).Split("&")
}

function GetAuthSignedStringSa
{
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$uri,

        [Parameter(Mandatory=$false)]
        [string]$key
    )

    # Building Authorization Header for Storage Account

    $saName = GetStorageAccountName -uri $uri
    $containerName = GetContainerName -uri $uri

    # Time in GMT
    $resourceTz = [System.TimeZoneInfo]::FindSystemTimeZoneById(([System.TimeZoneInfo]::Local).Id)
    [string]$currentDateTimeUtc = Get-Date ([System.TimeZoneInfo]::ConvertTimeToUtc((Get-Date).ToString(),$resourceTz)) -Format r

    # String to be signed with storage account key
    $signatureSb = New-Object System.Text.StringBuilder
    $null = $signatureSb.Append("GET`n`n`n`n`napplication/xml`n`n`n`n`n`n`nx-ms-date:$currentDateTimeUtc`nx-ms-version:2015-02-21`n/$saName/$containerName")
    
    if ($containerName -ne $null)
    {
        $null = $signatureSb.Append("/")
    }

    $restParameters = GetRestApiParameters -uri $uri

    if ($restParameters -ne $null)
    {
        foreach ($param in $restParameters)
        {
            $null = $signatureSb.Append("`n$($param.Replace('=',':'))")   
        }
    }

    # Signing string with SA key UTF8 enconded with HMAC-SHA256 algorithm
    [byte[]]$singnatureStringByteArray=[Text.Encoding]::UTF8.GetBytes($signatureSb.ToString())
    $hmacsha = New-Object System.Security.Cryptography.HMACSHA256
    $hmacsha.key = [convert]::FromBase64String($key)
    $signature = [Convert]::ToBase64String($hmacsha.ComputeHash($singnatureStringByteArray))

    return  @{
        'x-ms-date'="$currentDateTimeUtc"
        'Content-Type'='application\xml'
        'Authorization'= "SharedKey $saName`:$signature"
        'x-ms-version'='2015-02-21'
    }
}

# Defining Azure Management API endpoint, if working with Graph Api, change to graph.windows.net
$ApiEndpointUri = "https://management.core.windows.net/"

# Getting authentication token
$token = GetAuthToken -ApiEndPointUri $ApiEndpointUri -AADTenant $AzureAdTenant

# Defining Rest API header to be used to query storage account resources
$header = @{
    'Content-Type'='application\json'
    'Authorization'=$token.CreateAuthorizationHeader()
}

# Obtaining the list of all storage accounts in the subscription
$uriSAs = "https://management.azure.com/subscriptions/${subscriptionid}/resources?`$filter=resourceType eq 'Microsoft.Storage/storageAccounts'&api-version=2016-02-01"
$storageAccounts = (Invoke-RestMethod -Uri $uriSAs -Headers $header -Method Get).value 

# Looping into each storage account and obtaning specific page blob information to check its status (if attached or not to a VM)
$result = @()

foreach ($sa in $storageAccounts)
{
    # Getting authentication key for current storage account
    $uriListKeys = "https://management.azure.com/$($sa.Id)/listKeys?api-version=2015-05-01-preview"
    $keys = Invoke-RestMethod -Uri $uriListKeys -Headers $header -Method Post

    # Getting list of containers within storage account
    $uriListContainers = "https://$($sa.name).blob.core.windows.net/?comp=list"
    $headerListContainer = GetAuthSignedStringSa -uri $uriListContainers -key $keys.key1
    $containersText = Invoke-RestMethod -Uri $uriListContainers -Headers $headerListContainer -Method Get -ContentType application/xml
    [xml]$containersXml = $containersText.Substring($containersText.IndexOf("<"))

    foreach ($container in $containersXml.EnumerationResults.Containers.Container)
    {
        # Listing Blobs from container
        $uriListBlobs = "https://$($sa.name).blob.core.windows.net/$($container.Name)/?comp=list&include=metadata&restype=container"
        $headerBlobs = GetAuthSignedStringSa -uri $uriListBlobs -key $keys.key1
        $responseText = Invoke-RestMethod -Uri $uriListBlobs -Headers $headerBlobs -Method Get -ContentType application/xml
        [xml]$responseXml = $responseText.Substring($responseText.IndexOf("<"))

        # Just collection all needed information into a PS Object and appending it to result array
        foreach ($blob in $responseXml.EnumerationResults.Blobs.Blob)
        {
            $blobStatus = New-Object -TypeName PSCustomObject -Property @{ "StorageAccountName"=$sa.Name;`
                                                                           "BlobUrl"=[string]::Format("https://{0}.blob.core.windows.net/{1}/{2}",$sa.Name,$container.Name,$blob.Name);`
                                                                           "BlobName"= $blob.Name;`
                                                                           "Container"=$container.Name;`
                                                                           "SizeInBytes"=$blob.Properties.'Content-Length'
                                                                           "ResourceGroupName"=[string]::Empty;`
                                                                           "VMName"=[string]::Empty;`
                                                                           "DiskId"=[string]::Empty;`
                                                                           "DiskType"=[string]::Empty;`
                                                                           "DiskName"=[string]::Empty;`
                                                                           "BlobType"=$blob.Properties.BlobType;`
                                                                           "LeaseStatus"=$blob.Properties.LeaseStatus;`
                                                                           "LeaseState"=$blob.Properties.LeaseState;`
                                                                           "LastModified"=$blob.Properties.'Last-Modified';`
                                                                           "VHDAttached"=$false}
                        
            if ($blob.Properties.BlobType -eq "PageBlob")
            {
                if (![string]::IsNullOrEmpty($blob.Metadata))
                {
                    if (![string]::IsNullOrEmpty($blob.Metadata.MicrosoftAzureCompute_ResourceGroupName) -and `
                        ![string]::IsNullOrEmpty($blob.Metadata.MicrosoftAzureCompute_VMName) -and `
                        ![string]::IsNullOrEmpty($blob.Metadata.MicrosoftAzureCompute_DiskId) -and `
                        ![string]::IsNullOrEmpty($blob.Metadata.MicrosoftAzureCompute_DiskName) -and `
                        ![string]::IsNullOrEmpty($blob.Metadata.MicrosoftAzureCompute_DiskName))
                    {
                        $blobStatus.VHDAttached = $true 
                        $blobStatus.ResourceGroupName = $blob.Metadata.MicrosoftAzureCompute_ResourceGroupName
                        $blobStatus.VMName = $blob.Metadata.MicrosoftAzureCompute_VMName
                        $blobStatus.DiskId = $blob.Metadata.MicrosoftAzureCompute_DiskId 
                        $blobStatus.DiskName = $blob.Metadata.MicrosoftAzureCompute_DiskName
                        $blobStatus.DiskType = $blob.Metadata.MicrosoftAzureCompute_DiskType
                    }
                }
                $result += $blobStatus
            }
            else
            {
                if ($IncludeBlockBlob)
                {
                    $result += $blobStatus
                }
            }
        }
    }
}

$result

