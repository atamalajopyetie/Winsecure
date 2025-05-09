# ---------------------------------------------
# WINDOWS VULNERABILITY SCANNER USING NVD API
# ---------------------------------------------

# 1. GET INSTALLED SOFTWARE
function Get-InstalledSoftware {
    $paths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $softwareList = foreach ($path in $paths) {
        Get-ItemProperty $path -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -and $_.DisplayVersion } |
        Select-Object @{Name='Name';Expression={$_.DisplayName}}, 
                      @{Name='Version';Expression={$_.DisplayVersion}}, 
                      @{Name='Publisher';Expression={$_.Publisher}}
    }

    return $softwareList | Sort-Object Name -Unique
}

# 2. FETCH VULNERABILITIES FROM NVD
function Get-NVDVulnerabilities {
    param (
        [string]$ProductName,
        [string]$ApiKey
    )

    $encodedQuery = [System.Web.HttpUtility]::UrlEncode($ProductName)
    $url = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$encodedQuery"

    $headers = @{ "apiKey" = $ApiKey }

    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -UseBasicParsing -TimeoutSec 20
        return $response.vulnerabilities
    } catch {
        Write-Warning "Error fetching CVEs for '$ProductName': $_"
        return @()
    }
}

# 3. MAP VULNERABILITIES TO INSTALLED SOFTWARE
function Scan-And-Map-Vulnerabilities {
    param (
        [string]$ApiKey
    )

    $apps = Get-InstalledSoftware
    $results = @()

    foreach ($app in $apps) {
        Write-Host "`nScanning '$($app.Name)'..." -ForegroundColor Cyan

        $cves = Get-NVDVulnerabilities -ProductName $app.Name -ApiKey $ApiKey

        foreach ($item in $cves) {
            $results += [PSCustomObject]@{
                Software    = $app.Name
                Version     = $app.Version
                CVE_ID      = $item.cve.id
                Severity    = $item.cve.metrics.cvssMetricV31.cvssData.baseSeverity
                Score       = $item.cve.metrics.cvssMetricV31.cvssData.baseScore
                Description = $item.cve.descriptions[0].value
            }
        }

        Start-Sleep -Seconds 1  # prevent NVD rate-limiting
    }

    return $results
}

# ----------------------------
# MAIN SCRIPT
# ----------------------------
$NVD_API_KEY = "3b2d3210-e337-4cb8-a391-a2fcc5243992"  # INSERT YOUR NVD API KEY HERE

if (-not $NVD_API_KEY -or $NVD_API_KEY -eq "YOUR_NVD_API_KEY_HERE") {
    Write-Host "Please insert your NVD API key in the script." -ForegroundColor Red
    exit
}

Write-Host "`nStarting Windows Vulnerability Scan..." -ForegroundColor Green
$finalResults = Scan-And-Map-Vulnerabilities -ApiKey $NVD_API_KEY

if ($finalResults.Count -gt 0) {
    Write-Host "`nVULNERABILITIES FOUND:" -ForegroundColor Yellow
    $finalResults | Format-Table -AutoSize

    # Export results to CSV
    $csvPath = "C:\Users\Manas\OneDrive\Desktop\Winsecure\vulnreport.csv"
    $finalResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "`nReport saved to: $csvPath" -ForegroundColor Green
} else {
    Write-Host "`nNo known CVEs detected for installed software." -ForegroundColor Green
}
