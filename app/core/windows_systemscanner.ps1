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

    # Use System.Uri to URL encode the query string
    $encodedQuery = [Uri]::EscapeDataString($ProductName)
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
function Get-InstalledVulnerabilityMap {
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

$NVD_API_KEY = $env:NVD_API_KEY  # <-- Get from environment variable

if (-not $NVD_API_KEY) {
    Write-Host "Environment variable 'NVD_API_KEY' is not set. Please set it before running the script." -ForegroundColor Red
    exit
}

Write-Host "`nStarting Windows Vulnerability Scan..." -ForegroundColor Green
$finalResults = Get-InstalledVulnerabilityMap -ApiKey $NVD_API_KEY

if ($finalResults.Count -gt 0) {
    Write-Host "`nVULNERABILITIES FOUND:" -ForegroundColor Yellow
    $finalResults | Format-Table -AutoSize

    # Dynamically set the base directory based on the script location
    $BASE_DIR = $PSScriptRoot
    $TEMP_DIR = Join-Path $BASE_DIR "\temp"
    $OUTPUT_PATH = Join-Path $TEMP_DIR "system_scan_results.json"

    # Ensure the temp folder exists
    if (-not (Test-Path $TEMP_DIR)) {
        Write-Host "Temp folder not found, creating it..." -ForegroundColor Yellow
        New-Item -ItemType Directory -Path $TEMP_DIR | Out-Null
    }

    # Export results to JSON
    $finalResults | ConvertTo-Json -Depth 5 | Out-File $OUTPUT_PATH -Encoding utf8

    Write-Host "`nReport saved to: $OUTPUT_PATH" -ForegroundColor Green
} else {
    Write-Host "`nNo known CVEs detected for installed software." -ForegroundColor Green
}
