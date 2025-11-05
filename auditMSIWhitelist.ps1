# Identifies all installed MSI packages present in the SecureRepair whitelist 
# and generates a report for each one.
# For every package, performs an advanced analysis of its Custom Actions (NoImpersonate and within repair sequence).

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$ReportPath,

    [Parameter(Mandatory = $false)]
    [string]$ReportBaseName = "MSI_Audit_Report"
)

$OutputEncoding = [System.Text.Encoding]::UTF8

#region FUNCTIONS
Function Get-InstalledMsiPackages {
    Write-Host "Retrieving all installed MSI packages..." -ForegroundColor Cyan
	$Installer = New-Object -ComObject WindowsInstaller.Installer
	$InstallerProducts = $Installer.ProductsEx("", "", 7)
	$InstalledProducts = ForEach($Product in $InstallerProducts){
		[PSCustomObject]@{
			ProductCode   = $Product.ProductCode();
			LocalPackage  = $Product.InstallProperty("LocalPackage");
			VersionString = $Product.InstallProperty("VersionString");
			ProductName   = $Product.InstallProperty("ProductName")
		}
	}
	Write-Host "   -> $($InstalledProducts.Count) products found." -ForegroundColor Green
	return $InstalledProducts
}

Function Get-SecureRepairWhitelist {
    Write-Host "Retrieving the SecureRepair whitelist..." -ForegroundColor Cyan
    $WhitelistProductCodes = @()
    $RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\SecureRepairWhitelist"
    $WhitelistProperties = Get-ItemProperty -Path $RegistryPath -ErrorAction SilentlyContinue

    if ($WhitelistProperties) {
        $WhitelistProductCodes = $WhitelistProperties.psobject.Properties.Name
        Write-Host "   -> $($WhitelistProductCodes.Count) ProductCodes found in the whitelist." -ForegroundColor Green
    }
    else {
        Write-Warning "The registry key '$RegistryPath' was not found or is empty."
    }
    return $WhitelistProductCodes
}

Function Analyze-MsiCustomAction {
    [CmdletBinding()]
    param([string]$MsiPath)
    $NoImpersonateFlag = 2048; $CommitFlag = 1024; $RollbackFlag = 256
    $msiOpenDatabaseModeReadOnly = 0
    if (-not (Test-Path -Path $MsiPath -PathType Leaf)) { return $null }
    $Installer = $null; $Database = $null; $results = [System.Collections.Generic.List[pscustomobject]]::new()
    try {
        $Installer = New-Object -ComObject WindowsInstaller.Installer
        $Database = $Installer.OpenDatabase($MsiPath, $msiOpenDatabaseModeReadOnly)
        $allCustomActions = [System.Collections.Generic.List[pscustomobject]]::new()
        $customActionsView = $Database.OpenView("SELECT Action, Type, Source, Target FROM CustomAction")
        $customActionsView.Execute() | Out-Null
        while ($Record = $customActionsView.Fetch()) {
            $allCustomActions.Add([PSCustomObject]@{ Action = $Record.StringData(1); Type = $Record.IntegerData(2); Source = $Record.StringData(3); Target = $Record.StringData(4) })
        }
        $customActionsView.Close() | Out-Null
        $installSequence = [System.Collections.Generic.List[pscustomobject]]::new()
        $sequenceView = $Database.OpenView("SELECT Action, Sequence FROM InstallExecuteSequence")
        $sequenceView.Execute() | Out-Null
        while ($Record = $sequenceView.Fetch()) {
            if ($Record.IntegerData(2) -ne 0) {
                 $installSequence.Add([PSCustomObject]@{ Action = $Record.StringData(1); Sequence = $Record.IntegerData(2) })
            }
        }
        $sequenceView.Close() | Out-Null
        $sortedSequence = $installSequence | Sort-Object Sequence
        $initSequenceNumber = ($sortedSequence | Where-Object { $_.Action -eq 'InstallInitialize' } | Select-Object -ExpandProperty Sequence -First 1)
        $finalizeSequenceNumber = ($sortedSequence | Where-Object { $_.Action -eq 'InstallFinalize' } | Select-Object -ExpandProperty Sequence -First 1)
        if (-not $initSequenceNumber -or -not $finalizeSequenceNumber) { return $null }
        $candidateActions = $allCustomActions | Where-Object { ($_.Type -band $NoImpersonateFlag) -ne 0 -and ((($_.Type -band $CommitFlag) -ne 0) -or (($_.Type -band $RollbackFlag) -ne 0)) }
        foreach ($action in $candidateActions) {
            $actionInSequence = $sortedSequence | Where-Object { $_.Action -eq $action.Action }
            if ($actionInSequence -and $actionInSequence.Sequence -gt $initSequenceNumber -and $actionInSequence.Sequence -lt $finalizeSequenceNumber) {
                $results.Add([PSCustomObject]@{ Action = $action.Action; Type = $action.Type; Source = $action.Source; Target = $action.Target; Sequence = $actionInsequence.Sequence })
            }
        }
        if ($results.Count -gt 0) { return ($results | Sort-Object Sequence) } else { return $null }
    } catch { return $null }
    finally {
        if ($Database) { $null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($Database) }
        if ($Installer) { $null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($Installer) }
    }
}
#endregion

if (-not (Test-Path -Path $ReportPath -PathType Container)) {
    Write-Host "The directory '$ReportPath' does not exist. Creating it..." -ForegroundColor Yellow
    try { New-Item -Path $ReportPath -ItemType Directory -Force | Out-Null }
    catch { Write-Error "Could not create the report directory. Please check permissions."; return }
}

$installedProducts = Get-InstalledMsiPackages
$whitelist = Get-SecureRepairWhitelist

if (-not $installedProducts) { Write-Warning "No installed MSI products were found. Stopping script."; return }

Write-Host "Match installed MSI packages with the whitelist..." -ForegroundColor Cyan
$matchingProducts = $installedProducts | Where-Object { $whitelist -contains $_.ProductCode }

if (-not $matchingProducts) { Write-Host "No installed MSI package matches the whitelist. Audit finished." -ForegroundColor Green; return }

Write-Host "   -> $($matchingProducts.Count) matching products found. Starting in-depth analysis." -ForegroundColor Green

# ---  Analyze all whitelisted packages and collect their status ---
$finalReportData = [System.Collections.Generic.List[object]]::new()
foreach ($product in $matchingProducts) {
    $criticalActions = Analyze-MsiCustomAction -MsiPath $product.LocalPackage
    $criticalActionsCount = if ($criticalActions) { @($criticalActions).Count } else { 0 }
    
    if ($criticalActions) {
		Write-Host "------------------------------------------------------------"
        Write-Host "Analyzing: $($product.ProductName) ($($product.VersionString))" -ForegroundColor White
        Write-Host "   -> Potential privesc - Custom Actions: $criticalActionsCount" -ForegroundColor Yellow
		
		$finalReportData.Add([PSCustomObject]@{
          ProductName     = $product.ProductName
          Version         = $product.VersionString
          ProductCode     = $product.ProductCode
          MsiPath         = $product.LocalPackage
          CriticalActions = $criticalActions
        })
    } 
}

# --- Step 5: Generate reports ---
Write-Host "------------------------------------------------------------"
Write-Host "Generating comprehensive report..." -ForegroundColor Cyan

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$txtFilePath = Join-Path -Path $ReportPath -ChildPath "$($ReportBaseName)_$($timestamp).txt"
$htmlFilePath = Join-Path -Path $ReportPath -ChildPath "$($ReportBaseName)_$($timestamp).html"

# --- Generate TXT report ---
$txtReport = "MSI VULNERABILITY AUDIT REPORT - $(Get-Date)`n`nThis report lists all whitelisted MSI packages and their security status.`n"
foreach ($item in $finalReportData) {
    $txtReport += @"
----------------------------------------------------------------------
Product      : $($item.ProductName)
Version      : $($item.Version)
ProductCode  : $($item.ProductCode)
MSI Path     : $($item.MsiPath)
----------------------------------------------------------------------
"@
    if ($item.CriticalActions) {
        foreach ($action in $item.CriticalActions) {
            $txtReport += @"
  [!] Custom Action Found:
      Action      : $($action.Action)
      Source      : $($action.Source)
      Target      : $($action.Target)

"@
        }
    }
    else {
        $txtReport += @"
  [OK] No critical custom actions detected for this package.

"@
    }
}
$txtReport | Out-File -FilePath $txtFilePath -Encoding utf8

# --- Generate HTML report ---
$htmlHead = "<style>body{font-family:'Segoe UI',sans-serif;margin:20px;background-color:#f4f4f4}h1{color:#2c3e50;border-bottom:2px solid #2980b9}.product-box{background-color:#fff;border:1px solid #bdc3c7;border-left:5px solid #2ecc71;border-radius:5px;margin-bottom:20px;padding:15px;box-shadow:0 2px 4px rgba(0,0,0,.1)}.product-box.writable{border-left-color:#e74c3c !important;}.product-box.unsigned{border-left-color:#f39c12 !important;}.tag{font-weight:bold;font-size:1.1em}.tag.red{color:#e74c3c}.tag.orange{color:#f39c12}.tag.green{color:#27ae60}.no-actions{margin-top:15px;color:#555;font-style:italic}h2{color:#2980b9;margin-top:0}p{color:#34495e}table{border-collapse:collapse;width:100%;margin-top:15px}th,td{border:1px solid #ddd;text-align:left;padding:8px}th{background-color:#ecf0f1;color:#2c3e50}tr:nth-child(even){background-color:#f9f9f9}.code{font-family:'Consolas',monospace;background-color:#ecf0f1;padding:2px 5px;border-radius:3px}</style>"
$htmlBody = "<h1>MSI Vulnerability Audit Report</h1><p>Generated on $(Get-Date)</p><p>This report lists all whitelisted MSI packages and their security status.</p>"

foreach ($item in $finalReportData) {
    $class = "product-box"

    $htmlBody += "<div class='$($class)'>"
    $htmlBody += "<h2>$($item.ProductName) - v$($item.Version)</h2>"
    $htmlBody += "<p><strong>ProductCode:</strong> <span class='code'>$($item.ProductCode)</span><br>"
    $htmlBody += "<strong>Cached MSI Path:</strong> <span class='code'>$($item.MsiPath)</span></p>"
    
    if ($item.CriticalActions) {
        $htmlBody += "<h3>Detected Critical Actions:</h3>"
        $htmlBody += $item.CriticalActions | Select-Object Action, Source, Target | ConvertTo-Html -Fragment
    } else {
        $htmlBody += "<p class='no-actions'>No critical custom actions detected.</p>"
    }
	
    $htmlBody += "</div>"
}

ConvertTo-Html -Head $htmlHead -Body $htmlBody | Out-File -FilePath $htmlFilePath -Encoding utf8

Write-Host "Reports generated successfully:" -ForegroundColor Green
Write-Host "  -> TXT : $txtFilePath"
Write-Host "  -> HTML: $htmlFilePath"
Write-Host "------------------------------------------------------------"
Write-Host "AUDIT COMPLETE." -ForegroundColor Cyan