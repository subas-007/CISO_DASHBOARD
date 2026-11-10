<#
.SYNOPSIS
  WSUS compliance export for the CISO Dashboard "Microsoft WSUS (reporting bridge)" connector.

.DESCRIPTION
  WSUS exposes no REST API. Run this script on the WSUS server as a scheduled task
  (e.g. every 30 minutes) to write a JSON compliance report, and publish the output
  folder through IIS over HTTPS with client-certificate (mTLS) or API-key authentication.
  The connector reads: [{ computerName, ipAddress, os, neededCount, failedCount, lastSyncTime }]

  Only patch-compliance metadata is exported — no credentials or user data.

.EXAMPLE
  .\wsus-bridge.ps1 -OutFile "C:\inetpub\wsus-bridge\wsus\compliance.json"
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)] [string] $OutFile,
  [string] $WsusServer = 'localhost',
  [int] $Port = 8531,
  [switch] $NoSsl
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

[void][reflection.assembly]::LoadWithPartialName('Microsoft.UpdateServices.Administration')
$wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer($WsusServer, -not $NoSsl, $Port)

$scope = New-Object Microsoft.UpdateServices.Administration.ComputerTargetScope
$updateScope = New-Object Microsoft.UpdateServices.Administration.UpdateScope
$updateScope.ApprovedStates = [Microsoft.UpdateServices.Administration.ApprovedStates]::LatestRevisionApproved

$report = foreach ($c in $wsus.GetComputerTargets($scope)) {
  $s = $c.GetUpdateInstallationSummary($updateScope)
  [pscustomobject]@{
    computerName = $c.FullDomainName
    ipAddress    = [string]$c.IPAddress
    os           = $c.OSDescription
    neededCount  = $s.NotInstalledCount + $s.DownloadedCount + $s.InstalledPendingRebootCount
    failedCount  = $s.FailedCount
    lastSyncTime = $c.LastSyncTime.ToUniversalTime().ToString('o')
  }
}

$tmp = "$OutFile.tmp"
$report | ConvertTo-Json -Depth 3 | Set-Content -Path $tmp -Encoding UTF8
Move-Item -Path $tmp -Destination $OutFile -Force
Write-Host "Exported $($report.Count) computers to $OutFile"
