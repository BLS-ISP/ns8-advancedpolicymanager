#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ServerUrl = "{{SERVER_URL}}",

    [Parameter(Mandatory = $false)]
    [string]$Token = "{{ENROLLMENT_TOKEN}}",

    [Parameter(Mandatory = $false)]
    [string]$StateDir = "C:\ProgramData\NS8PolicyAgent"
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($ServerUrl) -or $ServerUrl -eq ("{{" + "SERVER_URL" + "}}")) {
    if (-not [string]::IsNullOrWhiteSpace($env:APM_SERVER_URL)) {
        $ServerUrl = $env:APM_SERVER_URL
    } elseif (-not [string]::IsNullOrWhiteSpace($env:SERVER_URL)) {
        $ServerUrl = $env:SERVER_URL
    } else {
        throw "ServerUrl is required. Pass -ServerUrl <https://policies.example.org> or set APM_SERVER_URL."
    }
}

if ([string]::IsNullOrWhiteSpace($Token) -or $Token -eq ("{{" + "ENROLLMENT_TOKEN" + "}}")) {
    if (-not [string]::IsNullOrWhiteSpace($env:APM_TOKEN)) {
        $Token = $env:APM_TOKEN
    } elseif (-not [string]::IsNullOrWhiteSpace($env:APM_ENROLL_TOKEN)) {
        $Token = $env:APM_ENROLL_TOKEN
    } elseif (-not [string]::IsNullOrWhiteSpace($env:ENROLLMENT_TOKEN)) {
        $Token = $env:ENROLLMENT_TOKEN
    } else {
        throw "Enrollment token is required. Pass -Token <apm_enroll_...> or set `$env:APM_TOKEN."
    }
}

$ServerUrl = $ServerUrl.TrimEnd("/")
$ServiceName = "NS8PolicyAgent"
$InstallDir = "C:\Program Files\NS8PolicyAgent"
$BinaryPath = Join-Path $InstallDir "ns8-policy-agent.exe"
$DownloadUrl = "$ServerUrl/api/v1/installers/binaries/windows/x86_64"

Write-Host "[NS8PolicyAgent] Preparing installation directories..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null

$ExistingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -ne $ExistingSvc -and $ExistingSvc.Status -ne "Stopped") {
    Write-Host "[NS8PolicyAgent] Stopping existing $ServiceName service..."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
}

Write-Host "[NS8PolicyAgent] Downloading binary from $DownloadUrl ..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $DownloadUrl -OutFile $BinaryPath -UseBasicParsing

Write-Host "[NS8PolicyAgent] Enrolling computer with $ServerUrl ..."
& $BinaryPath enroll --server $ServerUrl --token $Token --state-dir $StateDir
if ($LASTEXITCODE -ne 0) {
    throw "Enrollment failed with exit code $LASTEXITCODE"
}

$BinPathCmd = "`"$BinaryPath`" daemon --state-dir `"$StateDir`""
if ($null -eq $ExistingSvc) {
    Write-Host "[NS8PolicyAgent] Registering Windows Service '$ServiceName'..."
    & sc.exe create $ServiceName binPath= $BinPathCmd start= auto DisplayName= "NS8 Advanced Policy Manager Agent" | Out-Null
} else {
    Write-Host "[NS8PolicyAgent] Updating Windows Service '$ServiceName'..."
    & sc.exe config $ServiceName binPath= $BinPathCmd start= auto | Out-Null
}
& sc.exe description $ServiceName "Enforces NethServer 8 AdvancedPolicyManager policies and reports device compliance." | Out-Null
& sc.exe failure $ServiceName reset= 86400 actions= restart/15000/restart/30000/restart/60000 | Out-Null

Write-Host "[NS8PolicyAgent] Running initial policy synchronization..."
& $BinaryPath sync --once --state-dir $StateDir

Write-Host "[NS8PolicyAgent] Starting Windows Service '$ServiceName'..."
Start-Service -Name $ServiceName
Write-Host "[NS8PolicyAgent] Installation and enrollment completed successfully."
