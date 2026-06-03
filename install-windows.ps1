# rablab-hack-tracker - installeur Windows.
# Usage : iwr -useb https://raw.githubusercontent.com/rablab-mtl/rablab-hack-tracker/main/install-windows.ps1 | iex
$ErrorActionPreference = "Stop"

$RepoUrl    = "https://github.com/rablab-mtl/rablab-hack-tracker.git"
$InstallDir = Join-Path $env:LOCALAPPDATA "rablab-hack-tracker"
$AgentDir   = Join-Path $InstallDir "endpoint-agent"
$Venv       = Join-Path $InstallDir ".venv"
$VenvPy     = Join-Path $Venv "Scripts\python.exe"
$WorkerUrl  = "https://rablab-gads-monitor.rablab.workers.dev"
$BinDir     = Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps"

Write-Host "=== rablab-hack-tracker : installation (Windows) ==="

# 1. Trouver Python 3.11+
$PyCmd = $null
foreach ($c in @("py -3.13","py -3.12","py -3.11","python")) {
  try {
    $parts = $c.Split(" ")
    $ver = & $parts[0] $parts[1..($parts.Length-1)] -c "import sys;print('%d.%d'%sys.version_info[:2])" 2>$null
    if ($ver) {
      $maj,$min = $ver.Split(".")
      if ([int]$maj -eq 3 -and [int]$min -ge 11) { $PyCmd = $c; break }
    }
  } catch { }
}
if (-not $PyCmd) {
  Write-Host "Python 3.11+ requis. Installe-le puis relance :"
  Write-Host "  winget install Python.Python.3.11"
  exit 1
}
Write-Host "Python : $PyCmd"

# 2. Cloner ou mettre a jour
if (Test-Path (Join-Path $InstallDir ".git")) {
  git -C $InstallDir pull --ff-only
} else {
  git clone --depth 1 $RepoUrl $InstallDir
}

# 3. venv + dependances
$pp = $PyCmd.Split(" ")
& $pp[0] $pp[1..($pp.Length-1)] -m venv $Venv
& $VenvPy -m pip install -q --upgrade pip
& $VenvPy -m pip install -q -r (Join-Path $AgentDir "requirements.txt")

# 4. UNE seule question : email Rablab
$Email = Read-Host "Quel est ton email Rablab ? (ex : prenom.n@rablab.ca)"
if (-not $Email) { Write-Host "Email vide, annulation."; exit 1 }

# 5. Disclaimer Loi 25
Write-Host ""
Get-Content (Join-Path $AgentDir "DISCLAIMER.txt") | Write-Host
Write-Host ""
$Consent = Read-Host "Tu acceptes l'installation ? [O/N]"
if ($Consent -notmatch '^(o|y|ok)$') { Write-Host "Installation annulee."; exit 0 }

# 6. Config locale
$ConfigDir = $InstallDir
$cfg = @{ email = $Email; device_label = $env:COMPUTERNAME; worker_url = $WorkerUrl } | ConvertTo-Json
Set-Content -Path (Join-Path $ConfigDir "config.json") -Value $cfg -Encoding UTF8

# 7. Finaliser l'install (fetch config, hash, message Slack d'install)
& $VenvPy (Join-Path $AgentDir "src\agent.py") install

# 8. CLI rablab-hack-tracker (.cmd dans un dossier deja sur le PATH user)
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
$cmd = "@echo off`r`n" +
       "if /I `"%1`"==`"uninstall`" (powershell -ExecutionPolicy Bypass -File `"$AgentDir\uninstall-windows.ps1`" & goto :eof)`r`n" +
       "`"$VenvPy`" `"$AgentDir\src\agent.py`" %1`r`n"
Set-Content -Path (Join-Path $BinDir "rablab-hack-tracker.cmd") -Value $cmd -Encoding ASCII

# 9. Scheduled Task au logon (redemarre la session de monitoring)
$action  = New-ScheduledTaskAction -Execute $VenvPy -Argument "`"$AgentDir\src\agent.py`" run"
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName "rablab-hack-tracker" -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName "rablab-hack-tracker"

Write-Host ""
Write-Host "Installation terminee. Tu peux fermer cette fenetre."
Write-Host "  Verifier : rablab-hack-tracker status"
Write-Host "  Desinstaller : rablab-hack-tracker uninstall"
