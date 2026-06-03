# rablab-hack-tracker - desinstalleur Windows.
# Usage normal : rablab-hack-tracker uninstall
# Usage kill switch (declenche par l'agent) : powershell -File uninstall-windows.ps1 -KillSwitch
param([switch]$KillSwitch)
$ErrorActionPreference = "SilentlyContinue"

$InstallDir = Join-Path $env:LOCALAPPDATA "rablab-hack-tracker"
$AgentDir   = Join-Path $InstallDir "endpoint-agent"
$VenvPy     = Join-Path $InstallDir ".venv\Scripts\python.exe"
$BinCmd     = Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps\rablab-hack-tracker.cmd"

if (-not $KillSwitch) {
  $ans = Read-Host "Tu vas desinstaller l'agent rablab-hack-tracker. Sur ? [O/N]"
  if ($ans -notmatch '^(o|y)$') { Write-Host "Annule."; exit 0 }
  # Message Slack 👋 (le kill switch a deja envoye son propre message).
  & $VenvPy (Join-Path $AgentDir "src\agent.py") notify-uninstall
}

# Retrait du demarrage auto (cle Run HKCU) + arret du process en cours
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "rablab-hack-tracker" -ErrorAction SilentlyContinue
# Tuer le process agent (lance via pythonw/python depuis notre dossier d'install)
Get-CimInstance Win32_Process -Filter "Name='pythonw.exe' OR Name='python.exe'" |
  Where-Object { $_.CommandLine -like "*rablab-hack-tracker*agent.py*" } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
# Au cas ou une ancienne version aurait cree une tache planifiee
Unregister-ScheduledTask -TaskName "rablab-hack-tracker" -Confirm:$false -ErrorAction SilentlyContinue

# Retrait du CLI
Remove-Item -Force $BinCmd

# Logs : conserves par defaut (audit). On retire les secrets runtime.
if (-not $KillSwitch) {
  $rl = Read-Host "Supprimer aussi les logs locaux ? [O/N] (defaut N)"
} else { $rl = "N" }

Remove-Item -Force (Join-Path $InstallDir "runtime.json")
Remove-Item -Force (Join-Path $InstallDir "config.json")

# Le code + venv. On laisse l'agent.log si on ne supprime pas les logs.
if ($rl -match '^(o|y)$') {
  Remove-Item -Recurse -Force $InstallDir
} else {
  Get-ChildItem $InstallDir -Exclude "agent.log","tracker.db" | Remove-Item -Recurse -Force
}

Write-Host "Desinstallation terminee. A plus."
