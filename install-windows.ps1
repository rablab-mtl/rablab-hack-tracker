# rablab-hack-tracker - installeur Windows.
# Usage : iwr -useb https://raw.githubusercontent.com/rablab-mtl/rablab-hack-tracker/main/install-windows.ps1 | iex
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$ZipUrl     = "https://github.com/rablab-mtl/rablab-hack-tracker/archive/refs/heads/main.zip"
$InstallDir = Join-Path $env:LOCALAPPDATA "rablab-hack-tracker"
$AgentDir   = Join-Path $InstallDir "endpoint-agent"
$Venv       = Join-Path $InstallDir ".venv"
$VenvPy     = Join-Path $Venv "Scripts\python.exe"
$WorkerUrl  = "https://rablab-gads-monitor.rablab.workers.dev"
$BinDir     = Join-Path $env:LOCALAPPDATA "Microsoft\WindowsApps"
$LogPath    = Join-Path $env:TEMP "rablab-hack-tracker-install.log"

Start-Transcript -Path $LogPath -Force | Out-Null
try {
  Write-Host "=== rablab-hack-tracker : installation (Windows) ==="

  # PowerShell par defaut est en "Restricted", ce qui bloque uv et certains outils.
  # On passe en Bypass UNIQUEMENT pour ce processus : non permanent, sans droits admin.
  try { Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force } catch { }

  # 1. Obtenir Python 3.9+ en UNE etape. uv en secours (sans winget, sans Microsoft Store, sans git).
  $PyExe = $null
  foreach ($c in @("py -3.13","py -3.12","py -3.11","py -3.10","py -3.9")) {
    try {
      $parts = $c.Split(" ")
      $exe = & $parts[0] $parts[1..($parts.Length-1)] -c "import sys;print(sys.executable)" 2>$null
      if ($exe -and (Test-Path $exe)) { $PyExe = $exe; break }
    } catch { }
  }
  if (-not $PyExe) {
    # python.exe reel uniquement (pas l'alias Microsoft Store dans WindowsApps)
    try {
      $exe = & python -c "import sys;print(sys.executable)" 2>$null
      if ($exe -and (Test-Path $exe) -and ($exe -notlike "*WindowsApps*")) {
        $v = & python -c "import sys;print('%d%d'%sys.version_info[:2])" 2>$null
        if ([int]$v -ge 39) { $PyExe = $exe }
      }
    } catch { }
  }
  if (-not $PyExe) {
    Write-Host "Aucun Python detecte : installation automatique d'un Python dedie (uv)..."
    irm https://astral.sh/uv/install.ps1 | iex
    $env:Path = "$env:USERPROFILE\.local\bin;$env:Path"
    uv python install 3.12
    $PyExe = (uv python find 3.12)
  }
  if (-not $PyExe) { throw "Impossible d'obtenir Python automatiquement." }
  Write-Host "Python : $PyExe"

  # 2. Telecharger le code en ZIP (PAS besoin de git, souvent absent sur Windows).
  Write-Host "Telechargement du code..."
  $zip = Join-Path $env:TEMP "rablab-hack-tracker-main.zip"
  Invoke-WebRequest -UseBasicParsing -Uri $ZipUrl -OutFile $zip
  if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir }
  $extract = Join-Path $env:TEMP "rht-extract"
  if (Test-Path $extract) { Remove-Item -Recurse -Force $extract }
  Expand-Archive -Path $zip -DestinationPath $extract -Force
  Move-Item (Join-Path $extract "rablab-hack-tracker-main") $InstallDir
  Remove-Item -Recurse -Force $extract -ErrorAction SilentlyContinue
  Remove-Item -Force $zip -ErrorAction SilentlyContinue

  # 3. venv + dependances
  Write-Host "Creation de l'environnement Python..."
  & $PyExe -m venv $Venv
  & $VenvPy -m pip install -q --upgrade pip
  & $VenvPy -m pip install -q -r (Join-Path $AgentDir "requirements.txt")

  # 4. UNE seule question : email Rablab
  $Email = Read-Host "Quel est ton email Rablab ? (ex : prenom.n@rablab.ca)"
  if (-not $Email) { throw "Email vide, installation annulee." }

  # 5. Disclaimer Loi 25
  Write-Host ""
  Get-Content (Join-Path $AgentDir "DISCLAIMER.txt") | Write-Host
  Write-Host ""
  $Consent = Read-Host "Tu acceptes l'installation ? [O/N]"
  if ($Consent -notmatch '^(o|y|ok)$') {
    Write-Host "Installation annulee."
  } else {
    # 6. Config locale
    $cfg = @{ email = $Email; device_label = $env:COMPUTERNAME; worker_url = $WorkerUrl } | ConvertTo-Json
    # Ecrire SANS BOM : Python lit le JSON en utf-8, un BOM le ferait echouer.
    [System.IO.File]::WriteAllText((Join-Path $InstallDir "config.json"), $cfg, (New-Object System.Text.UTF8Encoding($false)))

    # 7. Finaliser l'install (fetch config, hash, message Slack d'install)
    & $VenvPy (Join-Path $AgentDir "src\agent.py") install

    # 8. CLI rablab-hack-tracker (.cmd dans un dossier deja sur le PATH user)
    New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
    $cmd = "@echo off`r`n" +
           "if /I `"%1`"==`"uninstall`" (powershell -ExecutionPolicy Bypass -File `"$AgentDir\uninstall-windows.ps1`" & goto :eof)`r`n" +
           "`"$VenvPy`" `"$AgentDir\src\agent.py`" %1`r`n"
    Set-Content -Path (Join-Path $BinDir "rablab-hack-tracker.cmd") -Value $cmd -Encoding ASCII

    # 9. Demarrage auto au logon via la cle Run (HKCU, sans admin, contrairement aux
    #    taches planifiees souvent bloquees par la politique d'org) + lancement immediat.
    #    pythonw.exe = pas de fenetre console qui s'ouvre.
    $VenvPyw = Join-Path $Venv "Scripts\pythonw.exe"
    if (-not (Test-Path $VenvPyw)) { $VenvPyw = $VenvPy }  # repli si pythonw absent
    $AgentPy = Join-Path $AgentDir "src\agent.py"
    $runValue = '"' + $VenvPyw + '" "' + $AgentPy + '" run'
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "rablab-hack-tracker" -Value $runValue
    Start-Process -FilePath $VenvPyw -ArgumentList @($AgentPy, "run") -WindowStyle Hidden

    Write-Host ""
    Write-Host "Installation terminee. Tu verras une confirmation dans le canal Slack."
    Write-Host "  Verifier : rablab-hack-tracker status"
    Write-Host "  Desinstaller : rablab-hack-tracker uninstall"
  }
} catch {
  Write-Host ""
  Write-Host "ERREUR pendant l'installation : $($_.Exception.Message)"
  Write-Host "Envoie ce fichier de journal a l'equipe securite : $LogPath"
} finally {
  Stop-Transcript | Out-Null
  Read-Host "Appuie sur Entree pour fermer cette fenetre"
}
