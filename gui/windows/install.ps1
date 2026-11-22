# Installs hem-ssh-agent for the current user - no administrator rights:
#
#     powershell -ExecutionPolicy Bypass -File install.ps1 [-Config <file>]
#
# Copies the programs to %LOCALAPPDATA%\Programs\hem-ssh-agent, adds a Start
# menu entry, names the notifications, and registers the window to start at
# logon (`hem-ssh-agent install`, the current user's Run key); the window
# starts the agent. An installed copy that is running is stopped first.
#
# The configuration (default %APPDATA%\hem-ssh-agent\config.toml) must exist
# and name the keys; it is never written here.
param([string]$Config)
$ErrorActionPreference = 'Stop'

$source = $PSScriptRoot
$target = Join-Path $env:LOCALAPPDATA 'Programs\hem-ssh-agent'
$files  = @('hem-ssh-agent.exe', 'hem-ssh-agentw.exe', 'hem-ssh-agent-gui.exe', 'icon.ico')
foreach ($f in $files) {
    if (-not (Test-Path (Join-Path $source $f))) {
        throw "$f is missing from $source. Unpack the whole bundle before running this."
    }
}

$cfg = if ($Config) { (Resolve-Path $Config).Path } else { Join-Path $env:APPDATA 'hem-ssh-agent\config.toml' }
if (-not (Test-Path $cfg)) {
    $cli = Join-Path $source 'hem-ssh-agent.exe'
    Write-Host @"
No configuration at $cfg. Make one first (README.txt):

  & '$cli' keys   --url https://<your HEM>
  & '$cli' pubkey --url https://<your HEM> --kid <kid>

then put url, auth and a [[key]] with that kid and pubkey into $cfg
and run this again.
"@
    exit 1
}

# An installed copy that is running holds the files: stop it (only that one).
Get-Process -Name 'hem-ssh-agent-gui', 'hem-ssh-agentw' -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -and $_.Path.StartsWith($target, [StringComparison]::OrdinalIgnoreCase) } |
    Stop-Process -Force
Start-Sleep -Milliseconds 500

New-Item -ItemType Directory -Force -Path $target | Out-Null
foreach ($f in $files) {
    Copy-Item -Force (Join-Path $source $f) (Join-Path $target $f)
}
Write-Host "Placed in $target"

$menu  = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\HEM SSH agent.lnk'
$shell = New-Object -ComObject WScript.Shell
$link  = $shell.CreateShortcut($menu)
$link.TargetPath       = Join-Path $target 'hem-ssh-agent-gui.exe'
$link.WorkingDirectory = $target
$link.IconLocation     = Join-Path $target 'icon.ico'
$link.Description      = 'SSH keys that never leave the Encedo HEM'
if ($Config) { $link.Arguments = "-config `"$cfg`"" }
$link.Save()

# What a notification calls this program: Fyne sends it under the app ID,
# which without this shows as "com.encedo.hem-ssh-agent".
$aumid = 'HKCU:\SOFTWARE\Classes\AppUserModelId\com.encedo.hem-ssh-agent'
New-Item -Path $aumid -Force | Out-Null
New-ItemProperty -Path $aumid -Name DisplayName -PropertyType String -Force -Value 'HEM SSH agent' | Out-Null
New-ItemProperty -Path $aumid -Name IconUri -PropertyType String -Force -Value (Join-Path $target 'icon.ico') | Out-Null

$installArgs = @()
if ($Config) { $installArgs += @('--config', $cfg) }
$installArgs += @('install', '--start')
& (Join-Path $target 'hem-ssh-agent.exe') @installArgs
if ($LASTEXITCODE -ne 0) { throw "hem-ssh-agent install failed ($LASTEXITCODE)" }

Write-Host @"

Done. The tray icon is the window; it starts the agent, now and at every logon.

  ssh:  use the Windows OpenSSH (C:\Windows\System32\OpenSSH), README.txt says how for Git
  log:  %LOCALAPPDATA%\hem-ssh-agent\agent.log
  remove all of it: uninstall.ps1
"@
