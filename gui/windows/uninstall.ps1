# Removes what install.ps1 put in place, for the current user:
#
#     powershell -ExecutionPolicy Bypass -File uninstall.ps1
#
# The configuration and the log are kept (%APPDATA%\hem-ssh-agent,
# %LOCALAPPDATA%\hem-ssh-agent); the keys are in the HEM and stay there.
$ErrorActionPreference = 'Stop'

$target = Join-Path $env:LOCALAPPDATA 'Programs\hem-ssh-agent'
$cli    = Join-Path $target 'hem-ssh-agent.exe'

if (Test-Path $cli) { & $cli uninstall | Out-Null }

Get-Process -Name 'hem-ssh-agent-gui', 'hem-ssh-agentw' -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -and $_.Path.StartsWith($target, [StringComparison]::OrdinalIgnoreCase) } |
    Stop-Process -Force
Start-Sleep -Milliseconds 500

Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\HEM SSH agent.lnk')
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue 'HKCU:\SOFTWARE\Classes\AppUserModelId\com.encedo.hem-ssh-agent'
if (Test-Path $target) { Remove-Item -Recurse -Force $target }

Write-Host "Removed. Kept: $(Join-Path $env:APPDATA 'hem-ssh-agent') (configuration) and $(Join-Path $env:LOCALAPPDATA 'hem-ssh-agent') (log)."
