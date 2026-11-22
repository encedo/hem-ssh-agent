hem-ssh-agent for Windows (@ARCH@), build @BUILD@
An SSH agent whose Ed25519 keys live in an Encedo HEM (firmware 1.3 or later).

  hem-ssh-agent.exe      the command line: keys, pubkey, run, install
  hem-ssh-agentw.exe     the same agent without a console window
  hem-ssh-agent-gui.exe  the tray icon: state, phone approvals, Unlock
  install.ps1            installs for the current user (no administrator)
  uninstall.ps1          removes it again

1. The configuration, %APPDATA%\hem-ssh-agent\config.toml:

     .\hem-ssh-agent.exe keys   --url https://<your HEM>
     .\hem-ssh-agent.exe pubkey --url https://<your HEM> --kid <kid>

     url  = "https://<your HEM>"
     auth = "remote"        # approve on the phone; "password": Unlock in the tray
     [[key]]
     kid    = "<kid>"
     pubkey = "<the pubkey line>"

2. powershell -ExecutionPolicy Bypass -File install.ps1

   The agent listens on the Windows OpenSSH pipe; the Windows "ssh-agent"
   service must be stopped and disabled (as administrator):
     Stop-Service ssh-agent; Set-Service ssh-agent -StartupType Disabled

3. Git: use the Windows OpenSSH, not the one bundled with Git:
     git config --global core.sshCommand C:/Windows/System32/OpenSSH/ssh.exe
   Commit signing:
     git config --global gpg.format ssh
     git config --global gpg.ssh.program C:/Windows/System32/OpenSSH/ssh-keygen.exe
     git config --global user.signingkey C:/path/to/key.pub

Password mode: Unlock from the tray icon. "Remember the password until Lock"
keeps the key derived from it in the window, which renews the agent's token
by itself; off, unlock again when the token expires.

Log: %LOCALAPPDATA%\hem-ssh-agent\agent.log (tray: Show log)
Source, licence (MIT): https://github.com/encedo/hem-ssh-agent
