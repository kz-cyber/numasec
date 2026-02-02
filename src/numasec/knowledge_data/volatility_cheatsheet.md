# Volatility Cheatsheet (Memory Forensics)

## Basic Usage
`volatility -f <image.mem> <plugin>`

## 1. Image Identification
- `imageinfo`: Identify OS profile.
  - `vol -f dump.mem imageinfo`

## 2. Process Enumeration
- `pslist`: List running processes (high level).
- `psscan`: Scan for process structures (finds hidden/terminated processes).
- `pstree`: Process tree (parent/child relationship).
- `cmdline`: Command line arguments used to start processes.

## 3. Network
- `netscan`: Active network connections (Vista+).
- `connscan`: Active connections (XP/2003).

## 4. File System & DLLs
- `filescan`: Scan for file objects in memory.
  - `vol -f dump.mem --profile=Win7SP1x64 filescan | grep flag`
- `dlllist`: List loaded DLLs for each process.
- `dumpfiles`: Dump a file from memory.
  - `vol -f dump.mem --profile=... dumpfiles -Q <physical_offset> -D output/`

## 5. Code Injection & Malware
- `malfind`: Find injected code / hidden DLLs.
- `ldrmodules`: Detect unlinked DLLs (hollowed processes).

## 6. Miscellaneous
- `hashdump`: Dump password hashes (SAM).
- `clipboard`: Extract clipboard contents.
- `screenshot`: Save screenshots of desktop.
- `consoles`: Command history (cmd.exe).

## Example Workflow
1. `imageinfo` -> Get Profile (e.g., Win7SP1x64).
2. `pslist` -> Look for suspicious processes (e.g., `nc.exe`, `malware.exe`).
3. `netscan` -> Check connections to bad IPs.
4. `cmdline` -> See how the suspicious process was launched.
5. `memdump -p <PID> -D output/` -> Dump process memory for strings analysis.
