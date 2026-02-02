# Pwn & Reverse Engineering Cheatsheet

## GDB (GNU Debugger)

### Basic Commands
- `break main` (or `b main`): Set breakpoint at main.
- `run` (or `r`): Start execution.
- `continue` (or `c`): Continue execution.
- `next` (or `n`): Step over.
- `step` (or `s`): Step into.
- `info registers` (or `i r`): Show registers.
- `x/10gx $rsp`: Examine 10 giant words (64-bit) in hex at stack pointer.
- `x/10i $rip`: Examine 10 instructions at instruction pointer.

### Pwntools Cyclic
- Generate pattern: `cyclic 100`
- Find offset: `cyclic -l <crash_address>`

## GDB Enhanced (Pwndbg / GEF)

### Pwndbg Specific
- `checksec`: Check binary security settings.
- `vmmap`: Show memory mappings.
- `searchmem "string"`: Search for string in memory.
- `rop`: List ROP gadgets (if configured).
- `telescope`: Dump stack with resolved pointers.

### GEF Specific
- `gef config`: Configure GEF.
- `pattern create 100`: Create cyclic pattern.
- `pattern offset <value>`: Find offset.
- `heap chunks`: Inspect heap chunks.

## ROP (Return Oriented Programming)

### ROPgadget Tool
- **Find gadgets:** `ROPgadget --binary <binary>`
- **Find specific gadget:** `ROPgadget --binary <binary> | grep "pop rdi"`
- **Generate ROP chain:** `ROPgadget --binary <binary> --ropchain`
- **Search for string:** `ROPgadget --binary <binary> --string "/bin/sh"`

### Ropper
- `ropper --file <binary> --search "pop rdi"`
- `ropper --file <binary> --chain "execve"`

## Common Shellcodes

### Linux x64 (27 bytes)
`\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05`

### Linux x86 (23 bytes)
`\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80`

## Format String Vulnerabilities

- `%s`: Read string from address on stack.
- `%x`: Read hex value from stack.
- `%p`: Read pointer value.
- `%n`: Write number of bytes printed so far to address.
- `%10$p`: Read the 10th argument on the stack.

## Checksec (Security Mitigations)

- **RELRO**: Read-Only Relocations (Partial/Full). Harder to overwrite GOT.
- **Stack Canary**: Value on stack to detect overflows.
- **NX**: No-Execute. Stack is not executable (need ROP).
- **PIE**: Position Independent Executable. Randomizes code segment base address.
