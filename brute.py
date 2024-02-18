import angr
from pwn import *
import logging

logging.getLogger('angr').setLevel('DEBUG')
# Load the binary
project = angr.Project('../lactf/aplet123', main_opts={'base_addr': 0}, auto_load_libs=False)
elf = context.binary = ELF('../lactf/aplet123', checksec=False)

# Set the target address
target_address = elf.sym.print_flag
avoid_address = 0x004013d5

# Create a symbolic state at the target address
initial_state = project.factory.entry_state()
print(initial_state)

# Continue executing instructions
sm = project.factory.simgr(initial_state)

sm.explore(find=target_address, avoid=avoid_address)
print(sm)
print(sm.found[0].posix.dumps(1))
