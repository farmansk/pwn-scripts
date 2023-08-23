from pwn import *
io = process('../../TFC/random')

#random
import ctypes
import time

# Load the C library
libc = ctypes.CDLL("libc.so.6")

# Define the C functions
libc.time.argtypes = [ctypes.POINTER(ctypes.c_long)]
libc.time.restype = ctypes.c_long

libc.srand.argtypes = [ctypes.c_uint]
libc.srand.restype = None

libc.rand.restype = ctypes.c_int

# Seed the random number generator with the current time
current_time = ctypes.c_long()
libc.time(ctypes.byref(current_time))
current_time_seconds = int(current_time.value)
libc.srand(current_time_seconds)

# Generate and print 10 random numbers
for i in range(10):
    random_number = libc.rand()
    io.sendline(str(random_number).encode())
io.interactive()
