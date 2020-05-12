import sys
from ctypes import *

#./dlinjector <PID> <Path to DLL>. (give full path even if dll in same directory)

pid=sys.argv[1]
dll_path=sys.argv[2]
PAGE_READWRITE=0x04 ##Enables read-only or read/write access to the committed region of pages.
PROCESS_ALL_ACCESS=(0x000F0000 | 0x00100000 | 0xFFF) ##All possible access rights for a process object.
VIRTUAL_MEM=(0x1000 | 0x2000) ##MEM_COMMIT | MEM_RESERVE
kernel32=windll.kernel32
dll_length=len(dll_path)
handle_process=kernel32.OpenProcess(PROCESS_ALL_ACCESS,False,int(pid))
arg_address=kernel32.VirtualAllocEx(handle_process,0,dll_length,VIRTUAL_MEM,PAGE_READWRITE)
written = c_int(0)
kernel32.WriteProcessMemory(handle_process,arg_address,dll_path,dll_len,byref(written))
handle_kernel32=kernel32.GetModuleHandleA("kernel32.dll")
handle_loadlib=kernel32.GetProcAddress(handle_kernel32,"LoadLibraryA")
thread_id=c_ulong(0)
kernel32.CreateRemoteThread(handle_process, None,0,handle_loadlib,arg_address,0,byref(thread_id))

print("Thread with ID 0x%08x created."%thread_id.value)
