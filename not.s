[BITS 32]
not ecx
not dword [ecx]
not dword [byte ecx + 4]
not dword [dword ecx + 4]
not dword [0x44556677]