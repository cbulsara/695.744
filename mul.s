[BITS 32]
mul ecx
mul dword [ecx]
mul dword [byte ecx + 4]
mul dword [dword ecx + 4]
mul dword [0x44556677]