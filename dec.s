[BITS 32]
dec ecx
dec dword [ecx]
dec dword [byte ecx + 4]
dec dword [dword ecx + 4]
dec dword [0x44556677]