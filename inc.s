[BITS 32]
inc eax
inc dword [ecx]
inc dword [byte ecx + 4]
inc dword [dword ecx + 4]
inc dword [0x44556677]