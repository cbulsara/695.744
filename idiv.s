[BITS 32]
idiv ecx
idiv dword [ecx]
idiv dword [byte ecx + 4]
idiv dword [dword ecx + 4]
idiv dword [0x44556677]