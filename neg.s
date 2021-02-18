[BITS 32]
neg ecx
neg dword [ecx]
neg dword [byte ecx + 4]
neg dword [dword ecx + 4]
neg dword [0x44556677]