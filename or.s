[BITS 32]
or ecx, 0x11223344
or dword [ecx], 0x11223344
or dword [byte ecx + 4], 0x11223344
or dword [dword ecx + 4], 0x11223344
or dword [0x44556677], 0x11223344
or ecx, esi
or dword [ecx], esi
or dword [byte ecx + 4], esi
or dword [dword ecx + 4], esi
or esi, dword [ecx]
or esi, dword [byte ecx + 4]
or esi, dword [dword ecx + 4]
or esi, dword [0x44556677]