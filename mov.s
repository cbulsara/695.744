[BITS 32]
mov ecx, 0x11223344
mov dword [ecx], 0x11223344
mov dword [byte ecx + 4], 0x11223344
mov dword [dword ecx + 4], 0x11223344
mov dword [0x44556677], 0x11223344
mov ecx, esi
mov dword [ecx], esi
mov dword [byte ecx + 4], esi
mov dword [dword ecx + 4], esi
mov esi, dword [ecx]
mov esi, dword [byte ecx + 4]
mov esi, dword [dword ecx + 4]
mov esi, dword [0x44556677]