[BITS 32]
imul ecx
imul dword [ecx]
imul dword [byte ecx + 4]
imul dword [dword ecx + 4]
imul esi, dword [ecx]
imul esi, dword [0x44556677]
imul dword [0x11223344]