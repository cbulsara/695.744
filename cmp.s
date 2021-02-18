[BITS 32]
label_cmp:
db  0x3d
db  0x44
db  0x43
db  0x42
db  0x41
cmp ecx, 0x11223344
cmp dword [ecx], 0x11223344
cmp dword [byte ecx + 4], 0x11223344
cmp dword [dword ecx + 4], 0x11223344
cmp dword [0x44556677], 0x11223344
cmp ecx, esi
cmp dword [ecx], esi
cmp dword [byte ecx + 4], esi
cmp dword [dword ecx + 4], esi
cmp esi, dword [ecx]
cmp esi, dword [byte ecx + 4]
cmp esi, dword [dword ecx + 4]
cmp esi, dword [0x44556677]