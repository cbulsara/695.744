[BITS 32]
;;;;;;;;;;
;; TEST
;;;;;;;;;;
db  0xA9
db  0x44
db  0x43
db  0x42
db  0x41
test ecx, 0x11223344
test dword [ecx], 0x11223344
test dword [byte ecx + 4], 0x11223344
test dword [dword ecx + 4], 0x11223344
test dword [0x44556677], 0x11223344
test ecx, esi
test dword [ecx], esi
test dword [byte ecx + 4], esi
test dword [dword ecx + 4], esi
test esi, dword [ecx]
test esi, dword [byte ecx + 4]
test esi, dword [dword ecx + 4]
test esi, dword [0x44556677]