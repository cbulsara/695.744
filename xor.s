[BITS 32]
;;;;;;;;;;
;; XOR
;;;;;;;;;;
db  0x35
db  0x44
db  0x43
db  0x42
db  0x41
xor ecx, 0x11223344
xor dword [ecx], 0x11223344
xor dword [byte ecx + 4], 0x11223344
xor dword [dword ecx + 4], 0x11223344
xor dword [0x44556677], 0x11223344
xor ecx, esi
xor dword [ecx], esi
xor dword [byte ecx + 4], esi
xor dword [dword ecx + 4], esi
xor esi, dword [ecx]
xor esi, dword [byte ecx + 4]
xor esi, dword [dword ecx + 4]
xor esi, dword [0x44556677]