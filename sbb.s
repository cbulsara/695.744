[BITS 32]
;;;;;;;;;;
;; SBB
;;;;;;;;;;
sbb ecx, 0x11223344
sbb dword [ecx], 0x11223344
sbb dword [byte ecx + 4], 0x11223344
sbb dword [dword ecx + 4], 0x11223344
sbb dword [0x44556677], 0x11223344
sbb ecx, esi
sbb dword [ecx], esi
sbb dword [byte ecx + 4], esi
sbb dword [dword ecx + 4], esi
sbb esi, dword [ecx]
sbb esi, dword [byte ecx + 4]
sbb esi, dword [dword ecx + 4]
sbb esi, dword [0x44556677]