[BITS 32]

add dword [edx], 0x11223344
add dword [0x55667788], 0x11223344
;add dword [edx + 4], 0x11223344
;add dword [edx + 0x55667788], 0x11223344
;mov [edi], eax
;mov edi, [eax]