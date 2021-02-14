[BITS 32]

add eax, 0x11223344
add dword [edx], 0x11223344
add dword [0x55667788], 0x11223344
add dword [edx + 4], 0x11223344
add dword [edx + 0x55667788], 0x11223344
add edx, 0x11223344
add edx, [eax]
add [edx], eax
add dword [0x112344], esp
add edx, [eax + 4]
add [edx + 4], eax
add [edx + 0x11223344], eax
add edx, [eax + 0x11223344]
add edx, edx
add edi, dword [0x44556677]
