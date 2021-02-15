[BITS 32]
and eax, 0x11223344
and dword [edx], 0x11223344
and dword [0x55667788], 0x11223344
and dword [edx + 4], 0x11223344
and dword [edx + 0x55667788], 0x11223344
and edx, 0x11223344
and edx, [eax]
and [edx], eax
and dword [0x112344], esp
and edx, [eax + 4]
and [edx + 4], eax
and [edx + 0x11223344], eax
and edx, [eax + 0x11223344]
and edx, edx