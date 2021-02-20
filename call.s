[BITS 32]
label_back:
call label_back
call label_forward
call edx
call [byte edx + 0x04]
label_forward:
call [edx]
call [dword 0x11223344]
call [dword edx + 0x11223344]
