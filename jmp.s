[BITS 32]
short_label:
jmp short 0x08
jmp near short_label ; jmp back
jmp near forward_label ; jmp forward
jmp near 0x11223344
jmp short forward_label
forward_label:
jmp short short_label
jmp ecx
jmp dword [ecx]
jmp dword [byte ecx + 4]
jmp dword [dword ecx + 4]
jmp dword [0x44556677]