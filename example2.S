[BITS 32]

push ebp
mov ebp, esp
push edx
push ecx
cmp ecx, edx
jz  label_error
mov eax, 041424344h
mov edx, dword [ byte ebp + 08h] ; by default, the assembler will likely make 0x08 a byte, but the byte qualifier guarantees it
mov ecx, dword [ byte ebp + 0ch] ; by default, the assembler will likely make 0x0c a byte, but the byte qualifier guarantees it
add ecx, edx
mov eax, ecx
label_error:
pop edx
pop ecx
pop ebp
retn 08h
