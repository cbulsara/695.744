[BITS 32]

xor eax, eax
add eax, ecx
add eax, edx
push ebp
mov ebp, esp
push edx
push ecx
mov eax, 041424344h
mov edx, dword [ dword ebp + 08h] ; the first dword refers to the memory access, the second refers to the size of the immediate (0x00000008)
mov ecx, dword [ dword ebp + 0ch] ; the first dword refers to the memory access, the second refers to the size of the immediate (0x0000000c)
add ecx, edx
mov eax, ecx
pop edx
pop ecx
pop ebp
retn 08h
