[BITS 32]
db 0x8F
db 0xC7
pop ecx
pop dword [ ecx ]
pop dword [ byte ecx + 4 ]
pop dword [ dword ecx + 4 ]
pop dword [ 0x44556677 ]
