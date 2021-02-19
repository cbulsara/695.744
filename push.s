[BITS 32]
db 0xFF
db 0xF7 
push ecx
push dword [ ecx ]
push dword [ byte ecx + 4 ]
push dword [ dword ecx + 4 ]
push dword [ 0x44556677 ]
push 0x44556677