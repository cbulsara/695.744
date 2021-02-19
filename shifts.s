[BITS 32]
sal ecx, 1
sal dword [ ecx ], 1
sal dword [ byte ecx + 4 ], 1
sal dword [ dword ecx + 4 ], 1
sar ecx, 1
sar dword [ ecx ], 1
sar dword [ byte ecx + 4 ], 1
sar dword [ dword ecx + 4 ], 1
shr ecx, 1
shr dword [ ecx ], 1
shr dword [ byte ecx + 4 ], 1
shr dword [ dword ecx + 4 ], 1
